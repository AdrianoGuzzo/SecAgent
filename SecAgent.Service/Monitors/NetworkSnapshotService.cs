using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Models;
using SecAgent.Service.Monitors.Native;

namespace SecAgent.Service.Monitors;

/// <summary>
/// Periodically enumerates ALL established TCP connections (with owning process)
/// and writes a network.json snapshot for the Tray dashboard to render a live
/// connections table. Unlike the legacy NetworkMonitor (outbound diff only),
/// this also classifies inbound connections and — when enabled — emits a
/// SecurityEvent for each NEW inbound connection from a public IP, so external
/// access (RDP/SMB/etc.) flows into the existing incident/Claude pipeline.
/// </summary>
public class NetworkSnapshotService : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly ILogger<NetworkSnapshotService> _logger;
    private readonly ChannelWriter<SecurityEvent> _writer;
    private readonly MonitorOptions _opts;
    private readonly HashSet<int> _inboundPortWhitelist;
    private readonly HashSet<int> _sensitivePorts;
    private readonly List<string> _selfFragments;
    private readonly Dictionary<string, DateTime> _lastAlertPerIp = new();
    private readonly object _alertLock = new();
    private HashSet<string> _seenInbound = new();
    private int _alertSeq;

    // Per-connection cumulative byte counters from the previous cycle, keyed by
    // 4-tuple, so we can derive a current throughput (bytes/s) by diffing.
    private Dictionary<string, ulong> _prevBytes = new();
    private DateTime _lastCycleUtc;

    public NetworkSnapshotService(
        ILogger<NetworkSnapshotService> logger,
        Channel<SecurityEvent> channel,
        IOptions<MonitorOptions> opts)
    {
        _logger = logger;
        _writer = channel.Writer;
        _opts = opts.Value;
        _inboundPortWhitelist = new HashSet<int>(_opts.InboundPortWhitelist);
        _sensitivePorts = new HashSet<int>(_opts.SensitiveInboundPorts);
        _selfFragments = _opts.SelfReferenceFragments ?? new List<string>();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.NetworkSnapshotEnabled)
        {
            _logger.LogInformation("NetworkSnapshotService disabled by config");
            return;
        }

        _logger.LogInformation("NetworkSnapshotService started (snapshot every {Sec}s)", _opts.NetworkSnapshotSeconds);

        try { Directory.CreateDirectory(_opts.AlertsDirectory); PruneOldAlerts(); } catch { }

        // Baseline so we don't fire inbound events for connections that already
        // existed when the service started.
        try { _seenInbound = SnapshotInboundKeys(); } catch { /* first cycle will rebuild */ }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                BuildAndWriteSnapshot();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "NetworkSnapshotService cycle failed");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(_opts.NetworkSnapshotSeconds), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void BuildAndWriteSnapshot()
    {
        var listeners = GetListenerPorts();
        var pidNames = BuildPidNameMap();
        var rows = IpHlpApi.GetEstablishedConnections();

        var connections = new List<NetworkConnection>(rows.Count);
        var currentInbound = new HashSet<string>();

        // Elapsed since last cycle drives the bytes/s derivation. First cycle (or
        // after a long pause) leaves _prevBytes empty → every rate is 0.
        var now = DateTime.UtcNow;
        double elapsed = (now - _lastCycleUtc).TotalSeconds;
        if (elapsed <= 0 || elapsed > 60) elapsed = 0;       // ignore stale/garbage intervals
        var nextBytes = new Dictionary<string, ulong>(rows.Count);

        foreach (var r in rows)
        {
            // Direction: if our local port is one we're listening on, the peer
            // initiated the connection → inbound. Otherwise outbound.
            bool inbound = listeners.Contains(r.LocalPort);
            string direction = inbound ? "inbound" : "outbound";
            bool remotePublic = !IsZero(r.RemoteAddress) && NetworkMonitor.IsPublicAddress(r.RemoteAddress);
            string procName = pidNames.TryGetValue(r.OwningPid, out var n) ? n : "desconhecido";

            // Throughput: diff this connection's cumulative bytes vs last cycle.
            ulong cum = r.CumBytesIn + r.CumBytesOut;
            var connKey = $"{r.LocalAddress}:{r.LocalPort}|{r.RemoteAddress}:{r.RemotePort}";
            nextBytes[connKey] = cum;
            long bytesPerSec = 0;
            if (elapsed > 0 && _prevBytes.TryGetValue(connKey, out var prev) && cum >= prev)
                bytesPerSec = (long)((cum - prev) / elapsed);

            connections.Add(new NetworkConnection(
                Direction: direction,
                LocalAddress: r.LocalAddress.ToString(),
                LocalPort: r.LocalPort,
                RemoteAddress: r.RemoteAddress.ToString(),
                RemotePort: r.RemotePort,
                ProcessName: procName,
                Pid: r.OwningPid,
                RemoteIsPublic: remotePublic,
                BytesPerSec: bytesPerSec));

            if (inbound && remotePublic)
            {
                var key = $"{r.RemoteAddress}:{r.RemotePort}|{r.LocalPort}";
                currentInbound.Add(key);
                MaybeEmitInbound(key, r, procName);
            }
        }

        _prevBytes = nextBytes;        // drop connections that vanished — no leak
        _lastCycleUtc = now;
        _seenInbound = currentInbound;
        WriteSnapshotAtomic(new NetworkSnapshot(now, connections));
    }

    private void MaybeEmitInbound(string key, IpHlpApi.TcpConnectionRow r, string procName)
    {
        if (!_opts.EmitInboundEvents) return;
        if (_seenInbound.Contains(key)) return;               // already handled this connection
        if (_inboundPortWhitelist.Contains(r.LocalPort)) return;
        if (IsSelfReference(procName)) return;

        bool sensitive = _sensitivePorts.Contains(r.LocalPort);

        // 1) SecurityEvent → slower incident/Claude pipeline.
        var evt = new SecurityEvent(
            TimestampUtc: DateTime.UtcNow,
            Source: "network",
            Severity: sensitive ? "high" : "medium",
            Title: $"Conexão de entrada de {r.RemoteAddress}:{r.RemotePort}",
            Description: "Um host externo (IP público) abriu uma conexão de ENTRADA para esta máquina. Pode ser acesso legítimo (ex.: serviço exposto) ou tentativa de acesso não autorizado.",
            Details: new Dictionary<string, string>
            {
                ["direction"] = "inbound",
                ["remoteAddress"] = r.RemoteAddress.ToString(),
                ["remotePort"] = r.RemotePort.ToString(),
                ["localPort"] = r.LocalPort.ToString(),
                ["processName"] = procName,
                ["pid"] = r.OwningPid.ToString(),
                ["sensitivePort"] = sensitive ? "true" : "false"
            });
        _writer.TryWrite(evt);

        // 2) Immediate alert file → always-on Tray toast (per-IP cooldown).
        WriteAlertIfDue(r, procName, sensitive);
    }

    private void WriteAlertIfDue(IpHlpApi.TcpConnectionRow r, string procName, bool sensitive)
    {
        var ip = r.RemoteAddress.ToString();
        lock (_alertLock)
        {
            if (_lastAlertPerIp.TryGetValue(ip, out var last) &&
                DateTime.UtcNow - last < TimeSpan.FromMinutes(_opts.InboundAlertCooldownMinutes))
                return;
            _lastAlertPerIp[ip] = DateTime.UtcNow;
        }

        var portLabel = PortLabel(r.LocalPort);
        var alert = new NetworkAlert(
            TimestampUtc: DateTime.UtcNow,
            Severity: sensitive ? "critical" : "medium",
            RemoteAddress: ip,
            RemotePort: r.RemotePort,
            LocalPort: r.LocalPort,
            ProcessName: procName,
            SensitivePort: sensitive,
            PortLabel: portLabel,
            Title: sensitive ? "Acesso externo a porta sensível!" : "Conexão externa detectada",
            Message: $"{ip} → {portLabel} · {procName}");

        try
        {
            Directory.CreateDirectory(_opts.AlertsDirectory);
            int seq = Interlocked.Increment(ref _alertSeq);
            var name = $"alert_{DateTime.UtcNow:yyyy-MM-dd_HHmmssfff}_{seq}.json";
            var path = Path.Combine(_opts.AlertsDirectory, name);
            // Unique, write-once file → direct write (a tmp+rename would raise a
            // Renamed event, which the Tray's Created-only watcher would miss).
            File.WriteAllText(path, JsonSerializer.Serialize(alert, JsonOpts));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write inbound alert file");
        }
    }

    private static string PortLabel(int port) => port switch
    {
        21   => "FTP (porta 21)",
        22   => "SSH (porta 22)",
        23   => "Telnet (porta 23)",
        135  => "RPC (porta 135)",
        139  => "NetBIOS (porta 139)",
        445  => "SMB / compartilhamento (porta 445)",
        1433 => "SQL Server (porta 1433)",
        3306 => "MySQL (porta 3306)",
        3389 => "RDP / área de trabalho remota (porta 3389)",
        5900 or 5901 => $"VNC (porta {port})",
        5985 or 5986 => $"WinRM (porta {port})",
        _ => $"porta {port}"
    };

    private void PruneOldAlerts()
    {
        try
        {
            var cutoff = DateTime.UtcNow.AddDays(-7);
            foreach (var f in new DirectoryInfo(_opts.AlertsDirectory).GetFiles("alert_*.json"))
                if (f.LastWriteTimeUtc < cutoff) { try { f.Delete(); } catch { } }
        }
        catch { /* best effort */ }
    }

    private void WriteSnapshotAtomic(NetworkSnapshot snapshot)
    {
        var path = _opts.SnapshotPath;
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(snapshot, JsonOpts));
        File.Move(tmp, path, overwrite: true);
    }

    private static HashSet<int> GetListenerPorts()
    {
        var set = new HashSet<int>();
        try
        {
            foreach (var ep in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners())
                set.Add(ep.Port);
        }
        catch { /* best effort */ }
        return set;
    }

    private static Dictionary<int, string> BuildPidNameMap()
    {
        var map = new Dictionary<int, string>();
        foreach (var p in Process.GetProcesses())
        {
            try { map[p.Id] = p.ProcessName; }
            catch { /* exited / access denied */ }
            finally { p.Dispose(); }
        }
        return map;
    }

    private HashSet<string> SnapshotInboundKeys()
    {
        var listeners = GetListenerPorts();
        var keys = new HashSet<string>();
        foreach (var r in IpHlpApi.GetEstablishedConnections())
        {
            if (!listeners.Contains(r.LocalPort)) continue;
            if (IsZero(r.RemoteAddress) || !NetworkMonitor.IsPublicAddress(r.RemoteAddress)) continue;
            keys.Add($"{r.RemoteAddress}:{r.RemotePort}|{r.LocalPort}");
        }
        return keys;
    }

    private bool IsSelfReference(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        foreach (var frag in _selfFragments)
            if (!string.IsNullOrEmpty(frag) && text.Contains(frag, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static bool IsZero(IPAddress addr)
        => addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any);
}
