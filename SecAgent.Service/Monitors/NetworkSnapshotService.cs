using System.Net.NetworkInformation;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Monitors;

/// <summary>
/// Periodically enumerates ALL established TCP connections (with owning process)
/// and writes a network.json snapshot for the Tray dashboard. Also classifies
/// inbound connections and — when enabled — emits a SecurityEvent plus an
/// immediate alert file for each NEW inbound connection from a public IP.
///
/// Robustez:
///  - Uma leitura FALHA da tabela TCP (null) mantém o estado anterior. Antes ela
///    virava "lista vazia" e no ciclo seguinte todas as conexões de entrada
///    existentes eram re-alertadas.
///  - Sem baseline (falhou no startup), o primeiro ciclo bem-sucedido vira o
///    baseline em vez de alertar tudo que já existia.
///  - O cooldown de alerta por IP é podado (antes crescia sem limite).
/// </summary>
public class NetworkSnapshotService : BackgroundService
{
    private readonly ILogger<NetworkSnapshotService> _logger;
    private readonly ChannelWriter<SecurityEvent> _writer;
    private readonly MonitorOptions _opts;
    private readonly ITcpConnectionSource _tcp;
    private readonly INetworkInfo _net;
    private readonly TimeProvider _time;
    private readonly HashSet<int> _inboundPortWhitelist;
    private readonly HashSet<int> _sensitivePorts;
    private readonly List<string> _selfFragments;
    private readonly Dictionary<string, DateTime> _lastAlertPerIp = new();
    private HashSet<string>? _seenInbound;   // null = ainda sem baseline
    private int _alertSeq;

    // Contadores cumulativos do ciclo anterior (por 4-tupla e por NIC) para
    // derivar bytes/s por diferença.
    private Dictionary<string, ulong> _prevBytes = new();
    private Dictionary<string, (ulong Rx, ulong Tx)> _prevIfaceBytes = new();
    private DateTime _lastCycleUtc;

    public NetworkSnapshotService(
        ILogger<NetworkSnapshotService> logger,
        ChannelWriter<SecurityEvent> writer,
        IOptions<MonitorOptions> opts,
        ITcpConnectionSource tcp,
        INetworkInfo net,
        TimeProvider time)
    {
        _logger = logger;
        _writer = writer;
        _opts = opts.Value;
        _tcp = tcp;
        _net = net;
        _time = time;
        _inboundPortWhitelist = new HashSet<int>(_opts.InboundPortWhitelist ?? new());
        _sensitivePorts = new HashSet<int>(_opts.SensitiveInboundPorts ?? MonitorOptions.DefaultSensitiveInboundPorts.ToList());
        _selfFragments = _opts.SelfReferenceFragments ?? new List<string>();
    }

    private DateTime UtcNow => _time.GetUtcNow().UtcDateTime;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.NetworkSnapshotEnabled)
        {
            _logger.LogInformation("NetworkSnapshotService disabled by config");
            return;
        }

        _logger.LogInformation("NetworkSnapshotService started (snapshot every {Sec}s)", _opts.NetworkSnapshotSeconds);
        PruneOldAlertFiles();

        while (!stoppingToken.IsCancellationRequested)
        {
            try { RunCycle(); }
            catch (Exception ex) { _logger.LogWarning(ex, "NetworkSnapshotService cycle failed"); }

            try { await Task.Delay(TimeSpan.FromSeconds(_opts.NetworkSnapshotSeconds), _time, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Um ciclo completo. False quando a tabela TCP não pôde ser lida (estado preservado).</summary>
    internal bool RunCycle()
    {
        var rows = _tcp.TryGetEstablished();
        if (rows is null)
        {
            _logger.LogDebug("TCP table read failed; keeping previous state");
            return false;
        }

        var listeners = Safe(() => _net.GetTcpListeners().Select(ep => ep.Port).ToHashSet(), new HashSet<int>());
        var pidNames = Safe(() => _net.GetProcessNames(), (IReadOnlyDictionary<int, string>)new Dictionary<int, string>());

        var now = UtcNow;
        var elapsed = Throughput.ElapsedSeconds(_lastCycleUtc, now);
        var connections = new List<NetworkConnection>(rows.Count);
        var currentInbound = new HashSet<string>();
        var nextBytes = new Dictionary<string, ulong>(rows.Count);

        foreach (var r in rows)
        {
            // Direção: se a porta local é uma em que escutamos, o par iniciou → entrada.
            bool inbound = listeners.Contains(r.LocalPort);
            bool remotePublic = IpClassifier.IsPublic(r.RemoteAddress);
            string procName = pidNames.TryGetValue(r.OwningPid, out var n) ? n : "desconhecido";

            ulong cum = r.CumBytesIn + r.CumBytesOut;
            var connKey = $"{r.LocalAddress}:{r.LocalPort}|{r.RemoteAddress}:{r.RemotePort}";
            nextBytes[connKey] = cum;
            long bytesPerSec = _prevBytes.TryGetValue(connKey, out var prev) ? Throughput.Rate(prev, cum, elapsed) : 0;

            connections.Add(new NetworkConnection(
                Direction: inbound ? "inbound" : "outbound",
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
                if (_seenInbound is not null && !_seenInbound.Contains(key))
                    EmitInbound(r, procName, now);
            }
        }

        var interfaces = BuildInterfaceStats(elapsed);

        _prevBytes = nextBytes;        // descarta conexões que sumiram — sem leak
        _lastCycleUtc = now;
        _seenInbound = currentInbound;
        PruneAlertCooldowns(now);

        AtomicFile.WriteAllText(_opts.SnapshotPath,
            JsonSerializer.Serialize(new NetworkSnapshot(now, connections, interfaces), JsonDefaults.Compact));
        return true;
    }

    private List<NetworkInterfaceStat>? BuildInterfaceStats(double elapsed)
    {
        if (!_opts.InterfaceStatsEnabled) return null;

        var stats = new List<NetworkInterfaceStat>();
        var next = new Dictionary<string, (ulong Rx, ulong Tx)>();
        foreach (var ni in Safe(() => _net.GetInterfaceCounters(), (IReadOnlyList<InterfaceCounters>)Array.Empty<InterfaceCounters>()))
        {
            if (!NicFilter.IsPhysicalUp(ni)) continue;
            next[ni.Id] = (ni.BytesReceived, ni.BytesSent);

            long down = 0, up = 0;
            if (_prevIfaceBytes.TryGetValue(ni.Id, out var prev))
            {
                down = Throughput.Rate(prev.Rx, ni.BytesReceived, elapsed);
                up = Throughput.Rate(prev.Tx, ni.BytesSent, elapsed);
            }
            stats.Add(new NetworkInterfaceStat(ni.Name, down, up));
        }
        _prevIfaceBytes = next;        // descarta NICs que sumiram
        return stats;
    }

    private void EmitInbound(TcpConnectionRow r, string procName, DateTime now)
    {
        if (!_opts.EmitInboundEvents) return;
        if (_inboundPortWhitelist.Contains(r.LocalPort)) return;
        if (IsSelfReference(procName)) return;

        bool sensitive = _sensitivePorts.Contains(r.LocalPort);

        // 1) SecurityEvent → pipeline de incidente (mais lento).
        _writer.TryWrite(new SecurityEvent(
            TimestampUtc: now,
            Source: "network",
            Severity: sensitive ? SeverityLevels.High : SeverityLevels.Medium,
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
            }));

        // 2) Arquivo de alerta imediato → toast do Tray (cooldown por IP).
        WriteAlertIfDue(r, procName, sensitive, now);
    }

    private void WriteAlertIfDue(TcpConnectionRow r, string procName, bool sensitive, DateTime now)
    {
        var ip = r.RemoteAddress.ToString();
        if (_lastAlertPerIp.TryGetValue(ip, out var last) &&
            now - last < TimeSpan.FromMinutes(_opts.InboundAlertCooldownMinutes))
            return;
        _lastAlertPerIp[ip] = now;

        var portLabel = PortLabels.For(r.LocalPort);
        var alert = new NetworkAlert(
            TimestampUtc: now,
            Severity: sensitive ? SeverityLevels.Critical : SeverityLevels.Medium,
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
            var path = Path.Combine(_opts.AlertsDirectory, ReportNames.Alert(now, Interlocked.Increment(ref _alertSeq)));
            // Arquivo único, escrito uma vez → escrita direta (o watcher do Tray é Created).
            File.WriteAllText(path, JsonSerializer.Serialize(alert, JsonDefaults.Compact));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write inbound alert file");
        }
    }

    private void PruneAlertCooldowns(DateTime now)
    {
        var cooldown = TimeSpan.FromMinutes(_opts.InboundAlertCooldownMinutes);
        foreach (var ip in _lastAlertPerIp.Where(kv => now - kv.Value >= cooldown).Select(kv => kv.Key).ToList())
            _lastAlertPerIp.Remove(ip);
    }

    internal int AlertCooldownEntries => _lastAlertPerIp.Count;

    private void PruneOldAlertFiles()
    {
        try
        {
            if (!Directory.Exists(_opts.AlertsDirectory)) return;
            var cutoff = UtcNow.AddDays(-7);
            foreach (var f in new DirectoryInfo(_opts.AlertsDirectory).GetFiles("alert_*.json"))
                if (f.LastWriteTimeUtc < cutoff) { try { f.Delete(); } catch { } }
        }
        catch { /* best effort */ }
    }

    private bool IsSelfReference(string processName)
        => !string.IsNullOrEmpty(processName) &&
           _selfFragments.Any(f => !string.IsNullOrEmpty(f) && processName.Contains(f, StringComparison.OrdinalIgnoreCase));

    private T Safe<T>(Func<T> f, T fallback)
    {
        try { return f(); }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Network info read failed");
            return fallback;
        }
    }
}

/// <summary>Derivação de bytes/s a partir de contadores cumulativos.</summary>
internal static class Throughput
{
    /// <summary>Segundos desde o último ciclo; 0 (= sem taxa) no 1º ciclo ou intervalo absurdo (&gt;60s).</summary>
    public static double ElapsedSeconds(DateTime lastCycleUtc, DateTime nowUtc)
    {
        if (lastCycleUtc == default) return 0;
        var e = (nowUtc - lastCycleUtc).TotalSeconds;
        return e <= 0 || e > 60 ? 0 : e;
    }

    /// <summary>Taxa entre dois contadores; 0 se não há intervalo ou se o contador "voltou" (reset).</summary>
    public static long Rate(ulong previous, ulong current, double elapsedSeconds)
        => elapsedSeconds > 0 && current >= previous ? (long)((current - previous) / elapsedSeconds) : 0;
}

/// <summary>Só NICs físicas (Wi-Fi/Ethernet) ativas — exclui loopback, túnel e adaptadores virtuais.</summary>
internal static class NicFilter
{
    private static readonly string[] VirtualNicFragments =
    {
        "virtual", "vmware", "hyper-v", "vethernet", "vpn", "tap",
        "loopback", "pseudo", "bluetooth", "miniport", "npcap"
    };

    public static bool IsPhysicalUp(InterfaceCounters ni)
    {
        if (ni.Status != OperationalStatus.Up) return false;
        if (ni.Type is not (NetworkInterfaceType.Ethernet
            or NetworkInterfaceType.GigabitEthernet
            or NetworkInterfaceType.Wireless80211))
            return false;

        var hay = ni.Description + " " + ni.Name;
        return !VirtualNicFragments.Any(f => hay.Contains(f, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>Rótulo amigável (pt-BR) da porta local de uma conexão de entrada.</summary>
internal static class PortLabels
{
    public static string For(int port) => port switch
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
}
