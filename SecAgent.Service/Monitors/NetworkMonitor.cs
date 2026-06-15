using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Models;

namespace SecAgent.Service.Monitors;

/// <summary>
/// Polls active TCP connections at a configurable interval. Emits a SecurityEvent
/// for each NEW connection (vs. previous snapshot) whose remote endpoint is on
/// a public IP and whose remote port is not in the whitelist.
/// </summary>
public class NetworkMonitor : BackgroundService
{
    private readonly ILogger<NetworkMonitor> _logger;
    private readonly ChannelWriter<SecurityEvent> _writer;
    private readonly MonitorOptions _opts;
    private readonly HashSet<int> _portWhitelist;
    private HashSet<string> _previous = new();

    public NetworkMonitor(
        ILogger<NetworkMonitor> logger,
        Channel<SecurityEvent> channel,
        IOptions<MonitorOptions> opts)
    {
        _logger = logger;
        _writer = channel.Writer;
        _opts = opts.Value;
        _portWhitelist = new HashSet<int>(_opts.NetworkPortWhitelist);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.NetworkMonitorEnabled)
        {
            _logger.LogInformation("NetworkMonitor disabled by config");
            return;
        }

        _logger.LogInformation("NetworkMonitor started (poll every {Sec}s)", _opts.NetworkPollSeconds);
        _previous = SnapshotConnections();        // baseline: don't fire on startup

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(_opts.NetworkPollSeconds), stoppingToken); }
            catch (OperationCanceledException) { break; }

            try
            {
                var current = SnapshotConnections();
                foreach (var conn in current)
                {
                    if (_previous.Contains(conn)) continue;
                    if (!TryParseConnection(conn, out var localEp, out var remoteEp)) continue;

                    if (!IsPublicAddress(remoteEp!.Address)) continue;
                    if (_portWhitelist.Contains(remoteEp.Port)) continue;

                    var evt = new SecurityEvent(
                        TimestampUtc: DateTime.UtcNow,
                        Source: "network",
                        Severity: "low",
                        Title: $"New outbound connection to {remoteEp.Address}:{remoteEp.Port}",
                        Description: "New TCP connection established to a public IP on a non-whitelisted port. Could be legitimate app traffic or unauthorized exfiltration.",
                        Details: new Dictionary<string, string>
                        {
                            ["localEndpoint"] = localEp?.ToString() ?? "",
                            ["remoteEndpoint"] = remoteEp.ToString(),
                            ["remoteAddress"] = remoteEp.Address.ToString(),
                            ["remotePort"] = remoteEp.Port.ToString()
                        });
                    _writer.TryWrite(evt);
                }
                _previous = current;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "NetworkMonitor poll failed");
            }
        }
    }

    private static HashSet<string> SnapshotConnections()
    {
        var props = IPGlobalProperties.GetIPGlobalProperties();
        var set = new HashSet<string>();
        foreach (var c in props.GetActiveTcpConnections())
        {
            if (c.State != TcpState.Established) continue;
            set.Add($"{c.LocalEndPoint}|{c.RemoteEndPoint}");
        }
        return set;
    }

    private static bool TryParseConnection(string key, out IPEndPoint? local, out IPEndPoint? remote)
    {
        local = null; remote = null;
        var parts = key.Split('|');
        if (parts.Length != 2) return false;
        try
        {
            local = IPEndPoint.Parse(parts[0]);
            remote = IPEndPoint.Parse(parts[1]);
            return true;
        }
        catch { return false; }
    }

    public static bool IsPublicAddress(IPAddress addr)
    {
        if (IPAddress.IsLoopback(addr)) return false;

        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            // 10.0.0.0/8
            if (b[0] == 10) return false;
            // 172.16.0.0/12
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            // 192.168.0.0/16
            if (b[0] == 192 && b[1] == 168) return false;
            // 169.254.0.0/16 (link-local APIPA)
            if (b[0] == 169 && b[1] == 254) return false;
            // 100.64.0.0/10 (CGNAT)
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
            return true;
        }
        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal) return false;
            var b = addr.GetAddressBytes();
            // fc00::/7 unique-local
            if ((b[0] & 0xfe) == 0xfc) return false;
            return true;
        }
        return false;
    }
}
