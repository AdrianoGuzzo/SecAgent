using System.Net;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Platform;

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
    private readonly INetworkInfo _net;
    private readonly TimeProvider _time;
    private readonly HashSet<int> _portWhitelist;
    private HashSet<string> _previous = new();

    public NetworkMonitor(
        ILogger<NetworkMonitor> logger,
        ChannelWriter<SecurityEvent> writer,
        IOptions<MonitorOptions> opts,
        INetworkInfo net,
        TimeProvider time)
    {
        _logger = logger;
        _writer = writer;
        _opts = opts.Value;
        _net = net;
        _time = time;
        _portWhitelist = new HashSet<int>(_opts.NetworkPortWhitelist ?? MonitorOptions.DefaultNetworkPortWhitelist.ToList());
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.NetworkMonitorEnabled)
        {
            _logger.LogInformation("NetworkMonitor disabled by config");
            return;
        }

        _logger.LogInformation("NetworkMonitor started (poll every {Sec}s)", _opts.NetworkPollSeconds);
        try { _previous = SnapshotKeys(); }   // baseline: não dispara no startup
        catch (Exception ex) { _logger.LogWarning(ex, "NetworkMonitor baseline failed"); }

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(_opts.NetworkPollSeconds), _time, stoppingToken); }
            catch (OperationCanceledException) { break; }

            try { Poll(); }
            catch (Exception ex) { _logger.LogWarning(ex, "NetworkMonitor poll failed"); }
        }
    }

    /// <summary>Um ciclo: compara com o snapshot anterior e emite eventos das conexões novas.</summary>
    internal void Poll()
    {
        var current = SnapshotKeys();
        foreach (var (local, remote) in NewPublicOutbound(_previous, current, _portWhitelist))
        {
            _writer.TryWrite(new SecurityEvent(
                TimestampUtc: _time.GetUtcNow().UtcDateTime,
                Source: "network",
                Severity: SeverityLevels.Low,
                Title: $"New outbound connection to {remote.Address}:{remote.Port}",
                Description: "New TCP connection established to a public IP on a non-whitelisted port. Could be legitimate app traffic or unauthorized exfiltration.",
                Details: new Dictionary<string, string>
                {
                    ["localEndpoint"] = local.ToString(),
                    ["remoteEndpoint"] = remote.ToString(),
                    ["remoteAddress"] = remote.Address.ToString(),
                    ["remotePort"] = remote.Port.ToString()
                }));
        }
        _previous = current;
    }

    private HashSet<string> SnapshotKeys()
        => _net.GetEstablishedTcp().Select(c => Key(c.Local, c.Remote)).ToHashSet();

    internal static string Key(IPEndPoint local, IPEndPoint remote) => $"{local}|{remote}";

    /// <summary>Conexões presentes em <paramref name="current"/> e não em <paramref name="previous"/>, para IP público fora do whitelist.</summary>
    internal static IEnumerable<(IPEndPoint Local, IPEndPoint Remote)> NewPublicOutbound(
        IReadOnlySet<string> previous, IEnumerable<string> current, IReadOnlySet<int> portWhitelist)
    {
        foreach (var key in current)
        {
            if (previous.Contains(key)) continue;
            if (!TryParseKey(key, out var local, out var remote)) continue;
            if (!IpClassifier.IsPublic(remote.Address)) continue;
            if (portWhitelist.Contains(remote.Port)) continue;
            yield return (local, remote);
        }
    }

    internal static bool TryParseKey(string key, out IPEndPoint local, out IPEndPoint remote)
    {
        local = remote = new IPEndPoint(IPAddress.None, 0);
        var parts = key.Split('|');
        if (parts.Length != 2) return false;
        if (!IPEndPoint.TryParse(parts[0], out var l) || !IPEndPoint.TryParse(parts[1], out var r)) return false;
        local = l;
        remote = r;
        return true;
    }
}
