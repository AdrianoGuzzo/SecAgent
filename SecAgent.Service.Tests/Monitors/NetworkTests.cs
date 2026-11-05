using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Channels;
using SecAgent.Service.Monitors;
using SecAgent.Service.Monitors.Native;
using SecAgent.Service.Platform;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests.Monitors;

public class IpClassifierTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("fec0::1", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("192.0.2.1", false)]
    [InlineData("198.51.100.1", false)]
    [InlineData("203.0.113.1", false)]
    [InlineData("192.0.0.1", false)]
    public void Classic_ranges(string ip, bool expected) => Assert.Equal(expected, IpClassifier.IsPublic(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("224.0.0.251")]       // mDNS multicast
    [InlineData("239.255.255.250")]   // SSDP
    [InlineData("0.1.2.3")]           // 0/8
    [InlineData("255.255.255.255")]   // broadcast
    [InlineData("240.0.0.1")]         // reservado
    [InlineData("198.18.0.1")]        // benchmarking
    [InlineData("198.19.255.1")]
    [InlineData("::ffff:10.0.0.1")]   // IPv4-mapped privado
    [InlineData("ff02::1")]           // multicast v6
    [InlineData("::")]
    public void Bug_special_ranges_are_not_public(string ip) => Assert.False(IpClassifier.IsPublic(IPAddress.Parse(ip)));

    [Fact]
    public void Mapped_public_is_public() => Assert.True(IpClassifier.IsPublic(IPAddress.Parse("::ffff:8.8.8.8")));
}

public class NativeLayoutTests
{
    [Fact]
    public void Bug_estats_rod_struct_matches_windows_layout()
    {
        // Ordem oficial: DataBytesOut, DataSegsOut, DataBytesIn, ... — antes DataBytesIn
        // estava no offset 8 e lia DataSegsOut (bytes-in errado no painel).
        Assert.Equal(0, (int)Marshal.OffsetOf<IpHlpApi.TCP_ESTATS_DATA_ROD_v0>(nameof(IpHlpApi.TCP_ESTATS_DATA_ROD_v0.DataBytesOut)));
        Assert.Equal(16, (int)Marshal.OffsetOf<IpHlpApi.TCP_ESTATS_DATA_ROD_v0>(nameof(IpHlpApi.TCP_ESTATS_DATA_ROD_v0.DataBytesIn)));
        Assert.Equal(48, (int)Marshal.OffsetOf<IpHlpApi.TCP_ESTATS_DATA_ROD_v0>(nameof(IpHlpApi.TCP_ESTATS_DATA_ROD_v0.SoftErrors)));
        Assert.Equal(88, (int)Marshal.OffsetOf<IpHlpApi.TCP_ESTATS_DATA_ROD_v0>(nameof(IpHlpApi.TCP_ESTATS_DATA_ROD_v0.ThruBytesReceived)));
        Assert.Equal(96, Marshal.SizeOf<IpHlpApi.TCP_ESTATS_DATA_ROD_v0>());
    }

    [Theory]
    [InlineData(0x5000u, 80)]          // 80 em network order = 0x0050 → bytes trocados
    [InlineData(0xBB01u, 443)]
    [InlineData(0xFFFF3D0Du, 3389)]    // bits altos ignorados
    public void PortSwap_from_network_order(uint raw, int expected) => Assert.Equal(expected, PortSwap.FromNetworkOrder(raw));
}

public class NetworkHelpersTests
{
    [Fact]
    public void Throughput_rates()
    {
        var t = Test.T0.UtcDateTime;
        Assert.Equal(0, Throughput.ElapsedSeconds(default, t));
        Assert.Equal(2, Throughput.ElapsedSeconds(t, t.AddSeconds(2)));
        Assert.Equal(0, Throughput.ElapsedSeconds(t, t.AddSeconds(61)));
        Assert.Equal(0, Throughput.ElapsedSeconds(t, t.AddSeconds(-1)));
        Assert.Equal(500, Throughput.Rate(1000, 2000, 2));
        Assert.Equal(0, Throughput.Rate(2000, 1000, 2));   // contador resetado
        Assert.Equal(0, Throughput.Rate(0, 1000, 0));
    }

    private static InterfaceCounters Nic(string name, NetworkInterfaceType type = NetworkInterfaceType.Wireless80211,
        OperationalStatus status = OperationalStatus.Up, string desc = "Intel Wi-Fi") =>
        new(name, name, desc, type, status, 0, 0);

    [Fact]
    public void NicFilter_keeps_only_physical_up()
    {
        Assert.True(NicFilter.IsPhysicalUp(Nic("Wi-Fi")));
        Assert.True(NicFilter.IsPhysicalUp(Nic("Ethernet", NetworkInterfaceType.Ethernet, desc: "Realtek")));
        Assert.False(NicFilter.IsPhysicalUp(Nic("Wi-Fi", status: OperationalStatus.Down)));
        Assert.False(NicFilter.IsPhysicalUp(Nic("lo", NetworkInterfaceType.Loopback)));
        Assert.False(NicFilter.IsPhysicalUp(Nic("vEthernet (WSL)", NetworkInterfaceType.Ethernet, desc: "Hyper-V Virtual Ethernet")));
    }

    [Theory]
    [InlineData(3389, "RDP / área de trabalho remota (porta 3389)")]
    [InlineData(5901, "VNC (porta 5901)")]
    [InlineData(5985, "WinRM (porta 5985)")]
    [InlineData(445, "SMB / compartilhamento (porta 445)")]
    [InlineData(21, "FTP (porta 21)")]
    [InlineData(22, "SSH (porta 22)")]
    [InlineData(23, "Telnet (porta 23)")]
    [InlineData(135, "RPC (porta 135)")]
    [InlineData(139, "NetBIOS (porta 139)")]
    [InlineData(1433, "SQL Server (porta 1433)")]
    [InlineData(3306, "MySQL (porta 3306)")]
    [InlineData(8080, "porta 8080")]
    public void PortLabels_for(int port, string label) => Assert.Equal(label, PortLabels.For(port));
}

public class NetworkMonitorTests
{
    private static readonly IPEndPoint Local = IPEndPoint.Parse("192.168.0.10:50000");

    [Fact]
    public void Emits_only_new_public_non_whitelisted_connections()
    {
        var net = Substitute.For<INetworkInfo>();
        var channel = Channel.CreateUnbounded<SecurityEvent>();
        var monitor = new NetworkMonitor(Test.Log<NetworkMonitor>(), channel.Writer,
            Test.Opts(new MonitorOptions().ApplyDefaults()), net, Test.Clock());

        net.GetEstablishedTcp().Returns(new[] { (Local, IPEndPoint.Parse("8.8.8.8:4444")) });
        monitor.Poll();   // primeira vez: nova
        net.GetEstablishedTcp().Returns(new[]
        {
            (Local, IPEndPoint.Parse("8.8.8.8:4444")),      // já vista
            (Local, IPEndPoint.Parse("1.1.1.1:443")),       // whitelist
            (Local, IPEndPoint.Parse("10.0.0.5:4444")),     // privada
            (Local, IPEndPoint.Parse("9.9.9.9:8443")),      // nova
        });
        monitor.Poll();

        var events = new List<SecurityEvent>();
        while (channel.Reader.TryRead(out var e)) events.Add(e);
        Assert.Equal(new[] { "8.8.8.8", "9.9.9.9" }, events.Select(e => e.Details["remoteAddress"]));
        Assert.All(events, e => Assert.Equal("low", e.Severity));
    }

    [Theory]
    [InlineData("a|b", false)]
    [InlineData("1.2.3.4:1", false)]
    [InlineData("1.2.3.4:1|5.6.7.8:2", true)]
    public void TryParseKey(string key, bool ok) => Assert.Equal(ok, NetworkMonitor.TryParseKey(key, out _, out _));

    [Fact]
    public void Bug_whitelist_from_config_replaces_defaults()
    {
        var current = new[] { NetworkMonitor.Key(Local, IPEndPoint.Parse("8.8.8.8:443")) };
        var withDefaults = NetworkMonitor.NewPublicOutbound(new HashSet<string>(), current, new HashSet<int> { 80, 443 });
        var withoutHttps = NetworkMonitor.NewPublicOutbound(new HashSet<string>(), current, new HashSet<int> { 80 });
        Assert.Empty(withDefaults);
        Assert.Single(withoutHttps);
    }

    [Fact]
    public async Task Execute_baselines_then_polls_and_survives_errors()
    {
        var net = Substitute.For<INetworkInfo>();
        net.GetEstablishedTcp().Returns(new[] { (Local, IPEndPoint.Parse("8.8.8.8:4444")) });
        var channel = Channel.CreateUnbounded<SecurityEvent>();
        var clock = Test.Clock();
        var monitor = new NetworkMonitor(Test.Log<NetworkMonitor>(), channel.Writer,
            Test.Opts(new MonitorOptions { NetworkPollSeconds = 30 }.ApplyDefaults()), net, clock);

        await monitor.StartAsync(CancellationToken.None);
        await Test.Eventually(() => net.ReceivedCalls().Count() >= 1);
        net.GetEstablishedTcp().Returns(_ => throw new NetworkInformationException());
        await Test.Eventually(() => { clock.Advance(TimeSpan.FromSeconds(30)); return net.ReceivedCalls().Count() >= 3; });
        await monitor.StopAsync(CancellationToken.None);

        Assert.False(channel.Reader.TryRead(out _));   // baseline não dispara

        var disabled = new NetworkMonitor(Test.Log<NetworkMonitor>(), channel.Writer,
            Test.Opts(new MonitorOptions { NetworkMonitorEnabled = false }), Substitute.For<INetworkInfo>(), clock);
        await disabled.StartAsync(CancellationToken.None);
        await disabled.StopAsync(CancellationToken.None);
    }
}

public sealed class NetworkSnapshotServiceTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly ITcpConnectionSource _tcp = Substitute.For<ITcpConnectionSource>();
    private readonly INetworkInfo _net = Substitute.For<INetworkInfo>();
    private readonly Channel<SecurityEvent> _channel = Channel.CreateUnbounded<SecurityEvent>();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = Test.Clock();
    private readonly MonitorOptions _opts;

    public NetworkSnapshotServiceTests()
    {
        _opts = new MonitorOptions
        {
            SnapshotPath = _dir.File("network.json"),
            AlertsDirectory = Path.Combine(_dir.Path, "alerts"),
            InboundAlertCooldownMinutes = 10,
        }.ApplyDefaults();
        _net.GetTcpListeners().Returns(new[] { new IPEndPoint(IPAddress.Any, 3389), new IPEndPoint(IPAddress.Any, 8080) });
        _net.GetProcessNames().Returns(new Dictionary<int, string> { [4] = "svchost", [9] = "SecAgent.Service" });
        _net.GetInterfaceCounters().Returns(Array.Empty<InterfaceCounters>());
    }

    public void Dispose() => _dir.Dispose();

    private NetworkSnapshotService Create() => new(Test.Log<NetworkSnapshotService>(), _channel.Writer,
        Test.Opts(_opts), _tcp, _net, _clock);

    private static TcpConnectionRow Row(string remote, int remotePort, int localPort, int pid = 4, ulong inB = 0, ulong outB = 0)
        => new(IPAddress.Parse("192.168.0.10"), localPort, IPAddress.Parse(remote), remotePort, pid, inB, outB);

    private List<SecurityEvent> DrainEvents()
    {
        var list = new List<SecurityEvent>();
        while (_channel.Reader.TryRead(out var e)) list.Add(e);
        return list;
    }

    private string[] Alerts() => Directory.Exists(_opts.AlertsDirectory) ? Directory.GetFiles(_opts.AlertsDirectory) : Array.Empty<string>();

    private NetworkSnapshot Snapshot()
        => JsonSerializer.Deserialize<NetworkSnapshot>(File.ReadAllText(_opts.SnapshotPath), JsonDefaults.Read)!;

    [Fact]
    public void First_cycle_is_baseline_then_new_inbound_alerts()
    {
        var svc = Create();
        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 5000, 3389) });
        Assert.True(svc.RunCycle());
        Assert.Empty(DrainEvents());
        Assert.Empty(Alerts());

        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 5000, 3389), Row("9.9.9.9", 6000, 3389), Row("1.1.1.1", 443, 50123) });
        _clock.Advance(TimeSpan.FromSeconds(1));
        svc.RunCycle();

        var e = Assert.Single(DrainEvents());
        Assert.Equal("high", e.Severity);   // porta sensível
        Assert.Equal("9.9.9.9", e.Details["remoteAddress"]);
        var alert = JsonSerializer.Deserialize<NetworkAlert>(File.ReadAllText(Assert.Single(Alerts())))!;
        Assert.Equal("critical", alert.Severity);
        Assert.Equal("RDP / área de trabalho remota (porta 3389)", alert.PortLabel);

        var snap = Snapshot();
        Assert.Equal(3, snap.Connections.Count);
        Assert.Equal("outbound", snap.Connections.Single(c => c.RemoteAddress == "1.1.1.1").Direction);
        Assert.Equal("svchost", snap.Connections[0].ProcessName);
    }

    [Fact]
    public void Bug_failed_tcp_read_keeps_state_and_does_not_realert()
    {
        var svc = Create();
        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 5000, 8080) });
        svc.RunCycle();

        _tcp.TryGetEstablished().Returns((IReadOnlyList<TcpConnectionRow>?)null);   // GetExtendedTcpTable falhou
        Assert.False(svc.RunCycle());

        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 5000, 8080) });
        svc.RunCycle();

        Assert.Empty(DrainEvents());
    }

    [Fact]
    public void Medium_alert_cooldown_per_ip_and_bug_cooldown_table_is_pruned()
    {
        var svc = Create();
        _tcp.TryGetEstablished().Returns(Array.Empty<TcpConnectionRow>());
        svc.RunCycle();

        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 5000, 8080) });
        svc.RunCycle();
        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 5001, 8080) });   // nova conexão, mesmo IP
        svc.RunCycle();

        Assert.Equal(2, DrainEvents().Count);   // eventos sempre
        Assert.Single(Alerts());                // alerta só 1 (cooldown)
        Assert.Equal("medium", JsonSerializer.Deserialize<NetworkAlert>(File.ReadAllText(Alerts()[0]))!.Severity);
        Assert.Equal(1, svc.AlertCooldownEntries);

        _clock.Advance(TimeSpan.FromMinutes(11));
        _tcp.TryGetEstablished().Returns(Array.Empty<TcpConnectionRow>());
        svc.RunCycle();
        Assert.Equal(0, svc.AlertCooldownEntries);
    }

    [Fact]
    public void Self_whitelisted_and_disabled_inbound_events_are_suppressed()
    {
        _opts.InboundPortWhitelist = new() { 8080 };
        var svc = Create();
        _tcp.TryGetEstablished().Returns(Array.Empty<TcpConnectionRow>());
        svc.RunCycle();
        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 1, 8080), Row("9.9.9.9", 1, 3389, pid: 9) });
        svc.RunCycle();
        Assert.Empty(DrainEvents());

        _opts.EmitInboundEvents = false;
        var svc2 = Create();
        _tcp.TryGetEstablished().Returns(Array.Empty<TcpConnectionRow>());
        svc2.RunCycle();
        _tcp.TryGetEstablished().Returns(new[] { Row("7.7.7.7", 1, 3389) });
        svc2.RunCycle();
        Assert.Empty(DrainEvents());
    }

    [Fact]
    public void Throughput_per_connection_and_per_interface()
    {
        _net.GetInterfaceCounters().Returns(
            new[] { new InterfaceCounters("1", "Wi-Fi", "Intel", NetworkInterfaceType.Wireless80211, OperationalStatus.Up, 1000, 500),
                    new InterfaceCounters("2", "vEthernet", "Hyper-V", NetworkInterfaceType.Ethernet, OperationalStatus.Up, 0, 0) },
            new[] { new InterfaceCounters("1", "Wi-Fi", "Intel", NetworkInterfaceType.Wireless80211, OperationalStatus.Up, 3000, 1500) });
        var svc = Create();
        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 443, 50000, inB: 100, outB: 100) });
        svc.RunCycle();

        _clock.Advance(TimeSpan.FromSeconds(2));
        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 443, 50000, inB: 1100, outB: 1100) });
        svc.RunCycle();

        var snap = Snapshot();
        Assert.Equal(1000, snap.Connections.Single().BytesPerSec);
        var nic = Assert.Single(snap.Interfaces!);
        Assert.Equal(new NetworkInterfaceStat("Wi-Fi", 1000, 500), nic);
    }

    [Fact]
    public void Interface_stats_can_be_disabled_and_info_failures_degrade()
    {
        _opts.InterfaceStatsEnabled = false;
        _net.GetTcpListeners().Returns(_ => throw new NetworkInformationException());
        _net.GetProcessNames().Returns(_ => throw new InvalidOperationException());
        var svc = Create();
        _tcp.TryGetEstablished().Returns(new[] { Row("8.8.8.8", 443, 3389) });
        svc.RunCycle();

        var snap = Snapshot();
        Assert.Null(snap.Interfaces);
        Assert.Equal("outbound", snap.Connections[0].Direction);   // sem listeners → saída
        Assert.Equal("desconhecido", snap.Connections[0].ProcessName);
    }

    [Fact]
    public async Task Execute_runs_cycles_and_prunes_old_alert_files()
    {
        Directory.CreateDirectory(_opts.AlertsDirectory);
        var old = Path.Combine(_opts.AlertsDirectory, "alert_old.json");
        File.WriteAllText(old, "{}");
        File.SetLastWriteTimeUtc(old, Test.T0.UtcDateTime.AddDays(-8));
        var fresh = Path.Combine(_opts.AlertsDirectory, "alert_new.json");
        File.WriteAllText(fresh, "{}");
        File.SetLastWriteTimeUtc(fresh, Test.T0.UtcDateTime);

        _tcp.TryGetEstablished().Returns(_ => throw new Exception("boom"), _ => Array.Empty<TcpConnectionRow>());
        var svc = Create();
        await svc.StartAsync(CancellationToken.None);
        await Test.Eventually(() => { _clock.Advance(TimeSpan.FromSeconds(1)); return File.Exists(_opts.SnapshotPath); });
        await svc.StopAsync(CancellationToken.None);

        Assert.False(File.Exists(old));
        Assert.True(File.Exists(fresh));

        _opts.NetworkSnapshotEnabled = false;
        var disabled = Create();
        await disabled.StartAsync(CancellationToken.None);
        await disabled.StopAsync(CancellationToken.None);
    }
}
