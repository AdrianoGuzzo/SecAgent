using System.Net;
using SecAgent.Service.Collectors;
using SecAgent.Service.Models;
using SecAgent.Service.Platform;
using SecAgent.Service.Tests.Collectors;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests;

public class SecurityScannerTests
{
    private readonly IWmiQuery _wmi = Substitute.For<IWmiQuery>();
    private readonly IFirewallPolicy _fw = Substitute.For<IFirewallPolicy>();
    private readonly IUninstallRegistry _reg = Substitute.For<IUninstallRegistry>();
    private readonly IAclReader _acl = Substitute.For<IAclReader>();
    private readonly INetworkInfo _net = Substitute.For<INetworkInfo>();
    private readonly ISystemEnvironment _env = Substitute.For<ISystemEnvironment>();

    private SecurityScanner Create(params string[] folders) => new(
        Test.Log<SecurityScanner>(),
        Test.Opts(new ScannerOptions { CriticalFolders = folders.ToList() }),
        Test.Clock(),
        _env,
        new OpenPortsCollector(_net),
        new InstalledSoftwareCollector(_reg),
        new FolderPermissionsCollector(_acl),
        new DefenderStatusCollector(_wmi),
        new FirewallStatusCollector(_wmi),
        new FirewallRulesCollector(_fw),
        new InstalledUpdatesCollector(_wmi),
        new UserAccountsCollector(_wmi, _env));

    [Fact]
    public void Aggregates_all_collectors()
    {
        _env.MachineName.Returns("PC");
        _env.OsVersion.Returns("Win11");
        _net.GetTcpListeners().Returns(new[] { new IPEndPoint(IPAddress.Any, 3389) });
        _net.GetUdpListeners().Returns(Array.Empty<IPEndPoint>());
        _reg.ReadEntries().Returns(new[] { new SoftwareEntry("App", "1", null, null, "HKLM64") });
        _fw.GetRules().Returns(Array.Empty<FirewallRuleData>());
        _wmi.Query(Arg.Any<string>(), Arg.Any<string>()).Returns(Array.Empty<IReadOnlyDictionary<string, object?>>());
        _acl.DirectoryExists(Arg.Any<string>()).Returns(false);

        var r = Create("C:\\x").RunFullScan();

        Assert.Equal(Test.T0.UtcDateTime, r.TimestampUtc);
        Assert.Equal("PC", r.MachineName);
        Assert.Equal("Win11", r.OsVersion);
        Assert.Single(r.OpenPorts);
        Assert.Single(r.InstalledSoftware);
        Assert.Single(r.FolderPermissions);
        Assert.NotNull(r.Defender);
        Assert.NotNull(r.Firewall);
        Assert.Empty(r.Errors);
    }

    [Fact]
    public void A_failing_collector_becomes_an_error_and_the_rest_still_runs()
    {
        _env.MachineName.Returns("PC");
        _env.OsVersion.Returns("Win11");
        _net.GetTcpListeners().Returns(_ => throw new InvalidOperationException("boom"));
        _reg.ReadEntries().Returns(new[] { new SoftwareEntry("App", "1", null, null, "HKLM64") });
        _fw.GetRules().Returns(_ => throw new System.Runtime.InteropServices.COMException("com"));
        _wmi.Query(Arg.Any<string>(), Arg.Any<string>()).Returns(_ => throw new UnauthorizedAccessException("wmi"));

        var r = Create().RunFullScan();

        Assert.Empty(r.OpenPorts);
        Assert.Single(r.InstalledSoftware);
        Assert.Null(r.Defender);
        Assert.Null(r.Firewall);
        Assert.Empty(r.LocalUsers);
        Assert.Empty(r.Administrators);
        Assert.Equal(new[] { "OpenPorts", "Defender", "Firewall", "FirewallRules", "Updates", "Users" },
            r.Errors.Select(e => e.Collector));
        Assert.Contains("InvalidOperationException: boom", r.Errors[0].Message);
    }
}
