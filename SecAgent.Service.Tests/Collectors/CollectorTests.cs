using System.Globalization;
using System.Net;
using System.Security.AccessControl;
using SecAgent.Service.Collectors;
using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Tests.Collectors;

internal static class Wmi
{
    public static IReadOnlyDictionary<string, object?> Row(params (string Key, object? Value)[] kv)
        => kv.ToDictionary(x => x.Key, x => x.Value);

    public static IWmiQuery Returning(params IReadOnlyDictionary<string, object?>[] rows)
    {
        var wmi = Substitute.For<IWmiQuery>();
        wmi.Query(Arg.Any<string>(), Arg.Any<string>()).Returns(rows);
        return wmi;
    }
}

public class WmiValuesTests
{
    [Fact]
    public void Typed_getters_tolerate_missing_and_wrong_types()
    {
        var row = Wmi.Row(("s", "x"), ("b", true), ("n", 5), ("nul", null));
        Assert.Equal("x", WmiValues.GetString(row, "s"));
        Assert.Null(WmiValues.GetString(row, "n"));
        Assert.Null(WmiValues.GetString(row, "missing"));
        Assert.True(WmiValues.GetBool(row, "b"));
        Assert.Null(WmiValues.GetBool(row, "s"));
        Assert.True(WmiValues.GetFlag(row, "b"));
        Assert.False(WmiValues.GetFlag(row, "missing"));
    }

    [Fact]
    public void GetDate_handles_datetime_dmtf_iso_and_garbage()
    {
        var dt = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        Assert.Equal(dt, WmiValues.GetDate(Wmi.Row(("d", dt)), "d"));
        Assert.Null(WmiValues.GetDate(Wmi.Row(("d", null)), "d"));
        Assert.Null(WmiValues.GetDate(Wmi.Row(("d", "  ")), "d"));
        Assert.Null(WmiValues.GetDate(Wmi.Row(("d", "not a date")), "d"));
        Assert.Null(WmiValues.GetDate(Wmi.Row(), "d"));

        var dmtf = WmiValues.GetDate(Wmi.Row(("d", "20260102030405.000000+000")), "d");
        Assert.NotNull(dmtf);
        Assert.Equal(2026, dmtf!.Value.Year);

        var iso = WmiValues.GetDate(Wmi.Row(("d", "2026-01-02T03:04:05Z")), "d");
        Assert.Equal(dt, iso);
    }

    [Fact]
    public void Bug_hotfix_date_is_parsed_culture_invariant()
    {
        // WMI devolve "M/d/yyyy" independente do idioma; em pt-BR o parse antigo
        // lia 3/4/2026 como 3 de abril (ou falhava em 1/13/2026).
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("pt-BR");
            Assert.Equal(new DateTime(2026, 1, 13), WmiValues.ParseHotfixDate("1/13/2026"));
            Assert.Equal(new DateTime(2026, 3, 4), WmiValues.ParseHotfixDate("3/4/2026"));
        }
        finally { CultureInfo.CurrentCulture = previous; }

        Assert.Equal(new DateTime(2026, 3, 4), WmiValues.ParseHotfixDate("03/04/2026"));
        Assert.Equal(new DateTime(2026, 3, 4), WmiValues.ParseHotfixDate("20260304"));
        Assert.Equal(new DateTime(2026, 3, 4), WmiValues.ParseHotfixDate("2026-03-04"));
        Assert.Equal(new DateTime(2026, 3, 4, 13, 0, 0), WmiValues.ParseHotfixDate("3/4/2026 1:00:00 PM"));
        Assert.Null(WmiValues.ParseHotfixDate(""));
        Assert.Null(WmiValues.ParseHotfixDate(null));
        Assert.Null(WmiValues.ParseHotfixDate("13/13/2026"));
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData((ushort)1, true)]
    [InlineData((ushort)2, false)]
    [InlineData(1, true)]
    [InlineData((byte)1, true)]
    [InlineData("1", false)]
    [InlineData(null, false)]
    public void ParseGpoBoolean(object? value, bool expected) => Assert.Equal(expected, WmiValues.ParseGpoBoolean(value));

    [Theory]
    [InlineData(0, "NotConfigured")]
    [InlineData(2, "Allow")]
    [InlineData((ushort)4, "Block")]
    [InlineData(9, "Action9")]
    [InlineData("abc", "abc")]
    [InlineData(null, null)]
    public void Bug_firewall_default_action_is_mapped_to_names(object? raw, string? expected)
        => Assert.Equal(expected, WmiValues.MapFirewallDefaultAction(raw));

    [Fact]
    public void EscapeWql_escapes_quotes_and_backslashes()
        => Assert.Equal(@"O\'Brien\\X", WmiValues.EscapeWql(@"O'Brien\X"));
}

public class DefenderStatusCollectorTests
{
    [Fact]
    public void Maps_first_row()
    {
        var wmi = Wmi.Returning(Wmi.Row(
            ("AntivirusEnabled", true), ("RealTimeProtectionEnabled", false), ("IsTamperProtected", true),
            ("AntivirusSignatureVersion", "1.2"), ("AntivirusSignatureLastUpdated", "20260102030405.000000+000"),
            ("AMEngineVersion", "9.9")));

        var s = new DefenderStatusCollector(wmi).Collect();

        Assert.True(s.AntivirusEnabled);
        Assert.False(s.RealTimeProtectionEnabled);
        Assert.True(s.IsTamperProtected);
        Assert.Equal("1.2", s.AntivirusSignatureVersion);
        Assert.Equal(2026, s.AntivirusSignatureLastUpdated!.Value.Year);
        Assert.Equal("9.9", s.EngineVersion);
    }

    [Fact]
    public void No_rows_yields_all_null()
        => Assert.Equal(new DefenderStatus(null, null, null, null, null, null), new DefenderStatusCollector(Wmi.Returning()).Collect());
}

public class FirewallStatusCollectorTests
{
    [Fact]
    public void Maps_each_profile_with_named_default_actions()
    {
        var wmi = Wmi.Returning(
            Wmi.Row(("Name", "Domain"), ("Enabled", (ushort)1), ("DefaultInboundAction", (ushort)4), ("DefaultOutboundAction", (ushort)2)),
            Wmi.Row(("Name", "private"), ("Enabled", (ushort)0), ("DefaultInboundAction", (ushort)0), ("DefaultOutboundAction", (ushort)0)),
            Wmi.Row(("Name", "Public"), ("Enabled", true), ("DefaultInboundAction", null), ("DefaultOutboundAction", (ushort)4)),
            Wmi.Row(("Name", "Other"), ("Enabled", true)));

        var s = new FirewallStatusCollector(wmi).Collect();

        Assert.Equal(new ProfileStatus(true, "Block", "Allow"), s.Domain);
        Assert.Equal(new ProfileStatus(false, "NotConfigured", "NotConfigured"), s.Private);
        Assert.Equal(new ProfileStatus(true, null, "Block"), s.Public);
    }
}

public class InstalledUpdatesCollectorTests
{
    [Fact]
    public void Skips_rows_without_id_and_orders_newest_first()
    {
        var wmi = Wmi.Returning(
            Wmi.Row(("HotFixID", "KB1"), ("Description", "Update"), ("InstalledOn", "1/13/2026"), ("InstalledBy", "SYSTEM")),
            Wmi.Row(("HotFixID", ""), ("InstalledOn", "1/1/2026")),
            Wmi.Row(("HotFixID", "KB2"), ("InstalledOn", "3/1/2026")),
            Wmi.Row(("HotFixID", "KB3"), ("InstalledOn", null)));

        var list = new InstalledUpdatesCollector(wmi).Collect();

        Assert.Equal(new[] { "KB2", "KB1", "KB3" }, list.Select(u => u.HotFixId));
        Assert.Equal(new DateTime(2026, 1, 13), list[1].InstalledOn);
        Assert.Equal("SYSTEM", list[1].InstalledBy);
    }
}

public class UserAccountsCollectorTests
{
    [Fact]
    public void Collects_users_and_admins_escaping_wql()
    {
        var wmi = Substitute.For<IWmiQuery>();
        wmi.Query(@"root\cimv2", Arg.Is<string>(q => q.Contains("Win32_UserAccount"))).Returns(new[]
        {
            Wmi.Row(("Name", "zed"), ("Disabled", true), ("PasswordRequired", false), ("LocalAccount", true), ("SID", "S-1")),
            Wmi.Row(("Name", "amy"), ("FullName", "Amy")),
        });
        wmi.Query(@"root\cimv2", Arg.Is<string>(q => q.Contains("Win32_Group WHERE"))).Returns(new[]
        {
            Wmi.Row(("Name", "Administradores"), ("Domain", null)),
        });
        wmi.Query(@"root\cimv2", Arg.Is<string>(q => q.StartsWith("ASSOCIATORS"))).Returns(new[]
        {
            Wmi.Row(("Domain", "PC"), ("Name", "zed")),
            Wmi.Row(("Domain", "PC"), ("Name", "amy")),
        });
        var env = Substitute.For<ISystemEnvironment>();
        env.MachineName.Returns("O'PC");

        var (users, admins) = new UserAccountsCollector(wmi, env).Collect();

        Assert.Equal(new[] { "amy", "zed" }, users.Select(u => u.Name));
        Assert.True(users[1].Disabled);
        Assert.False(users[0].Disabled);
        Assert.Equal(new[] { @"PC\amy", @"PC\zed" }, admins);
        wmi.Received().Query(@"root\cimv2", Arg.Is<string>(q => q.Contains(@"Domain='O\'PC'") && q.Contains("Name='Administradores'")));
    }
}

public class FirewallRulesCollectorTests
{
    [Fact]
    public void Keeps_only_enabled_inbound_rules_and_maps_fields()
    {
        var policy = Substitute.For<IFirewallPolicy>();
        policy.GetRules().Returns(new[]
        {
            new FirewallRuleData("rdp", FirewallConstants.DirectionIn, true, FirewallConstants.ActionAllow, 6, 4, "3389", null),
            new FirewallRuleData("off", FirewallConstants.DirectionIn, false, 1, 6, 1, "1", "*"),
            new FirewallRuleData("out", FirewallConstants.DirectionOut, true, 1, 6, 1, "1", "*"),
            new FirewallRuleData("blk", FirewallConstants.DirectionIn, true, FirewallConstants.ActionBlock, 256, FirewallConstants.ProfileAll, null, "1.2.3.4"),
        });

        var rules = new FirewallRulesCollector(policy).Collect();

        Assert.Equal(2, rules.Count);
        Assert.Equal(new FirewallRule("rdp", "Allow", "TCP", "3389", "*", new() { "Public" }, true) with { Profiles = rules[0].Profiles }, rules[0]);
        Assert.Equal(new[] { "Public" }, rules[0].Profiles);
        Assert.Equal("Block", rules[1].Action);
        Assert.Equal("Any", rules[1].Protocol);
        Assert.Equal("*", rules[1].LocalPorts);
        Assert.Equal(new[] { "All" }, rules[1].Profiles);
    }

    [Theory]
    [InlineData(1, "ICMP")]
    [InlineData(6, "TCP")]
    [InlineData(17, "UDP")]
    [InlineData(58, "ICMPv6")]
    [InlineData(256, "Any")]
    [InlineData(47, "IP47")]
    public void MapProtocol(int p, string expected) => Assert.Equal(expected, FirewallMappers.MapProtocol(p));

    [Fact]
    public void MapAction_and_profiles()
    {
        Assert.Equal("Action7", FirewallMappers.MapAction(7));
        Assert.Equal(new[] { "Domain", "Private", "Public" }, FirewallMappers.MapProfiles(7));
        Assert.Equal(new[] { "Private" }, FirewallMappers.MapProfiles(2));
        Assert.Equal(new[] { "Profile0" }, FirewallMappers.MapProfiles(0));
    }
}

public class FolderPermissionsCollectorTests
{
    [Fact]
    public void Missing_folder_and_error_reading_acl_are_reported()
    {
        var acl = Substitute.For<IAclReader>();
        acl.DirectoryExists("missing").Returns(false);
        acl.DirectoryExists("broken").Returns(true);
        acl.GetRules("broken").Returns(_ => throw new UnauthorizedAccessException("nope"));

        var list = new FolderPermissionsCollector(acl).Collect(new[] { "missing", "broken" });

        Assert.False(list[0].Exists);
        Assert.True(list[1].Exists);
        Assert.Contains("UnauthorizedAccessException", list[1].Concerns.Single());
    }

    [Fact]
    public void Bug_risky_ace_detected_by_sid_on_localized_windows()
    {
        // Em pt-BR o nome é "BUILTIN\Usuários" — a checagem por nome em inglês perdia.
        var acl = Substitute.For<IAclReader>();
        acl.DirectoryExists("C:\\x").Returns(true);
        acl.GetRules("C:\\x").Returns(new[]
        {
            new AclRuleData(@"BUILTIN\Usuários", "S-1-5-32-545", FileSystemRights.Modify, AccessControlType.Allow),
            new AclRuleData(@"AUTORIDADE NT\SISTEMA", "S-1-5-18", FileSystemRights.FullControl, AccessControlType.Allow),
            new AclRuleData("Todos", "S-1-1-0", FileSystemRights.ReadAndExecute, AccessControlType.Allow),
        });

        var folder = new FolderPermissionsCollector(acl).Collect(new[] { "C:\\x" }).Single();

        Assert.Equal(3, folder.Aces.Count);
        Assert.Single(folder.Concerns);
        Assert.Contains("Usuários", folder.Concerns[0]);
    }

    [Theory]
    [InlineData("S-1-1-0", "x", true)]
    [InlineData("S-1-5-11", "x", true)]
    [InlineData("S-1-5-18", "Everyone", false)]     // SID manda sobre o nome
    [InlineData(null, "Everyone", true)]             // fallback por nome
    [InlineData("", @"AUTORIDADE NT\Usuários autenticados", true)]
    [InlineData(null, "Alice", false)]
    public void IsWorldIdentity(string? sid, string name, bool expected)
        => Assert.Equal(expected, AclRiskClassifier.IsWorldIdentity(new AclRuleData(name, sid, 0, AccessControlType.Allow)));

    [Fact]
    public void Bug_generic_rights_count_as_risky()
    {
        Assert.True(AclRiskClassifier.HasRiskyRights((FileSystemRights)0x10000000)); // GENERIC_ALL
        Assert.True(AclRiskClassifier.HasRiskyRights((FileSystemRights)0x40000000)); // GENERIC_WRITE
        Assert.True(AclRiskClassifier.HasRiskyRights(FileSystemRights.Write));
        Assert.False(AclRiskClassifier.HasRiskyRights(FileSystemRights.ReadAndExecute));
    }

    [Fact]
    public void Deny_is_never_risky()
        => Assert.False(AclRiskClassifier.IsRisky(new AclRuleData("Everyone", "S-1-1-0", FileSystemRights.FullControl, AccessControlType.Deny)));
}

public class InstalledSoftwareCollectorTests
{
    [Fact]
    public void Drops_empty_names_dedupes_and_sorts()
    {
        var reg = Substitute.For<IUninstallRegistry>();
        reg.ReadEntries().Returns(new[]
        {
            new SoftwareEntry("Zed", "1", null, null, "HKLM64"),
            new SoftwareEntry(" ", "1", null, null, "HKLM64"),
            new SoftwareEntry("Alpha", "2", null, null, "HKLM64"),
            new SoftwareEntry("Zed", "1", null, null, "HKLM32"),
            new SoftwareEntry("Zed", "2", null, null, "HKCU"),
        });

        var list = new InstalledSoftwareCollector(reg).Collect();

        Assert.Equal(new[] { "Alpha:2", "Zed:1", "Zed:2" }, list.Select(s => $"{s.Name}:{s.Version}"));
        Assert.Equal("HKLM64", list[1].Source);
    }
}

public class OpenPortsCollectorTests
{
    [Fact]
    public void Merges_tcp_and_udp_sorted()
    {
        var net = Substitute.For<INetworkInfo>();
        net.GetTcpListeners().Returns(new[] { new IPEndPoint(IPAddress.Any, 445), new IPEndPoint(IPAddress.Loopback, 80) });
        net.GetUdpListeners().Returns(new[] { new IPEndPoint(IPAddress.IPv6Any, 53) });

        var ports = new OpenPortsCollector(net).Collect();

        Assert.Equal(new[] { "TCP:80", "TCP:445", "UDP:53" }, ports.Select(p => $"{p.Protocol}:{p.LocalPort}"));
        Assert.Equal("127.0.0.1", ports[0].LocalAddress);
    }
}
