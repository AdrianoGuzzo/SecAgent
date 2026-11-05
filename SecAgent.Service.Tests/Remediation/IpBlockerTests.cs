using System.Net;
using System.Text.Json;
using SecAgent.Service.Platform;
using SecAgent.Service.Remediation;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests.Remediation;

/// <summary>Firewall em memória: guarda os nomes das regras criadas.</summary>
internal sealed class FakeFirewall : IFirewallPolicy
{
    public readonly List<string> Rules = new();
    public Func<string, int, bool>? FailAdd;
    public bool FailEnumerate;

    public IReadOnlyList<FirewallRuleData> GetRules() => Array.Empty<FirewallRuleData>();

    public IReadOnlyList<string> GetRuleNames()
        => FailEnumerate ? throw new InvalidOperationException("enum") : Rules.ToList();

    public void AddBlockRule(string name, string remoteAddress, int direction, string description)
    {
        if (FailAdd?.Invoke(name, direction) == true) throw new UnauthorizedAccessException("denied");
        Rules.Add(name);
    }

    public bool RemoveRule(string name) => Rules.Remove(name);
}

public sealed class IpBlockerTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeFirewall _fw = new();

    public void Dispose() => _dir.Dispose();

    private IpBlocker Create() => new(Test.Log<IpBlocker>(), _fw, _dir.Paths, Test.Clock());

    private List<string> BlockedFile()
        => JsonSerializer.Deserialize<BlockedList>(File.ReadAllText(_dir.Paths.BlockedFile), JsonDefaults.Read)!
            .Blocked.Select(b => b.Ip).ToList();

    [Fact]
    public void Block_creates_in_and_out_rules_and_mirrors_blocked_json()
    {
        var b = Create();
        Assert.True(b.Block(" 8.8.8.8 "));
        Assert.True(b.Block("2001:4860::8888"));

        Assert.Equal(new[] { "SecAgent-Block-8.8.8.8-In", "SecAgent-Block-8.8.8.8-Out",
            "SecAgent-Block-2001:4860::8888-In", "SecAgent-Block-2001:4860::8888-Out" }, _fw.Rules);
        Assert.Equal(new[] { "2001:4860::8888", "8.8.8.8" }, BlockedFile());
    }

    [Fact]
    public void Block_is_idempotent_and_unblock_removes()
    {
        var b = Create();
        b.Block("8.8.8.8");
        b.Block("8.8.8.8");
        Assert.Equal(2, _fw.Rules.Count);

        Assert.True(b.Unblock("8.8.8.8"));
        Assert.Empty(_fw.Rules);
        Assert.Empty(BlockedFile());
        Assert.True(b.Unblock("8.8.8.8"));   // idempotente
    }

    [Theory]
    [InlineData("1")]            // IPAddress.TryParse aceitaria como 0.0.0.1
    [InlineData("1.2.3")]
    [InlineData("1.2.3.256")]
    [InlineData("01234.1.1.1")]
    [InlineData("a.b.c.d")]
    [InlineData("1.2.3.4/24")]
    [InlineData("")]
    [InlineData("not:an:ip:zz")]
    public void Bug_invalid_ips_are_rejected(string ip)
    {
        var b = Create();
        Assert.False(b.Block(ip));
        Assert.False(b.Unblock(ip));
        Assert.Empty(_fw.Rules);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("255.255.255.255")]
    [InlineData("224.0.0.251")]
    [InlineData("ff02::1")]
    [InlineData("::ffff:127.0.0.1")]
    public void Bug_special_addresses_cannot_be_blocked(string ip)
    {
        Assert.False(Create().Block(ip));
        Assert.Empty(_fw.Rules);
    }

    [Fact]
    public void Bug_half_block_is_rolled_back_and_reported_as_failure()
    {
        _fw.FailAdd = (_, dir) => dir == FirewallConstants.DirectionOut;
        var b = Create();

        Assert.False(b.Block("8.8.8.8"));
        Assert.Empty(_fw.Rules);
        Assert.Empty(BlockedFile());
    }

    [Fact]
    public void Inbound_failure_is_reported()
    {
        _fw.FailAdd = (_, _) => true;
        Assert.False(Create().Block("8.8.8.8"));
    }

    [Fact]
    public void Reconcile_rebuilds_from_existing_rules_ignoring_foreign_ones()
    {
        _fw.Rules.AddRange(new[]
        {
            "SecAgent-Block-1.2.3.4-In", "SecAgent-Block-1.2.3.4-Out", "SecAgent-Block-5.6.7.8-Out",
            "Remote Desktop", "SecAgent-Block-weird", "SecAgent-Block--In"
        });

        Create().Reconcile();

        Assert.Equal(new[] { "1.2.3.4", "5.6.7.8" }, BlockedFile());
    }

    [Fact]
    public void Enumeration_or_write_failures_are_swallowed()
    {
        _fw.FailEnumerate = true;
        Create().Reconcile();
        Assert.False(File.Exists(_dir.Paths.BlockedFile));

        _fw.FailEnumerate = false;
        Directory.CreateDirectory(_dir.Paths.BlockedFile);   // escrita falha
        Create().Reconcile();
    }

    [Fact]
    public void Unblock_failure_is_reported()
    {
        var fw = Substitute.For<IFirewallPolicy>();
        fw.RemoveRule(Arg.Any<string>()).Returns(_ => throw new InvalidOperationException("com"));
        fw.GetRuleNames().Returns(Array.Empty<string>());
        Assert.False(new IpBlocker(Test.Log<IpBlocker>(), fw, _dir.Paths, Test.Clock()).Unblock("8.8.8.8"));
    }

    [Theory]
    [InlineData("SecAgent-Block-1.2.3.4-In", true, "1.2.3.4")]
    [InlineData("secagent-block-::1-OUT", true, "::1")]
    [InlineData("SecAgent-Block-1.2.3.4", false, "")]
    [InlineData(null, false, "")]
    public void BlockRuleName_parse(string? name, bool ok, string ip)
    {
        Assert.Equal(ok, BlockRuleName.TryParseIp(name, out var parsed));
        Assert.Equal(ip, parsed);
    }

    [Fact]
    public void IpAddressPolicy_parses_canonical()
    {
        Assert.True(IpAddressPolicy.TryParseStrict("2001:DB8::1", out var v6));
        Assert.Equal(IPAddress.Parse("2001:db8::1"), v6);
        Assert.True(IpAddressPolicy.IsBlockable(IPAddress.Parse("8.8.8.8"), out _));
    }
}
