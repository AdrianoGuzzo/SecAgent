using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using SecAgent.Service.Analysis;
using SecAgent.Service.Monitors;
using SecAgent.Service.Remediation;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests;

public sealed class ServiceRegistrationTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private ServiceProvider Build(Dictionary<string, string?> overrides)
    {
        var values = new Dictionary<string, string?>
        {
            ["Agent:DataRoot"] = _dir.Path,
            ["Scanner:OutputDirectory"] = Path.Combine(_dir.Path, "scans"),
            ["Claude:ReportsDirectory"] = Path.Combine(_dir.Path, "reports"),
        };
        foreach (var kv in overrides) values[kv.Key] = kv.Value;
        var config = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecAgentService(config);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }

    [Fact]
    public void Whole_graph_resolves()
    {
        using var sp = Build(new());
        Assert.Equal(7, sp.GetServices<IHostedService>().Count());
        Assert.NotNull(sp.GetRequiredService<IScanRunner>());
        Assert.NotNull(sp.GetRequiredService<IClaudeAnalyzer>());
        Assert.NotNull(sp.GetRequiredService<IIpBlocker>());
        Assert.Equal(_dir.Path, sp.GetRequiredService<AgentPaths>().DataRoot);
    }

    [Fact]
    public void Bug_monitor_list_defaults_are_applied_only_when_absent()
    {
        using var sp = Build(new() { ["Monitors:NetworkPortWhitelist:0"] = "8443" });
        var o = sp.GetRequiredService<IOptions<MonitorOptions>>().Value;
        Assert.Equal(new[] { 8443 }, o.NetworkPortWhitelist);
        Assert.Equal(MonitorOptions.DefaultSecurityEventIds, o.SecurityEventIds);
    }

    [Theory]
    [InlineData("Scanner:ScanIntervalHours", "0")]
    [InlineData("Claude:TimeoutSeconds", "-1")]
    [InlineData("Monitors:NetworkPollSeconds", "0")]
    [InlineData("Monitors:NetworkSnapshotSeconds", "0")]
    [InlineData("Monitors:ChannelCapacity", "0")]
    [InlineData("Monitors:IncidentEventThreshold", "0")]
    [InlineData("Triggers:DebounceSeconds", "-5")]
    [InlineData("Agent:DataRoot", " ")]
    [InlineData("Scanner:OutputDirectory", "")]
    [InlineData("Claude:ReportsDirectory", "")]
    public async Task Bug_invalid_options_fail_at_startup(string key, string value)
    {
        using var sp = Build(new() { [key] = value });
        var validator = sp.GetRequiredService<IStartupValidator>();
        Assert.Throws<OptionsValidationException>(() => validator.Validate());
        await Task.CompletedTask;
    }
}
