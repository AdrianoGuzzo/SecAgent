using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service;
using SecAgent.Service.Analysis;
using SecAgent.Service.Collectors;
using SecAgent.Service.Models;
using SecAgent.Service.Monitors;
using SecAgent.Service.Remediation;
using SecAgent.Service.Triggers;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<ScannerOptions>(builder.Configuration.GetSection("Scanner"));
builder.Services.Configure<ClaudeOptions>(builder.Configuration.GetSection("Claude"));
builder.Services.Configure<MonitorOptions>(builder.Configuration.GetSection("Monitors"));
builder.Services.Configure<TriggerOptions>(builder.Configuration.GetSection("Triggers"));

// Phase 1+2: scheduled scan + Claude analysis
builder.Services.AddSingleton<OpenPortsCollector>();
builder.Services.AddSingleton<InstalledSoftwareCollector>();
builder.Services.AddSingleton<FolderPermissionsCollector>();
builder.Services.AddSingleton<DefenderStatusCollector>();
builder.Services.AddSingleton<FirewallStatusCollector>();
builder.Services.AddSingleton<FirewallRulesCollector>();
builder.Services.AddSingleton<InstalledUpdatesCollector>();
builder.Services.AddSingleton<UserAccountsCollector>();
builder.Services.AddSingleton<SecurityScanner>();
builder.Services.AddSingleton<StatusFileService>();
builder.Services.AddSingleton<ProgressTracker>();
builder.Services.AddSingleton<ClaudeAnalyzer>();
builder.Services.AddSingleton<ScanRunner>();
builder.Services.AddSingleton<IpBlocker>();
builder.Services.AddHostedService<Worker>();

// Phase 4.1: manual trigger via tray
builder.Services.AddHostedService<TriggerWatcher>();

// Phase 3: real-time monitors + incident processor
// Shared bounded channel between producers (monitors) and consumer (processor).
// DropOldest avoids blocking producers if the channel backs up during a long
// Claude call.
builder.Services.AddSingleton(sp =>
{
    var opts = sp.GetRequiredService<IOptions<MonitorOptions>>().Value;
    return Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(opts.ChannelCapacity)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
        SingleWriter = false
    });
});
builder.Services.AddHostedService<ProcessMonitor>();
builder.Services.AddHostedService<NetworkMonitor>();
builder.Services.AddHostedService<NetworkSnapshotService>();
builder.Services.AddHostedService<EventLogMonitor>();
builder.Services.AddHostedService<SuspiciousEventProcessor>();

builder.Services.AddWindowsService(o => o.ServiceName = "SecAgent");

var host = builder.Build();
host.Run();
