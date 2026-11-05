using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Analysis;
using SecAgent.Service.Collectors;
using SecAgent.Service.Diagnostics;
using SecAgent.Service.Monitors;
using SecAgent.Service.Platform;
using SecAgent.Service.Remediation;
using SecAgent.Service.Triggers;

namespace SecAgent.Service;

/// <summary>
/// Composição de DI do Service. Separado do Program.cs para que os testes
/// validem o grafo completo (todas as dependências resolvem) e a validação de options.
/// </summary>
public static class ServiceRegistration
{
    public static IServiceCollection AddSecAgentService(this IServiceCollection services, IConfiguration config)
    {
        services.AddSingleton(TimeProvider.System);

        // ---- Options (validadas no startup: config inválida falha cedo, não em loop) ----
        services.AddOptions<AgentOptions>().Bind(config.GetSection("Agent"))
            .Validate(o => !string.IsNullOrWhiteSpace(o.DataRoot), "Agent:DataRoot é obrigatório")
            .ValidateOnStart();
        services.AddOptions<ScannerOptions>().Bind(config.GetSection("Scanner"))
            .Validate(o => o.ScanIntervalHours > 0, "Scanner:ScanIntervalHours deve ser > 0")
            .Validate(o => !string.IsNullOrWhiteSpace(o.OutputDirectory), "Scanner:OutputDirectory é obrigatório")
            .ValidateOnStart();
        services.AddOptions<ClaudeOptions>().Bind(config.GetSection("Claude"))
            .Validate(o => o.TimeoutSeconds > 0, "Claude:TimeoutSeconds deve ser > 0")
            .Validate(o => !string.IsNullOrWhiteSpace(o.ReportsDirectory), "Claude:ReportsDirectory é obrigatório")
            .ValidateOnStart();
        services.AddOptions<MonitorOptions>().Bind(config.GetSection("Monitors"))
            .PostConfigure(o => o.ApplyDefaults())
            .Validate(o => o.NetworkPollSeconds > 0, "Monitors:NetworkPollSeconds deve ser > 0")
            .Validate(o => o.NetworkSnapshotSeconds > 0, "Monitors:NetworkSnapshotSeconds deve ser > 0")
            .Validate(o => o.ChannelCapacity > 0, "Monitors:ChannelCapacity deve ser > 0")
            .Validate(o => o.IncidentEventThreshold > 0, "Monitors:IncidentEventThreshold deve ser > 0")
            .ValidateOnStart();
        services.AddOptions<TriggerOptions>().Bind(config.GetSection("Triggers"))
            .Validate(o => o.DebounceSeconds >= 0, "Triggers:DebounceSeconds não pode ser negativo")
            .ValidateOnStart();

        services.AddSingleton(sp => new AgentPaths(sp.GetRequiredService<IOptions<AgentOptions>>().Value.DataRoot));

        // ---- Adapters de SO (únicos pontos sem cobertura de teste) ----
        services.AddSingleton<ISystemEnvironment, SystemEnvironment>();
        services.AddSingleton<IWmiQuery, WmiQuery>();
        services.AddSingleton<IFirewallPolicy, ComFirewallPolicy>();
        services.AddSingleton<IUninstallRegistry, RegistryUninstallReader>();
        services.AddSingleton<IAclReader, NtfsAclReader>();
        services.AddSingleton<INetworkInfo, SystemNetworkInfo>();
        services.AddSingleton<ITcpConnectionSource, IpHlpTcpConnectionSource>();
        services.AddSingleton<IProcessStartSource, WmiProcessStartSource>();
        services.AddSingleton<IEventLogSource, WindowsEventLogSource>();
        services.AddSingleton<IClaudeCli, ProcessClaudeCli>();
        services.AddSingleton<ITriggerDirectorySetup, TriggerDirectoryAclSetup>();
        services.AddSingleton<ITraceLog, FileTraceLog>();

        // ---- Scan agendado + análise Claude ----
        services.AddSingleton<OpenPortsCollector>();
        services.AddSingleton<InstalledSoftwareCollector>();
        services.AddSingleton<FolderPermissionsCollector>();
        services.AddSingleton<DefenderStatusCollector>();
        services.AddSingleton<FirewallStatusCollector>();
        services.AddSingleton<FirewallRulesCollector>();
        services.AddSingleton<InstalledUpdatesCollector>();
        services.AddSingleton<UserAccountsCollector>();
        services.AddSingleton<ISecurityScanner, SecurityScanner>();
        services.AddSingleton<IStatusFileService, StatusFileService>();
        services.AddSingleton<IProgressTracker, ProgressTracker>();
        services.AddSingleton<IClaudeAnalyzer, ClaudeAnalyzer>();
        services.AddSingleton<IScanRunner, ScanRunner>();
        services.AddSingleton<IIpBlocker, IpBlocker>();
        services.AddHostedService<Worker>();

        // ---- Trigger manual via Tray ----
        services.AddHostedService<TriggerWatcher>();

        // ---- Monitores em tempo real + processador de incidentes ----
        // Canal bounded compartilhado; DropOldest evita bloquear produtores.
        // Cada monitor recebe só o lado de que precisa (writer / reader).
        services.AddSingleton(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<MonitorOptions>>().Value;
            return Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(opts.ChannelCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });
        });
        services.AddSingleton(sp => sp.GetRequiredService<Channel<SecurityEvent>>().Writer);
        services.AddSingleton(sp => sp.GetRequiredService<Channel<SecurityEvent>>().Reader);
        services.AddHostedService<ProcessMonitor>();
        services.AddHostedService<NetworkMonitor>();
        services.AddHostedService<NetworkSnapshotService>();
        services.AddHostedService<EventLogMonitor>();
        services.AddHostedService<SuspiciousEventProcessor>();

        return services;
    }
}
