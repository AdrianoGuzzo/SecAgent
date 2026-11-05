namespace SecAgent.Service.Monitors;

/// <summary>
/// Seção "Monitors".
///
/// As listas são <c>null</c> por padrão e recebem os defaults em
/// <see cref="ApplyDefaults"/> (via PostConfigure) SÓ quando a config não as
/// define. Motivo: o ConfigurationBinder ANEXA itens a listas já inicializadas —
/// com defaults no inicializador era impossível remover, por exemplo, 80/443 do
/// whitelist ou deixar de monitorar o evento 4720.
/// </summary>
public class MonitorOptions
{
    public static readonly IReadOnlyList<string> DefaultSuspiciousPathFragments = new[]
    {
        @"\Temp\", @"\AppData\Local\Temp\", @"\Downloads\", @"\Users\Public\"
    };
    public static readonly IReadOnlyList<int> DefaultNetworkPortWhitelist = new[] { 80, 443, 53, 123 };
    public static readonly IReadOnlyList<int> DefaultSensitiveInboundPorts = new[]
    {
        21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 5901, 5985, 5986
    };
    public static readonly IReadOnlyList<int> DefaultSecurityEventIds = new[] { 4625, 4720, 4732, 4740, 1102 };
    public static readonly IReadOnlyList<int> DefaultSystemEventIds = new[] { 7045 };
    public static readonly IReadOnlyList<string> DefaultSelfServiceNames = new[] { "SecAgent" };

    public string EventsDirectory { get; set; } = AgentPaths.Default.EventsDir;

    // Fragmentos casados contra o NOME do executável (ProcessMonitor) e do
    // processo dono da conexão (NetworkSnapshot) para não auto-detectar o agente
    // (ex.: SecAgent-Setup.exe rodando de Downloads).
    public List<string>? SelfReferenceFragments { get; set; }

    // Pastas de instalação do agente; processos sob elas nunca são sinalizados.
    // Vazio → pasta-pai do executável do Service (cobre {app}\Service e {app}\Tray).
    public List<string>? SelfInstallDirectories { get; set; }

    // Nomes de serviço do próprio agente: evento 7045 (serviço instalado) com
    // esse ServiceName exato é ignorado (reinstalação do SecAgent).
    public List<string>? SelfServiceNames { get; set; }

    // Process monitor
    public bool ProcessMonitorEnabled { get; set; } = true;
    public List<string>? ProcessWhitelist { get; set; }
    public List<string>? SuspiciousPathFragments { get; set; }

    // Network monitor (legacy outbound diff)
    public bool NetworkMonitorEnabled { get; set; } = true;
    public int NetworkPollSeconds { get; set; } = 30;
    public List<int>? NetworkPortWhitelist { get; set; }

    // Network snapshot (live connections table + inbound alerting)
    public bool NetworkSnapshotEnabled { get; set; } = true;
    public double NetworkSnapshotSeconds { get; set; } = 0.5;
    public bool EmitInboundEvents { get; set; } = true;
    public List<int>? InboundPortWhitelist { get; set; }
    public string SnapshotPath { get; set; } = AgentPaths.Default.NetworkFile;

    // Per-interface throughput (total agregado + detalhe por NIC no snapshot).
    // Só interfaces físicas reais (Wi-Fi/Ethernet) ativas; ignora virtuais/loopback.
    public bool InterfaceStatsEnabled { get; set; } = true;

    // Immediate inbound alerts (toast via Tray). Sensitive (admin/remote-access)
    // ports raise a "critical" alert; others "medium".
    public string AlertsDirectory { get; set; } = AgentPaths.Default.AlertsDir;
    public int InboundAlertCooldownMinutes { get; set; } = 10;
    public List<int>? SensitiveInboundPorts { get; set; }

    // Event log monitor
    public bool EventLogMonitorEnabled { get; set; } = true;
    public List<int>? SecurityEventIds { get; set; }
    public List<int>? SystemEventIds { get; set; }

    // Incident processor
    // When false, events are still logged to JSONL (free, feeds the live feed),
    // but Claude is NOT invoked automatically — analysis is manual only.
    public bool IncidentAutoAnalysisEnabled { get; set; } = false;
    public int IncidentEventThreshold { get; set; } = 5;
    public int IncidentWindowMinutes { get; set; } = 30;
    public int IncidentCooldownMinutes { get; set; } = 60;   // don't fire Claude again within this period
    public int ChannelCapacity { get; set; } = 1000;

    /// <summary>Preenche as listas não configuradas com os defaults. Idempotente.</summary>
    public MonitorOptions ApplyDefaults()
    {
        SelfReferenceFragments ??= new() { "SecAgent" };
        SelfInstallDirectories ??= new();
        SelfServiceNames ??= new(DefaultSelfServiceNames);
        ProcessWhitelist ??= new();
        SuspiciousPathFragments ??= new(DefaultSuspiciousPathFragments);
        NetworkPortWhitelist ??= new(DefaultNetworkPortWhitelist);
        InboundPortWhitelist ??= new();
        SensitiveInboundPorts ??= new(DefaultSensitiveInboundPorts);
        SecurityEventIds ??= new(DefaultSecurityEventIds);
        SystemEventIds ??= new(DefaultSystemEventIds);
        return this;
    }
}
