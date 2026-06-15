namespace SecAgent.Service.Monitors;

public class MonitorOptions
{
    public string EventsDirectory { get; set; } = @"C:\ProgramData\SecAgent\events";

    // Fragments matched against process paths, command-lines, and eventlog
    // descriptions to suppress events about the agent itself (avoids self-flagging
    // every time the service is reinstalled or restarted).
    public List<string> SelfReferenceFragments { get; set; } = new();

    // Process monitor
    public bool ProcessMonitorEnabled { get; set; } = true;
    public List<string> ProcessWhitelist { get; set; } = new();
    public List<string> SuspiciousPathFragments { get; set; } = new()
    {
        @"\Temp\",
        @"\AppData\Local\Temp\",
        @"\Downloads\",
        @"\Users\Public\"
    };

    // Network monitor (legacy outbound diff)
    public bool NetworkMonitorEnabled { get; set; } = true;
    public int NetworkPollSeconds { get; set; } = 30;
    public List<int> NetworkPortWhitelist { get; set; } = new() { 80, 443, 53, 123 };

    // Network snapshot (live connections table + inbound alerting)
    public bool NetworkSnapshotEnabled { get; set; } = true;
    public int NetworkSnapshotSeconds { get; set; } = 2;
    public bool EmitInboundEvents { get; set; } = true;
    public List<int> InboundPortWhitelist { get; set; } = new();
    public string SnapshotPath { get; set; } = @"C:\ProgramData\SecAgent\network.json";

    // Immediate inbound alerts (toast via Tray). Sensitive (admin/remote-access)
    // ports raise a "critical" alert; others "medium".
    public string AlertsDirectory { get; set; } = @"C:\ProgramData\SecAgent\alerts";
    public int InboundAlertCooldownMinutes { get; set; } = 10;
    public List<int> SensitiveInboundPorts { get; set; } = new()
    {
        21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 5901, 5985, 5986
    };

    // Event log monitor
    public bool EventLogMonitorEnabled { get; set; } = true;
    public List<int> SecurityEventIds { get; set; } = new() { 4625, 4720, 4732, 4740, 1102 };
    public List<int> SystemEventIds { get; set; } = new() { 7045 };

    // Incident processor
    // When false, events are still logged to JSONL (free, feeds the live feed),
    // but Claude is NOT invoked automatically — analysis is manual only.
    public bool IncidentAutoAnalysisEnabled { get; set; } = false;
    public int IncidentEventThreshold { get; set; } = 5;
    public int IncidentWindowMinutes { get; set; } = 30;
    public int IncidentCooldownMinutes { get; set; } = 60;   // don't fire Claude again within this period
    public int ChannelCapacity { get; set; } = 1000;
}
