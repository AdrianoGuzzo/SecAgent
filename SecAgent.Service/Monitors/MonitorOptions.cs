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
    public int NetworkSnapshotSeconds { get; set; } = 5;
    public bool EmitInboundEvents { get; set; } = true;
    public List<int> InboundPortWhitelist { get; set; } = new();
    public string SnapshotPath { get; set; } = @"C:\ProgramData\SecAgent\network.json";

    // Event log monitor
    public bool EventLogMonitorEnabled { get; set; } = true;
    public List<int> SecurityEventIds { get; set; } = new() { 4625, 4720, 4732, 4740, 1102 };
    public List<int> SystemEventIds { get; set; } = new() { 7045 };

    // Incident processor
    public int IncidentEventThreshold { get; set; } = 5;
    public int IncidentWindowMinutes { get; set; } = 30;
    public int IncidentCooldownMinutes { get; set; } = 60;   // don't fire Claude again within this period
    public int ChannelCapacity { get; set; } = 1000;
}
