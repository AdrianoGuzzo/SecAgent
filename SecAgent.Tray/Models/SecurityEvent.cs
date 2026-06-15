namespace SecAgent.Tray.Models;

// Mirror of SecAgent.Service.Models.SecurityEvent (events/events_*.jsonl lines)
// and IncidentReport (reports/incident_*.json).

public record SecurityEvent(
    DateTime TimestampUtc,
    string Source,                              // "process" | "network" | "eventlog"
    string Severity,                            // "info" | "low" | "medium" | "high"
    string Title,
    string Description,
    Dictionary<string, string>? Details
);

public record IncidentReport(
    DateTime TimestampUtc,
    int EventCount,
    DateTime WindowStartUtc,
    DateTime WindowEndUtc,
    string Severity,
    string Title,
    string Summary,
    List<string>? RecommendedActions,
    AnalysisMeta? Meta
);
