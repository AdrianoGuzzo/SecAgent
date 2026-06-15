namespace SecAgent.Service.Models;

public record SecurityEvent(
    DateTime TimestampUtc,
    string Source,                                // "process" | "network" | "eventlog"
    string Severity,                              // "info" | "low" | "medium" | "high"
    string Title,
    string Description,
    Dictionary<string, string> Details            // raw fields for context
);

public record IncidentReport(
    DateTime TimestampUtc,
    int EventCount,
    DateTime WindowStartUtc,
    DateTime WindowEndUtc,
    string Severity,                              // model's assessment
    string Title,
    string Summary,
    List<string> RecommendedActions,
    AnalysisMeta Meta
);
