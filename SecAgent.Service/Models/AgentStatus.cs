namespace SecAgent.Service.Models;

public record AgentStatus(
    DateTime LastUpdatedUtc,
    string OverallSeverity,           // "green" | "yellow" | "red"
    ScanSnippet? LastScan,
    IncidentSnippet? LastIncident
);

public record ScanSnippet(
    DateTime TimestampUtc,
    string RiskLevel,
    int FindingsCount,
    string ReportFile
);

public record IncidentSnippet(
    DateTime TimestampUtc,
    string Severity,
    string Title,
    int EventCount,
    string ReportFile
);
