namespace SecAgent.Tray;

// Mirror of SecAgent.Service.Models.AgentStatus.
// Duplicated here to avoid a project reference on the service (which pulls in
// WMI and the full hosting stack).
public record AgentStatus(
    DateTime LastUpdatedUtc,
    string OverallSeverity,
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
