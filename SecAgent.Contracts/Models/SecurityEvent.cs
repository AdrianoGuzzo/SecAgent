namespace SecAgent.Contracts;

/// <summary>Uma linha de <c>events/events_*.jsonl</c>; também entrada da análise de incidente.</summary>
public record SecurityEvent(
    DateTime TimestampUtc,
    string Source,                                // "process" | "network" | "eventlog"
    string Severity,                              // "info" | "low" | "medium" | "high" | "critical"
    string Title,
    string Description,
    Dictionary<string, string> Details            // campos brutos para contexto
);

/// <summary>Schema de <c>reports/incident_*.json</c>.</summary>
public record IncidentReport(
    DateTime TimestampUtc,
    int EventCount,
    DateTime WindowStartUtc,
    DateTime WindowEndUtc,
    string Severity,                              // avaliação do modelo
    string Title,
    string Summary,
    List<string> RecommendedActions,
    AnalysisMeta Meta
);
