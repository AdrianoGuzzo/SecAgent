namespace SecAgent.Contracts;

/// <summary>Schema de <c>reports/report_*.json</c> (análise de scan pelo Claude).</summary>
public record AnalysisResult(
    DateTime TimestampUtc,
    string ScanFile,
    string RiskLevel,                  // "low" | "medium" | "high" | "critical" | "unknown"
    string Summary,
    List<Finding> Findings,
    AnalysisMeta Meta
);

public record Finding(
    string Severity,                   // "info" | "low" | "medium" | "high" | "critical"
    string Category,                   // livre: "auth" | "network" | "software" | "config" | ...
    string Title,
    string Description,
    string Recommendation,
    string? Evidence                   // referência opcional a um campo do scan
);

public record AnalysisMeta(
    string Model,
    long ElapsedMs,
    int? InputTokens,
    int? OutputTokens,
    int? CacheCreationTokens,
    int? CacheReadTokens,
    decimal? TotalCostUsd,
    string? SessionId,
    bool IsError,
    string? Effort = null              // esforço aplicado (null = não aplicável, ex. Haiku)
);
