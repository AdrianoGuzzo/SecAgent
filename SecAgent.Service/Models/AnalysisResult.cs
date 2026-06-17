namespace SecAgent.Service.Models;

public record AnalysisResult(
    DateTime TimestampUtc,
    string ScanFile,
    string RiskLevel,                  // "low" | "medium" | "high" | "critical"
    string Summary,
    List<Finding> Findings,
    AnalysisMeta Meta
);

public record Finding(
    string Severity,                   // "info" | "low" | "medium" | "high" | "critical"
    string Category,                   // free-form: "auth" | "network" | "software" | "config" | ...
    string Title,
    string Description,
    string Recommendation,
    string? Evidence                   // optional reference to scan field
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
    string? Effort = null              // nível de esforço usado (null = não aplicável, ex. Haiku)
);
