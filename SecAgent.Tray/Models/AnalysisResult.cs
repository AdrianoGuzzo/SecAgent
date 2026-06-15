namespace SecAgent.Tray.Models;

// Mirror of SecAgent.Service.Models.AnalysisResult (reports/report_*.json).
// Duplicated to avoid a project reference on the service (which pulls in WMI
// and the full hosting stack). Property names must match the Service.

public record AnalysisResult(
    DateTime TimestampUtc,
    string ScanFile,
    string RiskLevel,
    string Summary,
    List<Finding> Findings,
    AnalysisMeta? Meta
);

public record Finding(
    string Severity,
    string Category,
    string Title,
    string Description,
    string Recommendation,
    string? Evidence
);

public record AnalysisMeta(
    string? Model,
    long ElapsedMs,
    int? InputTokens,
    int? OutputTokens,
    int? CacheCreationTokens,
    int? CacheReadTokens,
    decimal? TotalCostUsd,
    string? SessionId,
    bool IsError
);
