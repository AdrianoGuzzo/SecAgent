namespace SecAgent.Contracts;

/// <summary>Schema de <c>progress.json</c>; o arquivo só existe durante trabalho ativo.</summary>
public record AnalysisProgress(
    string State,           // "scanning" | "analyzing"
    DateTime StartedAtUtc,
    string Step,
    string Trigger,         // "scheduled" | "tray" | "incident"
    string? ScanFile        // preenchido após o scan (state=analyzing)
)
{
    public const string Scanning = "scanning";
    public const string Analyzing = "analyzing";
}
