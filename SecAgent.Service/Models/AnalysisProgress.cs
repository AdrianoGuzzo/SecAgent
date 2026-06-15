namespace SecAgent.Service.Models;

public record AnalysisProgress(
    string State,           // "scanning" | "analyzing"
    DateTime StartedAtUtc,
    string Step,
    string Trigger,         // "scheduled" | "tray" | "incident"
    string? ScanFile        // set after scan completes (state=analyzing)
);
