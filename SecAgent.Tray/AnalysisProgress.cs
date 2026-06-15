namespace SecAgent.Tray;

// Mirror of SecAgent.Service.Models.AnalysisProgress.
public record AnalysisProgress(
    string State,
    DateTime StartedAtUtc,
    string Step,
    string Trigger,
    string? ScanFile
);
