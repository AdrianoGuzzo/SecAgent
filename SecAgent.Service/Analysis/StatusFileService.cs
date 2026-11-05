using System.Text.Json;

namespace SecAgent.Service.Analysis;

public interface IStatusFileService
{
    void UpdateAfterScan(AnalysisResult result);
    void UpdateAfterIncident(IncidentReport report);
}

/// <summary>
/// Mantém <c>status.json</c> (read-modify-write), que o Tray lê para a cor do
/// ícone. Escrita atômica: o Tray polleia a cada 10s e nunca vê JSON pela metade.
/// </summary>
public class StatusFileService : IStatusFileService
{
    private readonly ILogger<StatusFileService> _logger;
    private readonly TimeProvider _time;
    private readonly string _path;
    private readonly object _lock = new();

    public StatusFileService(ILogger<StatusFileService> logger, AgentPaths paths, TimeProvider time)
    {
        _logger = logger;
        _time = time;
        _path = paths.StatusFile;
    }

    public void UpdateAfterScan(AnalysisResult result)
    {
        var snippet = new ScanSnippet(
            result.TimestampUtc,
            result.RiskLevel,
            result.Findings.Count,
            ReportNames.ScanReportMarkdown(result.TimestampUtc));
        Mutate(s => s with { LastScan = snippet });
    }

    public void UpdateAfterIncident(IncidentReport report)
    {
        var snippet = new IncidentSnippet(
            report.TimestampUtc,
            report.Severity,
            report.Title,
            report.EventCount,
            ReportNames.IncidentMarkdown(report.TimestampUtc));
        Mutate(s => s with { LastIncident = snippet });
    }

    private void Mutate(Func<AgentStatus, AgentStatus> mutator)
    {
        lock (_lock)
        {
            try
            {
                var now = _time.GetUtcNow().UtcDateTime;
                var current = Read() ?? new AgentStatus(now, SeverityLevels.Green, null, null);
                var updated = mutator(current) with { LastUpdatedUtc = now };
                updated = updated with { OverallSeverity = ComputeOverall(updated) };
                AtomicFile.WriteAllText(_path, JsonSerializer.Serialize(updated, JsonDefaults.Indented));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to update status.json at {Path}", _path);
            }
        }
    }

    private AgentStatus? Read()
    {
        if (!File.Exists(_path)) return null;
        try { return JsonSerializer.Deserialize<AgentStatus>(File.ReadAllText(_path), JsonDefaults.Read); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "status.json corrompido em {Path}; recriando", _path);
            return null;
        }
    }

    internal static string ComputeOverall(AgentStatus s)
    {
        var lights = new List<string>();
        if (s.LastScan?.RiskLevel is { } r) lights.Add(SeverityLevels.ToTrafficLight(r));
        if (s.LastIncident?.Severity is { } i) lights.Add(SeverityLevels.ToTrafficLight(i));
        return SeverityLevels.Worst(lights);
    }
}
