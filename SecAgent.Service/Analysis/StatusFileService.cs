using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using SecAgent.Service.Models;

namespace SecAgent.Service.Analysis;

/// <summary>
/// Maintains a single status.json file that the Tray app polls to drive its
/// icon color and pop toast notifications.
/// </summary>
public class StatusFileService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly ILogger<StatusFileService> _logger;
    private readonly string _path;
    private readonly object _lock = new();

    public StatusFileService(ILogger<StatusFileService> logger, IOptions<ClaudeOptions> opts)
    {
        _logger = logger;
        var dir = Path.GetDirectoryName(opts.Value.ReportsDirectory) ?? @"C:\ProgramData\SecAgent";
        _path = Path.Combine(dir, "status.json");
    }

    public void UpdateAfterScan(AnalysisResult result)
    {
        var snippet = new ScanSnippet(
            result.TimestampUtc,
            result.RiskLevel,
            result.Findings.Count,
            $"report_{result.TimestampUtc:yyyy-MM-dd_HHmmss}.md");
        Mutate(s => s with { LastScan = snippet });
    }

    public void UpdateAfterIncident(IncidentReport report)
    {
        var snippet = new IncidentSnippet(
            report.TimestampUtc,
            report.Severity,
            report.Title,
            report.EventCount,
            $"incident_{report.TimestampUtc:yyyy-MM-dd_HHmmss}.md");
        Mutate(s => s with { LastIncident = snippet });
    }

    private void Mutate(Func<AgentStatus, AgentStatus> mutator)
    {
        lock (_lock)
        {
            try
            {
                var current = Read() ?? new AgentStatus(DateTime.UtcNow, "green", null, null);
                var updated = mutator(current) with { LastUpdatedUtc = DateTime.UtcNow };
                updated = updated with { OverallSeverity = ComputeOverall(updated) };
                File.WriteAllText(_path, JsonSerializer.Serialize(updated, JsonOpts));
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
        try { return JsonSerializer.Deserialize<AgentStatus>(File.ReadAllText(_path)); }
        catch { return null; }
    }

    private static string ComputeOverall(AgentStatus s)
    {
        var sevs = new List<string>();
        if (s.LastScan?.RiskLevel is { } r) sevs.Add(r);
        if (s.LastIncident?.Severity is { } i) sevs.Add(i);

        if (sevs.Any(IsRed))    return "red";
        if (sevs.Any(IsYellow)) return "yellow";
        return "green";
    }

    private static bool IsRed(string s) =>
        s.Equals("critical", StringComparison.OrdinalIgnoreCase) ||
        s.Equals("high", StringComparison.OrdinalIgnoreCase);

    private static bool IsYellow(string s) =>
        s.Equals("medium", StringComparison.OrdinalIgnoreCase) ||
        s.Equals("unknown", StringComparison.OrdinalIgnoreCase);
}
