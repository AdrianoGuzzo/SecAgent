using System.Text.Json;
using System.Text.Json.Serialization;
using SecAgent.Service.Models;

namespace SecAgent.Service.Analysis;

/// <summary>
/// Maintains a single progress.json file that the Tray app watches to render
/// live progress (tooltip + busy icon + transition toast) during scan and
/// Claude analysis. The file is deleted when work completes (idle state).
/// </summary>
public class ProgressTracker
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly ILogger<ProgressTracker> _logger;
    private readonly string _path;
    private readonly object _lock = new();
    private DateTime _scanStartedUtc;

    public ProgressTracker(ILogger<ProgressTracker> logger)
    {
        _logger = logger;
        var dir = @"C:\ProgramData\SecAgent";
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "progress.json");
        // Clean any stale file from a previous run (service was killed mid-work).
        TryDelete();
    }

    public void BeginScan(string trigger)
    {
        _scanStartedUtc = DateTime.UtcNow;
        Write(new AnalysisProgress(
            State: "scanning",
            StartedAtUtc: _scanStartedUtc,
            Step: "Coletando dados do sistema",
            Trigger: trigger,
            ScanFile: null));
    }

    public void EndScanBeginAnalysis(string scanFile, string model, string trigger)
    {
        Write(new AnalysisProgress(
            State: "analyzing",
            StartedAtUtc: _scanStartedUtc,    // keep total elapsed from scan start
            Step: $"Claude analisando (modelo={model})",
            Trigger: trigger,
            ScanFile: scanFile));
    }

    public void Clear() => TryDelete();

    private void Write(AnalysisProgress p)
    {
        lock (_lock)
        {
            try
            {
                File.WriteAllText(_path, JsonSerializer.Serialize(p, JsonOpts));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write progress.json");
            }
        }
    }

    private void TryDelete()
    {
        lock (_lock)
        {
            try { if (File.Exists(_path)) File.Delete(_path); }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to delete progress.json"); }
        }
    }
}
