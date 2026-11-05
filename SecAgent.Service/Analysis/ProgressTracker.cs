using System.Text.Json;

namespace SecAgent.Service.Analysis;

public interface IProgressTracker
{
    void BeginScan(string trigger);
    void EndScanBeginAnalysis(string scanFile, string model, string trigger);
    void Clear();
}

/// <summary>
/// Mantém <c>progress.json</c>, observado pelo Tray para o tooltip/ícone "busy"
/// e o toast de transição. O arquivo é removido ao terminar (estado ocioso).
/// </summary>
public class ProgressTracker : IProgressTracker
{
    private readonly ILogger<ProgressTracker> _logger;
    private readonly TimeProvider _time;
    private readonly string _path;
    private readonly object _lock = new();
    private DateTime _scanStartedUtc;

    public ProgressTracker(ILogger<ProgressTracker> logger, AgentPaths paths, TimeProvider time)
    {
        _logger = logger;
        _time = time;
        _path = paths.ProgressFile;
        // Limpa arquivo velho de uma execução anterior (serviço morto no meio do trabalho).
        TryDelete();
    }

    public void BeginScan(string trigger)
    {
        lock (_lock)
        {
            _scanStartedUtc = _time.GetUtcNow().UtcDateTime;
            Write(new AnalysisProgress(
                State: AnalysisProgress.Scanning,
                StartedAtUtc: _scanStartedUtc,
                Step: "Coletando dados do sistema",
                Trigger: trigger,
                ScanFile: null));
        }
    }

    public void EndScanBeginAnalysis(string scanFile, string model, string trigger)
    {
        lock (_lock)
        {
            Write(new AnalysisProgress(
                State: AnalysisProgress.Analyzing,
                StartedAtUtc: _scanStartedUtc,    // mantém o tempo total desde o início do scan
                Step: $"Claude analisando (modelo={model})",
                Trigger: trigger,
                ScanFile: scanFile));
        }
    }

    public void Clear() => TryDelete();

    private void Write(AnalysisProgress p)
    {
        try
        {
            AtomicFile.WriteAllText(_path, JsonSerializer.Serialize(p, JsonDefaults.Indented));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write progress.json");
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
