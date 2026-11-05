using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Options;
using SecAgent.Service.Analysis;
using SecAgent.Service.Models;

namespace SecAgent.Service;

public interface IScanRunner
{
    /// <summary>Scan sem IA. Null se falhou ou se já havia um scan em andamento.</summary>
    Task<(ScanResult Result, string ScanPath)?> RunScanOnlyAsync(string trigger, CancellationToken ct);

    /// <summary>Scan + análise Claude. Ignorado se já havia um scan em andamento.</summary>
    Task RunScanAndAnalyzeAsync(string trigger, CancellationToken ct, string? model = null, string? effort = null);
}

/// <summary>
/// Orquestração compartilhada pelo Worker (agendado) e pelo TriggerWatcher (sob
/// demanda). Reporta progresso ao ProgressTracker para o Tray.
///
/// Single-flight: o Worker e um trigger podiam rodar scans ao mesmo tempo —
/// um sobrescrevia o progress.json do outro, o Clear() de um apagava o arquivo
/// com o outro ainda rodando, e dois scans no mesmo segundo colidiam no nome.
/// Agora um pedido que chega durante um scan é logado e descartado.
/// </summary>
public class ScanRunner : IScanRunner
{
    private readonly ILogger<ScanRunner> _logger;
    private readonly ISecurityScanner _scanner;
    private readonly IClaudeAnalyzer _analyzer;
    private readonly IProgressTracker _progress;
    private readonly ScannerOptions _options;
    private readonly ClaudeOptions _claudeOptions;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public ScanRunner(
        ILogger<ScanRunner> logger,
        ISecurityScanner scanner,
        IClaudeAnalyzer analyzer,
        IProgressTracker progress,
        IOptions<ScannerOptions> options,
        IOptions<ClaudeOptions> claudeOptions)
    {
        _logger = logger;
        _scanner = scanner;
        _analyzer = analyzer;
        _progress = progress;
        _options = options.Value;
        _claudeOptions = claudeOptions.Value;
    }

    public async Task<(ScanResult Result, string ScanPath)?> RunScanOnlyAsync(string trigger, CancellationToken ct)
    {
        if (!TryEnter(trigger)) return null;
        try
        {
            _progress.BeginScan(trigger);
            return await DoScanAsync(ct);
        }
        finally
        {
            _progress.Clear();
            _gate.Release();
        }
    }

    // Sempre roda o Claude após o scan. Usado pelo botão "scan + análise".
    // Scans agendados passam pelo Worker, que decide se analisa.
    //
    // model/effort são opcionais: vêm do trigger quando o usuário escolhe no
    // painel; caem nos defaults de config quando ausentes/inválidos.
    public async Task RunScanAndAnalyzeAsync(
        string trigger, CancellationToken ct, string? model = null, string? effort = null)
    {
        if (!TryEnter(trigger)) return;

        var useModel = AiModels.NormalizeModel(model, _claudeOptions.Model);
        var useEffort = AiModels.NormalizeEffort(effort, _claudeOptions.Effort);
        try
        {
            _progress.BeginScan(trigger);
            var scan = await DoScanAsync(ct);
            if (scan is null) return;

            _progress.EndScanBeginAnalysis(Path.GetFileName(scan.Value.ScanPath), useModel, trigger);

            try
            {
                _logger.LogInformation("Invoking Claude analyzer (model={Model}, effort={Effort})", useModel, useEffort);
                await _analyzer.AnalyzeAsync(scan.Value.Result, scan.Value.ScanPath, ct, useModel, useEffort);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                _logger.LogInformation("Claude analysis cancelled (service stopping)");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Claude analysis failed");
            }
        }
        finally
        {
            _progress.Clear();
            _gate.Release();
        }
    }

    private bool TryEnter(string trigger)
    {
        if (_gate.Wait(0)) return true;
        _logger.LogWarning("Scan requested by {Trigger} ignored: another scan is already running", trigger);
        return false;
    }

    private async Task<(ScanResult Result, string ScanPath)?> DoScanAsync(CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            Directory.CreateDirectory(_options.OutputDirectory);
            var result = await Task.Run(() => _scanner.RunFullScan(), ct);
            sw.Stop();

            var path = Path.Combine(_options.OutputDirectory, ReportNames.ScanFile(result.TimestampUtc));
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(result, JsonDefaults.Indented), ct);

            _logger.LogInformation(
                "Scan complete in {Ms}ms. Ports={Ports} Software={Software} Updates={Updates} Users={Users} Admins={Admins} Errors={Errors} → {Path}",
                sw.ElapsedMilliseconds,
                result.OpenPorts.Count,
                result.InstalledSoftware.Count,
                result.InstalledUpdates.Count,
                result.LocalUsers.Count,
                result.Administrators.Count,
                result.Errors.Count,
                path);

            return (result, path);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Parada normal do serviço — não é "Scan failed".
            _logger.LogInformation("Scan cancelled after {Ms}ms (service stopping)", sw.ElapsedMilliseconds);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scan failed after {Ms}ms", sw.ElapsedMilliseconds);
            return null;
        }
    }
}
