using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Options;
using SecAgent.Service.Analysis;
using SecAgent.Service.Models;

namespace SecAgent.Service;

/// <summary>
/// Shared orchestration used by both the scheduled Worker and the on-demand
/// TriggerWatcher. Reports progress to ProgressTracker so the Tray can show
/// live feedback (tooltip, busy icon, transition toast).
/// </summary>
public class ScanRunner
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly ILogger<ScanRunner> _logger;
    private readonly SecurityScanner _scanner;
    private readonly ClaudeAnalyzer _analyzer;
    private readonly ProgressTracker _progress;
    private readonly ScannerOptions _options;
    private readonly ClaudeOptions _claudeOptions;

    public ScanRunner(
        ILogger<ScanRunner> logger,
        SecurityScanner scanner,
        ClaudeAnalyzer analyzer,
        ProgressTracker progress,
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
        _progress.BeginScan(trigger);
        try
        {
            return await DoScanAsync(ct);
        }
        finally
        {
            _progress.Clear();
        }
    }

    // Always runs Claude after the scan. Used by the manual "scan + análise"
    // button. Scheduled scans go through the Worker, which decides whether to
    // analyze (free scan-only by default) — automatic AI is opt-in via config.
    //
    // model/effort são opcionais: vêm do trigger quando o usuário escolhe no
    // painel; caem nos defaults de config quando ausentes/inválidos.
    public async Task RunScanAndAnalyzeAsync(
        string trigger, CancellationToken ct, string? model = null, string? effort = null)
    {
        var useModel = ClaudeCapabilities.NormalizeModel(model, _claudeOptions.Model);
        var useEffort = ClaudeCapabilities.NormalizeEffort(effort, _claudeOptions.Effort);

        _progress.BeginScan(trigger);
        try
        {
            var scan = await DoScanAsync(ct);
            if (scan is null) return;

            _progress.EndScanBeginAnalysis(
                Path.GetFileName(scan.Value.ScanPath),
                useModel,
                trigger);

            try
            {
                _logger.LogInformation("Invoking Claude analyzer (model={Model}, effort={Effort})", useModel, useEffort);
                await _analyzer.AnalyzeAsync(scan.Value.Result, scan.Value.ScanPath, ct, useModel, useEffort);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Claude analysis failed");
            }
        }
        finally
        {
            _progress.Clear();
        }
    }

    private async Task<(ScanResult Result, string ScanPath)?> DoScanAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(_options.OutputDirectory);
        var sw = Stopwatch.StartNew();
        try
        {
            var result = await Task.Run(() => _scanner.RunFullScan(), ct);
            sw.Stop();

            var fileName = $"scan_{result.TimestampUtc:yyyy-MM-dd_HHmmss}.json";
            var path = Path.Combine(_options.OutputDirectory, fileName);
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(result, JsonOpts), ct);

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
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scan failed after {Ms}ms", sw.ElapsedMilliseconds);
            return null;
        }
    }
}
