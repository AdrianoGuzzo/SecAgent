using Microsoft.Extensions.Options;
using SecAgent.Service.Analysis;

namespace SecAgent.Service;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly ScanRunner _runner;
    private readonly ScannerOptions _options;
    private readonly ClaudeOptions _claudeOptions;

    public Worker(ILogger<Worker> logger, ScanRunner runner,
        IOptions<ScannerOptions> options, IOptions<ClaudeOptions> claudeOptions)
    {
        _logger = logger;
        _runner = runner;
        _options = options.Value;
        _claudeOptions = claudeOptions.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_options.OutputDirectory);
        _logger.LogInformation(
            "SecAgent.Service started. Output={Output} IntervalHours={Hours} AutoAnalyze={Auto}",
            _options.OutputDirectory, _options.ScanIntervalHours, _claudeOptions.AnalyzeAfterScan);

        if (_options.RunOnStartup)
            await RunScheduledAsync(stoppingToken);

        var interval = TimeSpan.FromHours(_options.ScanIntervalHours);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(interval, stoppingToken); }
            catch (OperationCanceledException) { break; }

            await RunScheduledAsync(stoppingToken);
        }
    }

    // Scheduled scans are free (scan-only) by default. Automatic Claude analysis
    // is opt-in via Claude.AnalyzeAfterScan; the manual "scan + análise" button
    // always analyzes regardless.
    private async Task RunScheduledAsync(CancellationToken ct)
    {
        if (_claudeOptions.AnalyzeAfterScan)
            await _runner.RunScanAndAnalyzeAsync("scheduled", ct);
        else
            await _runner.RunScanOnlyAsync("scheduled", ct);
    }
}
