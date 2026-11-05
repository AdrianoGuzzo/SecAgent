using Microsoft.Extensions.Options;
using SecAgent.Service.Analysis;

namespace SecAgent.Service;

/// <summary>Agenda o scan periódico (e o de startup). Intervalo validado (> 0) no startup.</summary>
public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IScanRunner _runner;
    private readonly ScannerOptions _options;
    private readonly ClaudeOptions _claudeOptions;
    private readonly TimeProvider _time;

    public Worker(ILogger<Worker> logger, IScanRunner runner,
        IOptions<ScannerOptions> options, IOptions<ClaudeOptions> claudeOptions, TimeProvider time)
    {
        _logger = logger;
        _runner = runner;
        _options = options.Value;
        _claudeOptions = claudeOptions.Value;
        _time = time;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "SecAgent.Service started. Output={Output} IntervalHours={Hours} AutoAnalyze={Auto}",
            _options.OutputDirectory, _options.ScanIntervalHours, _claudeOptions.AnalyzeAfterScan);

        if (_options.RunOnStartup)
            await RunScheduledAsync(stoppingToken);

        var interval = TimeSpan.FromHours(_options.ScanIntervalHours);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(interval, _time, stoppingToken); }
            catch (OperationCanceledException) { break; }

            await RunScheduledAsync(stoppingToken);
        }
    }

    // Scheduled scans are free (scan-only) by default. Automatic Claude analysis
    // is opt-in via Claude.AnalyzeAfterScan; the manual "scan + análise" button
    // always analyzes regardless.
    private async Task RunScheduledAsync(CancellationToken ct)
    {
        try
        {
            if (_claudeOptions.AnalyzeAfterScan)
                await _runner.RunScanAndAnalyzeAsync("scheduled", ct);
            else
                await _runner.RunScanOnlyAsync("scheduled", ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // Nunca derruba o host por causa de um ciclo agendado.
            _logger.LogError(ex, "Scheduled scan failed");
        }
    }
}
