using Microsoft.Extensions.Options;

namespace SecAgent.Service;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly ScanRunner _runner;
    private readonly ScannerOptions _options;

    public Worker(ILogger<Worker> logger, ScanRunner runner, IOptions<ScannerOptions> options)
    {
        _logger = logger;
        _runner = runner;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_options.OutputDirectory);
        _logger.LogInformation("SecAgent.Service started. Output={Output} IntervalHours={Hours}",
            _options.OutputDirectory, _options.ScanIntervalHours);

        if (_options.RunOnStartup)
            await _runner.RunScanAndAnalyzeAsync("scheduled", stoppingToken);

        var interval = TimeSpan.FromHours(_options.ScanIntervalHours);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(interval, stoppingToken); }
            catch (OperationCanceledException) { break; }

            await _runner.RunScanAndAnalyzeAsync("scheduled", stoppingToken);
        }
    }
}
