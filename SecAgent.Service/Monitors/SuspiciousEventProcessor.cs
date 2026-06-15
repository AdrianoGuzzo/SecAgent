using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Analysis;
using SecAgent.Service.Models;

namespace SecAgent.Service.Monitors;

/// <summary>
/// Drains the shared SecurityEvent channel: persists every event to a daily
/// JSONL file (forensics), maintains a sliding in-memory window, and triggers
/// an ad-hoc Claude incident analysis when:
///   - the window has at least IncidentEventThreshold events, AND
///   - the last triggered analysis is older than IncidentCooldownMinutes.
/// </summary>
public class SuspiciousEventProcessor : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly ILogger<SuspiciousEventProcessor> _logger;
    private readonly ChannelReader<SecurityEvent> _reader;
    private readonly ClaudeAnalyzer _analyzer;
    private readonly MonitorOptions _opts;
    private readonly List<SecurityEvent> _window = new();
    private DateTime _lastFiredUtc = DateTime.MinValue;

    public SuspiciousEventProcessor(
        ILogger<SuspiciousEventProcessor> logger,
        Channel<SecurityEvent> channel,
        ClaudeAnalyzer analyzer,
        IOptions<MonitorOptions> opts)
    {
        _logger = logger;
        _reader = channel.Reader;
        _analyzer = analyzer;
        _opts = opts.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_opts.EventsDirectory);
        _logger.LogInformation(
            "SuspiciousEventProcessor started. Threshold={N} events / {W}min window, cooldown={C}min",
            _opts.IncidentEventThreshold, _opts.IncidentWindowMinutes, _opts.IncidentCooldownMinutes);

        try
        {
            await foreach (var evt in _reader.ReadAllAsync(stoppingToken))
            {
                AppendToJsonl(evt);
                AddToWindow(evt);

                if (ShouldTriggerAnalysis(out var snapshot, out var windowStart, out var windowEnd))
                {
                    _lastFiredUtc = DateTime.UtcNow;
                    _logger.LogWarning(
                        "Incident threshold crossed: {N} events in window. Invoking Claude.",
                        snapshot.Count);
                    try
                    {
                        await _analyzer.AnalyzeIncidentAsync(snapshot, windowStart, windowEnd, stoppingToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Claude incident analysis failed");
                    }
                }
            }
        }
        catch (OperationCanceledException) { /* graceful shutdown */ }
    }

    private void AppendToJsonl(SecurityEvent evt)
    {
        try
        {
            var path = Path.Combine(_opts.EventsDirectory,
                $"events_{DateTime.UtcNow:yyyy-MM-dd}.jsonl");
            File.AppendAllText(path, JsonSerializer.Serialize(evt, JsonOpts) + Environment.NewLine);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to append event to JSONL");
        }
    }

    private void AddToWindow(SecurityEvent evt)
    {
        _window.Add(evt);
        var cutoff = DateTime.UtcNow.AddMinutes(-_opts.IncidentWindowMinutes);
        _window.RemoveAll(e => e.TimestampUtc < cutoff);
    }

    private bool ShouldTriggerAnalysis(
        out List<SecurityEvent> snapshot,
        out DateTime windowStart,
        out DateTime windowEnd)
    {
        snapshot = new List<SecurityEvent>();
        windowStart = DateTime.MinValue;
        windowEnd = DateTime.UtcNow;

        if (_window.Count < _opts.IncidentEventThreshold) return false;
        if (DateTime.UtcNow - _lastFiredUtc < TimeSpan.FromMinutes(_opts.IncidentCooldownMinutes))
            return false;

        snapshot = new List<SecurityEvent>(_window);   // copy
        windowStart = _window.Min(e => e.TimestampUtc);
        return true;
    }
}
