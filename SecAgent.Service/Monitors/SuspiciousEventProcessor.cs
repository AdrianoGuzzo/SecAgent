using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Analysis;

namespace SecAgent.Service.Monitors;

/// <summary>
/// Drena o canal de SecurityEvent: grava TODO evento no JSONL diário (forense +
/// feed ao vivo), mantém a janela deslizante e dispara a análise de incidente
/// quando o limiar é cruzado (ver <see cref="IncidentWindow"/>).
///
/// A análise roda em BACKGROUND (single-flight): antes ela era aguardada dentro
/// do loop de leitura, o canal (bounded, DropOldest) enchia durante a chamada
/// longa ao Claude e eventos eram descartados sem nunca chegar ao JSONL.
/// </summary>
public class SuspiciousEventProcessor : BackgroundService
{
    private readonly ILogger<SuspiciousEventProcessor> _logger;
    private readonly ChannelReader<SecurityEvent> _reader;
    private readonly IClaudeAnalyzer _analyzer;
    private readonly MonitorOptions _opts;
    private readonly TimeProvider _time;
    private readonly IncidentWindow _window;
    private Task _analysis = Task.CompletedTask;

    public SuspiciousEventProcessor(
        ILogger<SuspiciousEventProcessor> logger,
        ChannelReader<SecurityEvent> reader,
        IClaudeAnalyzer analyzer,
        IOptions<MonitorOptions> opts,
        TimeProvider time)
    {
        _logger = logger;
        _reader = reader;
        _analyzer = analyzer;
        _opts = opts.Value;
        _time = time;
        _window = new IncidentWindow(_opts, time);
    }

    /// <summary>Análise em andamento (ou concluída) — exposto para testes.</summary>
    internal Task CurrentAnalysis => _analysis;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "SuspiciousEventProcessor started. Threshold={N} events / {W}min window, cooldown={C}min, auto={Auto}",
            _opts.IncidentEventThreshold, _opts.IncidentWindowMinutes, _opts.IncidentCooldownMinutes,
            _opts.IncidentAutoAnalysisEnabled);

        try
        {
            await foreach (var evt in _reader.ReadAllAsync(stoppingToken))
            {
                AppendToJsonl(evt);
                _window.Add(evt);

                if (_analysis.IsCompleted && _window.TryTrigger(out var snapshot, out var start, out var end))
                {
                    _logger.LogWarning("Incident threshold crossed: {N} events in window. Invoking Claude.", snapshot.Count);
                    _analysis = Task.Run(() => AnalyzeAsync(snapshot, start, end, stoppingToken), CancellationToken.None);
                }
            }
        }
        catch (OperationCanceledException) { /* parada normal */ }

        try { await _analysis; } catch { /* já logado */ }
    }

    private async Task AnalyzeAsync(List<SecurityEvent> snapshot, DateTime start, DateTime end, CancellationToken ct)
    {
        try
        {
            await _analyzer.AnalyzeIncidentAsync(snapshot, start, end, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Claude incident analysis failed");
        }
    }

    private void AppendToJsonl(SecurityEvent evt)
    {
        try
        {
            var path = Path.Combine(_opts.EventsDirectory, ReportNames.EventsJsonl(_time.GetUtcNow().UtcDateTime));
            Directory.CreateDirectory(_opts.EventsDirectory);
            File.AppendAllText(path, JsonSerializer.Serialize(evt, JsonDefaults.Compact) + Environment.NewLine);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to append event to JSONL");
        }
    }
}

/// <summary>
/// Janela deslizante de eventos + regra de disparo: análise automática habilitada,
/// pelo menos <c>IncidentEventThreshold</c> eventos na janela e cooldown vencido.
/// </summary>
internal sealed class IncidentWindow
{
    private readonly MonitorOptions _opts;
    private readonly TimeProvider _time;
    private readonly List<SecurityEvent> _events = new();
    private DateTime _lastFiredUtc = DateTime.MinValue;

    public IncidentWindow(MonitorOptions opts, TimeProvider time)
    {
        _opts = opts;
        _time = time;
    }

    public int Count => _events.Count;

    public void Add(SecurityEvent evt)
    {
        _events.Add(evt);
        var cutoff = _time.GetUtcNow().UtcDateTime.AddMinutes(-_opts.IncidentWindowMinutes);
        _events.RemoveAll(e => e.TimestampUtc < cutoff);
    }

    public bool TryTrigger(out List<SecurityEvent> snapshot, out DateTime windowStart, out DateTime windowEnd)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        snapshot = new List<SecurityEvent>();
        windowStart = DateTime.MinValue;
        windowEnd = now;

        if (!_opts.IncidentAutoAnalysisEnabled) return false;   // análise só manual
        if (_events.Count < _opts.IncidentEventThreshold) return false;
        if (now - _lastFiredUtc < TimeSpan.FromMinutes(_opts.IncidentCooldownMinutes)) return false;

        _lastFiredUtc = now;
        snapshot = new List<SecurityEvent>(_events);
        windowStart = _events.Min(e => e.TimestampUtc);
        return true;
    }
}
