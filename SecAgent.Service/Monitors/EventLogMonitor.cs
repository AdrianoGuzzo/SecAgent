using System.Globalization;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Monitors;

/// <summary>
/// Assina os canais Security e System do Event Log (push) para IDs comumente
/// associados a atividade de atacante. Ler Security exige SeSecurityPrivilege
/// (LocalSystem tem).
/// </summary>
public class EventLogMonitor : BackgroundService
{
    private readonly ILogger<EventLogMonitor> _logger;
    private readonly ChannelWriter<SecurityEvent> _writer;
    private readonly MonitorOptions _opts;
    private readonly IEventLogSource _source;
    private readonly TimeProvider _time;
    private readonly List<IDisposable> _subscriptions = new();

    public EventLogMonitor(
        ILogger<EventLogMonitor> logger,
        ChannelWriter<SecurityEvent> writer,
        IOptions<MonitorOptions> opts,
        IEventLogSource source,
        TimeProvider time)
    {
        _logger = logger;
        _writer = writer;
        _opts = opts.Value;
        _source = source;
        _time = time;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.EventLogMonitorEnabled)
        {
            _logger.LogInformation("EventLogMonitor disabled by config");
            return Task.CompletedTask;
        }

        var securityIds = _opts.SecurityEventIds ?? MonitorOptions.DefaultSecurityEventIds.ToList();
        var systemIds = _opts.SystemEventIds ?? MonitorOptions.DefaultSystemEventIds.ToList();
        try
        {
            Subscribe("Security", securityIds);
            Subscribe("System", systemIds);
            _logger.LogInformation("EventLogMonitor started (Security IDs={Sec}, System IDs={Sys})",
                string.Join(",", securityIds), string.Join(",", systemIds));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "EventLogMonitor failed to start");
            DisposeSubscriptions();
            return Task.CompletedTask;
        }

        return Task.Delay(Timeout.Infinite, stoppingToken)
            .ContinueWith(_ => DisposeSubscriptions(), TaskScheduler.Default);
    }

    private void Subscribe(string channel, IReadOnlyCollection<int> ids)
    {
        if (ids.Count == 0) return;
        _subscriptions.Add(_source.Subscribe(channel, EventLogRules.BuildXPath(ids), e => OnEvent(channel, e)));
    }

    internal void OnEvent(string channel, EventLogEntryData entry)
    {
        try
        {
            var evt = EventLogRules.CreateEvent(channel, entry, _opts, _time.GetUtcNow().UtcDateTime);
            if (evt is not null) _writer.TryWrite(evt);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "EventLogMonitor handler failed");
        }
    }

    private void DisposeSubscriptions()
    {
        lock (_subscriptions)
        {
            foreach (var s in _subscriptions) { try { s.Dispose(); } catch { } }
            _subscriptions.Clear();
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        DisposeSubscriptions();
        await base.StopAsync(cancellationToken);
    }
}

/// <summary>Regras puras do EventLogMonitor: XPath, classificação, auto-referência e montagem do evento.</summary>
internal static class EventLogRules
{
    public const int ServiceInstalledEventId = 7045;

    public static string BuildXPath(IEnumerable<int> ids)
        => $"*[System[({string.Join(" or ", ids.Select(id => $"EventID={id}"))})]]";

    public static (string Severity, string Title) Classify(string channel, int id) =>
        (channel, id) switch
        {
            ("Security", 4625) => (SeverityLevels.Medium,   "Failed logon (4625)"),
            ("Security", 4720) => (SeverityLevels.High,     "New local account created (4720)"),
            ("Security", 4732) => (SeverityLevels.High,     "Member added to security-enabled local group (4732)"),
            ("Security", 4740) => (SeverityLevels.Medium,   "Account locked out (4740)"),
            ("Security", 1102) => (SeverityLevels.Critical, "Security audit log was cleared (1102)"),
            ("System",   ServiceInstalledEventId) => (SeverityLevels.High, "New service installed (7045)"),
            _ => (SeverityLevels.Low, $"{channel} event {id}")
        };

    /// <summary>
    /// Auto-referência: só o 7045 (serviço instalado) cujo ServiceName (prop0)
    /// é EXATAMENTE um dos nomes do agente. Antes, qualquer evento cuja descrição
    /// contivesse "SecAgent" era descartado — um serviço malicioso chamado
    /// "SecAgentHelper" escapava da detecção.
    /// </summary>
    public static bool IsSelfReference(string channel, EventLogEntryData entry, IReadOnlyCollection<string> selfServiceNames)
    {
        if (channel != "System" || entry.Id != ServiceInstalledEventId) return false;
        var serviceName = entry.Properties.Count > 0 ? entry.Properties[0]?.Trim() : null;
        return !string.IsNullOrEmpty(serviceName) &&
               selfServiceNames.Any(n => string.Equals(n, serviceName, StringComparison.OrdinalIgnoreCase));
    }

    public static SecurityEvent? CreateEvent(string channel, EventLogEntryData entry, MonitorOptions opts, DateTime nowUtc)
    {
        var selfNames = opts.SelfServiceNames ?? MonitorOptions.DefaultSelfServiceNames.ToList();
        if (IsSelfReference(channel, entry, selfNames)) return null;

        var (severity, title) = Classify(channel, entry.Id);
        var description = entry.Description ?? "";

        var details = new Dictionary<string, string>
        {
            ["channel"] = channel,
            ["eventId"] = entry.Id.ToString(CultureInfo.InvariantCulture),
            ["provider"] = entry.ProviderName ?? "",
            ["recordedAt"] = (entry.TimeCreated ?? nowUtc).ToString("o", CultureInfo.InvariantCulture),
            ["level"] = entry.Level?.ToString(CultureInfo.InvariantCulture) ?? "",
            ["formatted"] = description.Truncate(2000)
        };
        for (int i = 0; i < Math.Min(entry.Properties.Count, 20); i++)
            details[$"prop{i}"] = entry.Properties[i]?.Truncate(200) ?? "";

        return new SecurityEvent(
            TimestampUtc: nowUtc,
            Source: "eventlog",
            Severity: severity,
            Title: title,
            Description: description.Truncate(800),
            Details: details);
    }
}
