using System.Diagnostics.Eventing.Reader;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Models;

namespace SecAgent.Service.Monitors;

using SecAgent.Service;

/// <summary>
/// Subscribes to live Security and System event log channels (push-based via
/// EventLogWatcher) for specific event IDs that are commonly associated with
/// attacker activity.
/// Requires SeSecurityPrivilege to read the Security channel — granted to LocalSystem.
/// </summary>
public class EventLogMonitor : BackgroundService
{
    private readonly ILogger<EventLogMonitor> _logger;
    private readonly ChannelWriter<SecurityEvent> _writer;
    private readonly MonitorOptions _opts;
    private EventLogWatcher? _securityWatcher;
    private EventLogWatcher? _systemWatcher;

    public EventLogMonitor(
        ILogger<EventLogMonitor> logger,
        Channel<SecurityEvent> channel,
        IOptions<MonitorOptions> opts)
    {
        _logger = logger;
        _writer = channel.Writer;
        _opts = opts.Value;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.EventLogMonitorEnabled)
        {
            _logger.LogInformation("EventLogMonitor disabled by config");
            return Task.CompletedTask;
        }

        try
        {
            if (_opts.SecurityEventIds.Count > 0)
                _securityWatcher = Subscribe("Security", _opts.SecurityEventIds);
            if (_opts.SystemEventIds.Count > 0)
                _systemWatcher = Subscribe("System", _opts.SystemEventIds);
            _logger.LogInformation("EventLogMonitor started (Security IDs={Sec}, System IDs={Sys})",
                string.Join(",", _opts.SecurityEventIds), string.Join(",", _opts.SystemEventIds));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "EventLogMonitor failed to start");
            return Task.CompletedTask;
        }

        return Task.Delay(Timeout.Infinite, stoppingToken).ContinueWith(_ =>
        {
            try { _securityWatcher?.Dispose(); } catch { }
            try { _systemWatcher?.Dispose(); } catch { }
        }, TaskScheduler.Default);
    }

    private EventLogWatcher Subscribe(string channel, IEnumerable<int> ids)
    {
        var idClause = string.Join(" or ", ids.Select(id => $"EventID={id}"));
        var xpath = $"*[System[({idClause})]]";
        var query = new EventLogQuery(channel, PathType.LogName, xpath);
        var watcher = new EventLogWatcher(query);
        watcher.EventRecordWritten += (s, e) => OnEvent(channel, e);
        watcher.Enabled = true;
        return watcher;
    }

    private void OnEvent(string channel, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventRecord is null) return;
            using var record = e.EventRecord;
            var id = record.Id;
            var (severity, title) = ClassifyEvent(channel, id);
            var description = TryFormatDescription(record);

            if (_opts.SelfReferenceFragments.Any(f =>
                    description.Contains(f, StringComparison.OrdinalIgnoreCase)))
                return;

            var details = new Dictionary<string, string>
            {
                ["channel"] = channel,
                ["eventId"] = id.ToString(),
                ["provider"] = record.ProviderName ?? "",
                ["recordedAt"] = (record.TimeCreated ?? DateTime.UtcNow).ToString("o"),
                ["level"] = record.Level?.ToString() ?? "",
                ["formatted"] = description.Truncate(2000)
            };
            // Best-effort: capture named properties when available
            try
            {
                if (record.Properties != null)
                {
                    int i = 0;
                    foreach (var p in record.Properties.Take(20))
                        details[$"prop{i++}"] = p.Value?.ToString()?.Truncate(200) ?? "";
                }
            }
            catch { }

            _writer.TryWrite(new SecurityEvent(
                TimestampUtc: DateTime.UtcNow,
                Source: "eventlog",
                Severity: severity,
                Title: title,
                Description: description.Truncate(800),
                Details: details));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "EventLogMonitor handler failed");
        }
    }

    private static (string Severity, string Title) ClassifyEvent(string channel, int id) =>
        (channel, id) switch
        {
            ("Security", 4625) => ("medium",  "Failed logon (4625)"),
            ("Security", 4720) => ("high",    "New local account created (4720)"),
            ("Security", 4732) => ("high",    "Member added to security-enabled local group (4732)"),
            ("Security", 4740) => ("medium",  "Account locked out (4740)"),
            ("Security", 1102) => ("critical","Security audit log was cleared (1102)"),
            ("System",   7045) => ("high",    "New service installed (7045)"),
            _ => ("low", $"{channel} event {id}")
        };

    private static string TryFormatDescription(EventRecord record)
    {
        try { return record.FormatDescription() ?? ""; }
        catch { return ""; }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _securityWatcher?.Dispose(); } catch { }
        try { _systemWatcher?.Dispose(); } catch { }
        await base.StopAsync(cancellationToken);
    }
}
