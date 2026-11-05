using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Eventing.Reader;

namespace SecAgent.Service.Platform;

/// <summary>Um registro do Event Log já extraído do EventRecord (que é selado e difícil de fabricar).</summary>
public record EventLogEntryData(
    int Id,
    string? ProviderName,
    DateTime? TimeCreated,
    byte? Level,
    string Description,
    IReadOnlyList<string?> Properties);

/// <summary>Assinatura push de canais do Event Log.</summary>
public interface IEventLogSource
{
    IDisposable Subscribe(string channel, string xpath, Action<EventLogEntryData> onEvent);
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de EventLogWatcher")]
internal sealed class WindowsEventLogSource : IEventLogSource
{
    public IDisposable Subscribe(string channel, string xpath, Action<EventLogEntryData> onEvent)
    {
        var watcher = new EventLogWatcher(new EventLogQuery(channel, PathType.LogName, xpath));
        watcher.EventRecordWritten += (_, e) =>
        {
            if (e.EventRecord is null) return;
            using var record = e.EventRecord;
            string description;
            try { description = record.FormatDescription() ?? ""; }
            catch { description = ""; }

            var props = new List<string?>();
            try
            {
                if (record.Properties != null)
                    props.AddRange(record.Properties.Select(p => p.Value?.ToString()));
            }
            catch { /* best effort */ }

            onEvent(new EventLogEntryData(record.Id, record.ProviderName, record.TimeCreated,
                record.Level, description, props));
        };
        watcher.Enabled = true;
        return watcher;
    }
}
