using System.Management;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Models;

namespace SecAgent.Service.Monitors;

using SecAgent.Service;

/// <summary>
/// Listens for process creation via WMI __InstanceCreationEvent on Win32_Process.
/// Emits a SecurityEvent only when the process runs from a suspicious path
/// (Temp/Downloads/etc.) and is not on the whitelist. Other process starts are
/// dropped to keep noise down.
/// </summary>
public class ProcessMonitor : BackgroundService
{
    private readonly ILogger<ProcessMonitor> _logger;
    private readonly ChannelWriter<SecurityEvent> _writer;
    private readonly MonitorOptions _opts;
    private readonly HashSet<string> _whitelist;
    private ManagementEventWatcher? _watcher;

    public ProcessMonitor(
        ILogger<ProcessMonitor> logger,
        Channel<SecurityEvent> channel,
        IOptions<MonitorOptions> opts)
    {
        _logger = logger;
        _writer = channel.Writer;
        _opts = opts.Value;
        _whitelist = new HashSet<string>(
            _opts.ProcessWhitelist.Select(s => s.ToLowerInvariant()),
            StringComparer.OrdinalIgnoreCase);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.ProcessMonitorEnabled)
        {
            _logger.LogInformation("ProcessMonitor disabled by config");
            return Task.CompletedTask;
        }

        try
        {
            var query = new WqlEventQuery(
                "SELECT TargetInstance FROM __InstanceCreationEvent WITHIN 2 " +
                "WHERE TargetInstance ISA 'Win32_Process'");
            _watcher = new ManagementEventWatcher(query);
            _watcher.EventArrived += OnProcessStarted;
            _watcher.Start();
            _logger.LogInformation("ProcessMonitor started (watching __InstanceCreationEvent every 2s)");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ProcessMonitor failed to start");
            return Task.CompletedTask;
        }

        return Task.Delay(Timeout.Infinite, stoppingToken)
            .ContinueWith(_ => { try { _watcher?.Stop(); } catch { } }, TaskScheduler.Default);
    }

    private void OnProcessStarted(object? sender, EventArrivedEventArgs e)
    {
        try
        {
            using var instance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var name = (instance["Name"] as string ?? "").ToLowerInvariant();
            if (string.IsNullOrEmpty(name) || _whitelist.Contains(name)) return;

            var path = instance["ExecutablePath"] as string;
            if (string.IsNullOrEmpty(path)) return;  // protected process or race; skip

            if (_opts.SelfReferenceFragments.Any(f =>
                    path.Contains(f, StringComparison.OrdinalIgnoreCase)))
                return;

            var matchedFragment = _opts.SuspiciousPathFragments
                .FirstOrDefault(f => path.Contains(f, StringComparison.OrdinalIgnoreCase));
            if (matchedFragment is null) return;  // not suspicious enough to surface

            var evt = new SecurityEvent(
                TimestampUtc: DateTime.UtcNow,
                Source: "process",
                Severity: "high",
                Title: $"Process from suspicious path: {name}",
                Description: $"Executable launched from path containing '{matchedFragment}', a common staging location for malware.",
                Details: new Dictionary<string, string>
                {
                    ["name"] = name,
                    ["pid"] = instance["ProcessId"]?.ToString() ?? "",
                    ["parentPid"] = instance["ParentProcessId"]?.ToString() ?? "",
                    ["path"] = path,
                    ["commandLine"] = (instance["CommandLine"] as string ?? "").Truncate(500),
                    ["fragment"] = matchedFragment
                });

            _writer.TryWrite(evt);
            _logger.LogInformation("Suspicious process emitted: {Name} from {Path}", name, path);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ProcessMonitor event handler failed");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _watcher?.Stop(); _watcher?.Dispose(); } catch { }
        await base.StopAsync(cancellationToken);
    }
}

