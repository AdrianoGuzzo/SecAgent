using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Options;

namespace SecAgent.Service.Triggers;

/// <summary>
/// Watches C:\ProgramData\SecAgent\triggers for *.trigger files written by the
/// SecAgent.Tray app (user-mode, cannot talk to the service directly).
/// Two known triggers:
///   scan-only.trigger         -> ScanRunner.RunScanOnlyAsync
///   scan-and-analyze.trigger  -> ScanRunner.RunScanAndAnalyzeAsync
/// Trigger file is always deleted after processing (success OR error).
/// Triggers written while the service was down are drained on startup.
/// </summary>
public class TriggerWatcher : BackgroundService
{
    private const string ScanOnlyTrigger = "scan-only.trigger";
    private const string ScanAndAnalyzeTrigger = "scan-and-analyze.trigger";

    private readonly ILogger<TriggerWatcher> _logger;
    private readonly ScanRunner _runner;
    private readonly TriggerOptions _opts;
    private readonly Dictionary<string, DateTime> _lastFiredUtc = new();
    private readonly object _lock = new();
    private FileSystemWatcher? _watcher;

    public TriggerWatcher(ILogger<TriggerWatcher> logger, ScanRunner runner, IOptions<TriggerOptions> opts)
    {
        _logger = logger;
        _runner = runner;
        _opts = opts.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.Enabled)
        {
            _logger.LogInformation("TriggerWatcher disabled by config");
            return;
        }

        try
        {
            EnsureDirectoryWithUserWriteAcl(_opts.TriggersDirectory);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TriggerWatcher failed to prepare {Dir}", _opts.TriggersDirectory);
            return;
        }

        // Drain any orphan triggers written while service was down
        foreach (var path in Directory.GetFiles(_opts.TriggersDirectory, "*.trigger"))
            _ = ProcessTriggerAsync(path, stoppingToken);

        _watcher = new FileSystemWatcher(_opts.TriggersDirectory, "*.trigger")
        {
            EnableRaisingEvents = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
        };
        _watcher.Created += (_, e) => _ = ProcessTriggerAsync(e.FullPath, stoppingToken);
        _watcher.Changed += (_, e) => _ = ProcessTriggerAsync(e.FullPath, stoppingToken);

        _logger.LogInformation("TriggerWatcher started, watching {Dir}", _opts.TriggersDirectory);
        try { await Task.Delay(Timeout.Infinite, stoppingToken); }
        catch (OperationCanceledException) { }
        finally { try { _watcher?.Dispose(); } catch { } }
    }

    private async Task ProcessTriggerAsync(string fullPath, CancellationToken ct)
    {
        var name = Path.GetFileName(fullPath).ToLowerInvariant();

        // Debounce per trigger name
        lock (_lock)
        {
            if (_lastFiredUtc.TryGetValue(name, out var last) &&
                DateTime.UtcNow - last < TimeSpan.FromSeconds(_opts.DebounceSeconds))
            {
                _logger.LogInformation("Trigger {Name} ignored (debounce, last fired {Sec}s ago)",
                    name, (int)(DateTime.UtcNow - last).TotalSeconds);
                TryDelete(fullPath);
                return;
            }
            _lastFiredUtc[name] = DateTime.UtcNow;
        }

        _logger.LogInformation("Trigger {Name} accepted", name);
        try
        {
            switch (name)
            {
                case ScanOnlyTrigger:
                    await _runner.RunScanOnlyAsync("tray", ct);
                    break;
                case ScanAndAnalyzeTrigger:
                    await _runner.RunScanAndAnalyzeAsync("tray", ct);
                    break;
                default:
                    _logger.LogWarning("Unknown trigger file: {Name}", name);
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Trigger {Name} processing failed", name);
        }
        finally
        {
            TryDelete(fullPath);
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    /// <summary>
    /// Creates the triggers directory and grants Authenticated Users the right
    /// to create new files (no delete, no list — minimum needed for the Tray
    /// to drop trigger files).
    /// </summary>
    private static void EnsureDirectoryWithUserWriteAcl(string path)
    {
        var di = Directory.CreateDirectory(path);
        var security = di.GetAccessControl();
        var authUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var rule = new FileSystemAccessRule(
            authUsers,
            FileSystemRights.WriteData | FileSystemRights.CreateFiles |
                FileSystemRights.AppendData | FileSystemRights.ReadAndExecute,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow);
        security.AddAccessRule(rule);
        di.SetAccessControl(security);
    }
}
