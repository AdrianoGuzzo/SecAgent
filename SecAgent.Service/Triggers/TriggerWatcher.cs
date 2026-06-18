using System.Net;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Options;
using SecAgent.Service.Monitors;
using SecAgent.Service.Remediation;

namespace SecAgent.Service.Triggers;

/// <summary>
/// Watches C:\ProgramData\SecAgent\triggers for *.trigger files written by the
/// SecAgent.Tray app (user-mode, cannot talk to the service directly).
/// Known triggers:
///   scan-only.trigger         -> ScanRunner.RunScanOnlyAsync
///   scan-and-analyze.trigger  -> ScanRunner.RunScanAndAnalyzeAsync
///   block-ip-&lt;ip&gt;.trigger     -> IpBlocker.Block   (IP read from file content)
///   unblock-ip-&lt;ip&gt;.trigger   -> IpBlocker.Unblock (IP read from file content)
///   traffic-track-start.trigger -> TrafficAccumulator.Start (medidor por IP)
///   traffic-track-stop.trigger  -> TrafficAccumulator.Stop
/// Trigger file is always deleted after processing (success OR error).
/// Triggers written while the service was down are drained on startup.
/// </summary>
public class TriggerWatcher : BackgroundService
{
    private const string ScanOnlyTrigger = "scan-only.trigger";
    private const string ScanAndAnalyzeTrigger = "scan-and-analyze.trigger";
    private const string BlockIpPrefix = "block-ip-";
    private const string UnblockIpPrefix = "unblock-ip-";
    private const string TrafficStartTrigger = "traffic-track-start.trigger";
    private const string TrafficStopTrigger = "traffic-track-stop.trigger";

    private readonly ILogger<TriggerWatcher> _logger;
    private readonly ScanRunner _runner;
    private readonly IpBlocker _blocker;
    private readonly TrafficAccumulator _traffic;
    private readonly TriggerOptions _opts;
    private readonly Dictionary<string, DateTime> _lastFiredUtc = new();
    private readonly object _lock = new();
    private FileSystemWatcher? _watcher;

    public TriggerWatcher(ILogger<TriggerWatcher> logger, ScanRunner runner, IpBlocker blocker, TrafficAccumulator traffic, IOptions<TriggerOptions> opts)
    {
        _logger = logger;
        _runner = runner;
        _blocker = blocker;
        _traffic = traffic;
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
            if (name.StartsWith(BlockIpPrefix, StringComparison.Ordinal) ||
                name.StartsWith(UnblockIpPrefix, StringComparison.Ordinal))
            {
                // The IP travels in the file CONTENT (filenames can't hold IPv6 ':').
                var ip = ReadIpPayload(fullPath);
                if (ip is null)
                    _logger.LogWarning("Trigger {Name} has no valid IP payload", name);
                else if (name.StartsWith(BlockIpPrefix, StringComparison.Ordinal))
                    _blocker.Block(ip);
                else
                    _blocker.Unblock(ip);
            }
            else
            {
                switch (name)
                {
                    case ScanOnlyTrigger:
                        await _runner.RunScanOnlyAsync("tray", ct);
                        break;
                    case ScanAndAnalyzeTrigger:
                        // O conteúdo carrega a escolha de modelo/esforço feita no painel
                        // ({"model":"sonnet","effort":"high"}). Conteúdo legado/ausente
                        // (timestamp ISO) → (null, null) → defaults no ScanRunner.
                        var (model, effort) = ReadAnalyzeOptions(fullPath);
                        await _runner.RunScanAndAnalyzeAsync("tray", ct, model, effort);
                        break;
                    case TrafficStartTrigger:
                        _traffic.Start();
                        break;
                    case TrafficStopTrigger:
                        _traffic.Stop();
                        break;
                    default:
                        _logger.LogWarning("Unknown trigger file: {Name}", name);
                        break;
                }
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

    /// <summary>Reads the IP written as the trigger's content; null if missing/invalid.</summary>
    private static string? ReadIpPayload(string path)
    {
        try
        {
            var content = File.ReadAllText(path).Trim();
            return IPAddress.TryParse(content, out var ip) ? ip.ToString() : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Reads the model/effort the Tray wrote into the scan-and-analyze trigger
    /// ({"model":"sonnet","effort":"high"}). Returns (null, null) for legacy
    /// timestamp content or anything unparseable — the ScanRunner then falls back
    /// to the configured defaults. Values are NOT validated here; ScanRunner does it.
    /// </summary>
    private static (string? Model, string? Effort) ReadAnalyzeOptions(string path)
    {
        try
        {
            var content = File.ReadAllText(path).Trim();
            if (string.IsNullOrEmpty(content) || content[0] != '{') return (null, null);

            using var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;
            var model = root.TryGetProperty("model", out var m) ? m.GetString() : null;
            var effort = root.TryGetProperty("effort", out var e) ? e.GetString() : null;
            return (model, effort);
        }
        catch { return (null, null); }
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
