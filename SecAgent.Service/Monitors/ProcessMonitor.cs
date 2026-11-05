using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Monitors;

/// <summary>
/// Escuta criação de processos (WMI) e emite um SecurityEvent só quando o
/// executável roda de um caminho suspeito (Temp/Downloads/etc.) e não está no
/// whitelist. Demais processos são descartados para manter o ruído baixo.
/// </summary>
public class ProcessMonitor : BackgroundService
{
    private readonly ILogger<ProcessMonitor> _logger;
    private readonly ChannelWriter<SecurityEvent> _writer;
    private readonly MonitorOptions _opts;
    private readonly IProcessStartSource _source;
    private readonly ProcessStartEvaluator _evaluator;
    private readonly TimeProvider _time;

    public ProcessMonitor(
        ILogger<ProcessMonitor> logger,
        ChannelWriter<SecurityEvent> writer,
        IOptions<MonitorOptions> opts,
        IProcessStartSource source,
        ISystemEnvironment env,
        TimeProvider time)
    {
        _logger = logger;
        _writer = writer;
        _opts = opts.Value;
        _source = source;
        _time = time;
        _evaluator = new ProcessStartEvaluator(_opts, env.BaseDirectory);
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
            _source.ProcessStarted += OnProcessStarted;
            _source.Start();
            _logger.LogInformation("ProcessMonitor started (watching __InstanceCreationEvent every 2s)");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ProcessMonitor failed to start");
            return Task.CompletedTask;
        }

        return Task.Delay(Timeout.Infinite, stoppingToken)
            .ContinueWith(_ => _source.Stop(), TaskScheduler.Default);
    }

    internal void OnProcessStarted(ProcessStartData data)
    {
        try
        {
            var evt = _evaluator.Evaluate(data, _time.GetUtcNow().UtcDateTime);
            if (evt is null) return;
            _writer.TryWrite(evt);
            _logger.LogInformation("Suspicious process emitted: {Name} from {Path}", data.Name, data.ExecutablePath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ProcessMonitor event handler failed");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _source.ProcessStarted -= OnProcessStarted; _source.Dispose(); } catch { }
        await base.StopAsync(cancellationToken);
    }
}

/// <summary>
/// Regra pura do ProcessMonitor. Auto-referência agora é estrita: (a) executável
/// sob a pasta de instalação do agente, ou (b) NOME do executável contendo um
/// fragmento (ex.: SecAgent-Setup.exe em Downloads). Antes bastava o CAMINHO
/// conter "SecAgent" — <c>Downloads\SecAgent\malware.exe</c> passava batido.
/// </summary>
internal sealed class ProcessStartEvaluator
{
    private readonly HashSet<string> _whitelist;
    private readonly List<string> _selfNameFragments;
    private readonly List<string> _selfDirs;
    private readonly List<string> _suspicious;

    public ProcessStartEvaluator(MonitorOptions opts, string serviceBaseDirectory)
    {
        _whitelist = new HashSet<string>(opts.ProcessWhitelist ?? new(), StringComparer.OrdinalIgnoreCase);
        _selfNameFragments = (opts.SelfReferenceFragments ?? new()).Where(f => !string.IsNullOrWhiteSpace(f)).ToList();
        _suspicious = opts.SuspiciousPathFragments ?? MonitorOptions.DefaultSuspiciousPathFragments.ToList();

        var dirs = (opts.SelfInstallDirectories ?? new()).Where(d => !string.IsNullOrWhiteSpace(d)).ToList();
        if (dirs.Count == 0 && DefaultInstallRoot(serviceBaseDirectory) is { } root) dirs.Add(root);
        _selfDirs = dirs.Select(NormalizeDir).ToList();
    }

    /// <summary>Pasta-pai do executável do Service ({app}\Service → {app}, cobrindo também {app}\Tray).</summary>
    internal static string? DefaultInstallRoot(string baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(baseDirectory)) return null;
        var trimmed = baseDirectory.TrimEnd('\\', '/');
        return Path.GetDirectoryName(trimmed) ?? trimmed;
    }

    private static string NormalizeDir(string d) => d.TrimEnd('\\', '/') + "\\";

    public bool IsSelf(string path)
    {
        var fileName = Path.GetFileName(path);
        if (_selfNameFragments.Any(f => fileName.Contains(f, StringComparison.OrdinalIgnoreCase))) return true;
        return _selfDirs.Any(d => path.StartsWith(d, StringComparison.OrdinalIgnoreCase));
    }

    public SecurityEvent? Evaluate(ProcessStartData p, DateTime nowUtc)
    {
        var name = (p.Name ?? "").ToLowerInvariant();
        if (string.IsNullOrEmpty(name) || _whitelist.Contains(name)) return null;

        var path = p.ExecutablePath;
        if (string.IsNullOrEmpty(path)) return null;   // processo protegido ou corrida; ignora
        if (IsSelf(path)) return null;

        var fragment = _suspicious.FirstOrDefault(f => path.Contains(f, StringComparison.OrdinalIgnoreCase));
        if (fragment is null) return null;              // não é suspeito o bastante

        return new SecurityEvent(
            TimestampUtc: nowUtc,
            Source: "process",
            Severity: SeverityLevels.High,
            Title: $"Process from suspicious path: {name}",
            Description: $"Executable launched from path containing '{fragment}', a common staging location for malware.",
            Details: new Dictionary<string, string>
            {
                ["name"] = name,
                ["pid"] = p.ProcessId ?? "",
                ["parentPid"] = p.ParentProcessId ?? "",
                ["path"] = path,
                ["commandLine"] = (p.CommandLine ?? "").Truncate(500),
                ["fragment"] = fragment
            });
    }
}
