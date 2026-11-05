using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Options;
using SecAgent.Service.Platform;
using SecAgent.Service.Remediation;

namespace SecAgent.Service.Triggers;

/// <summary>Resultado do processamento de um arquivo de trigger (para log e testes).</summary>
public enum TriggerOutcome
{
    Processed,
    Unknown,
    Debounced,
    AlreadyInFlight,
    InvalidPayload
}

/// <summary>
/// Observa <c>triggers\*.trigger</c> gravados pelo Tray (user-mode, não fala
/// direto com o serviço). Triggers conhecidos: ver <see cref="TriggerNames"/>.
///
/// Correções de concorrência:
///  - O watcher é ligado ANTES do dreno de órfãos (antes, arquivos criados no
///    intervalo entre os dois eram perdidos).
///  - Guard "em processamento" por nome: o Changed que chega logo após o Created
///    não processa nem APAGA o arquivo que o primeiro handler ainda está lendo.
///  - Espera curta + leitura com retry: Created dispara antes do Tray terminar
///    de gravar o conteúdo (IP / modelo+esforço).
///  - Nomes desconhecidos não entram na tabela de debounce; entradas antigas são podadas.
/// O arquivo é sempre apagado ao fim do processamento (sucesso OU erro).
/// </summary>
public class TriggerWatcher : BackgroundService
{
    private readonly ILogger<TriggerWatcher> _logger;
    private readonly IScanRunner _runner;
    private readonly IIpBlocker _blocker;
    private readonly ITriggerDirectorySetup _directorySetup;
    private readonly TimeProvider _time;
    private readonly TriggerOptions _opts;
    private readonly Dictionary<string, DateTime> _lastFiredUtc = new();
    private readonly ConcurrentDictionary<string, byte> _inFlight = new();
    private readonly object _lock = new();
    private FileSystemWatcher? _watcher;

    public TriggerWatcher(
        ILogger<TriggerWatcher> logger,
        IScanRunner runner,
        IIpBlocker blocker,
        IOptions<TriggerOptions> opts,
        ITriggerDirectorySetup directorySetup,
        TimeProvider time)
    {
        _logger = logger;
        _runner = runner;
        _blocker = blocker;
        _directorySetup = directorySetup;
        _time = time;
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
            _directorySetup.EnsureDirectory(_opts.TriggersDirectory);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TriggerWatcher failed to prepare {Dir}", _opts.TriggersDirectory);
            return;
        }

        // Reconcilia blocked.json com as regras existentes (pós-reboot).
        try { _blocker.Reconcile(); }
        catch (Exception ex) { _logger.LogError(ex, "IpBlocker startup reconcile failed"); }

        try
        {
            _watcher = new FileSystemWatcher(_opts.TriggersDirectory, "*" + TriggerNames.Extension)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
            };
            _watcher.Created += (_, e) => Fire(e.FullPath, stoppingToken);
            _watcher.Changed += (_, e) => Fire(e.FullPath, stoppingToken);
            _watcher.Renamed += (_, e) => Fire(e.FullPath, stoppingToken);
            _watcher.EnableRaisingEvents = true;

            // Drena triggers órfãos gravados com o serviço parado (deploy/reboot).
            foreach (var path in Directory.GetFiles(_opts.TriggersDirectory, "*" + TriggerNames.Extension))
                Fire(path, stoppingToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TriggerWatcher failed to start watching {Dir}", _opts.TriggersDirectory);
            return;
        }

        _logger.LogInformation("TriggerWatcher started, watching {Dir}", _opts.TriggersDirectory);
        try { await Task.Delay(Timeout.Infinite, stoppingToken); }
        catch (OperationCanceledException) { }
        finally { try { _watcher?.Dispose(); } catch { } }
    }

    private void Fire(string fullPath, CancellationToken ct) => _ = ProcessTriggerAsync(fullPath, ct);

    internal async Task<TriggerOutcome> ProcessTriggerAsync(string fullPath, CancellationToken ct)
    {
        var name = Path.GetFileName(fullPath).ToLowerInvariant();

        if (!TriggerNames.IsKnown(name))
        {
            _logger.LogWarning("Unknown trigger file: {Name}", name);
            TryDelete(fullPath);
            return TriggerOutcome.Unknown;
        }

        if (!_inFlight.TryAdd(name, 0))
            return TriggerOutcome.AlreadyInFlight;   // outro handler está com este arquivo

        try
        {
            if (IsDebounced(name))
            {
                TryDelete(fullPath);
                return TriggerOutcome.Debounced;
            }

            _logger.LogInformation("Trigger {Name} accepted", name);
            if (_opts.SettleMilliseconds > 0)
                await Task.Delay(_opts.SettleMilliseconds, ct);
            var content = await ReadContentAsync(fullPath, ct);

            return await DispatchAsync(name, content, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return TriggerOutcome.Processed;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Trigger {Name} processing failed", name);
            return TriggerOutcome.Processed;
        }
        finally
        {
            TryDelete(fullPath);
            _inFlight.TryRemove(name, out _);
        }
    }

    private async Task<TriggerOutcome> DispatchAsync(string name, string? content, CancellationToken ct)
    {
        if (TriggerNames.IsBlockIp(name) || TriggerNames.IsUnblockIp(name))
        {
            // O IP viaja no CONTEÚDO (nomes de arquivo não comportam o ':' do IPv6).
            var ip = TriggerPayloadParser.ParseIp(content);
            if (ip is null)
            {
                _logger.LogWarning("Trigger {Name} has no valid IP payload", name);
                return TriggerOutcome.InvalidPayload;
            }
            if (TriggerNames.IsBlockIp(name)) _blocker.Block(ip);
            else _blocker.Unblock(ip);
            return TriggerOutcome.Processed;
        }

        if (name == TriggerNames.ScanOnly)
        {
            await _runner.RunScanOnlyAsync("tray", ct);
        }
        else
        {
            // O conteúdo carrega a escolha de modelo/esforço feita no painel
            // ({"model":"sonnet","effort":"high"}). Conteúdo legado/ausente → defaults.
            var (model, effort) = TriggerPayloadParser.ParseAnalyzeOptions(content);
            await _runner.RunScanAndAnalyzeAsync("tray", ct, model, effort);
        }
        return TriggerOutcome.Processed;
    }

    private bool IsDebounced(string name)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        var window = TimeSpan.FromSeconds(_opts.DebounceSeconds);
        lock (_lock)
        {
            // Poda: block-ip-* criaria uma entrada por IP para sempre.
            foreach (var stale in _lastFiredUtc.Where(kv => now - kv.Value >= window).Select(kv => kv.Key).ToList())
                _lastFiredUtc.Remove(stale);

            if (_lastFiredUtc.TryGetValue(name, out var last))
            {
                _logger.LogInformation("Trigger {Name} ignored (debounce, last fired {Sec}s ago)",
                    name, (int)(now - last).TotalSeconds);
                return true;
            }
            _lastFiredUtc[name] = now;
            return false;
        }
    }

    /// <summary>Lê o conteúdo tolerando o Tray ainda com o arquivo aberto (sharing violation).</summary>
    private static async Task<string?> ReadContentAsync(string path, CancellationToken ct)
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var sr = new StreamReader(fs);
                return await sr.ReadToEndAsync(ct);
            }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
            catch (IOException) { await Task.Delay(100, ct); }
        }
        return null;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

/// <summary>Interpretação do conteúdo dos triggers (puro).</summary>
internal static class TriggerPayloadParser
{
    /// <summary>IP canônico do conteúdo, ou null se ausente/inválido.</summary>
    public static string? ParseIp(string? content)
        => IpAddressPolicy.TryParseStrict(content, out var ip) ? ip.ToString() : null;

    /// <summary>
    /// Modelo/esforço gravados pelo Tray no scan-and-analyze ({"model":"sonnet","effort":"high"}).
    /// (null, null) para conteúdo legado (timestamp ISO) ou inválido — o
    /// ScanRunner cai nos defaults. Os valores são validados lá.
    /// </summary>
    public static (string? Model, string? Effort) ParseAnalyzeOptions(string? content)
    {
        var s = (content ?? "").Trim();
        if (s.Length == 0 || s[0] != '{') return (null, null);
        try
        {
            using var doc = JsonDocument.Parse(s);
            var root = doc.RootElement;
            var model = root.TryGetProperty("model", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() : null;
            var effort = root.TryGetProperty("effort", out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;
            return (model, effort);
        }
        catch (JsonException) { return (null, null); }
    }
}
