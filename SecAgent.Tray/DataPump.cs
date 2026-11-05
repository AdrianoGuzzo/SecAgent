using System.Text.Json;
using SecAgent.Tray.Core;

namespace SecAgent.Tray;

/// <summary>
/// Lê os arquivos Service → Tray e empurra mensagens tipadas para o painel. O host
/// faz TODO o I/O; a página só renderiza. Mensagens saem como (type, payloadJson)
/// pelo evento <see cref="Message"/>; o form embrulha em {type,payload}.
///
/// Ativo só com o painel aberto (Start/Stop). Watchers + um poll leve de
/// fallback (3s) que roda num timer de thread pool — T4: antes era um timer
/// WinForms, ou seja, as leituras com retry (Thread.Sleep) rodavam na UI thread.
/// </summary>
public sealed class DataPump : IDisposable
{
    internal const int PreloadEventLines = 50;
    internal static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);

    private readonly AgentPaths _paths;
    private readonly IGeoLookup _geo;            // compartilhado, dono = TrayApplicationContext
    private readonly Func<bool> _tokenConfigured;
    private readonly AiPrefsStore _prefs;
    private readonly TimeProvider _time;
    private readonly EventsTail _events;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly SemaphoreSlim _pollGate = new(1, 1);
    private ITimer? _timer;
    private bool _started;

    /// <summary>(type, payloadJson) — payloadJson já é JSON válido ou "null".</summary>
    public event Action<string, string>? Message;

    public DataPump(IGeoLookup geo)
        : this(AgentPaths.Default, geo, TokenSetup.IsConfigured, AiPrefsStore.Default, TimeProvider.System) { }

    internal DataPump(AgentPaths paths, IGeoLookup geo, Func<bool> tokenConfigured, AiPrefsStore prefs, TimeProvider time)
    {
        _paths = paths;
        _geo = geo;
        _tokenConfigured = tokenConfigured;
        _prefs = prefs;
        _time = time;
        _events = new EventsTail(paths, time);
        _geo.Resolved += OnGeoResolved;
    }

    public void Start()
    {
        if (_started) return;
        _started = true;

        try { Directory.CreateDirectory(_paths.ReportsDir); } catch { }
        try { Directory.CreateDirectory(_paths.EventsDir); } catch { }

        Watch(_paths.DataRoot, "progress.json", () => EmitProgressAsync(), () => Emit("progress", "null"));
        Watch(_paths.DataRoot, "network.json", () => EmitNetworkAsync(), null);
        Watch(_paths.DataRoot, "blocked.json", () => EmitBlockedAsync(), null);
        Watch(_paths.ReportsDir, "*.json", null, null, OnReportChangedAsync);
        Watch(_paths.EventsDir, "events_*.jsonl", () => { ReadNewEvents(); return Task.CompletedTask; }, null);

        _timer = _time.CreateTimer(_ => { if (_started) _ = PollLightAsync(); }, null, PollInterval, PollInterval);
    }

    public void Stop()
    {
        if (!_started) return;
        _started = false;
        _timer?.Dispose();
        _timer = null;
        foreach (var w in _watchers) { try { w.Dispose(); } catch { } }
        _watchers.Clear();
    }

    /// <summary>Envia o estado completo para uma janela recém-aberta.</summary>
    public async Task RequestInitialSnapshotAsync()
    {
        await EmitStatusAsync();
        await EmitProgressAsync();
        await EmitLatestReportAsync();
        await EmitLatestIncidentAsync();
        await EmitNetworkAsync();
        await EmitBlockedAsync();
        EmitTokenStatus();
        EmitAiPrefs();
        PreloadEvents();
    }

    /// <summary>Última escolha de modelo/esforço (prefs locais, não arquivo do Service).</summary>
    public void EmitAiPrefs() => Emit("aiPrefs", _prefs.ToMessageJson());

    /// <summary>Token configurado? Público para o form atualizar logo após salvar.</summary>
    public void EmitTokenStatus()
        => Emit("tokenStatus", "{\"configured\":" + (_tokenConfigured() ? "true" : "false") + "}");

    // ---- emitters -----------------------------------------------------------

    private void Emit(string type, string payload) => Message?.Invoke(type, payload);

    internal async Task EmitStatusAsync()
    {
        var json = await JsonFileReader.ReadAsCamelAsync<AgentStatus>(_paths.StatusFile);
        if (json is not null) Emit("status", json);
    }

    internal async Task EmitProgressAsync()
    {
        var json = await JsonFileReader.ReadAsCamelAsync<AnalysisProgress>(_paths.ProgressFile);
        Emit("progress", json ?? "null");
    }

    internal async Task EmitLatestReportAsync()
    {
        var latest = LatestFile("report_*.json");
        if (latest is null) return;
        var json = await JsonFileReader.ReadAsCamelAsync<AnalysisResult>(latest);
        if (json is not null) Emit("report", json);
    }

    internal async Task EmitLatestIncidentAsync()
    {
        // Ignora os sidecars *.events.json (snapshot forense dos eventos).
        var latest = LatestFile("incident_*.json", f => !f.Name.EndsWith(".events.json", StringComparison.OrdinalIgnoreCase));
        if (latest is null) return;
        var json = await JsonFileReader.ReadAsCamelAsync<IncidentReport>(latest);
        if (json is not null) Emit("incident", json);
    }

    internal async Task EmitNetworkAsync()
    {
        var snap = await JsonFileReader.ReadAsync<NetworkSnapshot>(_paths.NetworkFile);
        if (snap is null) return;
        Emit("network", JsonSerializer.Serialize(snap, JsonDefaults.CamelCase));

        // Geolocalização dos IPs públicos: cache → emite já; senão enfileira.
        foreach (var ip in (snap.Connections ?? new()).Where(c => c.RemoteIsPublic).Select(c => c.RemoteAddress).Distinct())
        {
            if (_geo.TryGetCached(ip) is { } cached) EmitGeo(ip, cached);
            else _geo.QueueLookup(ip);
        }
    }

    internal async Task EmitBlockedAsync()
    {
        var json = await JsonFileReader.ReadAsCamelAsync<BlockedList>(_paths.BlockedFile);
        if (json is not null) Emit("blocked", json);
    }

    private void OnGeoResolved(string ip, GeoInfo info) => EmitGeo(ip, info);

    private void EmitGeo(string ip, GeoInfo info)
        => Emit("geo", JsonSerializer.Serialize(new { ip, geo = info }, JsonDefaults.CamelCase));

    // ---- eventos ------------------------------------------------------------

    internal void PreloadEvents() => EmitEvents(_events.Preload(PreloadEventLines));

    internal void ReadNewEvents() => EmitEvents(_events.ReadNew());

    private void EmitEvents(List<string> lines)
    {
        var events = new List<SecurityEvent>();
        foreach (var l in lines)
        {
            try
            {
                if (JsonSerializer.Deserialize<SecurityEvent>(l, JsonDefaults.Read) is { } e) events.Add(e);
            }
            catch (JsonException) { /* linha malformada */ }
        }
        if (events.Count > 0) Emit("events", JsonSerializer.Serialize(events, JsonDefaults.CamelCase));
    }

    // ---- watchers / poll ----------------------------------------------------

    internal Task OnReportChangedAsync(string? name)
    {
        name ??= "";
        if (name.StartsWith("incident_", StringComparison.OrdinalIgnoreCase)) return EmitLatestIncidentAsync();
        if (name.StartsWith("report_", StringComparison.OrdinalIgnoreCase)) return EmitLatestReportAsync();
        return Task.CompletedTask;
    }

    /// <summary>Fallback para eventos de watcher perdidos (barato; idempotente na página).</summary>
    internal async Task PollLightAsync()
    {
        if (!await _pollGate.WaitAsync(0)) return;   // poll anterior ainda rodando
        try
        {
            await EmitStatusAsync();
            await EmitProgressAsync();
            await EmitNetworkAsync();
            await EmitBlockedAsync();
            EmitTokenStatus();
            ReadNewEvents();
        }
        catch (Exception) { /* nunca derruba o timer */ }
        finally { _pollGate.Release(); }
    }

    private void Watch(string dir, string filter, Func<Task>? onChanged, Action? onDeleted,
        Func<string?, Task>? onChangedNamed = null)
    {
        try
        {
            var w = new FileSystemWatcher(dir, filter)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            void Fire(string? name)
            {
                if (!_started) return;   // evento atrasado após Stop
                var t = onChangedNamed is not null ? onChangedNamed(name) : onChanged?.Invoke();
                t?.ContinueWith(_ => { }, TaskContinuationOptions.OnlyOnFaulted);
            }
            w.Created += (_, e) => Fire(e.Name);
            w.Changed += (_, e) => Fire(e.Name);
            // O Service grava por escrita atômica (File.Move com overwrite), que no
            // Windows chega como Renamed — não Created/Changed.
            w.Renamed += (_, e) => Fire(e.Name);
            if (onDeleted is not null) w.Deleted += (_, _) => { if (_started) onDeleted(); };
            w.EnableRaisingEvents = true;
            _watchers.Add(w);
        }
        catch (Exception) { /* pasta pode não existir ainda — o poll cobre */ }
    }

    private string? LatestFile(string pattern, Func<FileInfo, bool>? filter = null)
    {
        try
        {
            return new DirectoryInfo(_paths.ReportsDir).GetFiles(pattern)
                .Where(filter ?? (_ => true))
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault()?.FullName;
        }
        catch (IOException) { return null; }
    }

    public void Dispose()
    {
        Stop();
        _geo.Resolved -= OnGeoResolved;   // instância compartilhada — NÃO descartar aqui
        _pollGate.Dispose();
    }
}
