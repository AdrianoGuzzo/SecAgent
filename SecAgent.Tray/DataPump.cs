using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecAgent.Tray.Models;

namespace SecAgent.Tray;

/// <summary>
/// Reads every Service→Tray file and pushes typed messages to the dashboard.
/// The host does ALL disk I/O; the WebView page only renders. Messages are
/// raised as (type, payloadJson) via <see cref="Message"/>; the form wraps them
/// in a {type,payload} envelope and posts to the page.
///
/// Active only while the dashboard window is open (Start/Stop), so there is no
/// overhead when the user isn't looking. The existing tray-icon watchers in
/// TrayApplicationContext are untouched.
/// </summary>
public sealed class DataPump : IDisposable
{
    private const string DataDir = @"C:\ProgramData\SecAgent";
    private const string StatusPath = @"C:\ProgramData\SecAgent\status.json";
    private const string ProgressPath = @"C:\ProgramData\SecAgent\progress.json";
    private const string NetworkPath = @"C:\ProgramData\SecAgent\network.json";
    private const string BlockedPath = @"C:\ProgramData\SecAgent\blocked.json";
    private const string ReportsDir = @"C:\ProgramData\SecAgent\reports";
    private const string EventsDir = @"C:\ProgramData\SecAgent\events";
    private const int PreloadEventLines = 50;

    // The Service writes PascalCase JSON; the dashboard page reads camelCase.
    // JsonOpts deserializes case-insensitively, OutOpts re-serializes to camelCase.
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };
    private static readonly JsonSerializerOptions OutOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly GeoLookup _geo;        // shared, owned by TrayApplicationContext
    private readonly System.Windows.Forms.Timer _timer;
    private FileSystemWatcher? _progressWatcher;
    private FileSystemWatcher? _networkWatcher;
    private FileSystemWatcher? _blockedWatcher;
    private FileSystemWatcher? _reportWatcher;
    private FileSystemWatcher? _eventsWatcher;

    private string? _eventsPath;
    private long _eventsOffset;
    private bool _started;
    private readonly object _eventsLock = new();

    /// <summary>(type, payloadJson) — payloadJson is already valid JSON or "null".</summary>
    public event Action<string, string>? Message;

    public DataPump(GeoLookup geo)
    {
        _geo = geo;
        _timer = new System.Windows.Forms.Timer { Interval = 3000 };
        _timer.Tick += (_, _) => PollLight();
        _geo.Resolved += OnGeoResolved;
    }

    public void Start()
    {
        if (_started) return;
        _started = true;

        try { Directory.CreateDirectory(ReportsDir); } catch { }
        try { Directory.CreateDirectory(EventsDir); } catch { }

        TryWatch(ref _progressWatcher, DataDir, "progress.json", OnProgressChanged, OnProgressDeleted);
        TryWatch(ref _networkWatcher, DataDir, "network.json", (_, _) => EmitNetwork(), null);
        TryWatch(ref _blockedWatcher, DataDir, "blocked.json", (_, _) => EmitBlocked(), null);
        TryWatch(ref _reportWatcher, ReportsDir, "*.json", OnReportChanged, null);
        TryWatch(ref _eventsWatcher, EventsDir, "events_*.jsonl", (_, _) => ReadNewEvents(), null);

        _timer.Start();
    }

    public void Stop()
    {
        if (!_started) return;
        _started = false;
        _timer.Stop();
        DisposeWatcher(ref _progressWatcher);
        DisposeWatcher(ref _networkWatcher);
        DisposeWatcher(ref _blockedWatcher);
        DisposeWatcher(ref _reportWatcher);
        DisposeWatcher(ref _eventsWatcher);
    }

    /// <summary>Pushes the full current state to a freshly-opened window.</summary>
    public void RequestInitialSnapshot()
    {
        EmitStatus();
        EmitProgress();
        EmitLatestReport();
        EmitLatestIncident();
        EmitNetwork();
        EmitBlocked();
        EmitTokenStatus();
        EmitAiPrefs();
        PreloadEvents();
    }

    /// <summary>
    /// Envia a última escolha de modelo/esforço para o painel pré-selecionar os
    /// dropdowns. Origem é o arquivo de prefs local (não um arquivo do Service),
    /// por isso é computado aqui no host.
    /// </summary>
    public void EmitAiPrefs()
    {
        var (model, effort) = AiPrefs.Load();
        Message?.Invoke("aiPrefs",
            $"{{\"model\":\"{model}\",\"effort\":\"{effort}\"}}");
    }

    /// <summary>
    /// Emits whether the Claude OAuth token is configured, so the page can show the
    /// AI button or the "Configurar IA" wrench. Sourced from the env var (not a
    /// Service file), so it's computed here in the host. Public so the form can
    /// refresh the page immediately after the token is saved.
    /// </summary>
    public void EmitTokenStatus()
        => Message?.Invoke("tokenStatus",
            "{\"configured\":" + (TokenSetup.IsConfigured() ? "true" : "false") + "}");

    // ---- emitters -----------------------------------------------------------

    private void EmitStatus()
    {
        var json = ReadAndCamel<AgentStatus>(StatusPath);
        if (json is not null) Message?.Invoke("status", json);
    }

    private void EmitProgress()
    {
        if (!File.Exists(ProgressPath)) { Message?.Invoke("progress", "null"); return; }
        var json = ReadAndCamel<AnalysisProgress>(ProgressPath);
        Message?.Invoke("progress", json ?? "null");
    }

    private void EmitLatestReport()
    {
        var latest = LatestFile(ReportsDir, "report_*.json");
        if (latest is null) return;
        var json = ReadAndCamel<AnalysisResult>(latest);
        if (json is not null) Message?.Invoke("report", json);
    }

    private void EmitLatestIncident()
    {
        var latest = LatestFile(ReportsDir, "incident_*.json");
        if (latest is null) return;
        // Skip the *.events.json sidecar files.
        if (latest.EndsWith(".events.json", StringComparison.OrdinalIgnoreCase))
        {
            latest = new DirectoryInfo(ReportsDir).GetFiles("incident_*.json")
                .Where(f => !f.Name.EndsWith(".events.json", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault()?.FullName;
            if (latest is null) return;
        }
        var json = ReadAndCamel<IncidentReport>(latest);
        if (json is not null) Message?.Invoke("incident", json);
    }

    private void EmitNetwork()
    {
        var raw = ReadJsonRaw(NetworkPath);
        if (raw is null) return;

        NetworkSnapshot? snap;
        try { snap = JsonSerializer.Deserialize<NetworkSnapshot>(raw, JsonOpts); }
        catch { return; }
        if (snap is null) return;

        Message?.Invoke("network", JsonSerializer.Serialize(snap, OutOpts));

        // Kick off / surface geolocation for public remote IPs.
        if (snap.Connections is null) return;
        foreach (var ip in snap.Connections
                     .Where(c => c.RemoteIsPublic)
                     .Select(c => c.RemoteAddress)
                     .Distinct())
        {
            var cached = _geo.TryGetCached(ip);
            if (cached is not null) EmitGeo(ip, cached);
            else _geo.QueueLookup(ip);
        }
    }

    private void EmitBlocked()
    {
        var json = ReadAndCamel<BlockedList>(BlockedPath);
        if (json is not null) Message?.Invoke("blocked", json);
    }

    private void OnGeoResolved(string ip, GeoLookup.GeoInfo info) => EmitGeo(ip, info);

    private void EmitGeo(string ip, GeoLookup.GeoInfo info)
    {
        var payload = JsonSerializer.Serialize(new { ip, geo = info }, OutOpts);
        Message?.Invoke("geo", payload);
    }

    // ---- events tailing -----------------------------------------------------

    private void PreloadEvents()
    {
        lock (_eventsLock)
        {
            var path = TodaysEventsPath();
            _eventsPath = path;
            _eventsOffset = 0;
            if (!File.Exists(path)) return;

            try
            {
                var lines = new List<string>();
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(fs, Encoding.UTF8))
                {
                    string? line;
                    while ((line = sr.ReadLine()) != null)
                        if (line.Length > 0) lines.Add(line);
                    _eventsOffset = fs.Length;
                }

                var recent = lines.Count > PreloadEventLines
                    ? lines.GetRange(lines.Count - PreloadEventLines, PreloadEventLines)
                    : lines;
                EmitEventsFromLines(recent);
            }
            catch { /* best effort */ }
        }
    }

    private void ReadNewEvents()
    {
        lock (_eventsLock)
        {
            var path = TodaysEventsPath();
            if (!string.Equals(path, _eventsPath, StringComparison.OrdinalIgnoreCase))
            {
                _eventsPath = path;          // UTC day rollover → new file
                _eventsOffset = 0;
            }
            if (!File.Exists(path)) return;

            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (fs.Length < _eventsOffset) _eventsOffset = 0;     // file truncated/rotated
                if (fs.Length == _eventsOffset) return;

                fs.Seek(_eventsOffset, SeekOrigin.Begin);
                var buffer = new byte[fs.Length - _eventsOffset];
                int read = fs.Read(buffer, 0, buffer.Length);

                // Only consume up to the last complete line (last '\n').
                int lastNl = Array.LastIndexOf(buffer, (byte)'\n', read - 1);
                if (lastNl < 0) return;                               // no complete line yet

                var text = Encoding.UTF8.GetString(buffer, 0, lastNl + 1);
                _eventsOffset += Encoding.UTF8.GetByteCount(text);

                var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                                .Select(l => l.Trim())
                                .Where(l => l.Length > 0)
                                .ToList();
                EmitEventsFromLines(lines);
            }
            catch { /* mid-write — retry next tick */ }
        }
    }

    private void EmitEventsFromLines(List<string> lines)
    {
        if (lines.Count == 0) return;
        var events = new List<SecurityEvent>();
        foreach (var l in lines)
        {
            try
            {
                var e = JsonSerializer.Deserialize<SecurityEvent>(l, JsonOpts);
                if (e is not null) events.Add(e);
            }
            catch { /* skip malformed line */ }
        }
        if (events.Count == 0) return;
        Message?.Invoke("events", JsonSerializer.Serialize(events, OutOpts));
    }

    private static string TodaysEventsPath()
        => Path.Combine(EventsDir, $"events_{DateTime.UtcNow:yyyy-MM-dd}.jsonl");

    // ---- watcher handlers ---------------------------------------------------

    private void OnProgressChanged(object? s, FileSystemEventArgs e) => EmitProgress();
    private void OnProgressDeleted(object? s, FileSystemEventArgs e) => Message?.Invoke("progress", "null");

    private void OnReportChanged(object? s, FileSystemEventArgs e)
    {
        var name = e.Name ?? "";
        if (name.StartsWith("incident_", StringComparison.OrdinalIgnoreCase))
            EmitLatestIncident();
        else if (name.StartsWith("report_", StringComparison.OrdinalIgnoreCase))
            EmitLatestReport();
    }

    private void PollLight()
    {
        // Fallback for missed watcher events (cheap, idempotent on the page side).
        EmitStatus();
        EmitProgress();
        EmitNetwork();
        EmitBlocked();
        EmitTokenStatus();
        ReadNewEvents();
    }

    // ---- helpers ------------------------------------------------------------

    private static void TryWatch(
        ref FileSystemWatcher? watcher, string dir, string filter,
        FileSystemEventHandler onChanged, FileSystemEventHandler? onDeleted)
    {
        try
        {
            var w = new FileSystemWatcher(dir, filter)
            {
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            w.Created += onChanged;
            w.Changed += onChanged;
            if (onDeleted is not null) w.Deleted += onDeleted;
            watcher = w;
        }
        catch { /* dir may not exist yet — fallback timer still polls */ }
    }

    private static void DisposeWatcher(ref FileSystemWatcher? w)
    {
        try { w?.Dispose(); } catch { }
        w = null;
    }

    private static string? LatestFile(string dir, string pattern)
    {
        try
        {
            return new DirectoryInfo(dir).GetFiles(pattern)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault()?.FullName;
        }
        catch { return null; }
    }

    /// <summary>Reads a PascalCase JSON file and re-serializes it as camelCase for the page.</summary>
    private static string? ReadAndCamel<T>(string path)
    {
        var raw = ReadJsonRaw(path);
        if (raw is null) return null;
        try
        {
            var obj = JsonSerializer.Deserialize<T>(raw, JsonOpts);
            return obj is null ? null : JsonSerializer.Serialize(obj, OutOpts);
        }
        catch { return null; }
    }

    /// <summary>Reads a JSON file with brief retry; returns null if missing/unparseable.</summary>
    private static string? ReadJsonRaw(string path)
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                if (!File.Exists(path)) return null;
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, Encoding.UTF8);
                var json = sr.ReadToEnd();
                if (string.IsNullOrWhiteSpace(json)) { Thread.Sleep(80); continue; }
                using var _ = JsonDocument.Parse(json);     // validate (mid-write guard)
                return json;
            }
            catch { Thread.Sleep(80); }
        }
        return null;
    }

    public void Dispose()
    {
        Stop();
        _geo.Resolved -= OnGeoResolved;     // shared instance — do NOT dispose it here
        _timer.Dispose();
    }
}
