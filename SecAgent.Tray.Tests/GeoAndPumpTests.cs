using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SecAgent.Tray.Core;

namespace SecAgent.Tray.Tests;

/// <summary>Handler HTTP falso: responde por IP e conta as chamadas.</summary>
internal sealed class FakeIpApi : HttpMessageHandler
{
    public readonly List<string> Requests = new();
    public Func<string, HttpResponseMessage> Respond = _ => Ok("Brasil", "BR");

    public static HttpResponseMessage Ok(string country, string cc) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(new { status = "success", country, countryCode = cc, city = "SP", isp = "ISP" }))
    };

    public static HttpResponseMessage Fail() => new(HttpStatusCode.OK)
    {
        Content = new StringContent("""{"status":"fail","message":"reserved range"}""")
    };

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        lock (Requests) Requests.Add(request.RequestUri!.AbsolutePath);
        return Task.FromResult(Respond(request.RequestUri!.AbsolutePath));
    }
}

public sealed class GeoLookupTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeIpApi _api = new();
    private readonly FakeTimeProvider _clock = T.Clock();
    public void Dispose() => _dir.Dispose();

    private string CachePath => _dir.File("geo-cache.json");
    private GeoLookup Create(bool worker = false) => new(CachePath, _api, _clock, worker);

    [Fact]
    public async Task ResolveNow_fetches_caches_and_raises_event()
    {
        using var geo = Create();
        var raised = new List<string>();
        geo.Resolved += (ip, _) => raised.Add(ip);

        var info = await geo.ResolveNowAsync(" 8.8.8.8 ");
        Assert.Equal(new GeoInfo("Brasil", "BR", "SP", "ISP"), info);
        Assert.Equal(info, geo.TryGetCached("8.8.8.8"));
        Assert.Equal(info, await geo.ResolveNowAsync("8.8.8.8"));   // cache
        Assert.Single(_api.Requests);
        Assert.Equal(new[] { "8.8.8.8" }, raised);
    }

    [Theory]
    [InlineData("8.8.8.8/../../admin")]
    [InlineData("evil.com")]
    [InlineData("")]
    [InlineData(null)]
    public async Task Bug_invalid_ip_never_reaches_the_url(string? ip)
    {
        using var geo = Create();
        Assert.Null(await geo.ResolveNowAsync(ip!));
        geo.QueueLookup(ip!);
        await geo.DrainQueueAsync();
        Assert.Null(geo.TryGetCached(ip!));
        Assert.Empty(_api.Requests);
    }

    [Fact]
    public async Task Bug_failures_are_negative_cached_in_memory_only_and_not_shown_as_unknown()
    {
        _api.Respond = _ => FakeIpApi.Fail();
        using (var geo = Create())
        {
            Assert.Null(await geo.ResolveNowAsync("10.0.0.1"));
            Assert.Null(geo.TryGetCached("10.0.0.1"));            // antes: "Desconhecido"
            Assert.Null(await geo.ResolveNowAsync("10.0.0.1"));   // negativo: sem nova chamada
            geo.QueueLookup("10.0.0.1");
            await geo.DrainQueueAsync();
            Assert.Single(_api.Requests);

            _clock.Advance(GeoLookup.NegativeTtl + TimeSpan.FromMinutes(1));
            _api.Respond = _ => FakeIpApi.Ok("X", "XX");
            Assert.NotNull(await geo.ResolveNowAsync("10.0.0.1"));
        }

        _api.Respond = _ => FakeIpApi.Fail();
        using (var geo = Create())
        {
            await geo.ResolveNowAsync("1.1.1.1");
        }
        var persisted = File.ReadAllText(CachePath);
        Assert.Contains("10.0.0.1", persisted);
        Assert.DoesNotContain("1.1.1.1", persisted);   // falha não vai para o disco
    }

    [Fact]
    public async Task Http_exceptions_are_failures()
    {
        _api.Respond = _ => throw new HttpRequestException("offline");
        using var geo = Create();
        Assert.Null(await geo.ResolveNowAsync("8.8.4.4"));
    }

    [Fact]
    public async Task Queue_dedupes_and_worker_resolves_in_background()
    {
        using var geo = Create(worker: true);
        var resolved = new List<string>();
        geo.Resolved += (ip, _) => { lock (resolved) resolved.Add(ip); };

        geo.QueueLookup("9.9.9.9");
        geo.QueueLookup("9.9.9.9");
        await T.Eventually(() => { lock (resolved) return resolved.Count == 1; });
        geo.QueueLookup("9.9.9.9");   // já em cache → no-op
        Assert.Single(_api.Requests);
    }

    [Fact]
    public async Task Cache_survives_restart_and_expires()
    {
        using (var geo = Create()) await geo.ResolveNowAsync("8.8.8.8");
        Assert.True(File.Exists(CachePath));

        using (var reloaded = Create())
            Assert.NotNull(reloaded.TryGetCached("8.8.8.8"));

        _clock.Advance(GeoLookup.SuccessTtl + TimeSpan.FromDays(1));
        using (var expired = Create())
            Assert.Null(expired.TryGetCached("8.8.8.8"));

        File.WriteAllText(CachePath, "{corrupt");
        using var fresh = Create();
        Assert.Null(fresh.TryGetCached("8.8.8.8"));
    }

    [Fact]
    public async Task Rate_limit_waits_for_the_window()
    {
        using var geo = Create();
        for (int i = 0; i < GeoLookup.MaxPerMinute; i++)
            await geo.ResolveNowAsync($"8.8.{i / 250}.{i % 250 + 1}");
        Assert.Equal(GeoLookup.MaxPerMinute, _api.Requests.Count);

        geo.QueueLookup("9.9.9.9");
        var drain = geo.DrainQueueAsync();
        await Task.Delay(50);
        Assert.False(drain.IsCompleted);                  // segurando no rate limit
        _clock.Advance(TimeSpan.FromMinutes(1));
        await drain;
        Assert.Equal(GeoLookup.MaxPerMinute + 1, _api.Requests.Count);
    }

    [Fact]
    public void Bug_dispose_stops_worker_and_is_idempotent()
    {
        var geo = Create(worker: true);
        geo.Dispose();
        geo.Dispose();
        geo.QueueLookup("8.8.8.8");   // após dispose: sem efeito, sem exceção
        Assert.True(File.Exists(CachePath));
    }

    [Fact]
    public void NormalizeIp_canonicalizes()
    {
        Assert.Equal("2001:db8::1", GeoLookup.NormalizeIp("2001:DB8:0::1"));
        Assert.Null(GeoLookup.NormalizeIp("300.1.1.1"));
    }

    [Fact]
    public void Default_constructor_works()
    {
        using var geo = new GeoLookup();
        Assert.Null(geo.TryGetCached("not-an-ip"));
    }
}

[Collection("JsonFileReader")]
public sealed class DataPumpTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly IGeoLookup _geo = Substitute.For<IGeoLookup>();
    private readonly FakeTimeProvider _clock = T.Clock();
    private readonly List<(string Type, string Payload)> _messages = new();
    private bool _token = true;

    public DataPumpTests() => JsonFileReader.RetryDelay = TimeSpan.FromMilliseconds(5);

    public void Dispose() => _dir.Dispose();

    private DataPump Create()
    {
        var pump = new DataPump(_dir.Paths, _geo, () => _token, new AiPrefsStore(_dir.File("prefs.json")), _clock);
        pump.Message += (t, p) => { lock (_messages) _messages.Add((t, p)); };
        return pump;
    }

    private string[] Types() { lock (_messages) return _messages.Select(m => m.Type).ToArray(); }
    private string Last(string type) { lock (_messages) return _messages.Last(m => m.Type == type).Payload; }

    private void WriteJson(string path, object value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(value, JsonDefaults.Indented));   // PascalCase, como o Service
    }

    private static readonly DateTime Now = T.T0.UtcDateTime;
    private static AnalysisMeta Meta => new("sonnet", 1, 1, 1, 1, 1, 0.1m, "s", false, "high");

    [Fact]
    public async Task Initial_snapshot_emits_everything_in_camel_case()
    {
        WriteJson(_dir.Paths.StatusFile, new AgentStatus(Now, "red", null, null));
        WriteJson(_dir.Paths.ProgressFile, new AnalysisProgress("scanning", Now, "s", "tray", null));
        WriteJson(Path.Combine(_dir.Paths.ReportsDir, "report_2026-03-15_120000.json"),
            new AnalysisResult(Now, "scan.json", "high", "S", new() { new("high", "c", "t", "d", "r", null) }, Meta));
        WriteJson(Path.Combine(_dir.Paths.ReportsDir, "incident_2026-03-15_120000.json"),
            new IncidentReport(Now, 1, Now, Now, "critical", "T", "S", new() { "a" }, Meta));
        WriteJson(Path.Combine(_dir.Paths.ReportsDir, "incident_2026-03-15_120000.events.json"), new[] { 1 });
        File.SetLastWriteTimeUtc(Path.Combine(_dir.Paths.ReportsDir, "incident_2026-03-15_120000.events.json"), DateTime.UtcNow.AddMinutes(1));
        WriteJson(_dir.Paths.BlockedFile, new BlockedList(Now, new() { new("1.2.3.4") }));
        WriteJson(_dir.Paths.NetworkFile, new NetworkSnapshot(Now, new()
        {
            new("inbound", "10.0.0.1", 3389, "8.8.8.8", 5000, "svc", 4, true),
            new("outbound", "10.0.0.1", 5001, "9.9.9.9", 443, "chrome", 8, true),
            new("outbound", "10.0.0.1", 5002, "10.0.0.2", 80, "x", 9, false),
        }));
        Directory.CreateDirectory(_dir.Paths.EventsDir);
        File.WriteAllText(_dir.Paths.EventsFileFor(Now),
            JsonSerializer.Serialize(new SecurityEvent(Now, "network", "medium", "t", "d", new() { ["k"] = "v" })) + "\nnot json\n");
        var cached = new GeoInfo("EUA", "US", "MV", "Google");
        _geo.TryGetCached("8.8.8.8").Returns(cached);

        using var pump = Create();
        await pump.RequestInitialSnapshotAsync();

        Assert.Equal(new[] { "status", "progress", "report", "incident", "network", "geo", "blocked", "tokenStatus", "aiPrefs", "events" }, Types());
        Assert.Contains("\"overallSeverity\":\"red\"", Last("status"));
        Assert.Contains("\"effort\":\"high\"", Last("report"));         // antes o Tray descartava Effort
        Assert.Contains("\"recommendedActions\":[\"a\"]", Last("incident"));
        Assert.Contains("\"remoteIsPublic\":true", Last("network"));
        Assert.Contains("\"countryCode\":\"US\"", Last("geo"));
        Assert.Contains("\"ip\":\"1.2.3.4\"", Last("blocked"));
        Assert.Equal("{\"configured\":true}", Last("tokenStatus"));
        Assert.Equal("""{"model":"sonnet","effort":"high"}""", Last("aiPrefs"));
        Assert.Contains("\"details\":{\"k\":\"v\"}", Last("events"));
        _geo.Received(1).QueueLookup("9.9.9.9");
        _geo.DidNotReceive().QueueLookup("10.0.0.2");
    }

    [Fact]
    public async Task Missing_files_emit_only_what_exists()
    {
        _token = false;
        using var pump = Create();
        await pump.RequestInitialSnapshotAsync();
        Assert.Equal(new[] { "progress", "tokenStatus", "aiPrefs" }, Types());
        Assert.Equal("null", Last("progress"));
        Assert.Equal("{\"configured\":false}", Last("tokenStatus"));
    }

    [Fact]
    public async Task Geo_resolved_event_is_forwarded_until_disposed()
    {
        var pump = Create();
        _geo.Resolved += Raise.Event<Action<string, GeoInfo>>("1.1.1.1", new GeoInfo("AU", "AU", "", ""));
        Assert.Contains("\"ip\":\"1.1.1.1\"", Last("geo"));

        pump.Dispose();
        lock (_messages) _messages.Clear();
        _geo.Resolved += Raise.Event<Action<string, GeoInfo>>("2.2.2.2", new GeoInfo("AU", "AU", "", ""));
        Assert.Empty(Types());
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Report_change_routes_by_name_and_poll_tails_events()
    {
        WriteJson(Path.Combine(_dir.Paths.ReportsDir, "report_a.json"),
            new AnalysisResult(Now, "s", "low", "", new(), Meta));
        using var pump = Create();

        await pump.OnReportChangedAsync("report_a.json");
        await pump.OnReportChangedAsync("incident_a.json");   // não existe → nada
        await pump.OnReportChangedAsync(null);
        Assert.Equal(new[] { "report" }, Types());

        pump.PreloadEvents();
        Directory.CreateDirectory(_dir.Paths.EventsDir);
        File.AppendAllText(_dir.Paths.EventsFileFor(Now),
            JsonSerializer.Serialize(new SecurityEvent(Now, "process", "high", "new", "d", new())) + "\n");
        await pump.PollLightAsync();
        Assert.Contains("events", Types());
        Assert.Contains("\"title\":\"new\"", Last("events"));
    }

    [Fact]
    public async Task Start_watches_files_and_polls_on_timer_until_stopped()
    {
        using var pump = Create();
        pump.Start();
        pump.Start();   // idempotente

        WriteJson(_dir.Paths.StatusFile, new AgentStatus(Now, "yellow", null, null));
        AtomicFile.WriteAllText(_dir.Paths.BlockedFile, JsonSerializer.Serialize(new BlockedList(Now, new())));
        await T.Eventually(() => Types().Contains("blocked"));   // watcher (Renamed)

        lock (_messages) _messages.Clear();
        _clock.Advance(DataPump.PollInterval);
        await T.Eventually(() => Types().Contains("status"));    // poll do timer

        File.WriteAllText(_dir.Paths.ProgressFile, "{}");
        File.Delete(_dir.Paths.ProgressFile);
        await T.Eventually(() => Types().Contains("progress"));

        pump.Stop();
        pump.Stop();
        await Task.Delay(100);   // poll em voo termina
        lock (_messages) _messages.Clear();
        _clock.Advance(DataPump.PollInterval * 3);
        await Task.Delay(50);
        Assert.Empty(Types());
    }

    [Fact]
    public void Default_constructor_uses_real_paths()
    {
        using var pump = new DataPump(_geo);
        pump.EmitAiPrefs();
    }
}

[CollectionDefinition("JsonFileReader", DisableParallelization = true)]
public sealed class JsonFileReaderCollection { }
