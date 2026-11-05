using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SecAgent.Tray.Core;

namespace SecAgent.Tray.Tests;

public sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "secagent-tray-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }
    public AgentPaths Paths => new(Path);
    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch { }
    }
}

internal static class T
{
    public static readonly DateTimeOffset T0 = new(2026, 3, 15, 12, 0, 0, TimeSpan.Zero);
    public static FakeTimeProvider Clock() => new(T0);

    public static async Task Eventually(Func<bool> condition, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException();
            await Task.Delay(10);
        }
    }
}

public class DashboardCommandParserTests
{
    [Theory]
    [InlineData("scanOnly", DashboardCommandKind.ScanOnly)]
    [InlineData("configureToken", DashboardCommandKind.ConfigureToken)]
    [InlineData("scanAndAnalyze", DashboardCommandKind.ScanAndAnalyze)]
    [InlineData("", DashboardCommandKind.Unknown)]
    [InlineData(null, DashboardCommandKind.Unknown)]
    [InlineData("rm -rf", DashboardCommandKind.Unknown)]
    [InlineData("blockIp:  ", DashboardCommandKind.Unknown)]
    public void Simple_commands(string? raw, DashboardCommandKind kind) => Assert.Equal(kind, DashboardCommandParser.Parse(raw).Kind);

    [Fact]
    public void Analyze_with_choice_is_normalized()
    {
        Assert.Equal(new DashboardCommand(DashboardCommandKind.ScanAndAnalyze, "opus", "max"),
            DashboardCommandParser.Parse("scanAndAnalyze:OPUS:Max"));
        Assert.Equal(new DashboardCommand(DashboardCommandKind.ScanAndAnalyze, "sonnet", "high"),
            DashboardCommandParser.Parse("scanAndAnalyze:gpt"));
        Assert.Null(DashboardCommandParser.Parse("scanAndAnalyze").Model);
    }

    [Fact]
    public void Ip_commands_keep_ipv6_colons()
    {
        Assert.Equal(new DashboardCommand(DashboardCommandKind.BlockIp, Ip: "2001:db8::1"), DashboardCommandParser.Parse("blockIp: 2001:db8::1 "));
        Assert.Equal(new DashboardCommand(DashboardCommandKind.UnblockIp, Ip: "8.8.8.8"), DashboardCommandParser.Parse("unblockIp:8.8.8.8"));
    }
}

public sealed class TriggerRequesterTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Writes_trigger_and_debounces_per_name()
    {
        var clock = T.Clock();
        var r = new TriggerRequester(_dir.Paths, clock);

        Assert.Equal(TriggerRequestStatus.Ok, r.Request(TriggerNames.ScanOnly).Status);
        var path = Path.Combine(_dir.Paths.TriggersDir, TriggerNames.ScanOnly);
        Assert.Equal("2026-03-15T12:00:00.0000000Z", File.ReadAllText(path));

        clock.Advance(TimeSpan.FromSeconds(10));
        var deb = r.Request(TriggerNames.ScanOnly);
        Assert.Equal(TriggerRequestStatus.Debounced, deb.Status);
        Assert.Equal(20, deb.WaitSeconds);
        Assert.Equal("Aguarde 20s entre solicitações.", r.Describe(deb, "ok"));

        // outro nome não é afetado
        Assert.Equal(TriggerRequestStatus.Ok, r.Request(TriggerNames.ScanAndAnalyze, TriggerRequester.AnalyzeContent("opus", "max")).Status);
        Assert.Equal("""{"model":"opus","effort":"max"}""", File.ReadAllText(Path.Combine(_dir.Paths.TriggersDir, TriggerNames.ScanAndAnalyze)));

        clock.Advance(TimeSpan.FromSeconds(21));
        Assert.Equal(TriggerRequestStatus.Ok, r.Request(TriggerNames.ScanOnly).Status);
        Assert.Equal("ok", r.Describe(new(TriggerRequestStatus.Ok), "ok"));
    }

    [Fact]
    public void Failures_are_reported_and_not_debounced()
    {
        Directory.CreateDirectory(Path.Combine(_dir.Paths.TriggersDir, TriggerNames.ScanOnly));   // diretório no lugar do arquivo
        var r = new TriggerRequester(_dir.Paths, T.Clock());

        var res = r.Request(TriggerNames.ScanOnly);
        Assert.NotEqual(TriggerRequestStatus.Ok, res.Status);
        Assert.NotEqual(TriggerRequestStatus.Debounced, r.Request(TriggerNames.ScanOnly).Status);

        Assert.Contains("Falha ao solicitar", r.Describe(new(TriggerRequestStatus.Failed, Error: "x"), "ok"));
        var denied = r.Describe(new(TriggerRequestStatus.Denied), "ok");
        Assert.Contains("serviço SecAgent", denied);
        Assert.DoesNotContain("deploy.ps1", denied);   // T7
    }
}

public class TrayStatePresenterTests
{
    private static readonly DateTime Now = T.T0.UtcDateTime;

    [Theory]
    [InlineData("red", TrayIconKind.Error)]
    [InlineData("YELLOW", TrayIconKind.Warning)]
    [InlineData("green", TrayIconKind.Shield)]
    [InlineData(null, TrayIconKind.Shield)]
    public void SeverityIcon(string? sev, TrayIconKind kind)
        => Assert.Equal(kind, TrayStatePresenter.SeverityIcon(new AgentStatus(Now, sev!, null, null)));

    [Fact]
    public void No_status_is_busy_icon_with_placeholder_tooltip()
    {
        Assert.Equal(TrayIconKind.Busy, TrayStatePresenter.SeverityIcon(null));
        Assert.Equal("SecAgent (sem status ainda)", TrayStatePresenter.StatusTooltip(null));
    }

    [Fact]
    public void Status_tooltip_lists_scan_and_incident_and_is_capped()
    {
        var s = new AgentStatus(Now, "red", new ScanSnippet(Now, "high", 3, "r.md"), new IncidentSnippet(Now, "critical", "t", 2, "i.md"));
        Assert.Equal("SecAgent\nScan: high (3 findings, 12:00)\nIncidente: critical (12:00)",
            TrayStatePresenter.StatusTooltip(s, d => d));

        var huge = s with { LastScan = s.LastScan! with { RiskLevel = new string('x', 300) } };
        Assert.Equal(127, TrayStatePresenter.StatusTooltip(huge).Length);
        Assert.Equal("SecAgent", TrayStatePresenter.StatusTooltip(new AgentStatus(Now, "green", null, null)));
    }

    [Fact]
    public void Progress_tooltip_and_bug_stale_progress_detection()
    {
        var p = new AnalysisProgress(AnalysisProgress.Analyzing, Now, "Claude analisando", "tray", "s.json");
        Assert.Equal("SecAgent — Claude analisando... 42s", TrayStatePresenter.ProgressTooltip(p, Now.AddSeconds(42)));
        Assert.Equal("SecAgent — Claude analisando... 0s", TrayStatePresenter.ProgressTooltip(p, Now.AddSeconds(-5)));

        // T3: Service caiu no meio do scan → progress.json órfão não prende o ícone
        Assert.False(TrayStatePresenter.IsStale(p, Now.AddMinutes(10)));
        Assert.True(TrayStatePresenter.IsStale(p, Now.AddMinutes(16)));
    }

    [Fact]
    public void Transition_toast_only_from_scanning_to_analyzing()
    {
        var analyzing = new AnalysisProgress(AnalysisProgress.Analyzing, Now, "Claude analisando", "tray", null);
        Assert.Contains("Scan concluído", TrayStatePresenter.TransitionToast(AnalysisProgress.Scanning, analyzing)!.Text);
        Assert.Null(TrayStatePresenter.TransitionToast(null, analyzing));
        Assert.Null(TrayStatePresenter.TransitionToast(AnalysisProgress.Analyzing, analyzing));
    }

    [Fact]
    public void Report_and_scan_toasts()
    {
        var inc = TrayStatePresenter.ReportToast("incident_x.md");
        Assert.True(inc.IsWarning);
        Assert.Contains("incidente", inc.Title);
        Assert.False(TrayStatePresenter.ReportToast(null).IsWarning);

        Assert.NotNull(TrayStatePresenter.ScanToast("scan_x.json", null));
        Assert.NotNull(TrayStatePresenter.ScanToast("scan_x.json", new(AnalysisProgress.Scanning, Now, "s", "t", null)));
        Assert.Null(TrayStatePresenter.ScanToast("scan_x.json", new(AnalysisProgress.Analyzing, Now, "s", "t", null)));
    }

    [Fact]
    public void Alert_toast_with_and_without_country()
    {
        var alert = new NetworkAlert(Now, "critical", "8.8.8.8", 1, 3389, "svchost", true, "RDP", "Acesso externo!", "8.8.8.8 → RDP");
        var t = TrayStatePresenter.AlertToast(alert, "Brasil", "br");
        Assert.True(t.IsError);
        Assert.Equal("SecAgent: Acesso externo!", t.Title);
        Assert.Equal("🇧🇷 Brasil · 8.8.8.8 → RDP", t.Text);

        var m = TrayStatePresenter.AlertToast(alert with { Severity = "medium" }, null, null);
        Assert.True(m.IsWarning);
        Assert.Equal("8.8.8.8 → RDP", m.Text);
    }

    [Theory]
    [InlineData("us", "🇺🇸")]
    [InlineData("BR", "🇧🇷")]
    [InlineData("", "🌐")]
    [InlineData(null, "🌐")]
    [InlineData("USA", "🌐")]
    [InlineData("1x", "🌐")]
    public void Flag(string? cc, string expected) => Assert.Equal(expected, TrayStatePresenter.Flag(cc));
}

[Collection("JsonFileReader")]
public sealed class JsonFileReaderTests : IDisposable
{
    private readonly TempDir _dir = new();
    public JsonFileReaderTests() => JsonFileReader.RetryDelay = TimeSpan.FromMilliseconds(5);
    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task Reads_valid_json_and_converts_to_camel_case()
    {
        var path = _dir.File("status.json");
        File.WriteAllText(path, """{"LastUpdatedUtc":"2026-03-15T12:00:00Z","OverallSeverity":"red","LastScan":null,"LastIncident":null}""");

        Assert.Equal("red", (await JsonFileReader.ReadAsync<AgentStatus>(path))!.OverallSeverity);
        var camel = await JsonFileReader.ReadAsCamelAsync<AgentStatus>(path);
        Assert.Contains("\"overallSeverity\":\"red\"", camel);
        Assert.DoesNotContain("lastScan", camel);   // nulls omitidos
    }

    [Fact]
    public async Task Missing_empty_partial_or_mistyped_return_null()
    {
        Assert.Null(await JsonFileReader.ReadRawAsync(_dir.File("nope.json")));
        Assert.Null(await JsonFileReader.ReadRawAsync(Path.Combine(_dir.Path, "no-dir", "x.json")));

        var empty = _dir.File("empty.json");
        File.WriteAllText(empty, "  ");
        Assert.Null(await JsonFileReader.ReadRawAsync(empty));

        var partial = _dir.File("partial.json");
        File.WriteAllText(partial, "{\"State\":\"scan");
        Assert.Null(await JsonFileReader.ReadAsync<AnalysisProgress>(partial));

        var wrong = _dir.File("wrong.json");
        File.WriteAllText(wrong, "[1,2]");
        Assert.Null(await JsonFileReader.ReadAsync<AgentStatus>(wrong));
        Assert.Null(await JsonFileReader.ReadAsCamelAsync<AgentStatus>(_dir.File("nope.json")));
    }

    [Fact]
    public async Task Bug_retry_is_async_and_recovers_after_writer_finishes()
    {
        var path = _dir.File("progress.json");
        File.WriteAllText(path, "{\"State\":\"scan");   // escrita em andamento
        JsonFileReader.RetryDelay = TimeSpan.FromMilliseconds(100);
        var read = JsonFileReader.ReadAsync<AnalysisProgress>(path);
        Assert.False(read.IsCompleted);                    // não bloqueou a thread chamadora (T4)
        File.WriteAllText(path, """{"State":"scanning","StartedAtUtc":"2026-03-15T12:00:00Z","Step":"s","Trigger":"tray"}""");
        Assert.Equal("scanning", (await read)!.State);
    }

    [Fact]
    public async Task Cancellation_propagates()
    {
        var path = _dir.File("bad.json");
        File.WriteAllText(path, "{");
        JsonFileReader.RetryDelay = TimeSpan.FromSeconds(10);
        using var cts = new CancellationTokenSource(50);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => JsonFileReader.ReadRawAsync(path, cts.Token));
    }
}

public sealed class EventsTailTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _clock = T.Clock();
    public void Dispose() => _dir.Dispose();

    private string Today => _dir.Paths.EventsFileFor(_clock.GetUtcNow().UtcDateTime);

    private void Append(string text)
    {
        Directory.CreateDirectory(_dir.Paths.EventsDir);
        File.AppendAllText(Today, text, new UTF8Encoding(false));
    }

    [Fact]
    public void Bug_preload_does_not_consume_partial_last_line()
    {
        Append("a\nb\nc\npart");
        var tail = new EventsTail(_dir.Paths, _clock);

        Assert.Equal(new[] { "b", "c" }, tail.Preload(2));
        Append("ial\n");
        Assert.Equal(new[] { "partial" }, tail.ReadNew());   // antes: perdida
        Assert.Empty(tail.ReadNew());
    }

    [Fact]
    public void Bug_offset_tracks_bytes_exactly_with_multibyte_and_invalid_utf8()
    {
        var tail = new EventsTail(_dir.Paths, _clock);
        tail.Preload(10);
        Directory.CreateDirectory(_dir.Paths.EventsDir);
        // linha com byte inválido (0xFF) + acentos: GetByteCount(GetString(...)) ≠ bytes lidos
        File.WriteAllBytes(Today, Encoding.UTF8.GetBytes("ação ").Concat(new byte[] { 0xFF }).Concat(Encoding.UTF8.GetBytes("\nnext\n")).ToArray());

        var first = tail.ReadNew();
        Assert.Equal(2, first.Count);
        Assert.Equal(new FileInfo(Today).Length, tail.Offset);

        Append("third\n");
        Assert.Equal(new[] { "third" }, tail.ReadNew());
    }

    [Fact]
    public void Handles_missing_file_truncation_and_day_rollover()
    {
        var tail = new EventsTail(_dir.Paths, _clock);
        Assert.Empty(tail.Preload(5));
        Assert.Empty(tail.ReadNew());

        Append("one\ntwo\n");
        Assert.Equal(new[] { "one", "two" }, tail.ReadNew());

        File.WriteAllText(Today, "x\n");   // truncado
        Assert.Equal(new[] { "x" }, tail.ReadNew());

        _clock.Advance(TimeSpan.FromDays(1));   // novo dia UTC
        Append("tomorrow\n");
        Assert.Equal(new[] { "tomorrow" }, tail.ReadNew());

        Append("no newline yet");
        Assert.Empty(tail.ReadNew());
    }
}

public class DashboardAssetsTests
{
    [Fact]
    public void Inlines_css_and_js_and_marks_missing()
    {
        var assets = new Dictionary<string, string>
        {
            ["dashboard.html"] = """<html><link rel="stylesheet" href="dashboard.css"><script src="js/core.js"></script><script src="js/gone.js"></script></html>""",
            ["dashboard.css"] = "body{}",
            ["js/core.js"] = "const price = '$1';",
        };
        var html = DashboardAssets.LoadHtml(r => assets.TryGetValue(r, out var v) ? v : null);

        Assert.Contains("<style>\nbody{}\n</style>", html);
        Assert.Contains("const price = '$1';", html);
        Assert.Contains("/* js/gone.js não encontrado */", html);
        Assert.DoesNotContain("src=", html);
        Assert.Equal(DashboardAssets.MissingHtml, DashboardAssets.LoadHtml(_ => null));
    }

    [Fact]
    public void Bug_resource_match_requires_dot_before_file_name()
    {
        var names = new[] { "SecAgent.Tray.Assets.js.xcore.js", "SecAgent.Tray.Assets.js.core.js" };
        Assert.Equal("SecAgent.Tray.Assets.js.core.js", DashboardAssets.FindResourceName(names, "js/core.js"));
        Assert.Null(DashboardAssets.FindResourceName(new[] { "SecAgent.Tray.Assets.js.xcore.js" }, "core.js"));
        Assert.Null(DashboardAssets.FindResourceName(names, "js/"));
    }

    [Fact]
    public void Real_embedded_dashboard_resolves_every_reference()
    {
        var html = DashboardAssets.LoadHtml();
        Assert.DoesNotContain("não encontrado", html);
        Assert.Contains("class MessageRouter", html);
        Assert.Contains("<style>", html);
        Assert.Null(DashboardAssets.ReadEmbedded(typeof(DashboardAssets).Assembly, "nope.js"));
    }
}

public class WebMessageTests
{
    [Fact]
    public void Envelope_escapes_type_and_defaults_payload()
    {
        Assert.Equal("""{"type":"status","payload":{"a":1}}""", WebMessage.Envelope("status", """{"a":1}"""));
        Assert.EndsWith(""","payload":null}""", WebMessage.Envelope("x", ""));
        using var doc = JsonDocument.Parse(WebMessage.Envelope("a\"b", "null"));
        Assert.Equal("a\"b", doc.RootElement.GetProperty("type").GetString());
    }

    [Theory]
    [InlineData("""{"cmd":"scanOnly"}""", "scanOnly")]
    [InlineData("""{"cmd":5}""", null)]
    [InlineData("""{"other":1}""", null)]
    [InlineData("""["cmd"]""", null)]
    [InlineData("{bad", null)]
    [InlineData("", null)]
    public void TryGetCommand(string json, string? expected) => Assert.Equal(expected, WebMessage.TryGetCommand(json));

    [Fact]
    public void Bug_queue_resends_messages_that_failed_to_post_in_order()
    {
        var q = new WebMessageQueue();
        var sent = new List<string>();

        q.Post("a", ready: false, m => { sent.Add(m); return true; });
        Assert.Empty(sent);
        Assert.Equal(1, q.PendingCount);

        q.Post("b", ready: true, _ => throw new InvalidOperationException("webview ocupado"));
        Assert.Equal(2, q.PendingCount);

        q.Post("c", ready: true, m => { sent.Add(m); return true; });
        Assert.Equal(new[] { "a", "b", "c" }, sent);
        Assert.Equal(0, q.PendingCount);

        q.Post("d", ready: true, _ => false);
        q.Flush(m => { sent.Add(m); return true; });
        Assert.Equal("d", sent.Last());
    }
}

public class TokenCommandsTests
{
    [Fact]
    public void Bug_script_never_writes_a_null_token()
    {
        var script = TokenSaveScriptBuilder.Build(@"C:\Temp\it's.tmp", "CLAUDE_CODE_OAUTH_TOKEN");

        Assert.StartsWith("$ErrorActionPreference = 'Stop'", script);
        Assert.Contains(@"$f = 'C:\Temp\it''s.tmp'", script);
        var guard = script.IndexOf("IsNullOrWhiteSpace($t)", StringComparison.Ordinal);
        var write = script.IndexOf("SetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', $t, 'Machine')", StringComparison.Ordinal);
        Assert.True(guard > 0 && write > guard, "validação precisa vir antes de gravar");
        Assert.Contains("if ($null -eq $t) { exit 2 }", script);
        Assert.Contains("catch { exit 1 }", script);
        Assert.Contains("Restart-Service SecAgent", script);
    }

    [Fact]
    public void PowerShell_arguments_use_encoded_command()
    {
        var args = TokenSaveScriptBuilder.PowerShellArguments("Write-Output \"oi\"");
        var b64 = args.Split(' ').Last();
        Assert.Contains("-EncodedCommand", args);
        Assert.Equal("Write-Output \"oi\"", Encoding.Unicode.GetString(Convert.FromBase64String(b64)));
    }

    [Fact]
    public void Claude_setup_command_quotes_path()
        => Assert.Equal("/k \"\"C:\\Program Files\\claude.exe\" setup-token\"",
            ClaudeSetupCommand.CmdArguments(" \"C:\\Program Files\\claude.exe\" "));
}

public class TokenSetupTests
{
    [Theory]
    [InlineData("sk-ant-oat01-x", null, true)]
    [InlineData(null, "sk-ant-oat01-user", true)]
    [InlineData("  ", "sk-ant-oat01-user", true)]
    [InlineData("sk-ant-api03-x", null, false)]
    [InlineData(null, null, false)]
    public void IsConfigured_prefers_machine_then_user(string? machine, string? user, bool expected)
    {
        TokenSetup.EnvironmentReader env = (name, target) =>
        {
            Assert.Equal(TokenSetup.TokenVar, name);
            return target == EnvironmentVariableTarget.Machine ? machine : user;
        };
        Assert.Equal(expected, TokenSetup.IsConfigured(env));
    }

    [Fact]
    public void DetectClaudeExe_checks_profile_then_path()
    {
        var env = new Dictionary<string, string?>
        {
            ["USERPROFILE"] = @"C:\Users\bob",
            ["PATH"] = @"C:\bad|path;""C:\tools"";C:\other".Replace(';', Path.PathSeparator),
        };
        var exists = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"C:\tools\claude.exe" };

        Assert.Equal(@"C:\tools\claude.exe", TokenSetup.DetectClaudeExe(k => env.GetValueOrDefault(k), exists.Contains));

        exists.Add(@"C:\Users\bob\.local\bin\claude.exe");
        Assert.Equal(@"C:\Users\bob\.local\bin\claude.exe", TokenSetup.DetectClaudeExe(k => env.GetValueOrDefault(k), exists.Contains));

        Assert.Null(TokenSetup.DetectClaudeExe(_ => null, _ => true));
    }

    [Fact]
    public void Real_environment_overloads_do_not_throw()
    {
        _ = TokenSetup.IsConfigured();
        _ = TokenSetup.DetectClaudeExe();
    }
}

public sealed class AiPrefsStoreTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Roundtrip_normalizes_and_defaults()
    {
        var store = new AiPrefsStore(Path.Combine(_dir.Path, "sub", "ai-prefs.json"));
        Assert.Equal(("sonnet", "high"), store.Load());

        store.Save("OPUS", "bogus");
        Assert.Equal(("opus", "high"), store.Load());
        Assert.Equal("""{"model":"opus","effort":"high"}""", store.ToMessageJson());
    }

    [Fact]
    public void Corrupt_or_unwritable_file_is_tolerated()
    {
        var path = _dir.File("ai-prefs.json");
        File.WriteAllText(path, "{oops");
        var store = new AiPrefsStore(path);
        Assert.Equal(("sonnet", "high"), store.Load());

        Directory.CreateDirectory(_dir.File("dir.json"));
        new AiPrefsStore(_dir.File("dir.json")).Save("opus", "low");

        File.WriteAllText(path, """{"Model":"haiku","Effort":"LOW"}""");
        Assert.Equal(("haiku", "low"), store.Load());
        Assert.NotNull(AiPrefsStore.Default);
    }
}
