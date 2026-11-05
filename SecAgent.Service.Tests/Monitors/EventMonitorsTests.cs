using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Configuration;
using SecAgent.Service.Analysis;
using SecAgent.Service.Monitors;
using SecAgent.Service.Platform;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests.Monitors;

public class MonitorOptionsBindingTests
{
    private static MonitorOptions Bind(Dictionary<string, string?> values)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var o = new MonitorOptions();
        config.GetSection("Monitors").Bind(o);
        return o.ApplyDefaults();
    }

    [Fact]
    public void Bug_configured_list_replaces_defaults_instead_of_appending()
    {
        // Antes: listas inicializadas com defaults + binder ANEXANDO → impossível tirar 443 do whitelist.
        var o = Bind(new() { ["Monitors:NetworkPortWhitelist:0"] = "8080", ["Monitors:SecurityEventIds:0"] = "4625" });
        Assert.Equal(new[] { 8080 }, o.NetworkPortWhitelist);
        Assert.Equal(new[] { 4625 }, o.SecurityEventIds);
    }

    [Fact]
    public void Missing_lists_get_defaults()
    {
        var o = Bind(new());
        Assert.Equal(MonitorOptions.DefaultNetworkPortWhitelist, o.NetworkPortWhitelist);
        Assert.Equal(MonitorOptions.DefaultSensitiveInboundPorts, o.SensitiveInboundPorts);
        Assert.Equal(MonitorOptions.DefaultSystemEventIds, o.SystemEventIds);
        Assert.Equal(new[] { "SecAgent" }, o.SelfReferenceFragments);
        Assert.Equal(new[] { "SecAgent" }, o.SelfServiceNames);
        Assert.Empty(o.ProcessWhitelist!);
        Assert.Empty(o.InboundPortWhitelist!);
        Assert.Empty(o.SelfInstallDirectories!);
        Assert.Equal(MonitorOptions.DefaultSuspiciousPathFragments, o.SuspiciousPathFragments);
    }
}

public class ProcessMonitorTests
{
    private static readonly MonitorOptions Opts = new MonitorOptions { ProcessWhitelist = new() { "trusted.exe" } }.ApplyDefaults();
    private static readonly ProcessStartEvaluator Eval = new(Opts, @"C:\Program Files\SecAgent\Service\");

    private static ProcessStartData P(string name, string? path) => new(name, path, "10", "4", "cmd /c x");

    [Fact]
    public void Suspicious_path_emits_high_event()
    {
        var e = Eval.Evaluate(P("Evil.exe", @"C:\Users\bob\Downloads\evil.exe"), Test.T0.UtcDateTime);
        Assert.NotNull(e);
        Assert.Equal("high", e!.Severity);
        Assert.Equal("evil.exe", e.Details["name"]);
        Assert.Equal(@"\Downloads\", e.Details["fragment"]);
    }

    [Fact]
    public void Benign_cases_are_ignored()
    {
        Assert.Null(Eval.Evaluate(P("notepad.exe", @"C:\Windows\notepad.exe"), Test.T0.UtcDateTime));
        Assert.Null(Eval.Evaluate(P("trusted.exe", @"C:\Users\bob\Downloads\trusted.exe"), Test.T0.UtcDateTime));
        Assert.Null(Eval.Evaluate(P("x.exe", null), Test.T0.UtcDateTime));
        Assert.Null(Eval.Evaluate(P("", @"C:\Temp\x.exe"), Test.T0.UtcDateTime));
        Assert.Null(Eval.Evaluate(P("SecAgent-Setup.exe", @"C:\Users\bob\Downloads\SecAgent-Setup.exe"), Test.T0.UtcDateTime));
        Assert.Null(Eval.Evaluate(P("SecAgent.Tray.exe", @"C:\Program Files\SecAgent\Tray\SecAgent.Tray.exe"), Test.T0.UtcDateTime));
    }

    [Fact]
    public void Bug_folder_named_like_agent_does_not_whitelist_malware()
    {
        // Antes: bastava o CAMINHO conter "SecAgent".
        var e = Eval.Evaluate(P("malware.exe", @"C:\Users\bob\Downloads\SecAgent\malware.exe"), Test.T0.UtcDateTime);
        Assert.NotNull(e);
    }

    [Fact]
    public void Install_root_defaults_and_explicit_dirs()
    {
        Assert.Equal(@"C:\Program Files\SecAgent", ProcessStartEvaluator.DefaultInstallRoot(@"C:\Program Files\SecAgent\Service\"));
        Assert.Null(ProcessStartEvaluator.DefaultInstallRoot(""));
        var custom = new ProcessStartEvaluator(new MonitorOptions { SelfInstallDirectories = new() { @"D:\Tools\Agent" } }.ApplyDefaults(), "");
        Assert.True(custom.IsSelf(@"D:\Tools\Agent\Temp\x.exe"));
        Assert.False(custom.IsSelf(@"D:\Tools\AgentX\x.exe"));
    }

    [Fact]
    public async Task Monitor_wires_source_events_to_channel()
    {
        var source = Substitute.For<IProcessStartSource>();
        var env = Substitute.For<ISystemEnvironment>();
        env.BaseDirectory.Returns(@"C:\Program Files\SecAgent\Service\");
        var channel = Channel.CreateUnbounded<SecurityEvent>();
        var m = new ProcessMonitor(Test.Log<ProcessMonitor>(), channel.Writer, Test.Opts(Opts), source, env, Test.Clock());

        await m.StartAsync(CancellationToken.None);
        source.Received(1).Start();
        source.ProcessStarted += Raise.Event<Action<ProcessStartData>>(P("evil.exe", @"C:\Temp\evil.exe"));
        source.ProcessStarted += Raise.Event<Action<ProcessStartData>>(P("ok.exe", @"C:\Windows\ok.exe"));
        await m.StopAsync(CancellationToken.None);

        Assert.True(channel.Reader.TryRead(out var e));
        Assert.Equal("evil.exe", e!.Details["name"]);
        Assert.False(channel.Reader.TryRead(out _));
        source.Received(1).Dispose();
    }

    [Fact]
    public async Task Monitor_disabled_or_failing_start_is_harmless()
    {
        var source = Substitute.For<IProcessStartSource>();
        var env = Substitute.For<ISystemEnvironment>();
        env.BaseDirectory.Returns("");
        var writer = Channel.CreateUnbounded<SecurityEvent>().Writer;

        var disabled = new ProcessMonitor(Test.Log<ProcessMonitor>(), writer,
            Test.Opts(new MonitorOptions { ProcessMonitorEnabled = false }.ApplyDefaults()), source, env, Test.Clock());
        await disabled.StartAsync(CancellationToken.None);
        source.DidNotReceive().Start();

        source.When(s => s.Start()).Do(_ => throw new System.Management.ManagementException("wmi"));
        var failing = new ProcessMonitor(Test.Log<ProcessMonitor>(), writer, Test.Opts(Opts), source, env, Test.Clock());
        await failing.StartAsync(CancellationToken.None);
        failing.OnProcessStarted(null!);   // handler nunca lança
        await failing.StopAsync(CancellationToken.None);
    }
}

public class EventLogMonitorTests
{
    private static EventLogEntryData Entry(int id, params string?[] props)
        => new(id, "Microsoft-Windows-Security-Auditing", Test.T0.UtcDateTime, 4, "Event description", props);

    [Theory]
    [InlineData("Security", 4625, "medium")]
    [InlineData("Security", 4720, "high")]
    [InlineData("Security", 4732, "high")]
    [InlineData("Security", 4740, "medium")]
    [InlineData("Security", 1102, "critical")]
    [InlineData("System", 7045, "high")]
    [InlineData("System", 1, "low")]
    public void Classify(string channel, int id, string severity) => Assert.Equal(severity, EventLogRules.Classify(channel, id).Severity);

    [Fact]
    public void BuildXPath_joins_ids()
        => Assert.Equal("*[System[(EventID=1 or EventID=2)]]", EventLogRules.BuildXPath(new[] { 1, 2 }));

    [Fact]
    public void Bug_service_named_like_agent_is_still_detected()
    {
        var opts = new MonitorOptions().ApplyDefaults();
        Assert.Null(EventLogRules.CreateEvent("System", Entry(7045, "SecAgent", @"C:\x.exe"), opts, Test.T0.UtcDateTime));
        Assert.NotNull(EventLogRules.CreateEvent("System", Entry(7045, "SecAgentHelper", @"C:\evil.exe"), opts, Test.T0.UtcDateTime));
        // Descrição citando "SecAgent" não suprime mais eventos de outro tipo
        Assert.NotNull(EventLogRules.CreateEvent("Security", Entry(4720, "SecAgent"), opts, Test.T0.UtcDateTime));
        Assert.NotNull(EventLogRules.CreateEvent("System", Entry(7045), opts, Test.T0.UtcDateTime));
    }

    [Fact]
    public void CreateEvent_maps_details_and_truncates()
    {
        var props = Enumerable.Range(0, 25).Select(i => i == 0 ? new string('x', 300) : (string?)$"p{i}").ToArray();
        props[3] = null;
        var e = EventLogRules.CreateEvent("Security", Entry(4625, props), new MonitorOptions(), Test.T0.UtcDateTime)!;

        Assert.Equal("eventlog", e.Source);
        Assert.Equal("4625", e.Details["eventId"]);
        Assert.Equal("4", e.Details["level"]);
        Assert.Equal(203, e.Details["prop0"].Length);
        Assert.Equal("", e.Details["prop3"]);
        Assert.False(e.Details.ContainsKey("prop20"));
    }

    [Fact]
    public async Task Monitor_subscribes_both_channels_and_forwards_events()
    {
        var source = Substitute.For<IEventLogSource>();
        var subs = new Dictionary<string, Action<EventLogEntryData>>();
        var handle = Substitute.For<IDisposable>();
        source.Subscribe(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<Action<EventLogEntryData>>())
            .Returns(c => { subs[c.ArgAt<string>(0)] = c.ArgAt<Action<EventLogEntryData>>(2); return handle; });
        var channel = Channel.CreateUnbounded<SecurityEvent>();
        var m = new EventLogMonitor(Test.Log<EventLogMonitor>(), channel.Writer,
            Test.Opts(new MonitorOptions().ApplyDefaults()), source, Test.Clock());

        await m.StartAsync(CancellationToken.None);
        subs["Security"](Entry(1102));
        subs["System"](Entry(7045, "SecAgent"));
        m.OnEvent("Security", null!);   // handler nunca lança
        await m.StopAsync(CancellationToken.None);

        Assert.True(channel.Reader.TryRead(out var e));
        Assert.Equal("critical", e!.Severity);
        Assert.False(channel.Reader.TryRead(out _));
        handle.Received(2).Dispose();
    }

    [Fact]
    public async Task Monitor_disabled_empty_ids_or_failing_subscribe()
    {
        var source = Substitute.For<IEventLogSource>();
        var writer = Channel.CreateUnbounded<SecurityEvent>().Writer;

        var disabled = new EventLogMonitor(Test.Log<EventLogMonitor>(), writer,
            Test.Opts(new MonitorOptions { EventLogMonitorEnabled = false }), source, Test.Clock());
        await disabled.StartAsync(CancellationToken.None);

        var noIds = new EventLogMonitor(Test.Log<EventLogMonitor>(), writer,
            Test.Opts(new MonitorOptions { SecurityEventIds = new(), SystemEventIds = new() }), source, Test.Clock());
        await noIds.StartAsync(CancellationToken.None);
        await noIds.StopAsync(CancellationToken.None);
        source.DidNotReceiveWithAnyArgs().Subscribe(default!, default!, default!);

        source.Subscribe(default!, default!, default!).ReturnsForAnyArgs(_ => throw new UnauthorizedAccessException());
        var failing = new EventLogMonitor(Test.Log<EventLogMonitor>(), writer,
            Test.Opts(new MonitorOptions().ApplyDefaults()), source, Test.Clock());
        await failing.StartAsync(CancellationToken.None);
        await failing.StopAsync(CancellationToken.None);
    }
}

public class IncidentWindowTests
{
    private static MonitorOptions Opts(bool auto = true) => new()
    {
        IncidentAutoAnalysisEnabled = auto,
        IncidentEventThreshold = 3,
        IncidentWindowMinutes = 10,
        IncidentCooldownMinutes = 60
    };

    [Fact]
    public void Fires_on_threshold_then_respects_cooldown()
    {
        var clock = Test.Clock();
        var w = new IncidentWindow(Opts(), clock);
        var now = Test.T0.UtcDateTime;

        w.Add(Test.Event(now.AddMinutes(-20)));   // fora da janela → podado
        w.Add(Test.Event(now.AddMinutes(-2)));
        w.Add(Test.Event(now.AddMinutes(-1)));
        Assert.Equal(2, w.Count);
        Assert.False(w.TryTrigger(out _, out _, out _));

        w.Add(Test.Event(now));
        Assert.True(w.TryTrigger(out var snap, out var start, out var end));
        Assert.Equal(3, snap.Count);
        Assert.Equal(now.AddMinutes(-2), start);
        Assert.Equal(now, end);

        w.Add(Test.Event(now));
        Assert.False(w.TryTrigger(out _, out _, out _));   // cooldown
        clock.Advance(TimeSpan.FromMinutes(61));
        w.Add(Test.Event(clock.GetUtcNow().UtcDateTime));
        w.Add(Test.Event(clock.GetUtcNow().UtcDateTime));
        w.Add(Test.Event(clock.GetUtcNow().UtcDateTime));
        Assert.True(w.TryTrigger(out _, out _, out _));
    }

    [Fact]
    public void Never_fires_when_auto_analysis_disabled()
    {
        var w = new IncidentWindow(Opts(auto: false), Test.Clock());
        for (int i = 0; i < 10; i++) w.Add(Test.Event(Test.T0.UtcDateTime));
        Assert.False(w.TryTrigger(out _, out _, out _));
    }
}

public sealed class SuspiciousEventProcessorTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private MonitorOptions Opts(bool auto) => new()
    {
        EventsDirectory = Path.Combine(_dir.Path, "events"),
        IncidentAutoAnalysisEnabled = auto,
        IncidentEventThreshold = 2,
        IncidentWindowMinutes = 30,
        IncidentCooldownMinutes = 60
    };

    [Fact]
    public async Task Bug_events_keep_flowing_to_jsonl_while_analysis_runs()
    {
        var gate = new TaskCompletionSource<IncidentReport>();
        var analyzer = Substitute.For<IClaudeAnalyzer>();
        analyzer.AnalyzeIncidentAsync(default!, default, default, default).ReturnsForAnyArgs(gate.Task);
        var channel = Channel.CreateUnbounded<SecurityEvent>();
        var opts = Opts(auto: true);
        var p = new SuspiciousEventProcessor(Test.Log<SuspiciousEventProcessor>(), channel.Reader, analyzer, Test.Opts(opts), Test.Clock());
        var jsonl = Path.Combine(opts.EventsDirectory, "events_2026-03-15.jsonl");

        await p.StartAsync(CancellationToken.None);
        for (int i = 0; i < 2; i++) channel.Writer.TryWrite(Test.Event(Test.T0.UtcDateTime, title: $"e{i}"));
        await Test.Eventually(() => analyzer.ReceivedCalls().Any());

        // análise "travada" no Claude: o journal continua recebendo
        for (int i = 2; i < 6; i++) channel.Writer.TryWrite(Test.Event(Test.T0.UtcDateTime, title: $"e{i}"));
        await Test.Eventually(() => File.Exists(jsonl) && File.ReadAllLines(jsonl).Length == 6);

        gate.SetResult(null!);
        channel.Writer.Complete();
        await p.StopAsync(CancellationToken.None);

        await analyzer.Received(1).AnalyzeIncidentAsync(Arg.Is<IReadOnlyList<SecurityEvent>>(l => l.Count == 2),
            Arg.Any<DateTime>(), Arg.Any<DateTime>(), Arg.Any<CancellationToken>());
        var first = JsonSerializer.Deserialize<SecurityEvent>(File.ReadAllLines(jsonl)[0], JsonDefaults.Read)!;
        Assert.Equal("e0", first.Title);
    }

    [Fact]
    public async Task Manual_mode_only_journals_and_analyzer_errors_are_contained()
    {
        var analyzer = Substitute.For<IClaudeAnalyzer>();
        var channel = Channel.CreateUnbounded<SecurityEvent>();
        var p = new SuspiciousEventProcessor(Test.Log<SuspiciousEventProcessor>(), channel.Reader, analyzer,
            Test.Opts(Opts(auto: false)), Test.Clock());
        await p.StartAsync(CancellationToken.None);
        for (int i = 0; i < 5; i++) channel.Writer.TryWrite(Test.Event(Test.T0.UtcDateTime));
        channel.Writer.Complete();
        await p.StopAsync(CancellationToken.None);
        Assert.Empty(analyzer.ReceivedCalls());

        var failing = Substitute.For<IClaudeAnalyzer>();
        failing.AnalyzeIncidentAsync(default!, default, default, default)
            .ReturnsForAnyArgs<Task<IncidentReport>>(_ => throw new Exception("claude"));
        var ch2 = Channel.CreateUnbounded<SecurityEvent>();
        var p2 = new SuspiciousEventProcessor(Test.Log<SuspiciousEventProcessor>(), ch2.Reader, failing,
            Test.Opts(Opts(auto: true)), Test.Clock());
        await p2.StartAsync(CancellationToken.None);
        ch2.Writer.TryWrite(Test.Event(Test.T0.UtcDateTime));
        ch2.Writer.TryWrite(Test.Event(Test.T0.UtcDateTime));
        await Test.Eventually(() => failing.ReceivedCalls().Any());
        await p2.CurrentAnalysis;
        await p2.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Journal_write_failure_does_not_stop_processing()
    {
        var opts = Opts(auto: false);
        File.WriteAllText(Path.Combine(_dir.Path, "events"), "file in the way");   // diretório não pode ser criado
        var channel = Channel.CreateUnbounded<SecurityEvent>();
        var p = new SuspiciousEventProcessor(Test.Log<SuspiciousEventProcessor>(), channel.Reader,
            Substitute.For<IClaudeAnalyzer>(), Test.Opts(opts), Test.Clock());
        await p.StartAsync(CancellationToken.None);
        channel.Writer.TryWrite(Test.Event(Test.T0.UtcDateTime));
        await Task.Delay(50);
        await p.StopAsync(CancellationToken.None);   // cancela o ReadAllAsync
    }
}
