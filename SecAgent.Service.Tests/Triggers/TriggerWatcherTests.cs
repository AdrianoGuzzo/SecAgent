using SecAgent.Service.Platform;
using SecAgent.Service.Remediation;
using SecAgent.Service.Tests.Helpers;
using SecAgent.Service.Triggers;

namespace SecAgent.Service.Tests.Triggers;

public sealed class TriggerWatcherTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly IScanRunner _runner = Substitute.For<IScanRunner>();
    private readonly IIpBlocker _blocker = Substitute.For<IIpBlocker>();
    private readonly ITriggerDirectorySetup _setup = Substitute.For<ITriggerDirectorySetup>();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = Test.Clock();
    private readonly TriggerOptions _opts;

    public TriggerWatcherTests()
    {
        _opts = new TriggerOptions { TriggersDirectory = _dir.Path, DebounceSeconds = 30, SettleMilliseconds = 0 };
        _setup.When(s => s.EnsureDirectory(Arg.Any<string>())).Do(c => Directory.CreateDirectory(c.Arg<string>()));
    }

    public void Dispose() => _dir.Dispose();

    private TriggerWatcher Create() => new(Test.Log<TriggerWatcher>(), _runner, _blocker, Test.Opts(_opts), _setup, _clock);

    private string Drop(string name, string content = "")
    {
        var path = _dir.File(name);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public async Task Scan_only_runs_and_deletes_file()
    {
        var path = Drop(TriggerNames.ScanOnly, "2026-01-01T00:00:00Z");
        Assert.Equal(TriggerOutcome.Processed, await Create().ProcessTriggerAsync(path, CancellationToken.None));
        await _runner.Received(1).RunScanOnlyAsync("tray", Arg.Any<CancellationToken>());
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Scan_and_analyze_passes_model_and_effort_from_content()
    {
        var path = Drop(TriggerNames.ScanAndAnalyze, """{"model":"opus","effort":"max"}""");
        await Create().ProcessTriggerAsync(path, CancellationToken.None);
        await _runner.Received(1).RunScanAndAnalyzeAsync("tray", Arg.Any<CancellationToken>(), "opus", "max");
    }

    [Fact]
    public async Task Debounce_within_window_then_accepts_after()
    {
        var w = Create();
        await w.ProcessTriggerAsync(Drop(TriggerNames.ScanOnly), CancellationToken.None);

        var second = Drop(TriggerNames.ScanOnly);
        Assert.Equal(TriggerOutcome.Debounced, await w.ProcessTriggerAsync(second, CancellationToken.None));
        Assert.False(File.Exists(second));

        _clock.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(TriggerOutcome.Processed, await w.ProcessTriggerAsync(Drop(TriggerNames.ScanOnly), CancellationToken.None));
        await _runner.Received(2).RunScanOnlyAsync("tray", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Unknown_trigger_is_deleted_and_not_dispatched()
    {
        var path = Drop("evil.trigger");
        Assert.Equal(TriggerOutcome.Unknown, await Create().ProcessTriggerAsync(path, CancellationToken.None));
        Assert.False(File.Exists(path));
        Assert.Empty(_runner.ReceivedCalls());
    }

    [Fact]
    public async Task Block_and_unblock_use_ip_from_content()
    {
        var w = Create();
        await w.ProcessTriggerAsync(Drop(TriggerNames.BlockIp("2001:db8::1"), " 2001:DB8::1\r\n"), CancellationToken.None);
        await w.ProcessTriggerAsync(Drop(TriggerNames.UnblockIp("8.8.8.8"), "8.8.8.8"), CancellationToken.None);

        _blocker.Received(1).Block("2001:db8::1");
        _blocker.Received(1).Unblock("8.8.8.8");
    }

    [Fact]
    public async Task Block_with_invalid_payload_is_rejected()
    {
        var path = Drop(TriggerNames.BlockIp("x"), "1");
        Assert.Equal(TriggerOutcome.InvalidPayload, await Create().ProcessTriggerAsync(path, CancellationToken.None));
        _blocker.DidNotReceiveWithAnyArgs().Block(default!);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Bug_second_event_for_same_file_does_not_process_or_delete_it_while_in_flight()
    {
        var gate = new TaskCompletionSource();
        _runner.RunScanOnlyAsync(default!, default).ReturnsForAnyArgs(async _ => { await gate.Task; return ((Models.ScanResult, string)?)null; });
        var w = Create();
        var path = Drop(TriggerNames.ScanOnly);

        var first = w.ProcessTriggerAsync(path, CancellationToken.None);
        await Test.Eventually(() => _runner.ReceivedCalls().Any());

        // Changed chega enquanto o primeiro handler ainda processa
        Assert.Equal(TriggerOutcome.AlreadyInFlight, await w.ProcessTriggerAsync(path, CancellationToken.None));
        Assert.True(File.Exists(path));

        gate.SetResult();
        Assert.Equal(TriggerOutcome.Processed, await first);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Bug_unknown_names_do_not_grow_debounce_table_and_old_entries_are_pruned()
    {
        // Indiretamente: um block-ip antigo não impede o mesmo IP depois da janela.
        var w = Create();
        await w.ProcessTriggerAsync(Drop(TriggerNames.BlockIp("8.8.8.8"), "8.8.8.8"), CancellationToken.None);
        _clock.Advance(TimeSpan.FromMinutes(5));
        await w.ProcessTriggerAsync(Drop(TriggerNames.BlockIp("8.8.8.8"), "8.8.8.8"), CancellationToken.None);
        _blocker.Received(2).Block("8.8.8.8");
    }

    [Fact]
    public async Task Runner_exception_is_logged_and_file_deleted()
    {
        _runner.RunScanOnlyAsync(default!, default).ReturnsForAnyArgs<Task<(Models.ScanResult, string)?>>(_ => throw new Exception("x"));
        var path = Drop(TriggerNames.ScanOnly);
        Assert.Equal(TriggerOutcome.Processed, await Create().ProcessTriggerAsync(path, CancellationToken.None));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Settle_delay_honours_cancellation()
    {
        _opts.SettleMilliseconds = 10_000;
        using var cts = new CancellationTokenSource(50);
        var path = Drop(TriggerNames.ScanOnly);
        Assert.Equal(TriggerOutcome.Processed, await Create().ProcessTriggerAsync(path, cts.Token));
        Assert.Empty(_runner.ReceivedCalls());
    }

    [Fact]
    public async Task Execute_drains_orphans_and_watches_new_files()
    {
        Drop(TriggerNames.ScanOnly);   // órfão de antes do start
        var w = Create();
        using var cts = new CancellationTokenSource();

        await w.StartAsync(cts.Token);
        await Test.Eventually(() => _runner.ReceivedCalls().Any(c => c.GetMethodInfo().Name == nameof(IScanRunner.RunScanOnlyAsync)));
        _blocker.Received(1).Reconcile();

        Drop(TriggerNames.UnblockIp("1.1.1.1"), "1.1.1.1");
        await Test.Eventually(() => _blocker.ReceivedCalls().Any(c => c.GetMethodInfo().Name == nameof(IIpBlocker.Unblock)));

        await w.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Execute_is_noop_when_disabled_or_setup_fails()
    {
        _opts.Enabled = false;
        var w = Create();
        await w.StartAsync(CancellationToken.None);
        await w.StopAsync(CancellationToken.None);
        _setup.DidNotReceiveWithAnyArgs().EnsureDirectory(default!);

        _opts.Enabled = true;
        _setup.When(s => s.EnsureDirectory(Arg.Any<string>())).Do(_ => throw new UnauthorizedAccessException());
        var w2 = Create();
        await w2.StartAsync(CancellationToken.None);
        await w2.StopAsync(CancellationToken.None);
        _blocker.DidNotReceive().Reconcile();
    }

    [Fact]
    public async Task Execute_survives_reconcile_failure_and_bad_directory()
    {
        _blocker.When(b => b.Reconcile()).Do(_ => throw new Exception("fw"));
        _setup.When(s => s.EnsureDirectory(Arg.Any<string>())).Do(_ => { });   // não cria
        _opts.TriggersDirectory = Path.Combine(_dir.Path, "does-not-exist");
        var w = Create();
        await w.StartAsync(CancellationToken.None);
        await w.StopAsync(CancellationToken.None);
    }
}

public class TriggerPayloadParserTests
{
    [Theory]
    [InlineData("8.8.8.8", "8.8.8.8")]
    [InlineData(" fe80::1 ", "fe80::1")]
    [InlineData("1", null)]
    [InlineData(null, null)]
    public void ParseIp(string? content, string? expected) => Assert.Equal(expected, TriggerPayloadParser.ParseIp(content));

    [Theory]
    [InlineData("""{"model":"opus","effort":"low"}""", "opus", "low")]
    [InlineData("""{"model":5}""", null, null)]
    [InlineData("""{"effort":"max"}""", null, "max")]
    [InlineData("2026-01-01T00:00:00Z", null, null)]   // legado
    [InlineData("{broken", null, null)]
    [InlineData("", null, null)]
    [InlineData(null, null, null)]
    public void ParseAnalyzeOptions(string? content, string? model, string? effort)
        => Assert.Equal((model, effort), TriggerPayloadParser.ParseAnalyzeOptions(content));
}
