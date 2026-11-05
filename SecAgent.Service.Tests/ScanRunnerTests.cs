using NSubstitute.Extensions;
using SecAgent.Service.Analysis;
using SecAgent.Service.Models;
using SecAgent.Service.Tests.Analysis;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests;

public sealed class ScanRunnerTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly ISecurityScanner _scanner = Substitute.For<ISecurityScanner>();
    private readonly IClaudeAnalyzer _analyzer = Substitute.For<IClaudeAnalyzer>();
    private readonly IProgressTracker _progress = Substitute.For<IProgressTracker>();

    public void Dispose() => _dir.Dispose();

    private ScanRunner Create() => new(
        Test.Log<ScanRunner>(), _scanner, _analyzer, _progress,
        Test.Opts(new ScannerOptions { OutputDirectory = Path.Combine(_dir.Path, "scans") }),
        Test.Opts(new ClaudeOptions { Model = "haiku", Effort = "low" }));

    [Fact]
    public async Task Scan_only_writes_scan_file_and_clears_progress()
    {
        _scanner.RunFullScan().Returns(Scans.Sample());

        var r = await Create().RunScanOnlyAsync("tray", CancellationToken.None);

        Assert.NotNull(r);
        Assert.EndsWith("scan_2026-03-15_123045.json", r!.Value.ScanPath);
        Assert.True(File.Exists(r.Value.ScanPath));
        Received.InOrder(() => { _progress.BeginScan("tray"); _progress.Clear(); });
        await _analyzer.DidNotReceiveWithAnyArgs().AnalyzeAsync(default!, default!, default);
    }

    [Fact]
    public async Task Scan_failure_returns_null_and_still_clears()
    {
        _scanner.RunFullScan().Returns(_ => throw new InvalidOperationException("x"));
        Assert.Null(await Create().RunScanOnlyAsync("tray", CancellationToken.None));
        _progress.Received(1).Clear();
    }

    [Fact]
    public async Task Bug_cancellation_is_not_a_scan_failure()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Null(await Create().RunScanOnlyAsync("scheduled", cts.Token));
        _scanner.DidNotReceive().RunFullScan();
    }

    [Fact]
    public async Task Scan_and_analyze_normalizes_model_and_reports_analysis_phase()
    {
        _scanner.RunFullScan().Returns(Scans.Sample());

        await Create().RunScanAndAnalyzeAsync("tray", CancellationToken.None, "OPUS", "bogus");

        _progress.Received(1).EndScanBeginAnalysis("scan_2026-03-15_123045.json", "opus", "tray");
        await _analyzer.Received(1).AnalyzeAsync(Arg.Any<ScanResult>(), Arg.Is<string>(p => p.EndsWith(".json")),
            Arg.Any<CancellationToken>(), "opus", "low");
        _progress.Received(1).Clear();
    }

    [Fact]
    public async Task Scan_and_analyze_skips_analysis_when_scan_fails_and_survives_analyzer_errors()
    {
        _scanner.RunFullScan().Returns(_ => throw new Exception("x"));
        var runner = Create();
        await runner.RunScanAndAnalyzeAsync("tray", CancellationToken.None);
        await _analyzer.DidNotReceiveWithAnyArgs().AnalyzeAsync(default!, default!, default);

        _scanner.Configure().RunFullScan().Returns(Scans.Sample());
        _analyzer.AnalyzeAsync(default!, default!, default, default, default)
            .ReturnsForAnyArgs<Task<AnalysisResult>>(_ => throw new Exception("claude down"));
        await runner.RunScanAndAnalyzeAsync("tray", CancellationToken.None);

        using var cts = new CancellationTokenSource();
        _analyzer.Configure().AnalyzeAsync(default!, default!, default, default, default)
            .ReturnsForAnyArgs<Task<AnalysisResult>>(_ => { cts.Cancel(); throw new OperationCanceledException(cts.Token); });
        await runner.RunScanAndAnalyzeAsync("tray", cts.Token);

        _progress.Received(3).Clear();
    }

    [Fact]
    public async Task Bug_concurrent_scans_are_single_flight()
    {
        var release = new ManualResetEventSlim();
        var entered = new ManualResetEventSlim();
        _scanner.RunFullScan().Returns(_ => { entered.Set(); release.Wait(); return Scans.Sample(); });
        var runner = Create();

        var first = runner.RunScanOnlyAsync("scheduled", CancellationToken.None);
        Assert.True(entered.Wait(5000));

        Assert.Null(await runner.RunScanOnlyAsync("tray", CancellationToken.None));
        await runner.RunScanAndAnalyzeAsync("tray", CancellationToken.None);   // também ignorado

        release.Set();
        Assert.NotNull(await first);
        _scanner.Received(1).RunFullScan();
        _progress.Received(1).BeginScan(Arg.Any<string>());

        // após terminar, um novo scan é aceito
        Assert.NotNull(await runner.RunScanOnlyAsync("tray", CancellationToken.None));
    }
}

public class WorkerTests
{
    private static Worker Create(IScanRunner runner, bool runOnStartup, bool analyze, Microsoft.Extensions.Time.Testing.FakeTimeProvider clock)
        => new(Test.Log<Worker>(), runner,
            Test.Opts(new ScannerOptions { RunOnStartup = runOnStartup, ScanIntervalHours = 1 }),
            Test.Opts(new ClaudeOptions { AnalyzeAfterScan = analyze }), clock);

    [Fact]
    public async Task Runs_on_startup_then_every_interval_scan_only_by_default()
    {
        var runner = Substitute.For<IScanRunner>();
        var clock = Test.Clock();
        var worker = Create(runner, runOnStartup: true, analyze: false, clock);

        await worker.StartAsync(CancellationToken.None);
        await Test.Eventually(() => runner.ReceivedCalls().Count() == 1);

        await Test.Eventually(() => { clock.Advance(TimeSpan.FromHours(1)); return runner.ReceivedCalls().Count() >= 2; });
        await worker.StopAsync(CancellationToken.None);

        Assert.All(runner.ReceivedCalls(), c => Assert.Equal(nameof(IScanRunner.RunScanOnlyAsync), c.GetMethodInfo().Name));
        await runner.DidNotReceiveWithAnyArgs().RunScanAndAnalyzeAsync(default!, default);
    }

    [Fact]
    public async Task Auto_analysis_when_enabled_and_errors_do_not_kill_the_loop()
    {
        var runner = Substitute.For<IScanRunner>();
        runner.RunScanAndAnalyzeAsync(default!, default).ReturnsForAnyArgs<Task>(_ => throw new Exception("boom"));
        var clock = Test.Clock();
        var worker = Create(runner, runOnStartup: false, analyze: true, clock);

        await worker.StartAsync(CancellationToken.None);
        await Task.Delay(50);
        Assert.Empty(runner.ReceivedCalls());

        await Test.Eventually(() => { clock.Advance(TimeSpan.FromHours(1)); return runner.ReceivedCalls().Count() >= 2; });
        await worker.StopAsync(CancellationToken.None);
    }
}
