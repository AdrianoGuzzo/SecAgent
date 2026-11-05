using SecAgent.Service.Analysis;
using SecAgent.Service.Diagnostics;
using SecAgent.Service.Platform;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests.Analysis;

public sealed class ClaudeAnalyzerTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly IClaudeCli _cli = Substitute.For<IClaudeCli>();
    private readonly IStatusFileService _status = Substitute.For<IStatusFileService>();
    private readonly ISystemEnvironment _env = Substitute.For<ISystemEnvironment>();
    private readonly ITraceLog _trace = Substitute.For<ITraceLog>();
    private readonly ClaudeOptions _opts;

    public ClaudeAnalyzerTests()
    {
        _opts = new ClaudeOptions
        {
            ExePath = @"C:\claude.exe",
            ReportsDirectory = Path.Combine(_dir.Path, "reports"),
            Model = "haiku",
            Effort = "medium",
            TimeoutSeconds = 30
        };
        _env.FileExists(_opts.ExePath).Returns(true);
        _env.GetEnvironmentVariable(_opts.TokenEnvVarName).Returns("sk-ant-oat01-xyz");
    }

    public void Dispose() => _dir.Dispose();

    private ClaudeAnalyzer Create() => new(Test.Log<ClaudeAnalyzer>(), Test.Opts(_opts), _status, _cli, _env, _trace, Test.Clock());

    private void CliReturns(string result, bool isError = false, int exit = 0)
    {
        var escaped = System.Text.Json.JsonSerializer.Serialize(result);
        var flag = isError ? "true" : "false";
        var stdout = "{\"type\":\"result\",\"is_error\":" + flag + ",\"result\":" + escaped +
                     ",\"session_id\":\"s\",\"total_cost_usd\":0.1,\"usage\":{\"input_tokens\":5,\"output_tokens\":6}}";
        _cli.RunAsync(Arg.Any<ClaudeCliRequest>(), Arg.Any<CancellationToken>())
            .Returns(new ClaudeCliResult(stdout, "", exit, 1000, null));
    }

    private string[] Reports() => Directory.GetFiles(_opts.ReportsDirectory).Select(Path.GetFileName).ToArray()!;

    [Fact]
    public async Task Scan_success_persists_json_and_md_and_updates_status()
    {
        CliReturns("```json\n{\"risk_level\":\"high\",\"summary\":\"S\",\"findings\":[{\"severity\":\"high\",\"title\":\"RDP\"}]}\n```");

        var r = await Create().AnalyzeAsync(Scans.Sample(), @"C:\data\scans\scan_x.json", CancellationToken.None, "opus", "max");

        Assert.Equal("high", r.RiskLevel);
        Assert.Equal("scan_x.json", r.ScanFile);
        Assert.Equal("opus", r.Meta.Model);
        Assert.Equal("max", r.Meta.Effort);
        Assert.Equal(5, r.Meta.InputTokens);
        Assert.Single(r.Findings);
        Assert.Equal(new[] { "report_2026-03-15_123045.json", "report_2026-03-15_123045.md" }, Reports().OrderBy(x => x));
        _status.Received(1).UpdateAfterScan(r);

        await _cli.Received(1).RunAsync(Arg.Is<ClaudeCliRequest>(q =>
            q.ExePath == _opts.ExePath &&
            q.Arguments.Contains("opus") && q.Arguments.Contains("max") && !q.Arguments.Contains("--bare") &&
            q.Stdin.Contains("\"MachineName\":\"PC\"") &&
            q.Environment["CLAUDE_CODE_OAUTH_TOKEN"] == "sk-ant-oat01-xyz" &&
            q.Timeout == TimeSpan.FromSeconds(30)), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Invalid_model_from_trigger_falls_back_to_config()
    {
        CliReturns("{\"risk_level\":\"low\"}");
        var r = await Create().AnalyzeAsync(Scans.Sample(), "scan.json", CancellationToken.None, "gpt-9", "ultra");
        Assert.Equal("haiku", r.Meta.Model);
        Assert.Null(r.Meta.Effort);   // haiku não suporta effort
        Assert.Equal("", r.Summary);
    }

    [Fact]
    public async Task Bug_failure_scan_file_is_name_only()
    {
        _env.FileExists(_opts.ExePath).Returns(false);

        var r = await Create().AnalyzeAsync(Scans.Sample(), @"C:\data\scans\scan_x.json", CancellationToken.None);

        Assert.Equal("scan_x.json", r.ScanFile);
        Assert.Equal("unknown", r.RiskLevel);
        Assert.Contains("claude.exe not found", r.Summary);
        Assert.True(r.Meta.IsError);
        await _cli.DidNotReceiveWithAnyArgs().RunAsync(default!, default);
        _status.DidNotReceiveWithAnyArgs().UpdateAfterScan(default!);
    }

    [Fact]
    public async Task Missing_token_fails_without_invoking_cli()
    {
        _env.GetEnvironmentVariable(_opts.TokenEnvVarName).Returns((string?)null);
        var r = await Create().AnalyzeAsync(Scans.Sample(), "scan.json", CancellationToken.None);
        Assert.Contains("is empty", r.Summary);
        await _cli.DidNotReceiveWithAnyArgs().RunAsync(default!, default);
    }

    [Fact]
    public async Task Cli_error_flag_is_a_failure()
    {
        CliReturns("Not logged in", isError: true);
        var r = await Create().AnalyzeAsync(Scans.Sample(), "scan.json", CancellationToken.None);
        Assert.Equal("Claude reported error: Not logged in", r.Summary);
        Assert.False(Directory.Exists(_opts.ReportsDirectory) && Reports().Any(f => f.StartsWith("report_")));
    }

    [Fact]
    public async Task Bug_empty_stdout_with_exit_code_is_reported()
    {
        _cli.RunAsync(Arg.Any<ClaudeCliRequest>(), Arg.Any<CancellationToken>())
            .Returns(new ClaudeCliResult("", "boom", 3, 10, null));
        var r = await Create().AnalyzeAsync(Scans.Sample(), "scan.json", CancellationToken.None);
        Assert.Contains("exit code 3", r.Summary);
    }

    [Fact]
    public async Task Unparseable_payload_saves_raw_failure()
    {
        CliReturns("this is not json");
        var r = await Create().AnalyzeAsync(Scans.Sample(), "scan.json", CancellationToken.None);
        Assert.StartsWith("Payload parse error", r.Summary);
        var raw = Reports().Single();
        Assert.StartsWith("scan_FAILED_", raw);
        Assert.Contains("this is not json", File.ReadAllText(Path.Combine(_opts.ReportsDirectory, raw)));
    }

    [Fact]
    public async Task Incident_success_persists_three_files()
    {
        CliReturns("{\"severity\":\"critical\",\"title\":\"Brute force\",\"summary\":\"S\",\"recommended_actions\":[\"block\"]}");
        var start = Test.T0.UtcDateTime.AddMinutes(-10);
        var events = new List<SecurityEvent> { Test.Event(start), Test.Event(start.AddMinutes(1)) };

        var rep = await Create().AnalyzeIncidentAsync(events, start, Test.T0.UtcDateTime, CancellationToken.None);

        Assert.Equal("critical", rep.Severity);
        Assert.Equal(2, rep.EventCount);
        Assert.Equal(new[] { "block" }, rep.RecommendedActions);
        Assert.Equal(3, Reports().Length);
        Assert.Contains("incident_2026-03-15_123045.events.json", Reports());
        _status.Received(1).UpdateAfterIncident(rep);
        await _cli.Received(1).RunAsync(Arg.Is<ClaudeCliRequest>(q => q.Stdin.Contains("2 evento(s)")), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Incident_failures_are_reported_not_thrown()
    {
        var events = new List<SecurityEvent> { Test.Event(Test.T0.UtcDateTime) };
        var a = Create();

        _cli.RunAsync(Arg.Any<ClaudeCliRequest>(), Arg.Any<CancellationToken>())
            .Returns(new ClaudeCliResult("", "", null, 10, "timed out"));
        var r1 = await a.AnalyzeIncidentAsync(events, Test.T0.UtcDateTime, Test.T0.UtcDateTime, CancellationToken.None);
        Assert.Equal("Analysis failure", r1.Title);
        Assert.Equal("timed out", r1.Summary);

        CliReturns("", isError: true);
        var r2 = await a.AnalyzeIncidentAsync(events, Test.T0.UtcDateTime, Test.T0.UtcDateTime, CancellationToken.None);
        Assert.Equal("Claude error: ", r2.Summary);

        CliReturns("garbage");
        var r3 = await a.AnalyzeIncidentAsync(events, Test.T0.UtcDateTime, Test.T0.UtcDateTime, CancellationToken.None);
        Assert.StartsWith("Payload parse error", r3.Summary);
        Assert.Contains(Reports(), f => f.StartsWith("incident_FAILED_"));

        CliReturns("{}");
        var r4 = await a.AnalyzeIncidentAsync(events, Test.T0.UtcDateTime, Test.T0.UtcDateTime, CancellationToken.None);
        Assert.Equal("unknown", r4.Severity);
        Assert.Equal("(no title)", r4.Title);
    }
}
