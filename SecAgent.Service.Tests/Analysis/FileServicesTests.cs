using System.Text.Json;
using SecAgent.Service.Analysis;
using SecAgent.Service.Diagnostics;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests.Analysis;

public class StatusFileServiceTests
{
    private static AgentStatus ReadStatus(TempDir dir)
        => JsonSerializer.Deserialize<AgentStatus>(File.ReadAllText(dir.Paths.StatusFile), JsonDefaults.Read)!;

    [Fact]
    public void Scan_then_incident_keeps_both_and_computes_worst()
    {
        using var dir = new TempDir();
        var clock = Test.Clock();
        var svc = new StatusFileService(Test.Log<StatusFileService>(), dir.Paths, clock);

        svc.UpdateAfterScan(new AnalysisResult(Test.T0.UtcDateTime, "scan.json", "low", "", new() { new("low", "c", "t", "d", "r", null) }, Test.Meta()));
        Assert.Equal("green", ReadStatus(dir).OverallSeverity);

        clock.Advance(TimeSpan.FromMinutes(1));
        svc.UpdateAfterIncident(new IncidentReport(Test.T0.UtcDateTime, 3, Test.T0.UtcDateTime, Test.T0.UtcDateTime, "critical", "x", "", new(), Test.Meta()));

        var s = ReadStatus(dir);
        Assert.Equal("red", s.OverallSeverity);
        Assert.Equal(1, s.LastScan!.FindingsCount);
        Assert.Equal("report_2026-03-15_123045.md", s.LastScan.ReportFile);
        Assert.Equal("incident_2026-03-15_123045.md", s.LastIncident!.ReportFile);
        Assert.Equal(Test.T0.UtcDateTime.AddMinutes(1), s.LastUpdatedUtc);
    }

    [Fact]
    public void Corrupt_status_file_is_recreated()
    {
        using var dir = new TempDir();
        File.WriteAllText(dir.Paths.StatusFile, "{not json");
        var svc = new StatusFileService(Test.Log<StatusFileService>(), dir.Paths, Test.Clock());

        svc.UpdateAfterScan(new AnalysisResult(Test.T0.UtcDateTime, "s", "medium", "", new(), Test.Meta()));

        Assert.Equal("yellow", ReadStatus(dir).OverallSeverity);
    }

    [Fact]
    public void Write_failure_is_swallowed()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(dir.Paths.StatusFile);   // status.json é um diretório → escrita falha
        var svc = new StatusFileService(Test.Log<StatusFileService>(), dir.Paths, Test.Clock());
        svc.UpdateAfterScan(new AnalysisResult(Test.T0.UtcDateTime, "s", "high", "", new(), Test.Meta()));
    }

    [Fact]
    public void ComputeOverall_without_snippets_is_green()
        => Assert.Equal("green", StatusFileService.ComputeOverall(new AgentStatus(DateTime.MinValue, "x", null, null)));
}

public class ProgressTrackerTests
{
    private static AnalysisProgress Read(TempDir dir)
        => JsonSerializer.Deserialize<AnalysisProgress>(File.ReadAllText(dir.Paths.ProgressFile), JsonDefaults.Read)!;

    [Fact]
    public void Stale_file_is_deleted_on_startup()
    {
        using var dir = new TempDir();
        File.WriteAllText(dir.Paths.ProgressFile, "{}");
        _ = new ProgressTracker(Test.Log<ProgressTracker>(), dir.Paths, Test.Clock());
        Assert.False(File.Exists(dir.Paths.ProgressFile));
    }

    [Fact]
    public void Scan_then_analysis_keeps_start_time_then_clear_deletes()
    {
        using var dir = new TempDir();
        var clock = Test.Clock();
        var t = new ProgressTracker(Test.Log<ProgressTracker>(), dir.Paths, clock);

        t.BeginScan("tray");
        var p1 = Read(dir);
        Assert.Equal(AnalysisProgress.Scanning, p1.State);
        Assert.Null(p1.ScanFile);

        clock.Advance(TimeSpan.FromSeconds(5));
        t.EndScanBeginAnalysis("scan.json", "opus", "tray");
        var p2 = Read(dir);
        Assert.Equal(AnalysisProgress.Analyzing, p2.State);
        Assert.Equal(p1.StartedAtUtc, p2.StartedAtUtc);
        Assert.Equal("scan.json", p2.ScanFile);
        Assert.Contains("opus", p2.Step);

        t.Clear();
        Assert.False(File.Exists(dir.Paths.ProgressFile));
    }

    [Fact]
    public void Write_and_delete_failures_are_swallowed()
    {
        using var dir = new TempDir();
        var t = new ProgressTracker(Test.Log<ProgressTracker>(), dir.Paths, Test.Clock());
        File.WriteAllText(dir.Paths.ProgressFile, "{}");
        using (new FileStream(dir.Paths.ProgressFile, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            t.BeginScan("x");
            t.Clear();
        }
    }
}

public class FileTraceLogTests
{
    [Fact]
    public void Appends_formatted_lines_and_never_throws()
    {
        using var dir = new TempDir();
        var paths = new AgentPaths(Path.Combine(dir.Path, "nested"));
        var log = new FileTraceLog(paths, Test.Clock());

        log.Write("cat", "hello");
        log.Write("cat", "world");

        var lines = File.ReadAllLines(paths.TraceFile);
        Assert.Equal(2, lines.Length);
        Assert.Matches(@"^\[\d\d:\d\d:\d\d\.\d{3}\] \[cat\] hello$", lines[0]);

        Directory.CreateDirectory(Path.Combine(dir.Path, "dirAsFile", "trace.log"));
        new FileTraceLog(new AgentPaths(Path.Combine(dir.Path, "dirAsFile")), Test.Clock()).Write("c", "m");
    }
}
