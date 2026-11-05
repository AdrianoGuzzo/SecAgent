using System.Text.Json;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests.Contracts;

public class AgentPathsTests
{
    [Fact]
    public void Derives_all_paths_from_data_root()
    {
        var p = new AgentPaths(@"D:\data");
        Assert.Equal(@"D:\data", p.DataRoot);
        Assert.Equal(@"D:\data\status.json", p.StatusFile);
        Assert.Equal(@"D:\data\progress.json", p.ProgressFile);
        Assert.Equal(@"D:\data\network.json", p.NetworkFile);
        Assert.Equal(@"D:\data\blocked.json", p.BlockedFile);
        Assert.Equal(@"D:\data\trace.log", p.TraceFile);
        Assert.Equal(@"D:\data\reports", p.ReportsDir);
        Assert.Equal(@"D:\data\scans", p.ScansDir);
        Assert.Equal(@"D:\data\events", p.EventsDir);
        Assert.Equal(@"D:\data\alerts", p.AlertsDir);
        Assert.Equal(@"D:\data\triggers", p.TriggersDir);
        Assert.Equal(@"D:\data\events\events_2026-03-15.jsonl", p.EventsFileFor(new DateTime(2026, 3, 15)));
    }

    [Fact]
    public void Default_points_to_ProgramData()
        => Assert.Equal(@"C:\ProgramData\SecAgent", AgentPaths.Default.DataRoot);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Rejects_empty_root(string root)
        => Assert.Throws<ArgumentException>(() => new AgentPaths(root));
}

public class AiModelsTests
{
    [Theory]
    [InlineData("opus", true)]
    [InlineData(" SONNET ", true)]
    [InlineData("haiku", true)]
    [InlineData("gpt", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsKnownModel(string? model, bool expected) => Assert.Equal(expected, AiModels.IsKnownModel(model));

    [Theory]
    [InlineData("low", true)]
    [InlineData("XHIGH", true)]
    [InlineData("max", true)]
    [InlineData("ultra", false)]
    [InlineData(null, false)]
    public void IsKnownEffort(string? effort, bool expected) => Assert.Equal(expected, AiModels.IsKnownEffort(effort));

    [Fact]
    public void Normalize_lowercases_known_and_falls_back_on_unknown()
    {
        Assert.Equal("opus", AiModels.NormalizeModel(" Opus "));
        Assert.Equal(AiModels.DefaultModel, AiModels.NormalizeModel("bogus"));
        Assert.Equal("haiku", AiModels.NormalizeModel(null, "haiku"));
        Assert.Equal("max", AiModels.NormalizeEffort("MAX"));
        Assert.Equal(AiModels.DefaultEffort, AiModels.NormalizeEffort("bogus"));
        Assert.Equal("low", AiModels.NormalizeEffort("", "low"));
    }

    [Theory]
    [InlineData("opus", true)]
    [InlineData("sonnet", true)]
    [InlineData("haiku", false)]
    [InlineData("HAIKU", false)]
    [InlineData("unknown", false)]
    [InlineData(null, false)]
    public void EffortSupported(string? model, bool expected) => Assert.Equal(expected, AiModels.EffortSupported(model));

    [Fact]
    public void Lists_are_exposed()
    {
        Assert.Equal(new[] { "opus", "sonnet", "haiku" }, AiModels.Models);
        Assert.Contains("xhigh", AiModels.Efforts);
    }
}

public class SeverityLevelsTests
{
    [Theory]
    [InlineData("critical", 4)]
    [InlineData("HIGH", 3)]
    [InlineData(" medium ", 2)]
    [InlineData("low", 1)]
    [InlineData("info", 0)]
    [InlineData(null, 0)]
    public void Rank(string? sev, int expected) => Assert.Equal(expected, SeverityLevels.Rank(sev));

    [Theory]
    [InlineData("critical", "red")]
    [InlineData("high", "red")]
    [InlineData("medium", "yellow")]
    [InlineData("unknown", "yellow")]
    [InlineData("low", "green")]
    [InlineData("info", "green")]
    [InlineData(null, "green")]
    public void ToTrafficLight(string? sev, string expected) => Assert.Equal(expected, SeverityLevels.ToTrafficLight(sev));

    [Fact]
    public void Worst_picks_the_most_severe_light()
    {
        Assert.Equal("red", SeverityLevels.Worst(new[] { "green", "RED", "yellow" }));
        Assert.Equal("yellow", SeverityLevels.Worst(new[] { "green", "yellow" }));
        Assert.Equal("green", SeverityLevels.Worst(new string?[] { null, "green" }));
        Assert.Equal("green", SeverityLevels.Worst(Array.Empty<string>()));
    }
}

public class ReportNamesTests
{
    private static readonly DateTime T = new(2026, 1, 2, 3, 4, 5, 678, DateTimeKind.Utc);

    [Fact]
    public void Builds_names_with_invariant_stamp()
    {
        Assert.Equal("2026-01-02_030405", ReportNames.Stamp(T));
        Assert.Equal("scan_2026-01-02_030405.json", ReportNames.ScanFile(T));
        Assert.Equal("report_2026-01-02_030405.json", ReportNames.ScanReportJson(T));
        Assert.Equal("report_2026-01-02_030405.md", ReportNames.ScanReportMarkdown(T));
        Assert.Equal("incident_2026-01-02_030405.json", ReportNames.IncidentJson(T));
        Assert.Equal("incident_2026-01-02_030405.md", ReportNames.IncidentMarkdown(T));
        Assert.Equal("incident_2026-01-02_030405.events.json", ReportNames.IncidentEvents(T));
        Assert.Equal("scan_FAILED_2026-01-02_030405.raw.txt", ReportNames.FailedRaw("scan", T));
        Assert.Equal("events_2026-01-02.jsonl", ReportNames.EventsJsonl(T));
        Assert.Equal("alert_2026-01-02_030405678_7.json", ReportNames.Alert(T, 7));
    }
}

public class TriggerNamesTests
{
    [Fact]
    public void Block_and_unblock_names_sanitize_ipv6()
    {
        Assert.Equal("block-ip-1.2.3.4.trigger", TriggerNames.BlockIp("1.2.3.4"));
        Assert.Equal("unblock-ip-fe80--1-12.trigger", TriggerNames.UnblockIp("fe80::1%12"));
        Assert.Equal("a-b-c", TriggerNames.SanitizeForFileName(@"a/b\c"));
        Assert.Equal("", TriggerNames.SanitizeForFileName(null));
    }

    [Theory]
    [InlineData("scan-only.trigger", true)]
    [InlineData("SCAN-AND-ANALYZE.TRIGGER", true)]
    [InlineData("block-ip-1.2.3.4.trigger", true)]
    [InlineData("unblock-ip-x.trigger", true)]
    [InlineData("block-ip-1.2.3.4.txt", false)]
    [InlineData("other.trigger", false)]
    public void IsKnown(string name, bool expected) => Assert.Equal(expected, TriggerNames.IsKnown(name));

    [Fact]
    public void Block_vs_unblock_are_distinguished()
    {
        Assert.True(TriggerNames.IsBlockIp("block-ip-1.trigger"));
        Assert.False(TriggerNames.IsBlockIp("unblock-ip-1.trigger"));
        Assert.True(TriggerNames.IsUnblockIp("unblock-ip-1.trigger"));
        Assert.False(TriggerNames.IsUnblockIp("block-ip-1.trigger"));
    }
}

public class AtomicFileTests
{
    [Fact]
    public void Writes_creating_directory_and_overwrites_without_leaving_tmp()
    {
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "sub", "x.json");

        AtomicFile.WriteAllText(path, "one");
        AtomicFile.WriteAllText(path, "two ç");

        Assert.Equal("two ç", File.ReadAllText(path));
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
        // UTF-8 sem BOM (o Tray/JS não espera BOM)
        Assert.NotEqual(0xEF, File.ReadAllBytes(path)[0]);
    }

    [Fact]
    public void Failure_cleans_tmp_and_throws()
    {
        using var dir = new TempDir();
        var target = Path.Combine(dir.Path, "locked.json");
        File.WriteAllText(target, "x");
        using (new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.ThrowsAny<Exception>(() => AtomicFile.WriteAllText(target, "y"));
        }
        Assert.Single(Directory.GetFiles(dir.Path));
    }
}

public class ModelJsonTests
{
    [Fact]
    public void AnalysisResult_roundtrips_including_effort()
    {
        var r = new AnalysisResult(Test.T0.UtcDateTime, "scan.json", "high", "s",
            new List<Finding> { new("high", "net", "t", "d", "r", null) }, Test.Meta());
        var json = JsonSerializer.Serialize(r, JsonDefaults.Indented);
        var back = JsonSerializer.Deserialize<AnalysisResult>(json, JsonDefaults.Read)!;
        Assert.Equal("high", back.Meta.Effort);
        Assert.Equal(r.Findings[0], back.Findings[0]);
        Assert.Equal(r.TimestampUtc, back.TimestampUtc);
    }

    [Fact]
    public void Camel_case_json_is_read_case_insensitively()
    {
        var status = new AgentStatus(Test.T0.UtcDateTime, "red",
            new ScanSnippet(Test.T0.UtcDateTime, "high", 2, "report.md"),
            new IncidentSnippet(Test.T0.UtcDateTime, "critical", "t", 3, "incident.md"));
        var camel = JsonSerializer.Serialize(status, JsonDefaults.CamelCase);
        Assert.Contains("\"overallSeverity\"", camel);
        Assert.Equal(status, JsonSerializer.Deserialize<AgentStatus>(camel, JsonDefaults.Read));
    }

    [Fact]
    public void Network_models_roundtrip_and_omit_nulls()
    {
        var snap = new NetworkSnapshot(Test.T0.UtcDateTime,
            new List<NetworkConnection> { new("inbound", "10.0.0.1", 3389, "8.8.8.8", 5000, "svchost", 4, true, 99) });
        var json = JsonSerializer.Serialize(snap, JsonDefaults.Compact);
        Assert.DoesNotContain("Interfaces", json);
        var back = JsonSerializer.Deserialize<NetworkSnapshot>(json, JsonDefaults.Read)!;
        Assert.Equal(snap.Connections[0], back.Connections[0]);

        var alert = new NetworkAlert(Test.T0.UtcDateTime, "critical", "8.8.8.8", 1, 3389, "p", true, "RDP", "t", "m");
        Assert.Equal(alert, JsonSerializer.Deserialize<NetworkAlert>(JsonSerializer.Serialize(alert), JsonDefaults.Read));

        var blocked = new BlockedList(Test.T0.UtcDateTime, new List<BlockedIp> { new("1.2.3.4") });
        var bBack = JsonSerializer.Deserialize<BlockedList>(JsonSerializer.Serialize(blocked), JsonDefaults.Read)!;
        Assert.Equal("1.2.3.4", bBack.Blocked.Single().Ip);

        var progress = new AnalysisProgress(AnalysisProgress.Analyzing, Test.T0.UtcDateTime, "s", "tray", "scan.json");
        Assert.Equal(progress, JsonSerializer.Deserialize<AnalysisProgress>(JsonSerializer.Serialize(progress), JsonDefaults.Read));
    }
}
