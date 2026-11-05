using System.Text.Json;
using SecAgent.Service.Analysis;
using SecAgent.Service.Models;
using SecAgent.Service.Platform;
using SecAgent.Service.Tests.Helpers;

namespace SecAgent.Service.Tests.Analysis;

internal static class Scans
{
    public static ScanResult Sample(
        List<OpenPort>? ports = null,
        List<FirewallRule>? rules = null,
        List<SoftwareEntry>? software = null,
        List<FolderAcl>? folders = null) => new(
        Test.T0.UtcDateTime, "PC", "Win11",
        ports ?? new(), software ?? new(), folders ?? new(),
        null, null, rules ?? new(), new(), new(), new(), new());
}

public class PromptBuilderTests
{
    [Fact]
    public void Bug_ipv6_loopback_is_not_collapsed_into_other()
    {
        var list = PromptBuilder.CompactAddresses(new[] { "::1", "127.0.0.1" });
        Assert.Equal(new[] { "::1", "127.0.0.1" }, list);
    }

    [Fact]
    public void CompactAddresses_keeps_any_and_collapses_other_v6()
    {
        var list = PromptBuilder.CompactAddresses(new[] { "::", "fe80::1", "2001:db8::5", "0.0.0.0", "0.0.0.0" });
        Assert.Equal(new[] { "::", "[IPv6:other]", "0.0.0.0" }.OrderBy(x => x), list);
    }

    [Theory]
    [InlineData(80, "80", true)]
    [InlineData(80, "443, 80", true)]
    [InlineData(3005, "3000-3010", true)]
    [InlineData(3011, "3000-3010", false)]
    [InlineData(80, "abc,,x-y", false)]
    [InlineData(80, "", false)]
    public void PortInRange(int port, string spec, bool expected) => Assert.Equal(expected, PromptBuilder.PortInRange(port, spec));

    [Fact]
    public void Summarize_groups_tcp_drops_udp_and_matches_only_block_rules()
    {
        var scan = Scans.Sample(
            ports: new()
            {
                new("TCP", "0.0.0.0", 445, null, null),
                new("TCP", "::", 445, null, null),
                new("TCP", "127.0.0.1", 80, null, null),
                new("UDP", "0.0.0.0", 5353, null, null),
                new("UDP", "0.0.0.0", 5355, null, null),
            },
            rules: new()
            {
                new("allow-all", "Allow", "TCP", "*", "*", new() { "All" }, true),
                new("block-smb", "Block", "TCP", "445", new string('x', 200), new() { "Public" }, true),
                new("block-any", "Block", "Any", "Any", "*", new() { "All" }, true),
                new("block-udp", "Block", "UDP", "445", "*", new() { "All" }, true),
                new("block-other", "Block", "TCP", "9999", "*", new() { "All" }, true),
            });

        var s = PromptBuilder.Summarize(scan);

        Assert.Equal(2, s.UdpListenerCount);
        Assert.Equal(new[] { 80, 445 }, s.ListeningPortsTcp.Select(p => p.Port));
        var smb = s.ListeningPortsTcp[1];
        Assert.Equal(new[] { "::", "0.0.0.0" }.OrderBy(x => x), smb.Addresses);
        Assert.Equal(new[] { "block-smb", "block-any" }, smb.InboundRules!.Select(r => r.Name));
        Assert.Equal(123, smb.InboundRules![0].RemoteAddresses.Length);  // 120 + "..."
    }

    [Fact]
    public void Summarize_caps_matched_rules_and_handles_no_rules()
    {
        var rules = Enumerable.Range(0, 8)
            .Select(i => new FirewallRule($"b{i}", "Block", "TCP", "*", "*", new() { "All" }, true)).ToList();
        var capped = PromptBuilder.Summarize(Scans.Sample(ports: new() { new("TCP", "0.0.0.0", 1, null, null) }, rules: rules));
        Assert.Equal(5, capped.ListeningPortsTcp[0].InboundRules!.Count);

        var none = PromptBuilder.Summarize(Scans.Sample(ports: new() { new("TCP", "0.0.0.0", 1, null, null) }));
        Assert.Null(none.ListeningPortsTcp[0].InboundRules);

        var onlyAllow = PromptBuilder.Summarize(Scans.Sample(
            ports: new() { new("TCP", "0.0.0.0", 1, null, null) },
            rules: new() { new("a", "Allow", "TCP", "1", "*", new(), true) }));
        Assert.Null(onlyAllow.ListeningPortsTcp[0].InboundRules);
    }

    [Fact]
    public void Summarize_splits_system_software_and_hides_healthy_aces()
    {
        var scan = Scans.Sample(
            software: new()
            {
                new("Zoom", "5", "Zoom Inc", null, "HKLM64"),
                new("Driver", "1", "NVIDIA Corporation", null, "HKLM64"),
                new("Edge", "1", "microsoft corporation", null, "HKLM64"),
                new("Tool", null, null, null, "HKCU"),
            },
            folders: new()
            {
                new("C:\\ok", true, new() { new("SYSTEM", "FullControl", "Allow") }, new()),
                new("C:\\bad", true, new() { new("Everyone", "Modify", "Allow") }, new() { "Everyone has Modify" }),
            });

        var s = PromptBuilder.Summarize(scan);

        Assert.Equal(2, s.SystemSoftwareCount);
        Assert.Equal(new[] { "Tool", "Zoom" }, s.NotableSoftware.Select(n => n.Name));
        Assert.Null(s.FolderPermissions[0].AcesIfConcerned);
        Assert.Equal(1, s.FolderPermissions[0].AceCount);
        Assert.Single(s.FolderPermissions[1].AcesIfConcerned!);
    }

    [Fact]
    public void Build_embeds_compact_json_of_summary()
    {
        var prompt = PromptBuilder.Build(Scans.Sample(ports: new() { new("TCP", "0.0.0.0", 3389, null, null) }));
        Assert.DoesNotContain("{SCAN_JSON}", prompt);
        Assert.Contains("\"Port\":3389", prompt);
        Assert.Contains("\"MachineName\":\"PC\"", prompt);
    }

    [Fact]
    public void BuildIncident_lists_events_and_window()
    {
        var start = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = new List<SecurityEvent> { Test.Event(start, "high", "Failed logon"), Test.Event(start.AddMinutes(5)) };

        var prompt = PromptBuilder.BuildIncident(events, start, start.AddMinutes(12));

        Assert.Contains("2 evento(s)", prompt);
        Assert.Contains("2026-01-01 10:00:00 UTC -> 2026-01-01 10:12:00 UTC", prompt);
        Assert.Contains("(12 min)", prompt);
        Assert.Contains("\"title\":\"Failed logon\"", prompt);
        Assert.Contains("recommended_actions", prompt);
    }
}

public class ClaudeArgsBuilderTests
{
    [Fact]
    public void Never_uses_bare_and_passes_prompt_via_stdin_format()
    {
        var args = ClaudeArgsBuilder.Build("sonnet", "high");
        Assert.DoesNotContain("--bare", args);
        Assert.Equal("-p", args[0]);
        Assert.Contains("--input-format", args);
        Assert.Equal("sonnet", args[args.ToList().IndexOf("--model") + 1]);
        Assert.Equal("*", args[args.ToList().IndexOf("--disallowedTools") + 1]);
        Assert.Equal(new[] { "--effort", "high" }, args.TakeLast(2));
    }

    [Fact]
    public void Effort_omitted_for_haiku_or_blank()
    {
        Assert.DoesNotContain("--effort", ClaudeArgsBuilder.Build("haiku", "high"));
        Assert.DoesNotContain("--effort", ClaudeArgsBuilder.Build("opus", " "));
        Assert.Null(ClaudeArgsBuilder.AppliedEffort("haiku", "high"));
        Assert.Equal("max", ClaudeArgsBuilder.AppliedEffort("opus", "max"));
    }
}

public class ClaudeResponseParserTests
{
    private static ClaudeCliResult Run(string stdout, int? exit = 0, string stderr = "", string? error = null)
        => new(stdout, stderr, exit, 100, error);

    [Fact]
    public void Run_error_is_propagated()
        => Assert.Equal("timeout", ClaudeResponseParser.ParseEnvelope(Run("", error: "timeout")).Error);

    [Fact]
    public void Bug_empty_stdout_reports_exit_code_and_stderr()
    {
        var o = ClaudeResponseParser.ParseEnvelope(Run("  ", exit: 1, stderr: "Not logged in"));
        Assert.Null(o.Envelope);
        Assert.Equal("Claude returned empty stdout (exit code 1): Not logged in", o.Error);
        Assert.Equal("Claude returned empty stdout", ClaudeResponseParser.ParseEnvelope(Run("")).Error);
    }

    [Fact]
    public void Bug_null_envelope_is_a_failure_not_a_crash()
    {
        var o = ClaudeResponseParser.ParseEnvelope(Run("null"));
        Assert.Null(o.Envelope);
        Assert.Equal("Envelope was null", o.Error);
    }

    [Fact]
    public void Invalid_json_reports_parse_error_with_exit_code()
    {
        var o = ClaudeResponseParser.ParseEnvelope(Run("{oops", exit: 2));
        Assert.StartsWith("Envelope parse error (exit code 2):", o.Error);
    }

    [Fact]
    public void Valid_envelope_maps_to_meta()
    {
        const string json = """
            {"type":"result","is_error":false,"result":"{}","session_id":"s1","total_cost_usd":0.12,
             "usage":{"input_tokens":1,"output_tokens":2,"cache_creation_input_tokens":3,"cache_read_input_tokens":4}}
            """;
        var env = ClaudeResponseParser.ParseEnvelope(Run(json)).Envelope!;
        var meta = ClaudeResponseParser.ToMeta(env, 500, "opus", "max");

        Assert.Equal(new AnalysisMeta("opus", 500, 1, 2, 3, 4, 0.12m, "s1", false, "max"), meta);
        Assert.Equal(new AnalysisMeta("haiku", 7, null, null, null, null, null, null, true, null),
            ClaudeResponseParser.EmptyMeta("haiku", "high", 7));
    }

    [Theory]
    [InlineData("```json\n{\"a\":1}\n```", "{\"a\":1}")]
    [InlineData("```\n{}```", "{}")]
    [InlineData("{\"a\":1}", "{\"a\":1}")]
    [InlineData("```", "")]
    public void StripCodeFence(string input, string expected) => Assert.Equal(expected, ClaudeResponseParser.StripCodeFence(input));

    [Fact]
    public void Findings_get_defaults_for_missing_fields()
    {
        var payload = ClaudeResponseParser.ParseScanPayload("""
            {"risk_level":"high","summary":"s","findings":[{"severity":"critical","title":"RDP"},{}]}
            """);
        var findings = ClaudeResponseParser.ToFindings(payload);

        Assert.Equal("high", payload!.RiskLevel);
        Assert.Equal(new Finding("critical", "outro", "RDP", "", "", null), findings[0]);
        Assert.Equal(new Finding("info", "outro", "(no title)", "", "", null), findings[1]);
        Assert.Empty(ClaudeResponseParser.ToFindings(null));
    }

    [Fact]
    public void Incident_payload_parses()
    {
        var p = ClaudeResponseParser.ParseIncidentPayload("""{"severity":"low","title":"t","summary":"s","recommended_actions":["a"]}""");
        Assert.Equal("low", p!.Severity);
        Assert.Equal(new[] { "a" }, p.RecommendedActions);
        Assert.Throws<JsonException>(() => ClaudeResponseParser.ParseIncidentPayload("nope"));
    }
}

public class ReportMarkdownRendererTests
{
    [Fact]
    public void Scan_report_orders_findings_by_severity()
    {
        var r = new AnalysisResult(Test.T0.UtcDateTime, "scan.json", "high", "Resumo",
            new List<Finding>
            {
                new("low", "cfg", "Low one", "d", "r", null),
                new("critical", "net", "Crit one", "d", "fix it", "port 3389"),
            }, Test.Meta());

        var md = ReportMarkdownRenderer.RenderScan(r);

        Assert.Contains("# Security Analysis — 2026-03-15 12:30 UTC", md);
        Assert.Contains("(effort: high)", md);
        Assert.True(md.IndexOf("Crit one", StringComparison.Ordinal) < md.IndexOf("Low one", StringComparison.Ordinal));
        Assert.Contains("*Evidence:* `port 3389`", md);
        Assert.Contains("## Findings (2)", md);
    }

    [Fact]
    public void Scan_report_without_findings_and_without_effort()
    {
        var r = new AnalysisResult(Test.T0.UtcDateTime, "scan.json", "low", "ok", new(), Test.Meta("haiku", null));
        var md = ReportMarkdownRenderer.RenderScan(r);
        Assert.Contains("_No findings._", md);
        Assert.DoesNotContain("effort", md);
    }

    [Fact]
    public void Incident_report_includes_events_and_actions()
    {
        var start = Test.T0.UtcDateTime;
        var report = new IncidentReport(start, 2, start, start.AddMinutes(30), "high", "Brute force", "sum",
            new List<string> { "Block IP" }, Test.Meta());
        var events = new List<SecurityEvent> { Test.Event(start.AddMinutes(1), "high", "Second"), Test.Event(start, "low", "First") };

        var md = ReportMarkdownRenderer.RenderIncident(report, events);

        Assert.Contains("(30 min)", md);
        Assert.Contains("- Block IP", md);
        Assert.Contains("k: v", md);
        Assert.True(md.IndexOf("First", StringComparison.Ordinal) < md.IndexOf("Second", StringComparison.Ordinal));

        var empty = ReportMarkdownRenderer.RenderIncident(report with { RecommendedActions = new() },
            new List<SecurityEvent> { new(start, "x", "low", "t", "d", new()) });
        Assert.Contains("_None._", empty);
        Assert.DoesNotContain("```", empty);
    }
}
