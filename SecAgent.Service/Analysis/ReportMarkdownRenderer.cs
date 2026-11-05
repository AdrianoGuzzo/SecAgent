using System.Text;

namespace SecAgent.Service.Analysis;

/// <summary>Versões Markdown dos relatórios (abertas pelo menu do Tray / fallback sem WebView2).</summary>
internal static class ReportMarkdownRenderer
{
    public static string RenderScan(AnalysisResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Security Analysis — {r.TimestampUtc:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine();
        sb.AppendLine($"- **Risk level:** {r.RiskLevel}");
        sb.AppendLine($"- **Scan source:** `{r.ScanFile}`");
        sb.AppendLine(MetaLine(r.Meta));
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine(r.Summary);
        sb.AppendLine();
        sb.AppendLine($"## Findings ({r.Findings.Count})");
        if (r.Findings.Count == 0) sb.AppendLine("_No findings._");
        foreach (var f in r.Findings.OrderByDescending(f => SeverityLevels.Rank(f.Severity)))
        {
            sb.AppendLine();
            sb.AppendLine($"### [{f.Severity.ToUpperInvariant()}] {f.Title}");
            sb.AppendLine($"*Category: {f.Category}*");
            sb.AppendLine();
            sb.AppendLine(f.Description);
            sb.AppendLine();
            sb.AppendLine($"**Recommendation:** {f.Recommendation}");
            if (!string.IsNullOrWhiteSpace(f.Evidence))
                sb.AppendLine($"*Evidence:* `{f.Evidence}`");
        }
        return sb.ToString();
    }

    public static string RenderIncident(IncidentReport r, IReadOnlyList<SecurityEvent> events)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Security Incident — {r.TimestampUtc:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine();
        sb.AppendLine($"- **Severity:** {r.Severity}");
        sb.AppendLine($"- **Title:** {r.Title}");
        sb.AppendLine($"- **Window:** {r.WindowStartUtc:HH:mm:ss} → {r.WindowEndUtc:HH:mm:ss} UTC ({(r.WindowEndUtc - r.WindowStartUtc).TotalMinutes:F0} min)");
        sb.AppendLine($"- **Events:** {r.EventCount}");
        sb.AppendLine(MetaLine(r.Meta));
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine(r.Summary);
        sb.AppendLine();
        sb.AppendLine("## Recommended actions");
        if (r.RecommendedActions.Count == 0) sb.AppendLine("_None._");
        foreach (var a in r.RecommendedActions) sb.AppendLine($"- {a}");
        sb.AppendLine();
        sb.AppendLine($"## Events that triggered this incident ({events.Count})");
        foreach (var e in events.OrderBy(x => x.TimestampUtc))
        {
            sb.AppendLine();
            sb.AppendLine($"### [{e.Severity.ToUpperInvariant()}] {e.Title} _({e.Source}, {e.TimestampUtc:HH:mm:ss})_");
            sb.AppendLine(e.Description);
            if (e.Details is { Count: > 0 })
            {
                sb.AppendLine();
                sb.AppendLine("```");
                foreach (var kv in e.Details.Take(8))
                    sb.AppendLine($"{kv.Key}: {kv.Value}");
                sb.AppendLine("```");
            }
        }
        return sb.ToString();
    }

    private static string MetaLine(AnalysisMeta m)
        => $"- **Model:** {m.Model}{(m.Effort is null ? "" : $" (effort: {m.Effort})")}  |  elapsed: {m.ElapsedMs}ms  |  " +
           $"tokens (in/cc/cr/out): {m.InputTokens}/{m.CacheCreationTokens}/{m.CacheReadTokens}/{m.OutputTokens}  |  cost: ${m.TotalCostUsd}";
}
