using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using SecAgent.Service.Models;

namespace SecAgent.Service.Analysis;

using SecAgent.Service;

public class ClaudeAnalyzer
{
    private static readonly JsonSerializerOptions WriteOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private static readonly JsonSerializerOptions ReadOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private const string SystemPrompt =
        "Você é um analista de segurança defensiva especializado em sistemas Windows. " +
        "Responda exatamente no formato JSON solicitado, sem markdown, sem texto fora do JSON.";

    private readonly ILogger<ClaudeAnalyzer> _logger;
    private readonly ClaudeOptions _opts;
    private readonly StatusFileService _status;

    public ClaudeAnalyzer(ILogger<ClaudeAnalyzer> logger, IOptions<ClaudeOptions> opts, StatusFileService status)
    {
        _logger = logger;
        _opts = opts.Value;
        _status = status;
    }

    // ============================================================
    // Scan analysis (daily)
    // ============================================================

    public async Task<AnalysisResult> AnalyzeAsync(ScanResult scan, string scanFilePath, CancellationToken ct)
    {
        Directory.CreateDirectory(_opts.ReportsDirectory);

        var (envelope, elapsedMs, error) = await InvokeClaudeAsync(PromptBuilder.Build(scan), ct);
        if (error != null)
            return ScanFailure(scanFilePath, error, elapsedMs);

        var meta = ToMeta(envelope!, elapsedMs);

        if (envelope!.IsError || string.IsNullOrWhiteSpace(envelope.Result))
            return ScanFailure(scanFilePath, $"Claude reported error: {envelope.Result ?? "(empty)"}", elapsedMs, meta);

        var raw = StripCodeFence(envelope.Result.Trim());
        ClaudeAnalysisPayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<ClaudeAnalysisPayload>(raw, ReadOpts);
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Could not parse scan analysis payload");
            SaveRawFailure(raw, "scan", scanFilePath);
            return ScanFailure(scanFilePath, $"Payload parse error: {ex.Message}", elapsedMs, meta);
        }

        var findings = payload?.Findings?.Select(f => new Finding(
            f.Severity ?? "info", f.Category ?? "outro",
            f.Title ?? "(no title)", f.Description ?? "",
            f.Recommendation ?? "", f.Evidence)).ToList() ?? new();

        var result = new AnalysisResult(
            TimestampUtc: DateTime.UtcNow,
            ScanFile: Path.GetFileName(scanFilePath),
            RiskLevel: payload?.RiskLevel ?? "unknown",
            Summary: payload?.Summary ?? "",
            Findings: findings,
            Meta: meta);

        PersistScanReport(result);
        return result;
    }

    private void PersistScanReport(AnalysisResult r)
    {
        var ts = r.TimestampUtc.ToString("yyyy-MM-dd_HHmmss");
        var jsonPath = Path.Combine(_opts.ReportsDirectory, $"report_{ts}.json");
        var mdPath = Path.Combine(_opts.ReportsDirectory, $"report_{ts}.md");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(r, WriteOpts));
        File.WriteAllText(mdPath, RenderScanMarkdown(r));
        _status.UpdateAfterScan(r);
        _logger.LogInformation(
            "Scan report saved. risk={Risk} findings={N} tokens(in/cc/cr/out)={In}/{CC}/{CR}/{Out} cost=${Cost} → {Md}",
            r.RiskLevel, r.Findings.Count,
            r.Meta.InputTokens, r.Meta.CacheCreationTokens, r.Meta.CacheReadTokens,
            r.Meta.OutputTokens, r.Meta.TotalCostUsd, mdPath);
    }

    private static string RenderScanMarkdown(AnalysisResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Security Analysis — {r.TimestampUtc:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine();
        sb.AppendLine($"- **Risk level:** {r.RiskLevel}");
        sb.AppendLine($"- **Scan source:** `{r.ScanFile}`");
        sb.AppendLine($"- **Model:** {r.Meta.Model}  |  elapsed: {r.Meta.ElapsedMs}ms  |  tokens (in/cc/cr/out): {r.Meta.InputTokens}/{r.Meta.CacheCreationTokens}/{r.Meta.CacheReadTokens}/{r.Meta.OutputTokens}  |  cost: ${r.Meta.TotalCostUsd}");
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine(r.Summary);
        sb.AppendLine();
        sb.AppendLine($"## Findings ({r.Findings.Count})");
        if (r.Findings.Count == 0) sb.AppendLine("_No findings._");
        foreach (var f in r.Findings.OrderByDescending(f => SeverityRank(f.Severity)))
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

    // ============================================================
    // Incident analysis (ad-hoc, triggered by SuspiciousEventProcessor)
    // ============================================================

    public async Task<IncidentReport> AnalyzeIncidentAsync(
        List<SecurityEvent> events,
        DateTime windowStartUtc,
        DateTime windowEndUtc,
        CancellationToken ct)
    {
        Directory.CreateDirectory(_opts.ReportsDirectory);

        var prompt = BuildIncidentPrompt(events, windowStartUtc, windowEndUtc);
        var (envelope, elapsedMs, error) = await InvokeClaudeAsync(prompt, ct);

        if (error != null)
            return IncidentFailure(events, windowStartUtc, windowEndUtc, error, elapsedMs);

        var meta = ToMeta(envelope!, elapsedMs);

        if (envelope!.IsError || string.IsNullOrWhiteSpace(envelope.Result))
            return IncidentFailure(events, windowStartUtc, windowEndUtc,
                $"Claude error: {envelope.Result ?? "(empty)"}", elapsedMs, meta);

        var raw = StripCodeFence(envelope.Result.Trim());
        ClaudeIncidentPayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<ClaudeIncidentPayload>(raw, ReadOpts);
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Could not parse incident payload");
            SaveRawFailure(raw, "incident", null);
            return IncidentFailure(events, windowStartUtc, windowEndUtc,
                $"Payload parse error: {ex.Message}", elapsedMs, meta);
        }

        var report = new IncidentReport(
            TimestampUtc: DateTime.UtcNow,
            EventCount: events.Count,
            WindowStartUtc: windowStartUtc,
            WindowEndUtc: windowEndUtc,
            Severity: payload?.Severity ?? "unknown",
            Title: payload?.Title ?? "(no title)",
            Summary: payload?.Summary ?? "",
            RecommendedActions: payload?.RecommendedActions ?? new(),
            Meta: meta);

        PersistIncidentReport(report, events);
        return report;
    }

    private string BuildIncidentPrompt(List<SecurityEvent> events, DateTime start, DateTime end)
    {
        var minutes = (end - start).TotalMinutes;
        var slim = events.Select(e => new
        {
            t = e.TimestampUtc,
            src = e.Source,
            sev = e.Severity,
            title = e.Title,
            desc = e.Description,
            details = e.Details
        }).ToList();
        var eventsJson = JsonSerializer.Serialize(slim, new JsonSerializerOptions { WriteIndented = false });

        return $$"""
            O agente local detectou {{events.Count}} evento(s) suspeito(s) em um sistema Windows
            na janela {{start:yyyy-MM-dd HH:mm:ss}} UTC -> {{end:yyyy-MM-dd HH:mm:ss}} UTC
            ({{minutes:F0}} min). Analise se há evidência de ataque coordenado, atividade
            suspeita, ou se são alarmes falsos. Considere correlações entre os eventos
            (mesmo processo pai, sequência temporal, mesmo IP, etc.).

            Responda APENAS com um único bloco JSON válido (sem markdown, sem texto antes/depois):
            {
              "severity": "info|low|medium|high|critical",
              "title": "Título curto da incidência (até 80 chars)",
              "summary": "2-4 frases avaliando se isto é ataque, atividade suspeita, ou normal",
              "recommended_actions": ["ação 1", "ação 2", "..."]
            }

            Eventos (JSON):
            {{eventsJson}}
            """;
    }

    private void PersistIncidentReport(IncidentReport r, List<SecurityEvent> events)
    {
        var ts = r.TimestampUtc.ToString("yyyy-MM-dd_HHmmss");
        var jsonPath = Path.Combine(_opts.ReportsDirectory, $"incident_{ts}.json");
        var mdPath = Path.Combine(_opts.ReportsDirectory, $"incident_{ts}.md");
        // Snapshot of the events that triggered this incident (forensics)
        var eventsPath = Path.Combine(_opts.ReportsDirectory, $"incident_{ts}.events.json");

        File.WriteAllText(jsonPath, JsonSerializer.Serialize(r, WriteOpts));
        File.WriteAllText(mdPath, RenderIncidentMarkdown(r, events));
        File.WriteAllText(eventsPath, JsonSerializer.Serialize(events, WriteOpts));
        _status.UpdateAfterIncident(r);

        _logger.LogWarning(
            "Incident report saved. severity={Sev} events={N} tokens(in/cc/cr/out)={In}/{CC}/{CR}/{Out} cost=${Cost} → {Md}",
            r.Severity, r.EventCount,
            r.Meta.InputTokens, r.Meta.CacheCreationTokens, r.Meta.CacheReadTokens,
            r.Meta.OutputTokens, r.Meta.TotalCostUsd, mdPath);
    }

    private static string RenderIncidentMarkdown(IncidentReport r, List<SecurityEvent> events)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Security Incident — {r.TimestampUtc:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine();
        sb.AppendLine($"- **Severity:** {r.Severity}");
        sb.AppendLine($"- **Title:** {r.Title}");
        sb.AppendLine($"- **Window:** {r.WindowStartUtc:HH:mm:ss} → {r.WindowEndUtc:HH:mm:ss} UTC ({(r.WindowEndUtc - r.WindowStartUtc).TotalMinutes:F0} min)");
        sb.AppendLine($"- **Events:** {r.EventCount}");
        sb.AppendLine($"- **Model:** {r.Meta.Model}  |  elapsed: {r.Meta.ElapsedMs}ms  |  tokens (in/cc/cr/out): {r.Meta.InputTokens}/{r.Meta.CacheCreationTokens}/{r.Meta.CacheReadTokens}/{r.Meta.OutputTokens}  |  cost: ${r.Meta.TotalCostUsd}");
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
            if (e.Details.Count > 0)
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

    // ============================================================
    // Low-level invocation (shared by both analyses)
    // ============================================================

    private async Task<(ClaudeJsonResponse? Envelope, long ElapsedMs, string? Error)>
        InvokeClaudeAsync(string prompt, CancellationToken ct)
    {
        Trace($"InvokeClaudeAsync entered, prompt size = {prompt.Length} chars");
        if (!File.Exists(_opts.ExePath))
            return (null, 0, $"claude.exe not found at {_opts.ExePath}");

        var token = Environment.GetEnvironmentVariable(_opts.TokenEnvVarName);
        if (string.IsNullOrEmpty(token))
            return (null, 0, $"env var {_opts.TokenEnvVarName} is empty");
        Trace($"token loaded ({token.Length} chars), about to Process.Start {_opts.ExePath}");

        // Prompt is piped via stdin to avoid the ~32K Windows command-line length limit.
        var psi = new ProcessStartInfo(_opts.ExePath)
        {
            ArgumentList =
            {
                "-p",
                "--output-format", "json",
                "--input-format", "text",
                "--model", _opts.Model,
                "--permission-mode", "bypassPermissions",
                "--system-prompt", SystemPrompt,
                "--disallowedTools", "*"
            },
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = _opts.ReportsDirectory
        };
        psi.Environment[_opts.TokenEnvVarName] = token;

        var sw = Stopwatch.StartNew();
        Process? process;
        try { process = Process.Start(psi); }
        catch (Exception ex)
        {
            sw.Stop();
            Trace($"Process.Start THREW {ex.GetType().Name}: {ex.Message}");
            return (null, sw.ElapsedMilliseconds, $"Process.Start failed: {ex.Message}");
        }
        if (process == null) { Trace("Process.Start returned null"); return (null, sw.ElapsedMilliseconds, "Process.Start returned null"); }
        Trace($"claude.exe started, PID={process.Id}");

        try
        {
            await process.StandardInput.WriteAsync(prompt.AsMemory(), ct);
            process.StandardInput.Close();
        }
        catch (Exception ex)
        {
            try { process.Kill(true); } catch { }
            sw.Stop();
            return (null, sw.ElapsedMilliseconds, $"Failed to send prompt: {ex.Message}");
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(_opts.TimeoutSeconds));

        try { await process.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            try { process.Kill(true); } catch { }
            sw.Stop();
            return (null, sw.ElapsedMilliseconds, $"Claude timed out after {_opts.TimeoutSeconds}s");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        sw.Stop();
        Trace($"claude exited code={process.ExitCode} elapsed={sw.ElapsedMilliseconds}ms stdoutLen={stdout.Length} stderrLen={stderr.Length}");
        if (!string.IsNullOrEmpty(stderr)) Trace($"stderr first 500: {stderr.Truncate(500)}");
        if (!string.IsNullOrEmpty(stdout)) Trace($"stdout first 500: {stdout.Truncate(500)}");
        process.Dispose();

        if (!string.IsNullOrWhiteSpace(stderr))
            _logger.LogDebug("claude stderr: {Err}", stderr.Truncate(500));

        if (string.IsNullOrWhiteSpace(stdout))
            return (null, sw.ElapsedMilliseconds, "Claude returned empty stdout");

        try
        {
            var envelope = JsonSerializer.Deserialize<ClaudeJsonResponse>(stdout);
            return (envelope, sw.ElapsedMilliseconds, null);
        }
        catch (JsonException ex)
        {
            return (null, sw.ElapsedMilliseconds, $"Envelope parse error: {ex.Message}");
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    private AnalysisMeta ToMeta(ClaudeJsonResponse envelope, long elapsedMs) => new(
        Model: _opts.Model,
        ElapsedMs: elapsedMs,
        InputTokens: envelope.Usage?.InputTokens,
        OutputTokens: envelope.Usage?.OutputTokens,
        CacheCreationTokens: envelope.Usage?.CacheCreationInputTokens,
        CacheReadTokens: envelope.Usage?.CacheReadInputTokens,
        TotalCostUsd: envelope.TotalCostUsd,
        SessionId: envelope.SessionId,
        IsError: envelope.IsError);

    private static AnalysisMeta EmptyMeta(string model, long elapsedMs) =>
        new(model, elapsedMs, null, null, null, null, null, null, IsError: true);

    private AnalysisResult ScanFailure(string scanFilePath, string msg, long elapsedMs, AnalysisMeta? meta = null)
    {
        _logger.LogWarning("Scan analysis failed: {Msg}", msg);
        return new AnalysisResult(DateTime.UtcNow, scanFilePath, "unknown", msg,
            new(), meta ?? EmptyMeta(_opts.Model, elapsedMs));
    }

    private IncidentReport IncidentFailure(
        List<SecurityEvent> events, DateTime start, DateTime end,
        string msg, long elapsedMs, AnalysisMeta? meta = null)
    {
        _logger.LogWarning("Incident analysis failed: {Msg}", msg);
        return new IncidentReport(DateTime.UtcNow, events.Count, start, end,
            "unknown", "Analysis failure", msg, new(), meta ?? EmptyMeta(_opts.Model, elapsedMs));
    }

    private static int SeverityRank(string s) => s.ToLowerInvariant() switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
    };

    private static string StripCodeFence(string s)
    {
        if (s.StartsWith("```"))
        {
            var firstNl = s.IndexOf('\n');
            if (firstNl > 0) s = s[(firstNl + 1)..];
            if (s.EndsWith("```")) s = s[..^3].TrimEnd();
        }
        return s;
    }

    private static readonly object _traceLock = new();
    private static void Trace(string msg)
    {
        try
        {
            lock (_traceLock)
            {
                File.AppendAllText(@"C:\ProgramData\SecAgent\trace.log",
                    $"[{DateTime.Now:HH:mm:ss.fff}] [analyzer] {msg}{Environment.NewLine}");
            }
        }
        catch { }
    }

    private void SaveRawFailure(string raw, string kind, string? context)
    {
        try
        {
            var path = Path.Combine(_opts.ReportsDirectory,
                $"{kind}_FAILED_{DateTime.UtcNow:yyyy-MM-dd_HHmmss}.raw.txt");
            File.WriteAllText(path, $"Context: {context ?? "(none)"}{Environment.NewLine}---{Environment.NewLine}{raw}");
        }
        catch { }
    }

    // Wire-format records

    private record ClaudeJsonResponse(
        [property: JsonPropertyName("type")] string? Type,
        [property: JsonPropertyName("subtype")] string? Subtype,
        [property: JsonPropertyName("is_error")] bool IsError,
        [property: JsonPropertyName("result")] string? Result,
        [property: JsonPropertyName("session_id")] string? SessionId,
        [property: JsonPropertyName("total_cost_usd")] decimal? TotalCostUsd,
        [property: JsonPropertyName("usage")] ClaudeUsage? Usage
    );

    private record ClaudeUsage(
        [property: JsonPropertyName("input_tokens")] int? InputTokens,
        [property: JsonPropertyName("output_tokens")] int? OutputTokens,
        [property: JsonPropertyName("cache_creation_input_tokens")] int? CacheCreationInputTokens,
        [property: JsonPropertyName("cache_read_input_tokens")] int? CacheReadInputTokens
    );

    private record ClaudeAnalysisPayload(
        [property: JsonPropertyName("risk_level")] string? RiskLevel,
        [property: JsonPropertyName("summary")] string? Summary,
        [property: JsonPropertyName("findings")] List<ClaudeFinding>? Findings
    );

    private record ClaudeFinding(
        [property: JsonPropertyName("severity")] string? Severity,
        [property: JsonPropertyName("category")] string? Category,
        [property: JsonPropertyName("title")] string? Title,
        [property: JsonPropertyName("description")] string? Description,
        [property: JsonPropertyName("recommendation")] string? Recommendation,
        [property: JsonPropertyName("evidence")] string? Evidence
    );

    private record ClaudeIncidentPayload(
        [property: JsonPropertyName("severity")] string? Severity,
        [property: JsonPropertyName("title")] string? Title,
        [property: JsonPropertyName("summary")] string? Summary,
        [property: JsonPropertyName("recommended_actions")] List<string>? RecommendedActions
    );
}
