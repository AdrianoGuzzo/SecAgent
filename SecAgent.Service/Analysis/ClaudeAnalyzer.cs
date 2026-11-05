using System.Text.Json;
using Microsoft.Extensions.Options;
using SecAgent.Service.Diagnostics;
using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Analysis;

public interface IClaudeAnalyzer
{
    Task<AnalysisResult> AnalyzeAsync(ScanResult scan, string scanFilePath, CancellationToken ct,
        string? model = null, string? effort = null);

    Task<IncidentReport> AnalyzeIncidentAsync(IReadOnlyList<SecurityEvent> events,
        DateTime windowStartUtc, DateTime windowEndUtc, CancellationToken ct);
}

/// <summary>
/// Orquestra a análise com IA: monta o prompt, invoca o claude CLI (via
/// <see cref="IClaudeCli"/>), interpreta a resposta e persiste JSON + Markdown.
/// Toda a parte pura vive em <see cref="ClaudeArgsBuilder"/>,
/// <see cref="ClaudeResponseParser"/>, <see cref="PromptBuilder"/> e
/// <see cref="ReportMarkdownRenderer"/>.
/// </summary>
public class ClaudeAnalyzer : IClaudeAnalyzer
{
    private const string TraceCategory = "analyzer";

    private readonly ILogger<ClaudeAnalyzer> _logger;
    private readonly ClaudeOptions _opts;
    private readonly IStatusFileService _status;
    private readonly IClaudeCli _cli;
    private readonly ISystemEnvironment _env;
    private readonly ITraceLog _trace;
    private readonly TimeProvider _time;

    public ClaudeAnalyzer(
        ILogger<ClaudeAnalyzer> logger,
        IOptions<ClaudeOptions> opts,
        IStatusFileService status,
        IClaudeCli cli,
        ISystemEnvironment env,
        ITraceLog trace,
        TimeProvider time)
    {
        _logger = logger;
        _opts = opts.Value;
        _status = status;
        _cli = cli;
        _env = env;
        _trace = trace;
        _time = time;
    }

    private DateTime UtcNow => _time.GetUtcNow().UtcDateTime;

    // ============================================================
    // Scan analysis
    // ============================================================

    // model/effort são opcionais: quando vêm do trigger (escolha do usuário no
    // painel) sobrepõem os defaults de config. Normalizados aqui de novo por
    // segurança (o conteúdo do trigger é gravável por qualquer usuário).
    public async Task<AnalysisResult> AnalyzeAsync(
        ScanResult scan, string scanFilePath, CancellationToken ct,
        string? model = null, string? effort = null)
    {
        Directory.CreateDirectory(_opts.ReportsDirectory);

        var useModel = AiModels.NormalizeModel(model, _opts.Model);
        var useEffort = AiModels.NormalizeEffort(effort, _opts.Effort);
        var scanFile = Path.GetFileName(scanFilePath);

        var (envelope, elapsedMs, error) = await InvokeClaudeAsync(PromptBuilder.Build(scan), useModel, useEffort, ct);
        if (envelope is null)
            return ScanFailure(scanFile, error!, ClaudeResponseParser.EmptyMeta(useModel, useEffort, elapsedMs));

        var meta = ClaudeResponseParser.ToMeta(envelope, elapsedMs, useModel, useEffort);
        if (envelope.IsError || string.IsNullOrWhiteSpace(envelope.Result))
            return ScanFailure(scanFile, $"Claude reported error: {envelope.Result ?? "(empty)"}", meta);

        var raw = ClaudeResponseParser.StripCodeFence(envelope.Result.Trim());
        ClaudeAnalysisPayload? payload;
        try
        {
            payload = ClaudeResponseParser.ParseScanPayload(raw);
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Could not parse scan analysis payload");
            SaveRawFailure(raw, "scan", scanFile);
            return ScanFailure(scanFile, $"Payload parse error: {ex.Message}", meta);
        }

        var result = new AnalysisResult(
            TimestampUtc: UtcNow,
            ScanFile: scanFile,
            RiskLevel: payload?.RiskLevel ?? SeverityLevels.Unknown,
            Summary: payload?.Summary ?? "",
            Findings: ClaudeResponseParser.ToFindings(payload),
            Meta: meta);

        PersistScanReport(result);
        return result;
    }

    private void PersistScanReport(AnalysisResult r)
    {
        var jsonPath = Path.Combine(_opts.ReportsDirectory, ReportNames.ScanReportJson(r.TimestampUtc));
        var mdPath = Path.Combine(_opts.ReportsDirectory, ReportNames.ScanReportMarkdown(r.TimestampUtc));
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(r, JsonDefaults.Indented));
        File.WriteAllText(mdPath, ReportMarkdownRenderer.RenderScan(r));
        _status.UpdateAfterScan(r);
        _logger.LogInformation(
            "Scan report saved. risk={Risk} findings={N} tokens(in/cc/cr/out)={In}/{CC}/{CR}/{Out} cost=${Cost} → {Md}",
            r.RiskLevel, r.Findings.Count,
            r.Meta.InputTokens, r.Meta.CacheCreationTokens, r.Meta.CacheReadTokens,
            r.Meta.OutputTokens, r.Meta.TotalCostUsd, mdPath);
    }

    // ============================================================
    // Incident analysis (ad-hoc, triggered by SuspiciousEventProcessor)
    // ============================================================

    public async Task<IncidentReport> AnalyzeIncidentAsync(
        IReadOnlyList<SecurityEvent> events,
        DateTime windowStartUtc,
        DateTime windowEndUtc,
        CancellationToken ct)
    {
        Directory.CreateDirectory(_opts.ReportsDirectory);

        // Incidentes são automáticos (sem escolha do usuário): usa os defaults de config.
        var useModel = AiModels.NormalizeModel(null, _opts.Model);
        var useEffort = AiModels.NormalizeEffort(null, _opts.Effort);

        var prompt = PromptBuilder.BuildIncident(events, windowStartUtc, windowEndUtc);
        var (envelope, elapsedMs, error) = await InvokeClaudeAsync(prompt, useModel, useEffort, ct);

        if (envelope is null)
            return IncidentFailure(events, windowStartUtc, windowEndUtc, error!,
                ClaudeResponseParser.EmptyMeta(useModel, useEffort, elapsedMs));

        var meta = ClaudeResponseParser.ToMeta(envelope, elapsedMs, useModel, useEffort);
        if (envelope.IsError || string.IsNullOrWhiteSpace(envelope.Result))
            return IncidentFailure(events, windowStartUtc, windowEndUtc,
                $"Claude error: {envelope.Result ?? "(empty)"}", meta);

        var raw = ClaudeResponseParser.StripCodeFence(envelope.Result.Trim());
        ClaudeIncidentPayload? payload;
        try
        {
            payload = ClaudeResponseParser.ParseIncidentPayload(raw);
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Could not parse incident payload");
            SaveRawFailure(raw, "incident", null);
            return IncidentFailure(events, windowStartUtc, windowEndUtc, $"Payload parse error: {ex.Message}", meta);
        }

        var report = new IncidentReport(
            TimestampUtc: UtcNow,
            EventCount: events.Count,
            WindowStartUtc: windowStartUtc,
            WindowEndUtc: windowEndUtc,
            Severity: payload?.Severity ?? SeverityLevels.Unknown,
            Title: payload?.Title ?? "(no title)",
            Summary: payload?.Summary ?? "",
            RecommendedActions: payload?.RecommendedActions ?? new(),
            Meta: meta);

        PersistIncidentReport(report, events);
        return report;
    }

    private void PersistIncidentReport(IncidentReport r, IReadOnlyList<SecurityEvent> events)
    {
        var jsonPath = Path.Combine(_opts.ReportsDirectory, ReportNames.IncidentJson(r.TimestampUtc));
        var mdPath = Path.Combine(_opts.ReportsDirectory, ReportNames.IncidentMarkdown(r.TimestampUtc));
        // Snapshot dos eventos que dispararam o incidente (forense).
        var eventsPath = Path.Combine(_opts.ReportsDirectory, ReportNames.IncidentEvents(r.TimestampUtc));

        File.WriteAllText(jsonPath, JsonSerializer.Serialize(r, JsonDefaults.Indented));
        File.WriteAllText(mdPath, ReportMarkdownRenderer.RenderIncident(r, events));
        File.WriteAllText(eventsPath, JsonSerializer.Serialize(events, JsonDefaults.Indented));
        _status.UpdateAfterIncident(r);

        _logger.LogWarning(
            "Incident report saved. severity={Sev} events={N} tokens(in/cc/cr/out)={In}/{CC}/{CR}/{Out} cost=${Cost} → {Md}",
            r.Severity, r.EventCount,
            r.Meta.InputTokens, r.Meta.CacheCreationTokens, r.Meta.CacheReadTokens,
            r.Meta.OutputTokens, r.Meta.TotalCostUsd, mdPath);
    }

    // ============================================================
    // Low-level invocation (shared by both analyses)
    // ============================================================

    private async Task<(ClaudeJsonResponse? Envelope, long ElapsedMs, string? Error)> InvokeClaudeAsync(
        string prompt, string model, string effort, CancellationToken ct)
    {
        _trace.Write(TraceCategory, $"InvokeClaudeAsync entered, prompt size = {prompt.Length} chars, model={model}, effort={effort}");
        if (!_env.FileExists(_opts.ExePath))
            return (null, 0, $"claude.exe not found at {_opts.ExePath}");

        var token = _env.GetEnvironmentVariable(_opts.TokenEnvVarName);
        if (string.IsNullOrEmpty(token))
            return (null, 0, $"env var {_opts.TokenEnvVarName} is empty");
        _trace.Write(TraceCategory, $"token loaded ({token.Length} chars), starting {_opts.ExePath}");

        var run = await _cli.RunAsync(new ClaudeCliRequest(
            ExePath: _opts.ExePath,
            Arguments: ClaudeArgsBuilder.Build(model, effort),
            Stdin: prompt,
            Environment: new Dictionary<string, string> { [_opts.TokenEnvVarName] = token },
            WorkingDirectory: _opts.ReportsDirectory,
            Timeout: TimeSpan.FromSeconds(_opts.TimeoutSeconds)), ct);

        _trace.Write(TraceCategory,
            $"claude finished exit={run.ExitCode?.ToString() ?? "-"} elapsed={run.ElapsedMs}ms " +
            $"stdoutLen={run.Stdout.Length} stderrLen={run.Stderr.Length} error={run.Error ?? "-"}");
        if (!string.IsNullOrEmpty(run.Stderr)) _trace.Write(TraceCategory, $"stderr first 500: {run.Stderr.Truncate(500)}");
        if (!string.IsNullOrEmpty(run.Stdout)) _trace.Write(TraceCategory, $"stdout first 500: {run.Stdout.Truncate(500)}");

        var outcome = ClaudeResponseParser.ParseEnvelope(run);
        return (outcome.Envelope, run.ElapsedMs, outcome.Error);
    }

    // ============================================================
    // Failures
    // ============================================================

    private AnalysisResult ScanFailure(string scanFile, string msg, AnalysisMeta meta)
    {
        _logger.LogWarning("Scan analysis failed: {Msg}", msg);
        // ScanFile só com o NOME (igual ao caminho de sucesso) — antes ia o caminho completo.
        return new AnalysisResult(UtcNow, scanFile, SeverityLevels.Unknown, msg, new(), meta);
    }

    private IncidentReport IncidentFailure(
        IReadOnlyList<SecurityEvent> events, DateTime start, DateTime end, string msg, AnalysisMeta meta)
    {
        _logger.LogWarning("Incident analysis failed: {Msg}", msg);
        return new IncidentReport(UtcNow, events.Count, start, end,
            SeverityLevels.Unknown, "Analysis failure", msg, new(), meta);
    }

    private void SaveRawFailure(string raw, string kind, string? context)
    {
        try
        {
            var path = Path.Combine(_opts.ReportsDirectory, ReportNames.FailedRaw(kind, UtcNow));
            File.WriteAllText(path, $"Context: {context ?? "(none)"}{Environment.NewLine}---{Environment.NewLine}{raw}");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not save raw failure");
        }
    }
}
