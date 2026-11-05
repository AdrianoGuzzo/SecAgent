using System.Text.Json;
using System.Text.Json.Serialization;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Analysis;

/// <summary>
/// Interpreta a saída do <c>claude -p --output-format json</c>: o envelope
/// (result/usage/custo) e o payload JSON que o modelo devolve dentro de "result".
/// Puro — sem I/O — para ser testado com saídas reais/sintéticas.
/// </summary>
internal static class ClaudeResponseParser
{
    /// <summary>Envelope válido (<see cref="Envelope"/>) ou mensagem de erro.</summary>
    public readonly record struct EnvelopeOutcome(ClaudeJsonResponse? Envelope, string? Error);

    public static EnvelopeOutcome ParseEnvelope(ClaudeCliResult run)
    {
        if (run.Error is not null) return new(null, run.Error);

        var exitInfo = run.ExitCode is int code && code != 0 ? $" (exit code {code})" : "";

        if (string.IsNullOrWhiteSpace(run.Stdout))
        {
            var err = string.IsNullOrWhiteSpace(run.Stderr) ? "" : $": {run.Stderr.Truncate(300)}";
            return new(null, $"Claude returned empty stdout{exitInfo}{err}");
        }

        try
        {
            var envelope = JsonSerializer.Deserialize<ClaudeJsonResponse>(run.Stdout);
            return envelope is null
                ? new(null, $"Envelope was null{exitInfo}")
                : new(envelope, null);
        }
        catch (JsonException ex)
        {
            return new(null, $"Envelope parse error{exitInfo}: {ex.Message}");
        }
    }

    /// <summary>Remove a cerca ```json ... ``` que o modelo às vezes adiciona.</summary>
    public static string StripCodeFence(string s)
    {
        if (s.StartsWith("```"))
        {
            var firstNl = s.IndexOf('\n');
            if (firstNl > 0) s = s[(firstNl + 1)..];
            if (s.EndsWith("```")) s = s[..^3].TrimEnd();
        }
        return s;
    }

    public static AnalysisMeta ToMeta(ClaudeJsonResponse envelope, long elapsedMs, string model, string? effort) => new(
        Model: model,
        ElapsedMs: elapsedMs,
        InputTokens: envelope.Usage?.InputTokens,
        OutputTokens: envelope.Usage?.OutputTokens,
        CacheCreationTokens: envelope.Usage?.CacheCreationInputTokens,
        CacheReadTokens: envelope.Usage?.CacheReadInputTokens,
        TotalCostUsd: envelope.TotalCostUsd,
        SessionId: envelope.SessionId,
        IsError: envelope.IsError,
        // Só registra o esforço quando ele foi de fato aplicado (não em Haiku).
        Effort: ClaudeArgsBuilder.AppliedEffort(model, effort));

    public static AnalysisMeta EmptyMeta(string model, string? effort, long elapsedMs) =>
        new(model, elapsedMs, null, null, null, null, null, null, IsError: true,
            Effort: ClaudeArgsBuilder.AppliedEffort(model, effort));

    public static ClaudeAnalysisPayload? ParseScanPayload(string raw)
        => JsonSerializer.Deserialize<ClaudeAnalysisPayload>(raw, JsonDefaults.Read);

    public static ClaudeIncidentPayload? ParseIncidentPayload(string raw)
        => JsonSerializer.Deserialize<ClaudeIncidentPayload>(raw, JsonDefaults.Read);

    /// <summary>Findings do payload com defaults para campos ausentes.</summary>
    public static List<Finding> ToFindings(ClaudeAnalysisPayload? payload)
        => payload?.Findings?.Select(f => new Finding(
            f.Severity ?? SeverityLevels.Info, f.Category ?? "outro",
            f.Title ?? "(no title)", f.Description ?? "",
            f.Recommendation ?? "", f.Evidence)).ToList() ?? new();
}

// Wire-format records (saída do claude CLI e o JSON pedido no prompt).

internal record ClaudeJsonResponse(
    [property: JsonPropertyName("type")] string? Type,
    [property: JsonPropertyName("subtype")] string? Subtype,
    [property: JsonPropertyName("is_error")] bool IsError,
    [property: JsonPropertyName("result")] string? Result,
    [property: JsonPropertyName("session_id")] string? SessionId,
    [property: JsonPropertyName("total_cost_usd")] decimal? TotalCostUsd,
    [property: JsonPropertyName("usage")] ClaudeUsage? Usage
);

internal record ClaudeUsage(
    [property: JsonPropertyName("input_tokens")] int? InputTokens,
    [property: JsonPropertyName("output_tokens")] int? OutputTokens,
    [property: JsonPropertyName("cache_creation_input_tokens")] int? CacheCreationInputTokens,
    [property: JsonPropertyName("cache_read_input_tokens")] int? CacheReadInputTokens
);

internal record ClaudeAnalysisPayload(
    [property: JsonPropertyName("risk_level")] string? RiskLevel,
    [property: JsonPropertyName("summary")] string? Summary,
    [property: JsonPropertyName("findings")] List<ClaudeFinding>? Findings
);

internal record ClaudeFinding(
    [property: JsonPropertyName("severity")] string? Severity,
    [property: JsonPropertyName("category")] string? Category,
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("recommendation")] string? Recommendation,
    [property: JsonPropertyName("evidence")] string? Evidence
);

internal record ClaudeIncidentPayload(
    [property: JsonPropertyName("severity")] string? Severity,
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("summary")] string? Summary,
    [property: JsonPropertyName("recommended_actions")] List<string>? RecommendedActions
);
