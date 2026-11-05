namespace SecAgent.Service.Analysis;

/// <summary>
/// Argumentos do <c>claude -p</c>. NUNCA usar <c>--bare</c>: ele bloqueia OAuth e
/// força ANTHROPIC_API_KEY (API paga). O prompt vai por stdin.
/// </summary>
internal static class ClaudeArgsBuilder
{
    public const string SystemPrompt =
        "Você é um analista de segurança defensiva especializado em sistemas Windows. " +
        "Responda exatamente no formato JSON solicitado, sem markdown, sem texto fora do JSON.";

    public static IReadOnlyList<string> Build(string model, string? effort)
    {
        var args = new List<string>
        {
            "-p",
            "--output-format", "json",
            "--input-format", "text",
            "--model", model,
            "--permission-mode", "bypassPermissions",
            "--system-prompt", SystemPrompt,
            "--disallowedTools", "*"
        };
        // Haiku não aceita --effort; só passamos o flag em modelos que suportam.
        if (AiModels.EffortSupported(model) && !string.IsNullOrWhiteSpace(effort))
        {
            args.Add("--effort");
            args.Add(effort);
        }
        return args;
    }

    /// <summary>Esforço efetivamente aplicado (null quando o modelo não suporta).</summary>
    public static string? AppliedEffort(string model, string? effort)
        => AiModels.EffortSupported(model) ? effort : null;
}
