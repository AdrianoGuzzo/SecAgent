namespace SecAgent.Service.Analysis;

/// <summary>
/// Conhece os modelos e níveis de esforço aceitos pelo claude CLI e faz a
/// normalização/validação central. Usado para "limpar" os valores que chegam
/// do Tray pelo conteúdo do trigger (gravável por Authenticated Users — vide
/// ACL da pasta triggers/), garantindo que só pares válidos cheguem ao CLI.
///
/// Importante: Haiku NÃO suporta --effort; <see cref="EffortSupported"/> reflete
/// isso para que o flag seja omitido nesse caso.
/// </summary>
public static class ClaudeCapabilities
{
    // Aliases aceitos pelo CLI (--model). Mantém-se em minúsculas para casar
    // com a entrada normalizada.
    private static readonly HashSet<string> ModelSet =
        new(StringComparer.OrdinalIgnoreCase) { "opus", "sonnet", "haiku" };

    // Níveis de esforço aceitos pelo CLI (--effort). "xhigh" só vale em alguns
    // modelos, mas o CLI ignora/ajusta — aqui validamos só o vocabulário.
    private static readonly HashSet<string> EffortSet =
        new(StringComparer.OrdinalIgnoreCase) { "low", "medium", "high", "xhigh", "max" };

    /// <summary>Modelo válido (minúsculo) ou o fallback se desconhecido/vazio.</summary>
    public static string NormalizeModel(string? model, string fallback)
        => !string.IsNullOrWhiteSpace(model) && ModelSet.Contains(model.Trim())
            ? model.Trim().ToLowerInvariant()
            : fallback;

    /// <summary>Esforço válido (minúsculo) ou o fallback se desconhecido/vazio.</summary>
    public static string NormalizeEffort(string? effort, string fallback)
        => !string.IsNullOrWhiteSpace(effort) && EffortSet.Contains(effort.Trim())
            ? effort.Trim().ToLowerInvariant()
            : fallback;

    /// <summary>Haiku não aceita --effort; qualquer outro modelo conhecido aceita.</summary>
    public static bool EffortSupported(string model)
        => !string.Equals(model, "haiku", StringComparison.OrdinalIgnoreCase);
}
