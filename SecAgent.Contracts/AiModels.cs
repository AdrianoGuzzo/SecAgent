namespace SecAgent.Contracts;

/// <summary>
/// Vocabulário de modelos (<c>--model</c>) e níveis de esforço (<c>--effort</c>)
/// aceitos pelo claude CLI. Única fonte de validação para Tray e Service — o
/// conteúdo do trigger é gravável por Authenticated Users, então só pares
/// válidos podem chegar ao CLI. Haiku NÃO aceita <c>--effort</c>.
/// </summary>
public static class AiModels
{
    public const string DefaultModel = "sonnet";
    public const string DefaultEffort = "high";

    public static IReadOnlyList<string> Models { get; } = new[] { "opus", "sonnet", "haiku" };
    public static IReadOnlyList<string> Efforts { get; } = new[] { "low", "medium", "high", "xhigh", "max" };

    private static readonly HashSet<string> ModelSet = new(Models, StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> EffortSet = new(Efforts, StringComparer.OrdinalIgnoreCase);

    public static bool IsKnownModel(string? model)
        => !string.IsNullOrWhiteSpace(model) && ModelSet.Contains(model.Trim());

    public static bool IsKnownEffort(string? effort)
        => !string.IsNullOrWhiteSpace(effort) && EffortSet.Contains(effort.Trim());

    /// <summary>Modelo válido (minúsculo) ou <paramref name="fallback"/> se desconhecido/vazio.</summary>
    public static string NormalizeModel(string? model, string fallback = DefaultModel)
        => IsKnownModel(model) ? model!.Trim().ToLowerInvariant() : fallback;

    /// <summary>Esforço válido (minúsculo) ou <paramref name="fallback"/> se desconhecido/vazio.</summary>
    public static string NormalizeEffort(string? effort, string fallback = DefaultEffort)
        => IsKnownEffort(effort) ? effort!.Trim().ToLowerInvariant() : fallback;

    /// <summary>Haiku não aceita --effort; os demais modelos conhecidos aceitam.</summary>
    public static bool EffortSupported(string? model)
        => IsKnownModel(model) && !string.Equals(model!.Trim(), "haiku", StringComparison.OrdinalIgnoreCase);
}
