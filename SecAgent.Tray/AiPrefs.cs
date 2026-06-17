using System.Text.Json;

namespace SecAgent.Tray;

/// <summary>
/// Lembra a última escolha de modelo/esforço da análise com IA, persistida em
/// %LOCALAPPDATA%\SecAgent\ai-prefs.json. Usado pelo painel (pré-selecionar os
/// dropdowns) e pelo item de menu do tray (que dispara com a última escolha).
///
/// O Service NÃO lê este arquivo — a escolha viaja no conteúdo do trigger. Aqui
/// só guardamos para a próxima vez. Valores são validados para nunca persistir lixo.
/// </summary>
public static class AiPrefs
{
    public const string DefaultModel = "sonnet";
    public const string DefaultEffort = "high";

    private static readonly HashSet<string> Models =
        new(StringComparer.OrdinalIgnoreCase) { "opus", "sonnet", "haiku" };
    private static readonly HashSet<string> Efforts =
        new(StringComparer.OrdinalIgnoreCase) { "low", "medium", "high", "xhigh", "max" };

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static string PrefsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SecAgent", "ai-prefs.json");

    public static string NormalizeModel(string? m)
        => !string.IsNullOrWhiteSpace(m) && Models.Contains(m.Trim())
            ? m.Trim().ToLowerInvariant() : DefaultModel;

    public static string NormalizeEffort(string? e)
        => !string.IsNullOrWhiteSpace(e) && Efforts.Contains(e.Trim())
            ? e.Trim().ToLowerInvariant() : DefaultEffort;

    /// <summary>Lê as prefs salvas (já normalizadas); defaults se ausente/inválido.</summary>
    public static (string Model, string Effort) Load()
    {
        try
        {
            var path = PrefsPath;
            if (File.Exists(path))
            {
                var p = JsonSerializer.Deserialize<PrefsDto>(File.ReadAllText(path), JsonOpts);
                if (p is not null)
                    return (NormalizeModel(p.Model), NormalizeEffort(p.Effort));
            }
        }
        catch { /* arquivo corrompido/ausente — usa defaults */ }
        return (DefaultModel, DefaultEffort);
    }

    /// <summary>Persiste a escolha (normalizada). Falha de I/O é silenciosa.</summary>
    public static void Save(string? model, string? effort)
    {
        try
        {
            var path = PrefsPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var dto = new PrefsDto(NormalizeModel(model), NormalizeEffort(effort));
            File.WriteAllText(path, JsonSerializer.Serialize(dto));
        }
        catch { /* best effort */ }
    }

    private record PrefsDto(string Model, string Effort);
}
