using System.Text.Json;

namespace SecAgent.Tray.Core;

/// <summary>
/// Lembra a última escolha de modelo/esforço da análise com IA
/// (%LOCALAPPDATA%\SecAgent\ai-prefs.json). Usado pelo painel (pré-seleção dos
/// dropdowns) e pelo item de menu (dispara com a última escolha).
///
/// O Service NÃO lê este arquivo — a escolha viaja no conteúdo do trigger. As
/// listas/validação vêm de <see cref="AiModels"/> (antes duplicadas aqui).
/// </summary>
internal sealed class AiPrefsStore
{
    private readonly string _path;

    public AiPrefsStore(string path) => _path = path;

    public static AiPrefsStore Default { get; } = new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecAgent", "ai-prefs.json"));

    /// <summary>Prefs salvas (normalizadas); defaults se ausente/inválido.</summary>
    public (string Model, string Effort) Load()
    {
        try
        {
            if (File.Exists(_path))
            {
                var p = JsonSerializer.Deserialize<PrefsDto>(File.ReadAllText(_path), JsonDefaults.Read);
                if (p is not null) return (AiModels.NormalizeModel(p.Model), AiModels.NormalizeEffort(p.Effort));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { }
        return (AiModels.DefaultModel, AiModels.DefaultEffort);
    }

    /// <summary>Persiste a escolha (normalizada). Falha de I/O é silenciosa.</summary>
    public void Save(string? model, string? effort)
    {
        try
        {
            var dto = new PrefsDto(AiModels.NormalizeModel(model), AiModels.NormalizeEffort(effort));
            AtomicFile.WriteAllText(_path, JsonSerializer.Serialize(dto));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>Payload "aiPrefs" para a página.</summary>
    public string ToMessageJson()
    {
        var (model, effort) = Load();
        return JsonSerializer.Serialize(new { model, effort });
    }

    private sealed record PrefsDto(string? Model, string? Effort);
}
