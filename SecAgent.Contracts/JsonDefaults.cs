using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecAgent.Contracts;

/// <summary>Opções de serialização compartilhadas (evita recriar <see cref="JsonSerializerOptions"/> por chamada).</summary>
public static class JsonDefaults
{
    /// <summary>Arquivos legíveis por humano (relatórios, status, scans).</summary>
    public static JsonSerializerOptions Indented { get; } = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>Arquivos de alta frequência / JSONL (uma linha por objeto).</summary>
    public static JsonSerializerOptions Compact { get; } = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>Leitura tolerante (PascalCase do Service ou camelCase).</summary>
    public static JsonSerializerOptions Read { get; } = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>Saída camelCase para a página do painel (WebView2).</summary>
    public static JsonSerializerOptions CamelCase { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}
