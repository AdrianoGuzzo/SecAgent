using System.Text;
using System.Text.Json;

namespace SecAgent.Tray.Core;

/// <summary>
/// Leitura tolerante dos JSONs do Service: compartilha o arquivo com o escritor,
/// valida o JSON e tenta de novo brevemente se pegou o arquivo no meio da escrita.
/// T4: as esperas são assíncronas (antes Thread.Sleep na UI thread).
/// </summary>
internal static class JsonFileReader
{
    public const int Attempts = 3;
    public static TimeSpan RetryDelay { get; set; } = TimeSpan.FromMilliseconds(80);

    /// <summary>Texto JSON válido, ou null se ausente/ilegível após as tentativas.</summary>
    public static async Task<string?> ReadRawAsync(string path, CancellationToken ct = default)
    {
        for (int attempt = 0; attempt < Attempts; attempt++)
        {
            if (attempt > 0) await Task.Delay(RetryDelay, ct);
            try
            {
                if (!File.Exists(path)) return null;
                string json;
                await using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var sr = new StreamReader(fs, Encoding.UTF8))
                    json = await sr.ReadToEndAsync(ct);
                if (string.IsNullOrWhiteSpace(json)) continue;
                using var _ = JsonDocument.Parse(json);   // guarda contra escrita parcial
                return json;
            }
            catch (OperationCanceledException) { throw; }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
            catch (Exception) { /* sharing violation / JSON parcial → tenta de novo */ }
        }
        return null;
    }

    public static async Task<T?> ReadAsync<T>(string path, CancellationToken ct = default) where T : class
    {
        var raw = await ReadRawAsync(path, ct);
        if (raw is null) return null;
        try { return JsonSerializer.Deserialize<T>(raw, JsonDefaults.Read); }
        catch (JsonException) { return null; }
    }

    /// <summary>
    /// O Service grava PascalCase; a página lê camelCase. Desserializa no modelo
    /// do Contracts (tolerante a caixa) e re-serializa em camelCase.
    /// </summary>
    public static async Task<string?> ReadAsCamelAsync<T>(string path, CancellationToken ct = default) where T : class
    {
        var obj = await ReadAsync<T>(path, ct);
        return obj is null ? null : JsonSerializer.Serialize(obj, JsonDefaults.CamelCase);
    }
}
