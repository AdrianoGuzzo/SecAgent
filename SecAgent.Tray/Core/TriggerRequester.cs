using System.Globalization;
using System.Text.Json;

namespace SecAgent.Tray.Core;

public enum TriggerRequestStatus { Ok, Debounced, Denied, Failed }

public sealed record TriggerRequestResult(TriggerRequestStatus Status, int WaitSeconds = 0, string? Error = null);

/// <summary>
/// Grava arquivos em <c>triggers\</c> para o Service (único canal Tray → Service),
/// com debounce client-side por nome (o Service também debounça).
/// </summary>
internal sealed class TriggerRequester
{
    public const int DefaultDebounceSeconds = 30;

    private readonly AgentPaths _paths;
    private readonly TimeProvider _time;
    private readonly TimeSpan _debounce;
    private readonly Dictionary<string, DateTime> _lastUtc = new(StringComparer.OrdinalIgnoreCase);

    public TriggerRequester(AgentPaths paths, TimeProvider time, int debounceSeconds = DefaultDebounceSeconds)
    {
        _paths = paths;
        _time = time;
        _debounce = TimeSpan.FromSeconds(debounceSeconds);
    }

    /// <summary>Conteúdo do scan-and-analyze: o Service lê e valida modelo/esforço.</summary>
    public static string AnalyzeContent(string model, string effort)
        => JsonSerializer.Serialize(new { model, effort });

    public TriggerRequestResult Request(string fileName, string? content = null)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        if (_lastUtc.TryGetValue(fileName, out var last) && now - last < _debounce)
        {
            var wait = (int)Math.Ceiling((_debounce - (now - last)).TotalSeconds);
            return new(TriggerRequestStatus.Debounced, WaitSeconds: Math.Max(1, wait));
        }

        try
        {
            Directory.CreateDirectory(_paths.TriggersDir);
            File.WriteAllText(Path.Combine(_paths.TriggersDir, fileName),
                content ?? now.ToString("o", CultureInfo.InvariantCulture));
            _lastUtc[fileName] = now;
            return new(TriggerRequestStatus.Ok);
        }
        catch (UnauthorizedAccessException ex)
        {
            return new(TriggerRequestStatus.Denied, Error: ex.Message);
        }
        catch (Exception ex)
        {
            return new(TriggerRequestStatus.Failed, Error: ex.Message);
        }
    }

    /// <summary>Mensagem amigável para o toast. <paramref name="okMessage"/> só no sucesso.</summary>
    public string Describe(TriggerRequestResult r, string okMessage) => r.Status switch
    {
        TriggerRequestStatus.Ok => okMessage,
        TriggerRequestStatus.Debounced => $"Aguarde {r.WaitSeconds}s entre solicitações.",
        // T7: antes mandava o usuário rodar deploy.ps1 (script de desenvolvimento).
        TriggerRequestStatus.Denied =>
            $"Sem permissão para escrever em {_paths.TriggersDir}. Verifique se o serviço SecAgent está " +
            "instalado e rodando (Serviços do Windows) ou reinstale o SecAgent.",
        _ => "Falha ao solicitar: " + r.Error
    };
}
