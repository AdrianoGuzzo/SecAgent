using System.Text.Json;

namespace SecAgent.Tray.Core;

/// <summary>Formato das mensagens host ↔ página do WebView2.</summary>
internal static class WebMessage
{
    /// <summary>
    /// Envelope {type,payload}. O tipo passa pelo serializer (antes era concatenado
    /// cru); o payload já é JSON válido (ou "null").
    /// </summary>
    public static string Envelope(string type, string payloadJson)
        => "{\"type\":" + JsonSerializer.Serialize(type) + ",\"payload\":" +
           (string.IsNullOrWhiteSpace(payloadJson) ? "null" : payloadJson) + "}";

    /// <summary>Extrai <c>cmd</c> de uma mensagem da página; null se malformada.</summary>
    public static string? TryGetCommand(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind == JsonValueKind.Object &&
                   doc.RootElement.TryGetProperty("cmd", out var cmd) &&
                   cmd.ValueKind == JsonValueKind.String
                ? cmd.GetString()
                : null;
        }
        catch (JsonException) { return null; }
    }
}

/// <summary>
/// Fila de mensagens enquanto a página não está pronta. T6: uma mensagem que
/// falhava ao postar era reenfileirada mas nunca reenviada; agora o próximo
/// post (ou o Flush da navegação) drena a fila em ordem.
/// </summary>
internal sealed class WebMessageQueue
{
    private readonly Queue<string> _pending = new();
    private readonly object _lock = new();

    public int PendingCount { get { lock (_lock) return _pending.Count; } }

    /// <summary>
    /// Enfileira <paramref name="envelope"/> e tenta postar tudo em ordem com
    /// <paramref name="post"/> (false/exceção = para e mantém o restante).
    /// </summary>
    public void Post(string envelope, bool ready, Func<string, bool> post)
    {
        lock (_lock) _pending.Enqueue(envelope);
        if (ready) Flush(post);
    }

    public void Flush(Func<string, bool> post)
    {
        lock (_lock)
        {
            while (_pending.Count > 0)
            {
                bool ok;
                try { ok = post(_pending.Peek()); }
                catch { ok = false; }
                if (!ok) return;
                _pending.Dequeue();
            }
        }
    }
}
