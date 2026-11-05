using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;

namespace SecAgent.Tray;

public record GeoInfo(string Country, string CountryCode, string City, string Isp);

public interface IGeoLookup
{
    /// <summary>Disparado (em thread de worker) quando um IP é resolvido.</summary>
    event Action<string, GeoInfo>? Resolved;

    GeoInfo? TryGetCached(string ip);
    void QueueLookup(string ip);
    Task<GeoInfo?> ResolveNowAsync(string ip);
}

/// <summary>
/// Resolve IPs remotos em país/cidade/ISP via ip-api.com, com cache em disco e
/// rate limit. As consultas rodam num único worker em background (a UI nunca
/// bloqueia); resultados saem pelo evento <see cref="Resolved"/>.
///
/// Fica no Tray (sessão do usuário), NÃO no serviço LocalSystem: o daemon de
/// segurança não faz chamadas web de saída.
///
/// T5:
///  - IP validado com <see cref="IPAddress.TryParse(string, out IPAddress)"/> antes de ir para a URL.
///  - Falhas ficam num cache NEGATIVO só em memória (antes viravam "Desconhecido",
///    eram exibidas como se fossem um país e persistidas em disco).
///  - Flush serializado por lock (worker e caminho de alerta corriam juntos).
///  - Dispose cancela e AGUARDA o worker antes do flush final.
/// </summary>
public sealed class GeoLookup : IGeoLookup, IDisposable
{
    private sealed record CacheEntry(GeoInfo Info, DateTime CachedAtUtc);

    internal static readonly TimeSpan SuccessTtl = TimeSpan.FromDays(7);
    internal static readonly TimeSpan NegativeTtl = TimeSpan.FromHours(1);
    internal static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(20);
    internal const int MaxPerMinute = 40;   // free tier do ip-api é ~45/min

    private readonly HttpClient _http;
    private readonly TimeProvider _time;
    private readonly string _cachePath;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private readonly ConcurrentDictionary<string, DateTime> _negativeUntil = new();
    private readonly Channel<string> _queue = Channel.CreateUnbounded<string>();
    private readonly HashSet<string> _queued = new();
    private readonly object _queueLock = new();
    private readonly object _flushLock = new();
    private readonly Queue<DateTime> _callTimes = new();
    private readonly SemaphoreSlim _throttle = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _worker;
    private DateTime _lastFlushUtc = DateTime.MinValue;
    private int _disposed;

    public event Action<string, GeoInfo>? Resolved;

    public GeoLookup() : this(DefaultCachePath(), null, TimeProvider.System, startWorker: true) { }

    internal GeoLookup(string cachePath, HttpMessageHandler? handler, TimeProvider time, bool startWorker)
    {
        _cachePath = cachePath;
        _time = time;
        _http = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: false);
        _http.Timeout = TimeSpan.FromSeconds(4);
        LoadCache();
        _worker = startWorker ? Task.Run(WorkerLoop) : Task.CompletedTask;
    }

    private static string DefaultCachePath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecAgent", "geo-cache.json");

    private DateTime UtcNow => _time.GetUtcNow().UtcDateTime;

    /// <summary>Normaliza e valida o IP; null se não for um endereço IP.</summary>
    internal static string? NormalizeIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return null;
        if (!IPAddress.TryParse(ip.Trim(), out var addr)) return null;
        if (addr.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)) return null;
        return addr.ToString();
    }

    public GeoInfo? TryGetCached(string ip)
    {
        var key = NormalizeIp(ip);
        return key is not null && _cache.TryGetValue(key, out var e) && !IsExpired(e) ? e.Info : null;
    }

    private bool IsNegative(string key)
        => _negativeUntil.TryGetValue(key, out var until) && UtcNow < until;

    public void QueueLookup(string ip)
    {
        var key = NormalizeIp(ip);
        if (key is null || TryGetCached(key) is not null || IsNegative(key)) return;
        lock (_queueLock)
        {
            if (!_queued.Add(key)) return;
        }
        _queue.Writer.TryWrite(key);
    }

    /// <summary>
    /// Resolve agora (cache = instantâneo), com timeout curto para o caminho do
    /// toast de alerta não ficar preso no rate limiter. Null se não resolver a tempo.
    /// </summary>
    public async Task<GeoInfo?> ResolveNowAsync(string ip)
    {
        var key = NormalizeIp(ip);
        if (key is null) return null;
        if (TryGetCached(key) is { } cached) return cached;
        if (IsNegative(key)) return null;

        using var to = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
        to.CancelAfter(TimeSpan.FromSeconds(3.5));
        try { return await LookupAsync(key, to.Token); }
        catch (OperationCanceledException) { return null; }
    }

    internal async Task WorkerLoop()
    {
        try
        {
            await foreach (var key in _queue.Reader.ReadAllAsync(_cts.Token))
            {
                lock (_queueLock) _queued.Remove(key);
                if (TryGetCached(key) is { } cached) { Resolved?.Invoke(key, cached); continue; }
                if (IsNegative(key)) continue;
                try { await LookupAsync(key, _cts.Token); }
                catch (OperationCanceledException) when (_cts.IsCancellationRequested) { throw; }
                catch (Exception) { /* nunca derruba o worker */ }
            }
        }
        catch (OperationCanceledException) { /* shutdown */ }
    }

    /// <summary>Processa a fila até esvaziar (testes, sem worker em background).</summary>
    internal async Task DrainQueueAsync()
    {
        while (_queue.Reader.TryRead(out var key))
        {
            lock (_queueLock) _queued.Remove(key);
            if (TryGetCached(key) is { } cached) { Resolved?.Invoke(key, cached); continue; }
            if (!IsNegative(key)) await LookupAsync(key, _cts.Token);
        }
    }

    private async Task<GeoInfo?> LookupAsync(string key, CancellationToken ct)
    {
        await ThrottleAsync(ct);
        var info = await FetchAsync(key, ct);
        if (info is null)
        {
            _negativeUntil[key] = UtcNow + NegativeTtl;   // só em memória
            return null;
        }
        _negativeUntil.TryRemove(key, out _);
        _cache[key] = new CacheEntry(info, UtcNow);
        Resolved?.Invoke(key, info);
        MaybeFlush();
        return info;
    }

    private async Task ThrottleAsync(CancellationToken ct)
    {
        // Serializado entre worker e caminho de alerta; janela deslizante de 60s.
        await _throttle.WaitAsync(ct);
        try
        {
            var now = UtcNow;
            while (_callTimes.Count > 0 && now - _callTimes.Peek() > TimeSpan.FromMinutes(1))
                _callTimes.Dequeue();
            if (_callTimes.Count >= MaxPerMinute)
            {
                var wait = TimeSpan.FromMinutes(1) - (now - _callTimes.Peek());
                if (wait > TimeSpan.Zero) await Task.Delay(wait, _time, ct);
                _callTimes.Dequeue();
            }
            _callTimes.Enqueue(UtcNow);
        }
        finally { _throttle.Release(); }
    }

    private async Task<GeoInfo?> FetchAsync(string key, CancellationToken ct)
    {
        try
        {
            var url = $"http://ip-api.com/json/{Uri.EscapeDataString(key)}?fields=status,country,countryCode,city,isp,query";
            var resp = await _http.GetFromJsonAsync<IpApiResponse>(url, JsonDefaults.Read, ct);
            return resp is { Status: "success" }
                ? new GeoInfo(resp.Country ?? "Desconhecido", resp.CountryCode ?? "", resp.City ?? "", resp.Isp ?? "")
                : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return null; }   // rede/timeout/JSON → negativo
    }

    private bool IsExpired(CacheEntry e) => UtcNow - e.CachedAtUtc > SuccessTtl;

    private void LoadCache()
    {
        try
        {
            if (!File.Exists(_cachePath)) return;
            var dict = JsonSerializer.Deserialize<Dictionary<string, CacheEntry>>(File.ReadAllText(_cachePath), JsonDefaults.Read);
            if (dict is null) return;
            foreach (var kv in dict)
                if (NormalizeIp(kv.Key) is { } key && kv.Value?.Info is not null && !IsExpired(kv.Value))
                    _cache[key] = kv.Value;
        }
        catch (Exception) { /* cache corrompido → começa do zero */ }
    }

    private void MaybeFlush()
    {
        if (UtcNow - _lastFlushUtc < FlushInterval) return;
        Flush();
    }

    internal void Flush()
    {
        lock (_flushLock)
        {
            try
            {
                _lastFlushUtc = UtcNow;
                var snapshot = _cache.ToDictionary(kv => kv.Key, kv => kv.Value);
                AtomicFile.WriteAllText(_cachePath, JsonSerializer.Serialize(snapshot, JsonDefaults.Compact));
            }
            catch (Exception) { /* best effort */ }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        try { _cts.Cancel(); } catch { }
        _queue.Writer.TryComplete();
        try { _worker.Wait(TimeSpan.FromSeconds(2)); } catch { /* cancelado */ }
        Flush();
        _cts.Dispose();
        _throttle.Dispose();
        _http.Dispose();
    }

    private sealed record IpApiResponse(
        [property: JsonPropertyName("status")] string? Status,
        [property: JsonPropertyName("country")] string? Country,
        [property: JsonPropertyName("countryCode")] string? CountryCode,
        [property: JsonPropertyName("city")] string? City,
        [property: JsonPropertyName("isp")] string? Isp);
}
