using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;

namespace SecAgent.Tray;

/// <summary>
/// Resolves remote IPs to country/city/ISP via ip-api.com, with an on-disk
/// cache and rate limiting. Lookups run on a single background worker so the UI
/// never blocks; results are surfaced via the <see cref="Resolved"/> event so
/// table cells can update in place.
///
/// Lives in the Tray (user session), NOT the LocalSystem service, so the
/// security daemon itself makes no outbound web calls.
/// </summary>
public sealed class GeoLookup : IDisposable
{
    public record GeoInfo(string Country, string CountryCode, string City, string Isp);

    private record CacheEntry(GeoInfo Info, DateTime CachedAtUtc);

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(4) };
    private static readonly TimeSpan SuccessTtl = TimeSpan.FromDays(7);
    private static readonly TimeSpan NegativeTtl = TimeSpan.FromHours(1);
    private const int MaxPerMinute = 40;                     // ip-api free tier is ~45/min

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly string _cachePath;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private readonly Channel<string> _queue = Channel.CreateUnbounded<string>();
    private readonly HashSet<string> _queued = new();
    private readonly object _queueLock = new();
    private readonly Queue<DateTime> _callTimes = new();
    private readonly SemaphoreSlim _throttleSem = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private DateTime _lastFlushUtc = DateTime.MinValue;

    /// <summary>Raised (on a worker thread) when an IP resolves.</summary>
    public event Action<string, GeoInfo>? Resolved;

    public GeoLookup()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecAgent");
        Directory.CreateDirectory(dir);
        _cachePath = Path.Combine(dir, "geo-cache.json");
        LoadCache();
        _ = Task.Run(WorkerLoop);
    }

    /// <summary>Returns a fresh cached value if available, else null.</summary>
    public GeoInfo? TryGetCached(string ip)
    {
        if (_cache.TryGetValue(ip, out var e) && !IsExpired(e))
            return e.Info;
        return null;
    }

    /// <summary>
    /// Resolves an IP right now (cache hit = instant), bounded by a short timeout
    /// so a caller on the alert path isn't blocked by the rate limiter. Returns
    /// null if it can't resolve in time.
    /// </summary>
    public async Task<GeoInfo?> ResolveNowAsync(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return null;
        if (TryGetCached(ip) is { } cached) return cached;

        using var to = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
        to.CancelAfter(TimeSpan.FromSeconds(3.5));
        try
        {
            await ThrottleAsync(to.Token);
            var info = await FetchAsync(ip, to.Token);
            if (info is not null)
            {
                _cache[ip] = new CacheEntry(info, DateTime.UtcNow);
                Resolved?.Invoke(ip, info);
                MaybeFlush();
            }
            return info;
        }
        catch { return null; }
    }

    /// <summary>Schedules a lookup for a public IP (no-op if already fresh/queued).</summary>
    public void QueueLookup(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return;
        if (TryGetCached(ip) is not null) return;

        lock (_queueLock)
        {
            if (!_queued.Add(ip)) return;
        }
        _queue.Writer.TryWrite(ip);
    }

    private async Task WorkerLoop()
    {
        try
        {
            await foreach (var ip in _queue.Reader.ReadAllAsync(_cts.Token))
            {
                lock (_queueLock) { _queued.Remove(ip); }

                if (TryGetCached(ip) is { } cached)
                {
                    Resolved?.Invoke(ip, cached);
                    continue;
                }

                await ThrottleAsync(_cts.Token);
                var info = await FetchAsync(ip, _cts.Token);
                if (info is not null)
                {
                    _cache[ip] = new CacheEntry(info, DateTime.UtcNow);
                    Resolved?.Invoke(ip, info);
                    MaybeFlush();
                }
            }
        }
        catch (OperationCanceledException) { /* shutdown */ }
        catch { /* never crash the worker */ }
    }

    private async Task ThrottleAsync(CancellationToken ct)
    {
        // Serialized across the worker and the alert path; sliding 60s window cap.
        await _throttleSem.WaitAsync(ct);
        try
        {
            var now = DateTime.UtcNow;
            while (_callTimes.Count > 0 && now - _callTimes.Peek() > TimeSpan.FromMinutes(1))
                _callTimes.Dequeue();

            if (_callTimes.Count >= MaxPerMinute)
            {
                var wait = TimeSpan.FromMinutes(1) - (now - _callTimes.Peek());
                if (wait > TimeSpan.Zero) await Task.Delay(wait, ct);
            }
            _callTimes.Enqueue(DateTime.UtcNow);
        }
        finally { _throttleSem.Release(); }
    }

    private async Task<GeoInfo?> FetchAsync(string ip, CancellationToken ct)
    {
        try
        {
            var url = $"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,query";
            var resp = await Http.GetFromJsonAsync<IpApiResponse>(url, JsonOpts, ct);
            if (resp is { Status: "success" })
            {
                return new GeoInfo(
                    Country: resp.Country ?? "Desconhecido",
                    CountryCode: resp.CountryCode ?? "",
                    City: resp.City ?? "",
                    Isp: resp.Isp ?? "");
            }
            // Negative-cache failures (e.g. rate limit / reserved range) briefly.
            _cache[ip] = new CacheEntry(new GeoInfo("Desconhecido", "", "", ""), DateTime.UtcNow.AddHours(-(SuccessTtl - NegativeTtl).TotalHours));
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsExpired(CacheEntry e) => DateTime.UtcNow - e.CachedAtUtc > SuccessTtl;

    private void LoadCache()
    {
        try
        {
            if (!File.Exists(_cachePath)) return;
            var dict = JsonSerializer.Deserialize<Dictionary<string, CacheEntry>>(
                File.ReadAllText(_cachePath), JsonOpts);
            if (dict is null) return;
            foreach (var kv in dict)
                if (!IsExpired(kv.Value)) _cache[kv.Key] = kv.Value;
        }
        catch { /* corrupt cache → start fresh */ }
    }

    private void MaybeFlush()
    {
        if (DateTime.UtcNow - _lastFlushUtc < TimeSpan.FromSeconds(20)) return;
        Flush();
    }

    private void Flush()
    {
        try
        {
            _lastFlushUtc = DateTime.UtcNow;
            var snapshot = new Dictionary<string, CacheEntry>(_cache);
            File.WriteAllText(_cachePath, JsonSerializer.Serialize(snapshot, JsonOpts));
        }
        catch { /* best effort */ }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        Flush();
        _cts.Dispose();
        _throttleSem.Dispose();
    }

    private record IpApiResponse(
        string? Status,
        string? Country,
        string? CountryCode,
        string? City,
        string? Isp,
        string? Query);
}
