using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace SecAgent.Service.Tests.Helpers;

/// <summary>Diretório temporário isolado por teste; apagado no Dispose.</summary>
public sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "secagent-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public AgentPaths Paths => new(Path);

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch { /* best effort */ }
    }
}

public static class Test
{
    public static readonly DateTimeOffset T0 = new(2026, 3, 15, 12, 30, 45, TimeSpan.Zero);

    public static FakeTimeProvider Clock(DateTimeOffset? start = null) => new(start ?? T0);

    public static IOptions<T> Opts<T>(T value) where T : class => Options.Create(value);

    public static ILogger<T> Log<T>() => NullLogger<T>.Instance;

    public static SecurityEvent Event(DateTime ts, string severity = "medium", string title = "t")
        => new(ts, "test", severity, title, "desc", new Dictionary<string, string> { ["k"] = "v" });

    public static AnalysisMeta Meta(string model = "sonnet", string? effort = "high") =>
        new(model, 1234, 10, 20, 30, 40, 0.05m, "sess", false, effort);

    /// <summary>Espera uma condição assíncrona (para trabalho em background).</summary>
    public static async Task Eventually(Func<bool> condition, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("Condição não satisfeita a tempo");
            await Task.Delay(10);
        }
    }
}
