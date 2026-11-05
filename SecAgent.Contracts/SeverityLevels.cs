namespace SecAgent.Contracts;

/// <summary>Vocabulário de severidade compartilhado (findings, eventos, incidentes, status).</summary>
public static class SeverityLevels
{
    public const string Info = "info";
    public const string Low = "low";
    public const string Medium = "medium";
    public const string High = "high";
    public const string Critical = "critical";
    public const string Unknown = "unknown";

    public const string Green = "green";
    public const string Yellow = "yellow";
    public const string Red = "red";

    /// <summary>Ordem para ordenar findings (critical primeiro). Desconhecido = 0.</summary>
    public static int Rank(string? severity) => Normalize(severity) switch
    {
        Critical => 4,
        High => 3,
        Medium => 2,
        Low => 1,
        _ => 0
    };

    /// <summary>Severidade de finding/incidente → cor agregada do status.json.</summary>
    public static string ToTrafficLight(string? severity) => Normalize(severity) switch
    {
        Critical or High => Red,
        Medium or Unknown => Yellow,
        _ => Green
    };

    /// <summary>A pior cor entre várias (red &gt; yellow &gt; green).</summary>
    public static string Worst(IEnumerable<string?> lights)
    {
        var list = lights.Select(Normalize).ToList();
        if (list.Contains(Red)) return Red;
        if (list.Contains(Yellow)) return Yellow;
        return Green;
    }

    private static string Normalize(string? s) => (s ?? "").Trim().ToLowerInvariant();
}
