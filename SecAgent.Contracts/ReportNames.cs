using System.Globalization;

namespace SecAgent.Contracts;

/// <summary>
/// Nomes dos arquivos gerados pelo Service. Centralizado porque o mesmo nome
/// era montado em dois lugares (ClaudeAnalyzer grava; StatusFileService aponta)
/// e os dois podiam divergir.
/// </summary>
public static class ReportNames
{
    public const string TimestampFormat = "yyyy-MM-dd_HHmmss";

    public static string Stamp(DateTime utc) => utc.ToString(TimestampFormat, CultureInfo.InvariantCulture);

    public static string ScanFile(DateTime utc) => $"scan_{Stamp(utc)}.json";

    public static string ScanReportJson(DateTime utc) => $"report_{Stamp(utc)}.json";
    public static string ScanReportMarkdown(DateTime utc) => $"report_{Stamp(utc)}.md";

    public static string IncidentJson(DateTime utc) => $"incident_{Stamp(utc)}.json";
    public static string IncidentMarkdown(DateTime utc) => $"incident_{Stamp(utc)}.md";
    public static string IncidentEvents(DateTime utc) => $"incident_{Stamp(utc)}.events.json";

    public static string FailedRaw(string kind, DateTime utc) => $"{kind}_FAILED_{Stamp(utc)}.raw.txt";

    public static string EventsJsonl(DateTime utc)
        => $"events_{utc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}.jsonl";

    public static string Alert(DateTime utc, int seq)
        => $"alert_{utc.ToString("yyyy-MM-dd_HHmmssfff", CultureInfo.InvariantCulture)}_{seq}.json";
}
