using System.Text;

namespace SecAgent.Tray.Core;

/// <summary>Ícone lógico; o glue mapeia para SystemIcons.</summary>
public enum TrayIconKind { Busy, Shield, Warning, Error }

/// <summary>Toast a exibir (o glue mapeia <see cref="IsWarning"/>/<see cref="IsError"/> para ToolTipIcon).</summary>
public sealed record TrayToast(string Title, string Text, bool IsWarning = false, bool IsError = false);

/// <summary>
/// Regras de apresentação do ícone da bandeja (puro, sem WinForms):
/// ícone por severidade, tooltips (limite de 127 chars do NotifyIcon), toasts
/// de relatório/scan/alerta e detecção de progress.json órfão.
/// </summary>
internal static class TrayStatePresenter
{
    public const int MaxTooltip = 127;
    public const string AppName = "SecAgent";

    /// <summary>
    /// T3: se o Service morre no meio de um scan, progress.json fica no disco e o
    /// ícone ficava "ocupado" para sempre. Scan leva segundos e a análise tem
    /// timeout de 5 min — qualquer progresso mais velho que isto é órfão.
    /// </summary>
    public static readonly TimeSpan StaleProgressAfter = TimeSpan.FromMinutes(15);

    public static string Truncate(string s) => s.Length > MaxTooltip ? s[..MaxTooltip] : s;

    public static TrayIconKind SeverityIcon(AgentStatus? status) =>
        (status?.OverallSeverity ?? "").Trim().ToLowerInvariant() switch
        {
            SeverityLevels.Red => TrayIconKind.Error,
            SeverityLevels.Yellow => TrayIconKind.Warning,
            _ => status is null ? TrayIconKind.Busy : TrayIconKind.Shield
        };

    public static string StatusTooltip(AgentStatus? s, Func<DateTime, DateTime>? toLocal = null)
    {
        if (s is null) return "SecAgent (sem status ainda)";
        toLocal ??= d => d.ToLocalTime();
        var sb = new StringBuilder(AppName);
        if (s.LastScan is { } scan)
            sb.Append($"\nScan: {scan.RiskLevel} ({scan.FindingsCount} findings, {toLocal(scan.TimestampUtc):HH:mm})");
        if (s.LastIncident is { } inc)
            sb.Append($"\nIncidente: {inc.Severity} ({toLocal(inc.TimestampUtc):HH:mm})");
        return Truncate(sb.ToString());
    }

    // T7: os dois ramos do ternário antigo eram idênticos.
    public static string ProgressTooltip(AnalysisProgress p, DateTime nowUtc)
    {
        var elapsed = Math.Max(0, (int)(nowUtc - p.StartedAtUtc).TotalSeconds);
        return Truncate($"SecAgent — {p.Step}... {elapsed}s");
    }

    public static bool IsStale(AnalysisProgress p, DateTime nowUtc) => nowUtc - p.StartedAtUtc > StaleProgressAfter;

    /// <summary>Toast de transição scanning → analyzing (null se não houver transição).</summary>
    public static TrayToast? TransitionToast(string? previousState, AnalysisProgress current)
        => previousState == AnalysisProgress.Scanning && current.State == AnalysisProgress.Analyzing
            ? new TrayToast(AppName, $"Scan concluído. {current.Step}, aguarde ~1 min...")
            : null;

    public static TrayToast ReportToast(string? fileName)
    {
        var name = fileName ?? "";
        bool incident = name.StartsWith("incident_", StringComparison.OrdinalIgnoreCase);
        return incident
            ? new TrayToast("SecAgent: novo incidente detectado", name, IsWarning: true)
            : new TrayToast("SecAgent: novo relatório de scan", name);
    }

    /// <summary>
    /// Só avisa de scan-only: no scan+análise o progresso vira "analyzing" e o
    /// toast do relatório final cobre o caso (evita toast duplo).
    /// </summary>
    public static TrayToast? ScanToast(string? fileName, AnalysisProgress? current)
        => current is null || current.State == AnalysisProgress.Scanning
            ? new TrayToast(AppName, "Snapshot capturado: " + (fileName ?? ""))
            : null;

    public static TrayToast AlertToast(NetworkAlert alert, string? country, string? countryCode)
    {
        var loc = country is null ? "" : $"{Flag(countryCode)} {country}".Trim() + " · ";
        bool critical = string.Equals(alert.Severity, SeverityLevels.Critical, StringComparison.OrdinalIgnoreCase);
        return new TrayToast("SecAgent: " + alert.Title, loc + alert.Message, IsWarning: !critical, IsError: critical);
    }

    /// <summary>Código de país de 2 letras → emoji de bandeira; 🌐 se inválido.</summary>
    public static string Flag(string? cc)
    {
        if (string.IsNullOrEmpty(cc) || cc.Length != 2) return "🌐";
        cc = cc.ToUpperInvariant();
        if (cc[0] is < 'A' or > 'Z' || cc[1] is < 'A' or > 'Z') return "🌐";
        return char.ConvertFromUtf32(0x1F1E6 + (cc[0] - 'A')) +
               char.ConvertFromUtf32(0x1F1E6 + (cc[1] - 'A'));
    }
}
