namespace SecAgent.Tray.Core;

public enum DashboardCommandKind
{
    Unknown,
    ScanOnly,
    ScanAndAnalyze,
    BlockIp,
    UnblockIp,
    ConfigureToken
}

/// <summary>Comando vindo da página (chrome.webview.postMessage({cmd})).</summary>
/// <param name="Model">Só em ScanAndAnalyze com escolha explícita (normalizado); null = usar a última escolha salva.</param>
/// <param name="Ip">Só em Block/Unblock (cru, validado pelo Service).</param>
public sealed record DashboardCommand(DashboardCommandKind Kind, string? Model = null, string? Effort = null, string? Ip = null)
{
    public static readonly DashboardCommand Unknown = new(DashboardCommandKind.Unknown);
}

/// <summary>
/// Interpreta os comandos do painel:
/// <c>scanOnly</c>, <c>configureToken</c>, <c>scanAndAnalyze</c>,
/// <c>scanAndAnalyze:&lt;model&gt;:&lt;effort&gt;</c>, <c>blockIp:&lt;ip&gt;</c>, <c>unblockIp:&lt;ip&gt;</c>.
/// </summary>
internal static class DashboardCommandParser
{
    private const string AnalyzePrefix = "scanAndAnalyze:";
    private const string BlockPrefix = "blockIp:";
    private const string UnblockPrefix = "unblockIp:";

    public static DashboardCommand Parse(string? cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return DashboardCommand.Unknown;

        switch (cmd)
        {
            case "scanOnly": return new(DashboardCommandKind.ScanOnly);
            case "configureToken": return new(DashboardCommandKind.ConfigureToken);
            case "scanAndAnalyze": return new(DashboardCommandKind.ScanAndAnalyze);
        }

        if (cmd.StartsWith(AnalyzePrefix, StringComparison.Ordinal))
        {
            var parts = cmd.Split(':');
            return new(DashboardCommandKind.ScanAndAnalyze,
                Model: AiModels.NormalizeModel(parts.Length > 1 ? parts[1] : null),
                Effort: AiModels.NormalizeEffort(parts.Length > 2 ? parts[2] : null));
        }

        // IPv6 tem ':' — por isso só o PRIMEIRO ':' separa o comando do IP.
        if (cmd.StartsWith(BlockPrefix, StringComparison.Ordinal))
            return IpCommand(DashboardCommandKind.BlockIp, cmd[BlockPrefix.Length..]);
        if (cmd.StartsWith(UnblockPrefix, StringComparison.Ordinal))
            return IpCommand(DashboardCommandKind.UnblockIp, cmd[UnblockPrefix.Length..]);

        return DashboardCommand.Unknown;
    }

    private static DashboardCommand IpCommand(DashboardCommandKind kind, string ip)
    {
        ip = ip.Trim();
        return ip.Length == 0 ? DashboardCommand.Unknown : new(kind, Ip: ip);
    }
}
