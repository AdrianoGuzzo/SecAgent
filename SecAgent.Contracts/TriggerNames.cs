namespace SecAgent.Contracts;

/// <summary>
/// Nomes dos arquivos <c>triggers/*.trigger</c> (Tray → Service). Antes eram
/// constantes duplicadas no TriggerWatcher e no TrayApplicationContext.
/// </summary>
public static class TriggerNames
{
    public const string Extension = ".trigger";
    public const string ScanOnly = "scan-only.trigger";
    public const string ScanAndAnalyze = "scan-and-analyze.trigger";
    public const string BlockIpPrefix = "block-ip-";
    public const string UnblockIpPrefix = "unblock-ip-";

    /// <summary>Nome do trigger de bloqueio; o IP bruto viaja no CONTEÚDO do arquivo.</summary>
    public static string BlockIp(string ip) => BlockIpPrefix + SanitizeForFileName(ip) + Extension;

    /// <summary>Nome do trigger de desbloqueio; o IP bruto viaja no CONTEÚDO do arquivo.</summary>
    public static string UnblockIp(string ip) => UnblockIpPrefix + SanitizeForFileName(ip) + Extension;

    /// <summary>
    /// IPv6 tem ':' / '%' (ilegais em nomes de arquivo no Windows). A forma
    /// sanitizada serve só para o NOME; o Service valida o IP do conteúdo.
    /// </summary>
    public static string SanitizeForFileName(string? ip)
        => (ip ?? "").Replace(':', '-').Replace('%', '-').Replace('/', '-').Replace('\\', '-');

    public static bool IsBlockIp(string name)
        => name.StartsWith(BlockIpPrefix, StringComparison.OrdinalIgnoreCase)
           && name.EndsWith(Extension, StringComparison.OrdinalIgnoreCase);

    public static bool IsUnblockIp(string name)
        => name.StartsWith(UnblockIpPrefix, StringComparison.OrdinalIgnoreCase)
           && name.EndsWith(Extension, StringComparison.OrdinalIgnoreCase);

    /// <summary>True para os nomes que o Service sabe processar.</summary>
    public static bool IsKnown(string name)
        => string.Equals(name, ScanOnly, StringComparison.OrdinalIgnoreCase)
           || string.Equals(name, ScanAndAnalyze, StringComparison.OrdinalIgnoreCase)
           || IsBlockIp(name)
           || IsUnblockIp(name);
}
