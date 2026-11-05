using System.Globalization;
using System.Management;

namespace SecAgent.Service.Collectors;

/// <summary>Conversões de valores crus do WMI, independentes da cultura da máquina.</summary>
internal static class WmiValues
{
    public static string? GetString(IReadOnlyDictionary<string, object?> obj, string name)
        => obj.TryGetValue(name, out var v) ? v as string : null;

    public static bool? GetBool(IReadOnlyDictionary<string, object?> obj, string name)
        => obj.TryGetValue(name, out var v) && v is bool b ? b : null;

    public static bool GetFlag(IReadOnlyDictionary<string, object?> obj, string name)
        => GetBool(obj, name) ?? false;

    /// <summary>
    /// Datas do WMI chegam como DateTime, string DMTF ("20240115103000.000000+000")
    /// ou texto livre. O parse livre usa InvariantCulture — com a cultura atual,
    /// uma máquina pt-BR lia "1/15/2024" errado (ou nem lia).
    /// </summary>
    public static DateTime? GetDate(IReadOnlyDictionary<string, object?> obj, string name)
    {
        if (!obj.TryGetValue(name, out var v) || v is null) return null;
        if (v is DateTime dt) return dt;

        var s = v.ToString()!.Trim();
        if (s.Length == 0) return null;

        if (LooksLikeDmtf(s))
        {
            try { return ManagementDateTimeConverter.ToDateTime(s); }
            catch { /* cai para o parse livre */ }
        }

        return DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : null;
    }

    private static bool LooksLikeDmtf(string s)
        => s.Length >= 14 && s.Take(14).All(char.IsDigit);

    private static readonly string[] HotfixFormats =
    {
        "M/d/yyyy", "MM/dd/yyyy", "M/d/yyyy h:mm:ss tt", "yyyyMMdd", "yyyy-MM-dd"
    };

    /// <summary>
    /// <c>Win32_QuickFixEngineering.InstalledOn</c> é string em formato US
    /// ("1/15/2024") independentemente do idioma do Windows.
    /// </summary>
    public static DateTime? ParseHotfixDate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        return DateTime.TryParseExact(raw.Trim(), HotfixFormats, CultureInfo.InvariantCulture,
            DateTimeStyles.None, out var d)
            ? d
            : null;
    }

    /// <summary>MSFT_NetFirewallProfile.Enabled é GpoBoolean (ushort: 0 False, 1 True, 2 NotConfigured) ou bool.</summary>
    public static bool ParseGpoBoolean(object? value) => value switch
    {
        bool b => b,
        ushort u => u == 1,
        int i => i == 1,
        byte by => by == 1,
        _ => false
    };

    /// <summary>MSFT_NetFirewallProfile.Default*Action: 0 NotConfigured, 2 Allow, 4 Block.</summary>
    public static string? MapFirewallDefaultAction(object? value)
    {
        if (value is null) return null;
        if (!int.TryParse(Convert.ToString(value, CultureInfo.InvariantCulture), out var n))
            return value.ToString();
        return n switch
        {
            0 => "NotConfigured",
            2 => "Allow",
            4 => "Block",
            _ => $"Action{n}"
        };
    }

    /// <summary>Escapa um literal para uso entre aspas simples em WQL.</summary>
    public static string EscapeWql(string s) => s.Replace("\\", "\\\\").Replace("'", "\\'");
}
