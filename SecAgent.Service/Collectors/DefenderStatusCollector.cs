using System.Management;
using SecAgent.Service.Models;

namespace SecAgent.Service.Collectors;

public class DefenderStatusCollector
{
    public DefenderStatus Collect()
    {
        using var searcher = new ManagementObjectSearcher(
            @"root\Microsoft\Windows\Defender",
            "SELECT * FROM MSFT_MpComputerStatus");

        foreach (ManagementObject obj in searcher.Get())
        {
            return new DefenderStatus(
                AntivirusEnabled:               GetBool(obj, "AntivirusEnabled"),
                RealTimeProtectionEnabled:      GetBool(obj, "RealTimeProtectionEnabled"),
                IsTamperProtected:              GetBool(obj, "IsTamperProtected"),
                AntivirusSignatureVersion:      obj["AntivirusSignatureVersion"] as string,
                AntivirusSignatureLastUpdated:  GetDate(obj, "AntivirusSignatureLastUpdated"),
                EngineVersion:                  obj["AMEngineVersion"] as string
            );
        }

        return new DefenderStatus(null, null, null, null, null, null);
    }

    private static bool? GetBool(ManagementObject obj, string name)
        => obj[name] is bool b ? b : null;

    private static DateTime? GetDate(ManagementObject obj, string name)
    {
        var v = obj[name];
        if (v is DateTime dt) return dt;
        if (v is string s && DateTime.TryParse(s, out var parsed)) return parsed;
        try
        {
            if (v != null) return ManagementDateTimeConverter.ToDateTime(v.ToString()!);
        }
        catch { }
        return null;
    }
}
