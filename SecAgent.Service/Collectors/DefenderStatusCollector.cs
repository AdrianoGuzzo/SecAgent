using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Collectors;

/// <summary>Status do Microsoft Defender via WMI <c>MSFT_MpComputerStatus</c>.</summary>
public class DefenderStatusCollector
{
    private readonly IWmiQuery _wmi;

    public DefenderStatusCollector(IWmiQuery wmi) => _wmi = wmi;

    public DefenderStatus Collect()
    {
        var obj = _wmi.Query(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus")
            .FirstOrDefault();
        if (obj is null) return new DefenderStatus(null, null, null, null, null, null);

        return new DefenderStatus(
            AntivirusEnabled:              WmiValues.GetBool(obj, "AntivirusEnabled"),
            RealTimeProtectionEnabled:     WmiValues.GetBool(obj, "RealTimeProtectionEnabled"),
            IsTamperProtected:             WmiValues.GetBool(obj, "IsTamperProtected"),
            AntivirusSignatureVersion:     WmiValues.GetString(obj, "AntivirusSignatureVersion"),
            AntivirusSignatureLastUpdated: WmiValues.GetDate(obj, "AntivirusSignatureLastUpdated"),
            EngineVersion:                 WmiValues.GetString(obj, "AMEngineVersion"));
    }
}
