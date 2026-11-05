using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Collectors;

/// <summary>Hotfixes instalados via WMI <c>Win32_QuickFixEngineering</c>.</summary>
public class InstalledUpdatesCollector
{
    private readonly IWmiQuery _wmi;

    public InstalledUpdatesCollector(IWmiQuery wmi) => _wmi = wmi;

    public List<UpdateEntry> Collect()
    {
        var result = new List<UpdateEntry>();

        foreach (var obj in _wmi.Query(@"root\cimv2",
                     "SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering"))
        {
            var id = WmiValues.GetString(obj, "HotFixID");
            if (string.IsNullOrEmpty(id)) continue;

            result.Add(new UpdateEntry(
                id,
                WmiValues.GetString(obj, "Description"),
                WmiValues.ParseHotfixDate(WmiValues.GetString(obj, "InstalledOn")),
                WmiValues.GetString(obj, "InstalledBy")));
        }

        return result.OrderByDescending(u => u.InstalledOn ?? DateTime.MinValue).ToList();
    }
}
