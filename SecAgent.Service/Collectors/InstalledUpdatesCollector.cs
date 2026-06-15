using System.Management;
using SecAgent.Service.Models;

namespace SecAgent.Service.Collectors;

public class InstalledUpdatesCollector
{
    public List<UpdateEntry> Collect()
    {
        var result = new List<UpdateEntry>();

        using var searcher = new ManagementObjectSearcher(
            @"root\cimv2",
            "SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering");

        foreach (ManagementObject obj in searcher.Get())
        {
            var id = obj["HotFixID"] as string ?? "";
            if (string.IsNullOrEmpty(id)) continue;

            DateTime? installedOn = null;
            if (obj["InstalledOn"] is string raw && DateTime.TryParse(raw, out var parsed))
                installedOn = parsed;

            result.Add(new UpdateEntry(
                id,
                obj["Description"] as string,
                installedOn,
                obj["InstalledBy"] as string));
        }

        return result.OrderByDescending(u => u.InstalledOn ?? DateTime.MinValue).ToList();
    }
}
