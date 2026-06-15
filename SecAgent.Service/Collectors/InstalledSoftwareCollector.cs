using Microsoft.Win32;
using SecAgent.Service.Models;

namespace SecAgent.Service.Collectors;

public class InstalledSoftwareCollector
{
    private static readonly (RegistryHive Hive, RegistryView View, string Path, string Source)[] Roots =
    {
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM64"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM32"),
        (RegistryHive.CurrentUser,  RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU")
    };

    public List<SoftwareEntry> Collect()
    {
        var result = new List<SoftwareEntry>();

        foreach (var (hive, view, path, source) in Roots)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var key = root.OpenSubKey(path);
                if (key == null) continue;

                foreach (var subName in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(subName);
                    if (sub == null) continue;

                    var name = sub.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(name)) continue;

                    result.Add(new SoftwareEntry(
                        name,
                        sub.GetValue("DisplayVersion") as string,
                        sub.GetValue("Publisher") as string,
                        sub.GetValue("InstallDate") as string,
                        source));
                }
            }
            catch { /* skip inaccessible roots */ }
        }

        return result
            .GroupBy(s => (s.Name, s.Version))
            .Select(g => g.First())
            .OrderBy(s => s.Name)
            .ToList();
    }
}
