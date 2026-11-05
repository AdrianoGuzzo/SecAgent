using System.Diagnostics.CodeAnalysis;
using Microsoft.Win32;
using SecAgent.Service.Models;

namespace SecAgent.Service.Platform;

/// <summary>Lê as entradas cruas das chaves Uninstall do registro.</summary>
public interface IUninstallRegistry
{
    IEnumerable<SoftwareEntry> ReadEntries();
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino do registro")]
internal sealed class RegistryUninstallReader : IUninstallRegistry
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    // Obs.: como LocalSystem, HKCU é a hive do SYSTEM (não a do usuário logado).
    private static readonly (RegistryHive Hive, RegistryView View, string Source)[] Roots =
    {
        (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM64"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM32"),
        (RegistryHive.CurrentUser,  RegistryView.Registry64, "HKCU")
    };

    public IEnumerable<SoftwareEntry> ReadEntries()
    {
        var result = new List<SoftwareEntry>();
        foreach (var (hive, view, source) in Roots)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var key = root.OpenSubKey(UninstallPath);
                if (key == null) continue;

                foreach (var subName in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(subName);
                    if (sub == null) continue;
                    result.Add(new SoftwareEntry(
                        sub.GetValue("DisplayName") as string ?? "",
                        sub.GetValue("DisplayVersion") as string,
                        sub.GetValue("Publisher") as string,
                        sub.GetValue("InstallDate") as string,
                        source));
                }
            }
            catch { /* raiz inacessível — ignora */ }
        }
        return result;
    }
}
