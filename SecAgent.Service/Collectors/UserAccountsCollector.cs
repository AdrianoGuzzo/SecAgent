using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Collectors;

/// <summary>Contas locais e membros do grupo Administradores via WMI.</summary>
public class UserAccountsCollector
{
    private readonly IWmiQuery _wmi;
    private readonly ISystemEnvironment _env;

    public UserAccountsCollector(IWmiQuery wmi, ISystemEnvironment env)
    {
        _wmi = wmi;
        _env = env;
    }

    public (List<UserAccount> Users, List<string> Administrators) Collect()
    {
        var users = _wmi.Query(@"root\cimv2",
                "SELECT Name, FullName, Disabled, PasswordRequired, LocalAccount, SID FROM Win32_UserAccount WHERE LocalAccount=TRUE")
            .Select(obj => new UserAccount(
                Name: WmiValues.GetString(obj, "Name") ?? "",
                FullName: WmiValues.GetString(obj, "FullName"),
                Disabled: WmiValues.GetFlag(obj, "Disabled"),
                PasswordRequired: WmiValues.GetFlag(obj, "PasswordRequired"),
                LocalAccount: WmiValues.GetFlag(obj, "LocalAccount"),
                SID: WmiValues.GetString(obj, "SID")))
            .OrderBy(u => u.Name)
            .ToList();

        var admins = new List<string>();
        // SID bem conhecido do grupo Administradores (independe do idioma).
        foreach (var group in _wmi.Query(@"root\cimv2", "SELECT Name, Domain FROM Win32_Group WHERE SID='S-1-5-32-544'"))
        {
            var domain = WmiValues.GetString(group, "Domain") ?? _env.MachineName;
            var groupName = WmiValues.GetString(group, "Name") ?? "Administrators";
            // Escapa os literais: nomes de domínio/grupo vão entre aspas no WQL.
            var query = $"ASSOCIATORS OF {{Win32_Group.Domain='{WmiValues.EscapeWql(domain)}',Name='{WmiValues.EscapeWql(groupName)}'}} WHERE ResultClass=Win32_Account";

            foreach (var m in _wmi.Query(@"root\cimv2", query))
                admins.Add($"{WmiValues.GetString(m, "Domain") ?? ""}\\{WmiValues.GetString(m, "Name") ?? ""}");
        }

        return (users, admins.OrderBy(a => a).ToList());
    }
}
