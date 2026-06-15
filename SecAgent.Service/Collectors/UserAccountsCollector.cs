using System.Management;
using SecAgent.Service.Models;

namespace SecAgent.Service.Collectors;

public class UserAccountsCollector
{
    public (List<UserAccount> Users, List<string> Administrators) Collect()
    {
        var users = new List<UserAccount>();

        using (var search = new ManagementObjectSearcher(@"root\cimv2",
            "SELECT Name, FullName, Disabled, PasswordRequired, LocalAccount, SID FROM Win32_UserAccount WHERE LocalAccount=TRUE"))
        {
            foreach (ManagementObject obj in search.Get())
            {
                users.Add(new UserAccount(
                    Name: obj["Name"] as string ?? "",
                    FullName: obj["FullName"] as string,
                    Disabled: obj["Disabled"] is bool d && d,
                    PasswordRequired: obj["PasswordRequired"] is bool p && p,
                    LocalAccount: obj["LocalAccount"] is bool l && l,
                    SID: obj["SID"] as string));
            }
        }

        var admins = new List<string>();
        // Administrators group SID is well-known: S-1-5-32-544
        using (var groupSearch = new ManagementObjectSearcher(@"root\cimv2",
            "SELECT Name, Domain FROM Win32_Group WHERE SID='S-1-5-32-544'"))
        {
            foreach (ManagementObject group in groupSearch.Get())
            {
                var domain = group["Domain"] as string ?? Environment.MachineName;
                var groupName = group["Name"] as string ?? "Administrators";
                var query = $"ASSOCIATORS OF {{Win32_Group.Domain='{domain}',Name='{groupName}'}} WHERE ResultClass=Win32_Account";

                using var memberSearch = new ManagementObjectSearcher(@"root\cimv2", query);
                foreach (ManagementObject m in memberSearch.Get())
                {
                    var memberDomain = m["Domain"] as string ?? "";
                    var memberName = m["Name"] as string ?? "";
                    admins.Add($"{memberDomain}\\{memberName}");
                }
            }
        }

        return (users.OrderBy(u => u.Name).ToList(), admins.OrderBy(a => a).ToList());
    }
}
