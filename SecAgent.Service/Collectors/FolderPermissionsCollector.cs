using System.Security.AccessControl;
using System.Security.Principal;
using SecAgent.Service.Models;

namespace SecAgent.Service.Collectors;

public class FolderPermissionsCollector
{
    private static readonly HashSet<string> WorldyIdentities = new(StringComparer.OrdinalIgnoreCase)
    {
        "Everyone", "BUILTIN\\Users", "NT AUTHORITY\\Authenticated Users", "Todos"
    };

    private static readonly FileSystemRights[] RiskyRights =
        { FileSystemRights.FullControl, FileSystemRights.Modify, FileSystemRights.Write };

    public List<FolderAcl> Collect(IEnumerable<string> paths)
    {
        var result = new List<FolderAcl>();

        foreach (var path in paths)
        {
            if (!Directory.Exists(path))
            {
                result.Add(new FolderAcl(path, false, new(), new()));
                continue;
            }

            var aces = new List<AceEntry>();
            var concerns = new List<string>();

            try
            {
                var di = new DirectoryInfo(path);
                var security = di.GetAccessControl();
                var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                foreach (FileSystemAccessRule rule in rules)
                {
                    var identity = rule.IdentityReference.Value;
                    aces.Add(new AceEntry(identity, rule.FileSystemRights.ToString(), rule.AccessControlType.ToString()));

                    if (rule.AccessControlType == AccessControlType.Allow &&
                        WorldyIdentities.Contains(identity) &&
                        RiskyRights.Any(r => rule.FileSystemRights.HasFlag(r)))
                    {
                        concerns.Add($"{identity} has {rule.FileSystemRights} via {rule.AccessControlType}");
                    }
                }
            }
            catch (Exception ex)
            {
                concerns.Add($"[error reading ACL] {ex.GetType().Name}: {ex.Message}");
            }

            result.Add(new FolderAcl(path, true, aces, concerns));
        }

        return result;
    }
}
