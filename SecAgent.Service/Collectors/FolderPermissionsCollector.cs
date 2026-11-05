using System.Security.AccessControl;
using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Collectors;

/// <summary>ACLs das pastas críticas, sinalizando escrita concedida a identidades "do mundo".</summary>
public class FolderPermissionsCollector
{
    private readonly IAclReader _acl;

    public FolderPermissionsCollector(IAclReader acl) => _acl = acl;

    public List<FolderAcl> Collect(IEnumerable<string> paths)
    {
        var result = new List<FolderAcl>();

        foreach (var path in paths)
        {
            if (!_acl.DirectoryExists(path))
            {
                result.Add(new FolderAcl(path, false, new(), new()));
                continue;
            }

            var aces = new List<AceEntry>();
            var concerns = new List<string>();
            try
            {
                foreach (var rule in _acl.GetRules(path))
                {
                    aces.Add(new AceEntry(rule.Identity, rule.Rights.ToString(), rule.Type.ToString()));
                    if (AclRiskClassifier.IsRisky(rule))
                        concerns.Add($"{rule.Identity} has {rule.Rights} via {rule.Type}");
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

/// <summary>
/// Decide se uma ACE é arriscada. Compara por SID (antes era por nome
/// localizado: numa máquina pt-BR "BUILTIN\Usuários" e "Usuários autenticados"
/// passavam batido) e considera direitos genéricos (GENERIC_ALL/GENERIC_WRITE),
/// comuns em ACEs herdáveis, que não batiam com HasFlag(FullControl).
/// </summary>
internal static class AclRiskClassifier
{
    public static readonly IReadOnlySet<string> WorldSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0",      // Everyone / Todos
        "S-1-5-32-545", // BUILTIN\Users / Usuários
        "S-1-5-11"      // NT AUTHORITY\Authenticated Users / Usuários autenticados
    };

    // Fallback quando o SID não está disponível.
    private static readonly IReadOnlySet<string> WorldNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Everyone", "Todos", @"BUILTIN\Users", @"BUILTIN\Usuários",
        @"NT AUTHORITY\Authenticated Users", @"AUTORIDADE NT\Usuários autenticados"
    };

    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;

    private static readonly FileSystemRights[] RiskyRights =
        { FileSystemRights.FullControl, FileSystemRights.Modify, FileSystemRights.Write };

    public static bool IsWorldIdentity(AclRuleData rule)
        => rule.Sid is { Length: > 0 } sid ? WorldSids.Contains(sid) : WorldNames.Contains(rule.Identity);

    public static bool HasRiskyRights(FileSystemRights rights)
    {
        var raw = (int)rights;
        if ((raw & GenericAll) != 0 || (raw & GenericWrite) != 0) return true;
        return RiskyRights.Any(r => rights.HasFlag(r));
    }

    public static bool IsRisky(AclRuleData rule)
        => rule.Type == AccessControlType.Allow && IsWorldIdentity(rule) && HasRiskyRights(rule.Rights);
}
