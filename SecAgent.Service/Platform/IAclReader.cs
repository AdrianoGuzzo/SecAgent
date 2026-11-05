using System.Diagnostics.CodeAnalysis;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SecAgent.Service.Platform;

/// <summary>Uma ACE de pasta: identidade legível + SID (para comparação independente de idioma).</summary>
public record AclRuleData(string Identity, string? Sid, FileSystemRights Rights, AccessControlType Type);

/// <summary>Lê ACLs de pastas (NTFS).</summary>
public interface IAclReader
{
    bool DirectoryExists(string path);
    IReadOnlyList<AclRuleData> GetRules(string path);
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de ACL NTFS")]
internal sealed class NtfsAclReader : IAclReader
{
    public bool DirectoryExists(string path) => Directory.Exists(path);

    public IReadOnlyList<AclRuleData> GetRules(string path)
    {
        var security = new DirectoryInfo(path).GetAccessControl();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        var result = new List<AclRuleData>();
        foreach (FileSystemAccessRule rule in rules)
        {
            var sid = rule.IdentityReference as SecurityIdentifier;
            string identity;
            try { identity = sid?.Translate(typeof(NTAccount)).Value ?? rule.IdentityReference.Value; }
            catch { identity = rule.IdentityReference.Value; }
            result.Add(new AclRuleData(identity, sid?.Value, rule.FileSystemRights, rule.AccessControlType));
        }
        return result;
    }
}
