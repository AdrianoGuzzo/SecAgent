using System.Diagnostics.CodeAnalysis;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SecAgent.Service.Platform;

/// <summary>Prepara a pasta de triggers com a ACL que permite ao Tray (usuário) gravar.</summary>
public interface ITriggerDirectorySetup
{
    void EnsureDirectory(string path);
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de ACL NTFS")]
internal sealed class TriggerDirectoryAclSetup : ITriggerDirectorySetup
{
    /// <summary>
    /// Cria a pasta e concede a Authenticated Users criar/gravar arquivos e ler
    /// (ReadAndExecute inclui listar). Sem Delete — a limpeza é do Service.
    /// </summary>
    public void EnsureDirectory(string path)
    {
        var di = Directory.CreateDirectory(path);
        var security = di.GetAccessControl();
        var authUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var rule = new FileSystemAccessRule(
            authUsers,
            FileSystemRights.WriteData | FileSystemRights.CreateFiles |
                FileSystemRights.AppendData | FileSystemRights.ReadAndExecute,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow);
        security.AddAccessRule(rule);
        di.SetAccessControl(security);
    }
}
