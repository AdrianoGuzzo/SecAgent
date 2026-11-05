using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace SecAgent.Service.Platform;

/// <summary>Constantes da API HNetCfg.FwPolicy2 (NET_FW_*).</summary>
public static class FirewallConstants
{
    public const int DirectionIn = 1;
    public const int DirectionOut = 2;
    public const int ActionBlock = 0;
    public const int ActionAllow = 1;
    public const int ProfileDomain = 1;
    public const int ProfilePrivate = 2;
    public const int ProfilePublic = 4;
    public const int ProfileAll = 0x7FFFFFFF;
    public const int ProtocolAny = 256;
}

/// <summary>Dados crus de uma regra de firewall, já fora do mundo COM.</summary>
public record FirewallRuleData(
    string Name,
    int Direction,
    bool Enabled,
    int Action,
    int Protocol,
    int Profiles,
    string? LocalPorts,
    string? RemoteAddresses);

/// <summary>
/// Acesso ao Windows Firewall (HNetCfg.FwPolicy2). Usado em leitura pelo
/// FirewallRulesCollector e em escrita pelo IpBlocker. Lança
/// <see cref="InvalidOperationException"/> se a API não estiver disponível.
/// </summary>
public interface IFirewallPolicy
{
    IReadOnlyList<FirewallRuleData> GetRules();
    IReadOnlyList<string> GetRuleNames();
    void AddBlockRule(string name, string remoteAddress, int direction, string description);

    /// <summary>Remove a regra; false se ela não existia/falhou (idempotente).</summary>
    bool RemoveRule(string name);
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de COM (HNetCfg.FwPolicy2)")]
internal sealed class ComFirewallPolicy : IFirewallPolicy
{
    public IReadOnlyList<FirewallRuleData> GetRules()
    {
        var result = new List<FirewallRuleData>();
        WithPolicy(policy =>
        {
            dynamic rules = policy.Rules;
            try
            {
                foreach (dynamic rule in rules)
                {
                    try
                    {
                        result.Add(new FirewallRuleData(
                            Name: (string?)rule.Name ?? "",
                            Direction: (int)rule.Direction,
                            Enabled: (bool)rule.Enabled,
                            Action: (int)rule.Action,
                            Protocol: (int)rule.Protocol,
                            Profiles: (int)rule.Profiles,
                            LocalPorts: (string?)rule.LocalPorts,
                            RemoteAddresses: (string?)rule.RemoteAddresses));
                    }
                    catch
                    {
                        // Algumas regras legadas/órfãs lançam ao ler propriedades — ignora.
                    }
                    finally { Release(rule); }
                }
            }
            finally { Release(rules); }
        });
        return result;
    }

    public IReadOnlyList<string> GetRuleNames()
    {
        var names = new List<string>();
        WithPolicy(policy =>
        {
            dynamic rules = policy.Rules;
            try
            {
                foreach (dynamic rule in rules)
                {
                    try { names.Add((string?)rule.Name ?? ""); }
                    catch { /* regra legada */ }
                    finally { Release(rule); }
                }
            }
            finally { Release(rules); }
        });
        return names;
    }

    public void AddBlockRule(string name, string remoteAddress, int direction, string description)
    {
        WithPolicy(policy =>
        {
            var rt = Type.GetTypeFromProgID("HNetCfg.FWRule")
                     ?? throw new InvalidOperationException("HNetCfg.FWRule indisponível");
            dynamic rule = Activator.CreateInstance(rt)!;
            dynamic rules = policy.Rules;
            try
            {
                rule.Name = name;
                rule.Description = description;
                rule.Direction = direction;
                rule.Action = FirewallConstants.ActionBlock;
                rule.Protocol = FirewallConstants.ProtocolAny;
                rule.RemoteAddresses = remoteAddress;
                rule.Profiles = FirewallConstants.ProfileAll;
                rule.Enabled = true;
                rules.Add(rule);
            }
            finally
            {
                Release(rules);
                Release(rule);
            }
        });
    }

    public bool RemoveRule(string name)
    {
        var removed = false;
        WithPolicy(policy =>
        {
            dynamic rules = policy.Rules;
            try { rules.Remove(name); removed = true; }
            catch { /* regra pode não existir — ok */ }
            finally { Release(rules); }
        });
        return removed;
    }

    private static void WithPolicy(Action<dynamic> action)
    {
        var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                ?? throw new InvalidOperationException("HNetCfg.FwPolicy2 indisponível");
        dynamic policy = Activator.CreateInstance(t)
                         ?? throw new InvalidOperationException("Falha ao criar HNetCfg.FwPolicy2");
        try { action(policy); }
        finally { Release(policy); }
    }

    private static void Release(object? com)
    {
        try { if (com is not null && Marshal.IsComObject(com)) Marshal.ReleaseComObject(com); }
        catch { /* best effort */ }
    }
}
