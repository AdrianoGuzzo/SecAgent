using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Collectors;

/// <summary>
/// Regras de ENTRADA habilitadas do Windows Firewall (mesma API do
/// Get-NetFirewallRule). Filtra direction=In e enabled=true para manter o
/// payload pequeno e com sinal.
/// </summary>
public class FirewallRulesCollector
{
    private readonly IFirewallPolicy _policy;

    public FirewallRulesCollector(IFirewallPolicy policy) => _policy = policy;

    public List<FirewallRule> Collect()
        => _policy.GetRules()
            .Where(r => r.Direction == FirewallConstants.DirectionIn && r.Enabled)
            .Select(r => new FirewallRule(
                Name: r.Name,
                Action: FirewallMappers.MapAction(r.Action),
                Protocol: FirewallMappers.MapProtocol(r.Protocol),
                LocalPorts: r.LocalPorts ?? "*",
                RemoteAddresses: r.RemoteAddresses ?? "*",
                Profiles: FirewallMappers.MapProfiles(r.Profiles),
                Enabled: r.Enabled))
            .ToList();
}

/// <summary>Traduções dos códigos NET_FW_* para texto.</summary>
internal static class FirewallMappers
{
    public static string MapAction(int action) => action switch
    {
        FirewallConstants.ActionBlock => "Block",
        FirewallConstants.ActionAllow => "Allow",
        _ => $"Action{action}"
    };

    public static string MapProtocol(int p) => p switch
    {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        FirewallConstants.ProtocolAny => "Any",
        _ => $"IP{p}"
    };

    public static List<string> MapProfiles(int mask)
    {
        if (mask == FirewallConstants.ProfileAll) return new List<string> { "All" };
        var list = new List<string>();
        if ((mask & FirewallConstants.ProfileDomain) != 0) list.Add("Domain");
        if ((mask & FirewallConstants.ProfilePrivate) != 0) list.Add("Private");
        if ((mask & FirewallConstants.ProfilePublic) != 0) list.Add("Public");
        return list.Count > 0 ? list : new List<string> { $"Profile{mask}" };
    }
}
