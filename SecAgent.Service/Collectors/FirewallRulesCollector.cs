using SecAgent.Service.Models;

namespace SecAgent.Service.Collectors;

/// <summary>
/// Reads enabled inbound Windows Firewall rules via the HNetCfg.FwPolicy2 COM
/// interface (same API surface used by Get-NetFirewallRule). Filters to
/// direction=In and enabled=true to keep the payload small and signal-rich.
/// </summary>
public class FirewallRulesCollector
{
    private const int NetFwRuleDirectionIn  = 1;
    private const int NetFwActionBlock      = 0;
    private const int NetFwActionAllow      = 1;
    private const int NetFwProfileDomain    = 1;
    private const int NetFwProfilePrivate   = 2;
    private const int NetFwProfilePublic    = 4;
    private const int NetFwProfileAll       = 0x7FFFFFFF;

    public List<FirewallRule> Collect()
    {
        var result = new List<FirewallRule>();

        var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        if (t is null) return result;

        dynamic? fw;
        try { fw = Activator.CreateInstance(t); }
        catch { return result; }
        if (fw is null) return result;

        dynamic rules;
        try { rules = fw.Rules; }
        catch { return result; }

        foreach (dynamic rule in rules)
        {
            try
            {
                int direction = (int)rule.Direction;
                if (direction != NetFwRuleDirectionIn) continue;

                bool enabled = (bool)rule.Enabled;
                if (!enabled) continue;

                int action = (int)rule.Action;
                int protocolNum = (int)rule.Protocol;
                int profiles = (int)rule.Profiles;

                result.Add(new FirewallRule(
                    Name: (string?)rule.Name ?? "",
                    Action: action == NetFwActionBlock ? "Block" :
                            action == NetFwActionAllow ? "Allow" : $"Action{action}",
                    Protocol: MapProtocol(protocolNum),
                    LocalPorts: (string?)rule.LocalPorts ?? "*",
                    RemoteAddresses: (string?)rule.RemoteAddresses ?? "*",
                    Profiles: MapProfiles(profiles),
                    Enabled: enabled));
            }
            catch
            {
                // Skip any rule whose properties throw (some legacy/orphan rules do).
            }
        }

        return result;
    }

    private static string MapProtocol(int p) => p switch
    {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        256 => "Any",
        _ => $"IP{p}"
    };

    private static List<string> MapProfiles(int mask)
    {
        if (mask == NetFwProfileAll) return new List<string> { "All" };
        var list = new List<string>();
        if ((mask & NetFwProfileDomain)  != 0) list.Add("Domain");
        if ((mask & NetFwProfilePrivate) != 0) list.Add("Private");
        if ((mask & NetFwProfilePublic)  != 0) list.Add("Public");
        return list.Count > 0 ? list : new List<string> { $"Profile{mask}" };
    }
}
