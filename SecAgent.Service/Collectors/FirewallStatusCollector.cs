using System.Management;
using SecAgent.Service.Models;

namespace SecAgent.Service.Collectors;

public class FirewallStatusCollector
{
    public FirewallStatus Collect()
    {
        ProfileStatus? domain = null, priv = null, pub = null;

        using var searcher = new ManagementObjectSearcher(
            @"root\StandardCimv2",
            "SELECT Name, Enabled, DefaultInboundAction, DefaultOutboundAction FROM MSFT_NetFirewallProfile");

        foreach (ManagementObject obj in searcher.Get())
        {
            var name = obj["Name"] as string ?? "";
            var enabled = obj["Enabled"] is ushort u ? u == 1 : (obj["Enabled"] as bool? ?? false);
            var inbound = obj["DefaultInboundAction"]?.ToString();
            var outbound = obj["DefaultOutboundAction"]?.ToString();
            var status = new ProfileStatus(enabled, inbound, outbound);

            if (name.Equals("Domain", StringComparison.OrdinalIgnoreCase))   domain = status;
            else if (name.Equals("Private", StringComparison.OrdinalIgnoreCase)) priv = status;
            else if (name.Equals("Public", StringComparison.OrdinalIgnoreCase))  pub  = status;
        }

        return new FirewallStatus(domain, priv, pub);
    }
}
