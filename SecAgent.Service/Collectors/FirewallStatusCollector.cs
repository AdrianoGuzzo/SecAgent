using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Collectors;

/// <summary>Estado dos perfis do firewall via WMI <c>MSFT_NetFirewallProfile</c>.</summary>
public class FirewallStatusCollector
{
    private readonly IWmiQuery _wmi;

    public FirewallStatusCollector(IWmiQuery wmi) => _wmi = wmi;

    public FirewallStatus Collect()
    {
        ProfileStatus? domain = null, priv = null, pub = null;

        foreach (var obj in _wmi.Query(@"root\StandardCimv2",
                     "SELECT Name, Enabled, DefaultInboundAction, DefaultOutboundAction FROM MSFT_NetFirewallProfile"))
        {
            var name = WmiValues.GetString(obj, "Name") ?? "";
            obj.TryGetValue("Enabled", out var enabledRaw);
            obj.TryGetValue("DefaultInboundAction", out var inRaw);
            obj.TryGetValue("DefaultOutboundAction", out var outRaw);

            // Antes os defaults saíam como "0"/"2"/"4" crus — o Claude via números sem sentido.
            var status = new ProfileStatus(
                WmiValues.ParseGpoBoolean(enabledRaw),
                WmiValues.MapFirewallDefaultAction(inRaw),
                WmiValues.MapFirewallDefaultAction(outRaw));

            if (name.Equals("Domain", StringComparison.OrdinalIgnoreCase)) domain = status;
            else if (name.Equals("Private", StringComparison.OrdinalIgnoreCase)) priv = status;
            else if (name.Equals("Public", StringComparison.OrdinalIgnoreCase)) pub = status;
        }

        return new FirewallStatus(domain, priv, pub);
    }
}
