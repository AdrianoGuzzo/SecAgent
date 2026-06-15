using System.Net.NetworkInformation;
using SecAgent.Service.Models;

namespace SecAgent.Service.Collectors;

public class OpenPortsCollector
{
    public List<OpenPort> Collect()
    {
        var result = new List<OpenPort>();
        var props = IPGlobalProperties.GetIPGlobalProperties();

        foreach (var ep in props.GetActiveTcpListeners())
            result.Add(new OpenPort("TCP", ep.Address.ToString(), ep.Port, null, null));

        foreach (var ep in props.GetActiveUdpListeners())
            result.Add(new OpenPort("UDP", ep.Address.ToString(), ep.Port, null, null));

        return result
            .OrderBy(p => p.Protocol)
            .ThenBy(p => p.LocalPort)
            .ToList();
    }
}
