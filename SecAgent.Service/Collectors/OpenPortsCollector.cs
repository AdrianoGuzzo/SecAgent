using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Collectors;

/// <summary>Listeners TCP/UDP ativos.</summary>
public class OpenPortsCollector
{
    private readonly INetworkInfo _net;

    public OpenPortsCollector(INetworkInfo net) => _net = net;

    public List<OpenPort> Collect()
        => _net.GetTcpListeners().Select(ep => new OpenPort("TCP", ep.Address.ToString(), ep.Port, null, null))
            .Concat(_net.GetUdpListeners().Select(ep => new OpenPort("UDP", ep.Address.ToString(), ep.Port, null, null)))
            .OrderBy(p => p.Protocol)
            .ThenBy(p => p.LocalPort)
            .ToList();
}
