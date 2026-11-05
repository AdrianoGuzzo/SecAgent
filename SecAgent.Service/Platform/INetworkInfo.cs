using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.NetworkInformation;

namespace SecAgent.Service.Platform;

/// <summary>Contadores cumulativos de uma NIC + metadados para filtrar só as físicas.</summary>
public record InterfaceCounters(
    string Id,
    string Name,
    string Description,
    NetworkInterfaceType Type,
    OperationalStatus Status,
    ulong BytesReceived,
    ulong BytesSent);

/// <summary>Informações de rede/processos via APIs gerenciadas do .NET.</summary>
public interface INetworkInfo
{
    IReadOnlyList<IPEndPoint> GetTcpListeners();
    IReadOnlyList<IPEndPoint> GetUdpListeners();

    /// <summary>Conexões TCP no estado ESTABLISHED (sem PID).</summary>
    IReadOnlyList<(IPEndPoint Local, IPEndPoint Remote)> GetEstablishedTcp();

    IReadOnlyDictionary<int, string> GetProcessNames();

    /// <summary>NICs com estatística IPv4 disponível (as demais são omitidas).</summary>
    IReadOnlyList<InterfaceCounters> GetInterfaceCounters();
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de APIs de rede/processo")]
internal sealed class SystemNetworkInfo : INetworkInfo
{
    public IReadOnlyList<IPEndPoint> GetTcpListeners()
        => IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();

    public IReadOnlyList<IPEndPoint> GetUdpListeners()
        => IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();

    public IReadOnlyList<(IPEndPoint Local, IPEndPoint Remote)> GetEstablishedTcp()
        => IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
            .Where(c => c.State == TcpState.Established)
            .Select(c => (c.LocalEndPoint, c.RemoteEndPoint))
            .ToList();

    public IReadOnlyDictionary<int, string> GetProcessNames()
    {
        var map = new Dictionary<int, string>();
        foreach (var p in Process.GetProcesses())
        {
            try { map[p.Id] = p.ProcessName; }
            catch { /* encerrou / acesso negado */ }
            finally { p.Dispose(); }
        }
        return map;
    }

    public IReadOnlyList<InterfaceCounters> GetInterfaceCounters()
    {
        var list = new List<InterfaceCounters>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var s = ni.GetIPv4Statistics();     // lança se a NIC não tem IPv4
                list.Add(new InterfaceCounters(ni.Id, ni.Name, ni.Description, ni.NetworkInterfaceType,
                    ni.OperationalStatus, (ulong)s.BytesReceived, (ulong)s.BytesSent));
            }
            catch { /* sem IPv4 — ignora */ }
        }
        return list;
    }
}
