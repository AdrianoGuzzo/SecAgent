using System.Net;
using System.Net.Sockets;

namespace SecAgent.Service.Monitors;

/// <summary>
/// "Este IP é público/roteável na internet?" — usado pelos dois monitores de rede.
/// Além das faixas privadas, exclui faixas especiais que antes eram tratadas
/// como públicas (multicast, 0/8, broadcast, benchmarking 198.18/15,
/// documentação, IPv4-mapped de IP privado, multicast IPv6, ::).
/// </summary>
public static class IpClassifier
{
    public static bool IsPublic(IPAddress addr)
    {
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
        if (IPAddress.IsLoopback(addr)) return false;

        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            return !(b[0] == 0                                   // 0.0.0.0/8 "this network"
                  || b[0] == 10                                  // 10/8
                  || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)  // 100.64/10 CGNAT
                  || (b[0] == 169 && b[1] == 254)                // 169.254/16 link-local
                  || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)   // 172.16/12
                  || (b[0] == 192 && b[1] == 0 && b[2] == 0)     // 192.0.0/24 IETF
                  || (b[0] == 192 && b[1] == 0 && b[2] == 2)     // 192.0.2/24 TEST-NET-1
                  || (b[0] == 192 && b[1] == 168)                // 192.168/16
                  || (b[0] == 198 && (b[1] == 18 || b[1] == 19)) // 198.18/15 benchmarking
                  || (b[0] == 198 && b[1] == 51 && b[2] == 100)  // TEST-NET-2
                  || (b[0] == 203 && b[1] == 0 && b[2] == 113)   // TEST-NET-3
                  || b[0] >= 224);                               // multicast 224/4 + reservado 240/4 + broadcast
        }

        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (addr.Equals(IPAddress.IPv6Any)) return false;
            if (addr.IsIPv6LinkLocal || addr.IsIPv6Multicast) return false;
            var b = addr.GetAddressBytes();
            if ((b[0] & 0xfe) == 0xfc) return false;             // fc00::/7 unique-local
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0) return false; // fec0::/10 site-local (obsoleto)
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return false; // 2001:db8::/32 doc
            return true;
        }

        return false;
    }
}
