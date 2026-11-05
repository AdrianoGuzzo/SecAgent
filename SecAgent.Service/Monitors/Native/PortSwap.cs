namespace SecAgent.Service.Monitors.Native;

/// <summary>Portas do GetExtendedTcpTable chegam em network byte order nos 16 bits baixos de um uint.</summary>
internal static class PortSwap
{
    public static int FromNetworkOrder(uint port)
    {
        uint p = port & 0xFFFF;
        return (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF));
    }
}
