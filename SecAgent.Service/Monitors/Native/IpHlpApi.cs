using System.Net;
using System.Runtime.InteropServices;

namespace SecAgent.Service.Monitors.Native;

/// <summary>
/// Thin P/Invoke wrapper over iphlpapi.dll's GetExtendedTcpTable, which (unlike
/// IPGlobalProperties.GetActiveTcpConnections) returns the owning PID for each
/// connection. Enumerates both IPv4 and IPv6 established connections.
///
/// Gotchas:
///  - Ports come back in network byte order packed in a uint → must byte-swap.
///  - The two-call pattern: probe size, allocate, fill, iterate, free.
/// </summary>
public static class IpHlpApi
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint NO_ERROR = 0;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;
    private const int MIB_TCP_STATE_ESTAB = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucRemoteAddr;
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
        public uint dwState;
        public uint dwOwningPid;
    }

    public record TcpConnectionRow(
        IPAddress LocalAddress,
        int LocalPort,
        IPAddress RemoteAddress,
        int RemotePort,
        int OwningPid);

    /// <summary>Returns all ESTABLISHED TCP connections (v4 + v6) with owning PID.</summary>
    public static List<TcpConnectionRow> GetEstablishedConnections()
    {
        var rows = new List<TcpConnectionRow>();
        rows.AddRange(GetV4());
        rows.AddRange(GetV6());
        return rows;
    }

    private static IEnumerable<TcpConnectionRow> GetV4()
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
                yield break;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;                       // skip dwNumEntries
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr += rowSize;
                if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

                yield return new TcpConnectionRow(
                    new IPAddress(row.dwLocalAddr),
                    SwapPort(row.dwLocalPort),
                    new IPAddress(row.dwRemoteAddr),
                    SwapPort(row.dwRemotePort),
                    (int)row.dwOwningPid);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IEnumerable<TcpConnectionRow> GetV6()
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0) yield break;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
                yield break;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                rowPtr += rowSize;
                if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

                yield return new TcpConnectionRow(
                    new IPAddress(row.ucLocalAddr, row.dwLocalScopeId),
                    SwapPort(row.dwLocalPort),
                    new IPAddress(row.ucRemoteAddr, row.dwRemoteScopeId),
                    SwapPort(row.dwRemotePort),
                    (int)row.dwOwningPid);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    // Ports arrive in network byte order in the low 16 bits of a uint.
    private static int SwapPort(uint port)
    {
        uint p = port & 0xFFFF;
        return (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF));
    }
}
