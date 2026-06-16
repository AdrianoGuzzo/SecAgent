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

    // TCP_ESTATS_TYPE — we only need TcpConnectionEstatsData (= 1) for byte counters.
    private enum TCP_ESTATS_TYPE
    {
        TcpConnectionEstatsSynOpts = 0,
        TcpConnectionEstatsData = 1
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        int reserved);

    // ---- Per-connection ESTATS (cumulative bytes in/out) --------------------
    // Requires admin to enable collection; the Service runs as LocalSystem, so OK.

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcpConnectionEStats(
        ref MIB_TCPROW row, TCP_ESTATS_TYPE estatsType,
        IntPtr rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcpConnectionEStats(
        ref MIB_TCPROW row, TCP_ESTATS_TYPE estatsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        IntPtr rod, uint rodVersion, uint rodSize);

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcp6ConnectionEStats(
        ref MIB_TCP6ROW row, TCP_ESTATS_TYPE estatsType,
        IntPtr rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcp6ConnectionEStats(
        ref MIB_TCP6ROW row, TCP_ESTATS_TYPE estatsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        IntPtr rod, uint rodVersion, uint rodSize);

    // The 4-tuple rows the ESTATS APIs match on (distinct from the *_OWNER_PID
    // rows GetExtendedTcpTable returns). Addr/port stay in network byte order.
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW
    {
        public uint State;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_ESTATS_DATA_RW_v0
    {
        public byte EnableCollection;
    }

    // Full read-only-dynamic block; we only read the first two counters but the
    // API requires a buffer sized to the whole struct.
    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_ESTATS_DATA_ROD_v0
    {
        public ulong DataBytesOut;
        public ulong DataBytesIn;
        public ulong DataSegsOut;
        public ulong DataSegsIn;
        public ulong SegsOut;
        public ulong SegsIn;
        public ulong SoftErrors;
        public uint SoftErrorReason;
        public uint SndUna;
        public uint SndNxt;
        public uint SndMax;
        public ulong ThruBytesAcked;
        public uint RcvNxt;
        public ulong ThruBytesReceived;
    }

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
        int OwningPid,
        ulong CumBytesIn = 0,
        ulong CumBytesOut = 0);

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

                var estatsRow = new MIB_TCPROW
                {
                    dwState = MIB_TCP_STATE_ESTAB,
                    dwLocalAddr = row.dwLocalAddr,
                    dwLocalPort = row.dwLocalPort,
                    dwRemoteAddr = row.dwRemoteAddr,
                    dwRemotePort = row.dwRemotePort
                };
                var (inBytes, outBytes) = TryReadEStatsV4(ref estatsRow);

                yield return new TcpConnectionRow(
                    new IPAddress(row.dwLocalAddr),
                    SwapPort(row.dwLocalPort),
                    new IPAddress(row.dwRemoteAddr),
                    SwapPort(row.dwRemotePort),
                    (int)row.dwOwningPid,
                    inBytes,
                    outBytes);
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

                var estatsRow = new MIB_TCP6ROW
                {
                    State = MIB_TCP_STATE_ESTAB,
                    LocalAddr = row.ucLocalAddr,
                    dwLocalScopeId = row.dwLocalScopeId,
                    dwLocalPort = row.dwLocalPort,
                    RemoteAddr = row.ucRemoteAddr,
                    dwRemoteScopeId = row.dwRemoteScopeId,
                    dwRemotePort = row.dwRemotePort
                };
                var (inBytes, outBytes) = TryReadEStatsV6(ref estatsRow);

                yield return new TcpConnectionRow(
                    new IPAddress(row.ucLocalAddr, row.dwLocalScopeId),
                    SwapPort(row.dwLocalPort),
                    new IPAddress(row.ucRemoteAddr, row.dwRemoteScopeId),
                    SwapPort(row.dwRemotePort),
                    (int)row.dwOwningPid,
                    inBytes,
                    outBytes);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    // Enables ESTATS data collection on the connection (idempotent) and reads
    // the cumulative (bytesIn, bytesOut). Best-effort: any failure (connection
    // gone, loopback without estats, access) yields (0, 0) instead of throwing.
    private static (ulong inBytes, ulong outBytes) TryReadEStatsV4(ref MIB_TCPROW row)
    {
        try
        {
            int rwSize = Marshal.SizeOf<TCP_ESTATS_DATA_RW_v0>();
            IntPtr rwPtr = Marshal.AllocHGlobal(rwSize);
            try
            {
                Marshal.StructureToPtr(new TCP_ESTATS_DATA_RW_v0 { EnableCollection = 1 }, rwPtr, false);
                SetPerTcpConnectionEStats(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsData, rwPtr, 0, (uint)rwSize, 0);
            }
            finally { Marshal.FreeHGlobal(rwPtr); }

            int rodSize = Marshal.SizeOf<TCP_ESTATS_DATA_ROD_v0>();
            IntPtr rodPtr = Marshal.AllocHGlobal(rodSize);
            try
            {
                uint err = GetPerTcpConnectionEStats(
                    ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsData,
                    IntPtr.Zero, 0, 0, IntPtr.Zero, 0, 0, rodPtr, 0, (uint)rodSize);
                if (err != NO_ERROR) return (0, 0);
                var rod = Marshal.PtrToStructure<TCP_ESTATS_DATA_ROD_v0>(rodPtr);
                return (rod.DataBytesIn, rod.DataBytesOut);
            }
            finally { Marshal.FreeHGlobal(rodPtr); }
        }
        catch { return (0, 0); }
    }

    private static (ulong inBytes, ulong outBytes) TryReadEStatsV6(ref MIB_TCP6ROW row)
    {
        try
        {
            int rwSize = Marshal.SizeOf<TCP_ESTATS_DATA_RW_v0>();
            IntPtr rwPtr = Marshal.AllocHGlobal(rwSize);
            try
            {
                Marshal.StructureToPtr(new TCP_ESTATS_DATA_RW_v0 { EnableCollection = 1 }, rwPtr, false);
                SetPerTcp6ConnectionEStats(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsData, rwPtr, 0, (uint)rwSize, 0);
            }
            finally { Marshal.FreeHGlobal(rwPtr); }

            int rodSize = Marshal.SizeOf<TCP_ESTATS_DATA_ROD_v0>();
            IntPtr rodPtr = Marshal.AllocHGlobal(rodSize);
            try
            {
                uint err = GetPerTcp6ConnectionEStats(
                    ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsData,
                    IntPtr.Zero, 0, 0, IntPtr.Zero, 0, 0, rodPtr, 0, (uint)rodSize);
                if (err != NO_ERROR) return (0, 0);
                var rod = Marshal.PtrToStructure<TCP_ESTATS_DATA_ROD_v0>(rodPtr);
                return (rod.DataBytesIn, rod.DataBytesOut);
            }
            finally { Marshal.FreeHGlobal(rodPtr); }
        }
        catch { return (0, 0); }
    }

    // Ports arrive in network byte order in the low 16 bits of a uint.
    private static int SwapPort(uint port)
    {
        uint p = port & 0xFFFF;
        return (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF));
    }
}
