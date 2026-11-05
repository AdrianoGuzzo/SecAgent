using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Runtime.InteropServices;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Monitors.Native;

/// <summary>
/// Thin P/Invoke wrapper over iphlpapi.dll's GetExtendedTcpTable, which (unlike
/// IPGlobalProperties.GetActiveTcpConnections) returns the owning PID for each
/// connection. Enumerates both IPv4 and IPv6 established connections.
///
/// Gotchas:
///  - Ports come back in network byte order packed in a uint → must byte-swap
///    (<see cref="PortSwap"/>).
///  - The two-call pattern: probe size, allocate, fill, iterate, free. The table
///    can grow between the probe and the fill (ERROR_INSUFFICIENT_BUFFER) → retry.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "P/Invoke puro; lógica testável em PortSwap e no layout das structs")]
internal static class IpHlpApi
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

    // Bloco read-only-dynamic completo (tcpestats.h). A ORDEM importa: a doc
    // oficial é DataBytesOut, DataSegsOut, DataBytesIn, ... e SoftErrors é ULONG
    // (32 bits). A versão anterior tinha DataBytesIn na 2ª posição, então o
    // "bytes recebidos" lia na verdade a contagem de SEGMENTOS enviados.
    [StructLayout(LayoutKind.Sequential)]
    internal struct TCP_ESTATS_DATA_ROD_v0
    {
        public ulong DataBytesOut;
        public ulong DataSegsOut;
        public ulong DataBytesIn;
        public ulong DataSegsIn;
        public ulong SegsOut;
        public ulong SegsIn;
        public uint SoftErrors;
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

    /// <summary>
    /// All ESTABLISHED connections (v4 + v6) with PID. Returns false when reading
    /// either table FAILED — callers must not treat that as "no connections".
    /// </summary>
    public static bool TryGetEstablishedConnections(out List<TcpConnectionRow> rows)
    {
        rows = new List<TcpConnectionRow>();
        IntPtr v4 = IntPtr.Zero, v6 = IntPtr.Zero;
        try
        {
            if (!TryReadTable(AF_INET, out v4)) return false;
            if (!TryReadTable(AF_INET6, out v6)) return false;
            rows.AddRange(ParseV4(v4));
            rows.AddRange(ParseV6(v6));
            return true;
        }
        finally
        {
            if (v4 != IntPtr.Zero) Marshal.FreeHGlobal(v4);
            if (v6 != IntPtr.Zero) Marshal.FreeHGlobal(v6);
        }
    }

    /// <summary>
    /// Probe size, allocate and fill — retrying when the table grew in between
    /// (ERROR_INSUFFICIENT_BUFFER). buffer = Zero when there are no entries.
    /// </summary>
    private static bool TryReadTable(int family, out IntPtr buffer)
    {
        buffer = IntPtr.Zero;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, true, family, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size == 0) return true;                       // empty table

            size += 1024;                                     // slack for growth
            buffer = Marshal.AllocHGlobal(size);
            uint err = GetExtendedTcpTable(buffer, ref size, true, family, TCP_TABLE_OWNER_PID_ALL, 0);
            if (err == NO_ERROR) return true;

            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
            if (err != ERROR_INSUFFICIENT_BUFFER) return false;
        }
        return false;
    }

    private static List<TcpConnectionRow> ParseV4(IntPtr buffer)
    {
        var list = new List<TcpConnectionRow>();
        if (buffer == IntPtr.Zero) return list;

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

            list.Add(new TcpConnectionRow(
                new IPAddress(row.dwLocalAddr),
                PortSwap.FromNetworkOrder(row.dwLocalPort),
                new IPAddress(row.dwRemoteAddr),
                PortSwap.FromNetworkOrder(row.dwRemotePort),
                (int)row.dwOwningPid,
                inBytes,
                outBytes));
        }
        return list;
    }

    private static List<TcpConnectionRow> ParseV6(IntPtr buffer)
    {
        var list = new List<TcpConnectionRow>();
        if (buffer == IntPtr.Zero) return list;

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

            list.Add(new TcpConnectionRow(
                new IPAddress(row.ucLocalAddr, row.dwLocalScopeId),
                PortSwap.FromNetworkOrder(row.dwLocalPort),
                new IPAddress(row.ucRemoteAddr, row.dwRemoteScopeId),
                PortSwap.FromNetworkOrder(row.dwRemotePort),
                (int)row.dwOwningPid,
                inBytes,
                outBytes));
        }
        return list;
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
}
