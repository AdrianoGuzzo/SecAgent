namespace SecAgent.Service.Models;

/// <summary>
/// A point-in-time snapshot of every established TCP connection on the machine,
/// written atomically to C:\ProgramData\SecAgent\network.json for the Tray to
/// render a live connections table. Geolocation is intentionally NOT included
/// here — the Tray enriches each remote IP so the LocalSystem service stays
/// offline-pure (no outbound web calls).
/// </summary>
public record NetworkSnapshot(
    DateTime GeneratedAtUtc,
    List<NetworkConnection> Connections
);

public record NetworkConnection(
    string Direction,        // "inbound" | "outbound"
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string ProcessName,
    int Pid,
    bool RemoteIsPublic,     // true when RemoteAddress is a routable public IP
    long BytesPerSec = 0     // current throughput (in+out) for this connection, bytes/s
);
