namespace SecAgent.Tray.Models;

// Mirror of SecAgent.Service.Models.NetworkSnapshot/NetworkConnection
// (network.json). Geolocation is added client-side by the Tray and is not part
// of the serialized snapshot.

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
    bool RemoteIsPublic
);
