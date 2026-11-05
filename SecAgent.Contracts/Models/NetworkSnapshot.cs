namespace SecAgent.Contracts;

/// <summary>
/// Snapshot de todas as conexões TCP estabelecidas, gravado atomicamente em
/// <c>network.json</c>. Geolocalização NÃO entra aqui — o Tray enriquece cada IP
/// remoto, mantendo o serviço LocalSystem sem chamadas web de saída.
/// </summary>
public record NetworkSnapshot(
    DateTime GeneratedAtUtc,
    List<NetworkConnection> Connections,
    List<NetworkInterfaceStat>? Interfaces = null
);

public record NetworkConnection(
    string Direction,        // "inbound" | "outbound"
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string ProcessName,
    int Pid,
    bool RemoteIsPublic,     // true quando RemoteAddress é um IP público roteável
    long BytesPerSec = 0     // throughput atual (in+out) da conexão, bytes/s
);

/// <summary>Throughput de uma interface física (Wi-Fi/Ethernet) derivado dos contadores do adaptador.</summary>
public record NetworkInterfaceStat(
    string Name,            // nome amigável da NIC (ex.: "Wi-Fi")
    long BytesDownPerSec,   // recebido, bytes/s
    long BytesUpPerSec      // enviado, bytes/s
);
