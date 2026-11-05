namespace SecAgent.Contracts;

/// <summary>Schema de <c>blocked.json</c>: IPs bloqueados por regras de firewall do SecAgent.</summary>
public record BlockedList(
    DateTime UpdatedUtc,
    List<BlockedIp> Blocked
);

public record BlockedIp(string Ip);
