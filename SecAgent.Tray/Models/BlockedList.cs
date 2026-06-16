namespace SecAgent.Tray.Models;

// Mirror of the blocked.json schema written by SecAgent.Service.Remediation.IpBlocker.
// Lists the remote IPs currently blocked by SecAgent firewall rules.

public record BlockedList(
    DateTime UpdatedUtc,
    List<BlockedIp> Blocked
);

public record BlockedIp(string Ip);
