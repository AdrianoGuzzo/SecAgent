namespace SecAgent.Tray.Models;

// Mirror of SecAgent.Service.Models.NetworkAlert (alerts/alert_*.json).

public record NetworkAlert(
    DateTime TimestampUtc,
    string Severity,         // "critical" | "medium"
    string RemoteAddress,
    int RemotePort,
    int LocalPort,
    string ProcessName,
    bool SensitivePort,
    string PortLabel,
    string Title,
    string Message
);
