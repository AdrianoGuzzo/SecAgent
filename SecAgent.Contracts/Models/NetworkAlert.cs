namespace SecAgent.Contracts;

/// <summary>
/// Alerta imediato de NOVA conexão de entrada vinda de IP público, gravado em
/// <c>alerts/alert_*.json</c> para o Tray (sempre ativo) emitir toast na hora.
/// </summary>
public record NetworkAlert(
    DateTime TimestampUtc,
    string Severity,         // "critical" (porta sensível) | "medium"
    string RemoteAddress,
    int RemotePort,
    int LocalPort,
    string ProcessName,
    bool SensitivePort,
    string PortLabel,        // rótulo amigável da porta local, ex.: "RDP / área de trabalho remota (porta 3389)"
    string Title,
    string Message
);
