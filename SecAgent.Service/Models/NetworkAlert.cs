namespace SecAgent.Service.Models;

/// <summary>
/// An immediate alert for a NEW inbound connection from a public IP, written to
/// C:\ProgramData\SecAgent\alerts\alert_*.json so the always-on Tray can toast
/// the user right away (the SecurityEvent path only feeds the slower incident
/// pipeline). The Tray enriches RemoteAddress with country before showing it.
/// </summary>
public record NetworkAlert(
    DateTime TimestampUtc,
    string Severity,         // "critical" (sensitive port) | "medium"
    string RemoteAddress,
    int RemotePort,
    int LocalPort,
    string ProcessName,
    bool SensitivePort,
    string PortLabel,        // friendly local-port label, e.g. "RDP (área de trabalho remota)"
    string Title,
    string Message
);
