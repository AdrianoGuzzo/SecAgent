namespace SecAgent.Tray.Models;

// Mirror de SecAgent.Service.Models.TrafficTrackSnapshot/TrafficTrackEntry
// (traffic-track.json). Resultado do medidor de tráfego por IP (play/stop).

public record TrafficTrackSnapshot(
    bool Active,
    DateTime? StartedUtc,
    DateTime? StoppedUtc,
    double ElapsedSeconds,
    List<TrafficTrackEntry> Totals
);

public record TrafficTrackEntry(
    string Ip,
    long BytesIn,
    long BytesOut,
    long BytesTotal,
    string ProcessName,
    bool RemoteIsPublic
);
