namespace SecAgent.Service.Models;

/// <summary>
/// Resultado do medidor de tráfego por IP (aba "Tráfego por IP" do painel).
/// Enquanto <see cref="Active"/> é true o <c>TrafficAccumulator</c> soma, a cada
/// snapshot (~0,5s), os deltas de bytes cumulativos (ESTATS) de cada conexão TCP,
/// agregando por IP remoto. Escrito atomicamente em
/// C:\ProgramData\SecAgent\traffic-track.json para o Tray renderizar os totais.
/// </summary>
public record TrafficTrackSnapshot(
    bool Active,
    DateTime? StartedUtc,
    DateTime? StoppedUtc,
    double ElapsedSeconds,
    List<TrafficTrackEntry> Totals
);

/// <summary>Total acumulado para um IP remoto durante o período de medição.</summary>
public record TrafficTrackEntry(
    string Ip,
    long BytesIn,            // bytes recebidos (entrada) acumulados no período
    long BytesOut,           // bytes enviados (saída) acumulados no período
    long BytesTotal,         // BytesIn + BytesOut (conveniência p/ ordenar/exibir)
    string ProcessName,      // último processo visto comunicando com este IP
    bool RemoteIsPublic      // true quando o IP é roteável público
);
