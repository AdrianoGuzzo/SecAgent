using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using SecAgent.Service.Models;

namespace SecAgent.Service.Monitors;

/// <summary>
/// Medidor de tráfego por IP com play/stop, acionado pelo painel via triggers
/// (traffic-track-start/stop). Acumula o tráfego EXATO transferido durante o
/// período: a fonte é o <see cref="NetworkTrafficEtwCollector"/> (ETW kernel
/// network), que durante a medição empurra cada evento de send/recv via
/// <see cref="Add"/>. Como cada evento já traz o tamanho daquele pedaço, basta
/// SOMAR por IP remoto — sem baseline nem delta. Diferente do antigo ESTATS por
/// conexão, isto cobre TCP E UDP/QUIC e mede ambas as direções corretamente.
///
/// O <see cref="NetworkSnapshotService"/> (sempre a ~0,5 s) chama <see cref="Flush"/>
/// a cada ciclo para regravar o arquivo do painel e resolver PID→nome.
///
/// Singleton compartilhado (DI). Thread-safety simples via lock: Start/Stop vêm
/// das threads de trigger; Add vem da thread de processamento do ETW; Flush vem
/// da thread do snapshot.
///
/// Limitações (por design): reinício do Service zera o estado em memória (a
/// medição NÃO retoma); só conta o que trafegar DEPOIS do play.
/// </summary>
public class TrafficAccumulator
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly ILogger<TrafficAccumulator> _logger;
    private readonly string _path;
    private readonly object _lock = new();

    private bool _active;
    private DateTime? _startedUtc;
    private DateTime? _stoppedUtc;
    private DateTime _cycleNow;

    // Totais acumulados por IP remoto durante o período.
    private readonly Dictionary<string, IpTotal> _totals = new();

    private sealed class IpTotal
    {
        public long BytesIn;
        public long BytesOut;
        public int LastPid;
        public string ProcessName = "desconhecido";
        public bool RemoteIsPublic;
    }

    public TrafficAccumulator(ILogger<TrafficAccumulator> logger, IOptions<MonitorOptions> opts)
    {
        _logger = logger;
        _path = opts.Value.TrafficTrackPath;

        // Resquício de um restart durante medição: reescreve como inativo para o
        // painel não parecer "travado" mostrando Active=true sem updates.
        try
        {
            if (File.Exists(_path))
                WriteSnapshot();   // _active=false por padrão → grava estado parado
        }
        catch (Exception ex) { _logger.LogWarning(ex, "TrafficAccumulator: falha ao normalizar arquivo no startup"); }
    }

    public bool IsActive
    {
        get { lock (_lock) return _active; }
    }

    /// <summary>Inicia (ou reinicia) a medição, zerando os totais.</summary>
    public void Start()
    {
        lock (_lock)
        {
            _totals.Clear();
            _active = true;
            _startedUtc = DateTime.UtcNow;
            _stoppedUtc = null;
            _cycleNow = default;
            WriteSnapshot();
        }
        _logger.LogInformation("TrafficAccumulator: medição iniciada");
    }

    /// <summary>Para a medição, preservando os totais finais no arquivo.</summary>
    public void Stop()
    {
        lock (_lock)
        {
            if (!_active && _stoppedUtc is not null) return;   // já parado
            _active = false;
            _stoppedUtc = DateTime.UtcNow;
            WriteSnapshot();
        }
        _logger.LogInformation("TrafficAccumulator: medição encerrada");
    }

    /// <summary>
    /// Soma um evento de tráfego ao IP remoto (chamado pela thread do ETW). No-op
    /// rápido quando a medição está parada.
    /// </summary>
    public void Add(string remoteIp, int pid, long bytesIn, long bytesOut, bool remoteIsPublic)
    {
        if (!_active) return;
        if (bytesIn <= 0 && bytesOut <= 0) return;
        lock (_lock)
        {
            if (!_active) return;
            if (!_totals.TryGetValue(remoteIp, out var t))
                _totals[remoteIp] = t = new IpTotal();
            t.BytesIn += bytesIn;
            t.BytesOut += bytesOut;
            t.LastPid = pid;
            t.RemoteIsPublic = remoteIsPublic;
        }
    }

    /// <summary>
    /// Regrava o snapshot do painel resolvendo PID→nome via o mapa do ciclo atual
    /// do snapshot. No-op quando a medição está parada (o estado final já foi
    /// gravado pelo Stop()).
    /// </summary>
    public void Flush(IReadOnlyDictionary<int, string> pidNames, DateTime now)
    {
        if (!_active) return;
        lock (_lock)
        {
            if (!_active) return;
            _cycleNow = now;
            foreach (var t in _totals.Values)
            {
                if (pidNames.TryGetValue(t.LastPid, out var name) && !string.IsNullOrEmpty(name))
                    t.ProcessName = name;
            }
            WriteSnapshot();
        }
    }

    // Constrói o snapshot a partir do estado atual e grava atomicamente.
    // Deve ser chamado sob _lock (exceto no ctor, antes de qualquer concorrência).
    private void WriteSnapshot()
    {
        var totals = _totals
            .Select(kv => new TrafficTrackEntry(
                Ip: kv.Key,
                BytesIn: kv.Value.BytesIn,
                BytesOut: kv.Value.BytesOut,
                BytesTotal: kv.Value.BytesIn + kv.Value.BytesOut,
                ProcessName: kv.Value.ProcessName,
                RemoteIsPublic: kv.Value.RemoteIsPublic))
            .OrderByDescending(e => e.BytesTotal)
            .ToList();

        // Fim do período: instante de parada (se parado), senão o "agora" do ciclo
        // corrente (se já houve ciclo), senão o relógio (logo após o Start()).
        DateTime endUtc = _stoppedUtc ?? (_cycleNow == default ? DateTime.UtcNow : _cycleNow);
        double elapsed = _startedUtc is null ? 0 : (endUtc - _startedUtc.Value).TotalSeconds;
        if (elapsed < 0) elapsed = 0;

        var snap = new TrafficTrackSnapshot(_active, _startedUtc, _stoppedUtc, elapsed, totals);

        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(snap, JsonOpts));
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TrafficAccumulator: falha ao gravar {Path}", _path);
        }
    }
}
