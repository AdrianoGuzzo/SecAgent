using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Options;

namespace SecAgent.Service.Monitors;

/// <summary>
/// Fonte ÚNICA de tráfego do projeto, via ETW (provedor kernel "NetworkTCPIP").
/// Roda 24/7 (BackgroundService) e alimenta dois consumidores:
///
///  1. Mapa cumulativo POR CONEXÃO (4-tupla, só TCP) → o
///     <see cref="NetworkSnapshotService"/> lê via <see cref="GetConnectionCumBytes"/>
///     e deriva o bytes/s de cada conexão na tabela do painel.
///  2. <see cref="TrafficAccumulator"/> (TCP + UDP/QUIC) → medidor por IP com
///     play/stop; <c>Add</c> é no-op rápido quando a medição está parada.
///
/// Cada evento de kernel traz o tamanho daquele send/recv + PID + endereços. O
/// endereço REMOTO é o que não é local (decidido por <see cref="IsLocal"/>,
/// evitando a ambiguidade saddr/daddr entre Send e Recv). Recv → bytesIn;
/// Send → bytesOut.
///
/// Requer privilégio de sessão ETW de kernel → OK como LocalSystem (em modo
/// console de debug, exige admin). A sessão "NT Kernel Logger" é singleton no
/// sistema: se outra ferramenta (xperf/wpr) a estiver usando, a abertura falha e
/// tentamos de novo a cada 30 s.
/// </summary>
public class NetworkTrafficEtwCollector : BackgroundService
{
    private readonly ILogger<NetworkTrafficEtwCollector> _logger;
    private readonly TrafficAccumulator _traffic;
    private readonly MonitorOptions _opts;

    // Cumulativo por conexão TCP (4-tupla), atualizado pela thread do ETW e lido
    // pela thread do snapshot. ConnCounter é mutado via Interlocked.
    private readonly ConcurrentDictionary<string, ConnCounter> _conns = new();

    // Endereços desta máquina (por bytes, ignorando scope id de IPv6). volatile:
    // trocado em bloco pela manutenção, lido pela thread do ETW.
    private volatile HashSet<string> _localKeys = new();

    private Timer? _maintenance;

    private sealed class ConnCounter
    {
        public long In;
        public long Out;
        public long LastTicks;
    }

    public NetworkTrafficEtwCollector(
        ILogger<NetworkTrafficEtwCollector> logger,
        TrafficAccumulator traffic,
        IOptions<MonitorOptions> opts)
    {
        _logger = logger;
        _traffic = traffic;
        _opts = opts.Value;
    }

    /// <summary>Bytes cumulativos (In+Out) observados para uma conexão TCP; 0 se desconhecida.</summary>
    public ulong GetConnectionCumBytes(string connKey)
    {
        if (_conns.TryGetValue(connKey, out var c))
            return (ulong)(Interlocked.Read(ref c.In) + Interlocked.Read(ref c.Out));
        return 0;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.TrafficEtwEnabled)
        {
            _logger.LogInformation("NetworkTrafficEtwCollector desabilitado por config (TrafficEtwEnabled=false)");
            return;
        }

        _localKeys = BuildLocalAddressKeys();
        _maintenance = new Timer(_ => Maintenance(), null,
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                bool clean = false;
                try
                {
                    await RunSessionAsync(stoppingToken);
                    clean = true;            // sessão encerrou sem exceção
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Sessão ETW de tráfego falhou — nova tentativa em 30s");
                }

                if (stoppingToken.IsCancellationRequested) break;
                try { await Task.Delay(TimeSpan.FromSeconds(clean ? 5 : 30), stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }
        finally
        {
            try { _maintenance?.Dispose(); } catch { }
        }
    }

    // Abre a sessão e processa eventos até o cancelamento (dispose quebra o Process()).
    private Task RunSessionAsync(CancellationToken ct) => Task.Run(() =>
    {
        TraceEventSession? session = null;
        try
        {
            session = new TraceEventSession(KernelTraceEventParser.KernelSessionName)
            {
                StopOnDispose = true
            };
            using var reg = ct.Register(() => { try { session!.Dispose(); } catch { } });

            session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

            var k = session.Source.Kernel;
            // size/saddr/daddr/sport/dport/ProcessID existem em todos esses *TraceData.
            k.TcpIpRecv      += d => Observe(d.saddr, d.daddr, d.sport, d.dport, d.size, d.ProcessID, recv: true,  isTcp: true);
            k.TcpIpSend      += d => Observe(d.saddr, d.daddr, d.sport, d.dport, d.size, d.ProcessID, recv: false, isTcp: true);
            k.TcpIpRecvIPV6  += d => Observe(d.saddr, d.daddr, d.sport, d.dport, d.size, d.ProcessID, recv: true,  isTcp: true);
            k.TcpIpSendIPV6  += d => Observe(d.saddr, d.daddr, d.sport, d.dport, d.size, d.ProcessID, recv: false, isTcp: true);
            k.UdpIpRecv      += d => Observe(d.saddr, d.daddr, d.sport, d.dport, d.size, d.ProcessID, recv: true,  isTcp: false);
            k.UdpIpSend      += d => Observe(d.saddr, d.daddr, d.sport, d.dport, d.size, d.ProcessID, recv: false, isTcp: false);
            k.UdpIpRecvIPV6  += d => Observe(d.saddr, d.daddr, d.sport, d.dport, d.size, d.ProcessID, recv: true,  isTcp: false);
            k.UdpIpSendIPV6  += d => Observe(d.saddr, d.daddr, d.sport, d.dport, d.size, d.ProcessID, recv: false, isTcp: false);

            _logger.LogInformation("NetworkTrafficEtwCollector: sessão ETW iniciada (always-on)");
            session.Source.Process();    // bloqueia até a sessão ser encerrada
        }
        finally
        {
            try { session?.Dispose(); } catch { }
        }
    }, ct);

    // Chamado pela thread de processamento do ETW (única → handlers não concorrem
    // entre si; a concorrência é com leituras/poda, tratada por Interlocked).
    private void Observe(IPAddress saddr, IPAddress daddr, int sport, int dport, int size, int pid, bool recv, bool isTcp)
    {
        if (size <= 0) return;

        bool sLocal = IsLocal(saddr);
        bool dLocal = IsLocal(daddr);

        IPAddress remote; int remotePort;
        IPAddress local; int localPort;
        if (!dLocal)                 { remote = daddr; remotePort = dport; local = saddr; localPort = sport; }
        else if (!sLocal)            { remote = saddr; remotePort = sport; local = daddr; localPort = dport; }
        else /* ambos locais (loopback) */ { remote = daddr; remotePort = dport; local = saddr; localPort = sport; }

        // Medidor por IP (TCP + UDP). No-op quando a medição está parada.
        bool isPublic = NetworkMonitor.IsPublicAddress(remote);
        if (recv) _traffic.Add(remote.ToString(), pid, size, 0, isPublic);
        else      _traffic.Add(remote.ToString(), pid, 0, size, isPublic);

        // Mapa cumulativo por conexão — só TCP (a tabela de conexões é só TCP).
        if (!isTcp) return;
        var connKey = $"{local}:{localPort}|{remote}:{remotePort}";
        var c = _conns.GetOrAdd(connKey, static _ => new ConnCounter());
        if (recv) Interlocked.Add(ref c.In, size);
        else      Interlocked.Add(ref c.Out, size);
        Interlocked.Exchange(ref c.LastTicks, Environment.TickCount64);
    }

    // A cada 30s: atualiza os endereços locais (Wi-Fi/VPN mudam) e poda conexões
    // que pararam de aparecer (evita leak — UDP nem entra no mapa).
    private void Maintenance()
    {
        try { _localKeys = BuildLocalAddressKeys(); } catch { }

        long cutoff = Environment.TickCount64 - 120_000;   // 2 min
        foreach (var kv in _conns)
            if (Interlocked.Read(ref kv.Value.LastTicks) < cutoff)
                _conns.TryRemove(kv.Key, out _);
    }

    private bool IsLocal(IPAddress addr) => _localKeys.Contains(Key(addr));

    private static string Key(IPAddress addr) => Convert.ToHexString(addr.GetAddressBytes());

    // Endereços desta máquina (todas as NICs) + loopback, por bytes (ignora scope
    // id de IPv6 link-local, que o ETW pode reportar diferente da NIC).
    private static HashSet<string> BuildLocalAddressKeys()
    {
        var set = new HashSet<string>
        {
            Key(IPAddress.Loopback),
            Key(IPAddress.IPv6Loopback)
        };
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        set.Add(Key(ua.Address));
                }
                catch { /* NIC sem propriedades IP */ }
            }
        }
        catch { /* best effort */ }
        return set;
    }
}
