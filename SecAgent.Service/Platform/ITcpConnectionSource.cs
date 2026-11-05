using System.Diagnostics.CodeAnalysis;
using System.Net;
using SecAgent.Service.Monitors.Native;

namespace SecAgent.Service.Platform;

/// <summary>Uma conexão TCP estabelecida com PID dono e contadores cumulativos (ESTATS).</summary>
public record TcpConnectionRow(
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    int OwningPid,
    ulong CumBytesIn = 0,
    ulong CumBytesOut = 0);

/// <summary>Tabela de conexões TCP (v4+v6) com PID — GetExtendedTcpTable.</summary>
public interface ITcpConnectionSource
{
    /// <summary>
    /// Conexões ESTABLISHED, ou <c>null</c> quando a leitura FALHOU. Importante
    /// distinguir "falhou" de "vazio": um ciclo vazio por falha fazia todas as
    /// conexões de entrada serem re-alertadas no ciclo seguinte.
    /// </summary>
    IReadOnlyList<TcpConnectionRow>? TryGetEstablished();
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de P/Invoke")]
internal sealed class IpHlpTcpConnectionSource : ITcpConnectionSource
{
    public IReadOnlyList<TcpConnectionRow>? TryGetEstablished()
        => IpHlpApi.TryGetEstablishedConnections(out var rows) ? rows : null;
}
