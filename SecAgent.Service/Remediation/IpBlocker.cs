using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Remediation;

public interface IIpBlocker
{
    /// <summary>Cria as regras In+Out para o IP. True só se as DUAS foram criadas.</summary>
    bool Block(string ip);

    /// <summary>Remove as regras do IP. Idempotente.</summary>
    bool Unblock(string ip);

    /// <summary>Reconstrói blocked.json a partir das regras SecAgent-Block-* existentes.</summary>
    void Reconcile();
}

/// <summary>
/// Bloqueia/desbloqueia um IP remoto criando um par de regras do Windows
/// Firewall (entrada + saída). Roda como LocalSystem dentro do Service.
///
/// O estado é espelhado em <c>blocked.json</c> após cada mudança (e reconstruído
/// das regras existentes no startup, sobrevivendo a reboots). O Tray lê esse
/// arquivo para a lista de bloqueados.
/// </summary>
public class IpBlocker : IIpBlocker
{
    private const string RuleDescription = "Bloqueado pelo SecAgent";

    private readonly ILogger<IpBlocker> _logger;
    private readonly IFirewallPolicy _policy;
    private readonly TimeProvider _time;
    private readonly string _blockedPath;
    private readonly object _lock = new();

    public IpBlocker(ILogger<IpBlocker> logger, IFirewallPolicy policy, AgentPaths paths, TimeProvider time)
    {
        _logger = logger;
        _policy = policy;
        _time = time;
        _blockedPath = paths.BlockedFile;
    }

    public bool Block(string ip)
    {
        if (!IpAddressPolicy.TryParseStrict(ip, out var parsed))
        {
            _logger.LogWarning("IpBlocker.Block ignored invalid IP {Ip}", ip);
            return false;
        }
        if (!IpAddressPolicy.IsBlockable(parsed, out var reason))
        {
            // Qualquer usuário pode soltar um trigger: não deixamos bloquear
            // loopback/unspecified/multicast (DoS local trivial).
            _logger.LogWarning("IpBlocker.Block refused {Ip}: {Reason}", ip, reason);
            return false;
        }
        var canonical = parsed.ToString();

        lock (_lock)
        {
            try
            {
                // Remove regras velhas de mesmo nome antes (idempotente).
                RemoveRules(canonical);
                _policy.AddBlockRule(BlockRuleName.For(canonical, FirewallConstants.DirectionIn), canonical,
                    FirewallConstants.DirectionIn, RuleDescription);
                try
                {
                    _policy.AddBlockRule(BlockRuleName.For(canonical, FirewallConstants.DirectionOut), canonical,
                        FirewallConstants.DirectionOut, RuleDescription);
                }
                catch
                {
                    // Sem bloqueio "meia-boca": desfaz a regra de entrada.
                    _policy.RemoveRule(BlockRuleName.For(canonical, FirewallConstants.DirectionIn));
                    throw;
                }
                _logger.LogInformation("Blocked IP {Ip} (inbound+outbound firewall rules)", canonical);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to block IP {Ip}", canonical);
                return false;
            }
            finally
            {
                WriteBlockedFile();
            }
        }
    }

    public bool Unblock(string ip)
    {
        if (!IpAddressPolicy.TryParseStrict(ip, out var parsed))
        {
            _logger.LogWarning("IpBlocker.Unblock ignored invalid IP {Ip}", ip);
            return false;
        }
        var canonical = parsed.ToString();

        lock (_lock)
        {
            try
            {
                RemoveRules(canonical);
                _logger.LogInformation("Unblocked IP {Ip}", canonical);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to unblock IP {Ip}", canonical);
                return false;
            }
            finally
            {
                WriteBlockedFile();
            }
        }
    }

    public void Reconcile()
    {
        lock (_lock) WriteBlockedFile();
    }

    private void RemoveRules(string ip)
    {
        _policy.RemoveRule(BlockRuleName.For(ip, FirewallConstants.DirectionIn));
        _policy.RemoveRule(BlockRuleName.For(ip, FirewallConstants.DirectionOut));
    }

    private void WriteBlockedFile()
    {
        IReadOnlyList<string> names;
        try { names = _policy.GetRuleNames(); }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to enumerate firewall rules for blocked.json");
            return;
        }

        var ips = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in names)
            if (BlockRuleName.TryParseIp(name, out var ip)) ips.Add(ip);

        var list = new BlockedList(_time.GetUtcNow().UtcDateTime, ips.Select(i => new BlockedIp(i)).ToList());
        try
        {
            AtomicFile.WriteAllText(_blockedPath, JsonSerializer.Serialize(list, JsonDefaults.Compact));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write blocked.json");
        }
    }
}

/// <summary>Nome das regras: <c>SecAgent-Block-&lt;ip&gt;-In|Out</c>.</summary>
internal static class BlockRuleName
{
    public const string Prefix = "SecAgent-Block-";

    public static string For(string ip, int direction)
        => $"{Prefix}{ip}-{(direction == FirewallConstants.DirectionIn ? "In" : "Out")}";

    /// <summary>Recupera o IP de um nome de regra do SecAgent (sufixo -In/-Out obrigatório).</summary>
    public static bool TryParseIp(string? name, out string ip)
    {
        ip = "";
        if (string.IsNullOrEmpty(name) || !name.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var core = name[Prefix.Length..];
        if (core.EndsWith("-In", StringComparison.OrdinalIgnoreCase)) core = core[..^3];
        else if (core.EndsWith("-Out", StringComparison.OrdinalIgnoreCase)) core = core[..^4];
        else return false;
        if (core.Length == 0) return false;
        ip = core;
        return true;
    }
}

/// <summary>Validação de IPs vindos do conteúdo de triggers (gravável por qualquer usuário).</summary>
internal static class IpAddressPolicy
{
    /// <summary>
    /// Parse estrito: IPv4 só na forma pontuada completa (a.b.c.d) — o
    /// <see cref="IPAddress.TryParse(string, out IPAddress)"/> aceita "1" como 0.0.0.1.
    /// </summary>
    public static bool TryParseStrict(string? text, out IPAddress address)
    {
        address = IPAddress.None;
        var s = (text ?? "").Trim();
        if (s.Length == 0) return false;

        if (s.Contains(':'))
        {
            if (!IPAddress.TryParse(s, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;
            address = v6;
            return true;
        }

        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (var p in parts)
            if (p.Length is 0 or > 3 || !p.All(char.IsAsciiDigit) || int.Parse(p) > 255) return false;

        if (!IPAddress.TryParse(s, out var v4)) return false;
        address = v4;
        return true;
    }

    public static bool IsBlockable(IPAddress ip, out string reason)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

        if (IPAddress.IsLoopback(ip)) { reason = "loopback"; return false; }
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) { reason = "unspecified"; return false; }
        if (ip.Equals(IPAddress.Broadcast)) { reason = "broadcast"; return false; }
        if (ip.AddressFamily == AddressFamily.InterNetwork && ip.GetAddressBytes()[0] is >= 224 and <= 239)
        { reason = "multicast"; return false; }
        if (ip.IsIPv6Multicast) { reason = "multicast"; return false; }

        reason = "";
        return true;
    }
}
