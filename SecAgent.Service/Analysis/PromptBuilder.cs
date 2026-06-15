using System.Text.Json;
using System.Text.Json.Serialization;
using SecAgent.Service.Models;

namespace SecAgent.Service.Analysis;

public static class PromptBuilder
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private const string Template = """
        Você é um analista de segurança experiente. Analise este snapshot de configuração
        de um sistema Windows e produza um relatório.

        IMPORTANTE: o usuário é iniciante em segurança defensiva. Para CADA finding,
        explique brevemente por que aquilo é um risco, não só o que fazer.

        REGRAS DE FIREWALL — cada `ListeningPorts[i]` pode ter um campo `InboundRules`
        com regras enabled do Windows Firewall que afetam aquela porta. Aplique:
        - Se há regra com `Action=Block`, `RemoteAddresses` abrangente (= `*`,
          `Internet`, ou cobrindo o IP público) E ao menos um perfil ativo
          (Public para internet), considere a porta MITIGADA — NÃO emita finding
          crítico de exposição, no máximo um info dizendo "porta X listening mas
          bloqueada por regra Y".
        - Se a regra Block é restrita (ex: só Domain profile, ou RemoteAddresses
          numa subnet específica), avalie se isso cobre o cenário real (IP público
          em `Addresses` da porta sugere acesso pela internet → perfil Public é o
          que importa). Mitigação parcial = severity menor, não eliminar.
        - Sem InboundRules ou só rules `Allow` → comportamento padrão (sem mitigação),
          mantenha a avaliação de exposição.

        Responda APENAS com um único bloco JSON válido (sem markdown, sem texto antes/depois),
        no formato exato:
        {
          "risk_level": "low|medium|high|critical",
          "summary": "2-3 frases descrevendo o estado geral",
          "findings": [
            {
              "severity": "info|low|medium|high|critical",
              "category": "auth|network|software|config|defender|firewall|updates|users|outro",
              "title": "Título curto",
              "description": "Explique o problema e por que é risco (1-3 frases)",
              "recommendation": "Ação concreta a tomar",
              "evidence": "Trecho ou nome do campo do scan que sustenta o finding (opcional)"
            }
          ]
        }

        Foque em findings ACIONÁVEIS — evite ruído tipo "atualize tudo". Se não há
        riscos relevantes, retorne risk_level=low e findings=[].

        Dados do scan (algumas listas foram agrupadas/resumidas para reduzir tokens):
        {SCAN_JSON}
        """;

    public static string Build(ScanResult scan)
    {
        var summary = Summarize(scan);
        var scanJson = JsonSerializer.Serialize(summary, JsonOpts);
        return Template.Replace("{SCAN_JSON}", scanJson);
    }

    // Publishers whose entries are almost always uninteresting system components
    // (drivers, OS bundled apps). They are summarized to a count instead of listed.
    private static readonly HashSet<string> SystemPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Corporation", "Microsoft",
        "Advanced Micro Devices, Inc.", "AMD",
        "NVIDIA Corporation", "NVIDIA Corp.",
        "Intel Corporation", "Intel",
        "Realtek Semiconductor Corp.", "Realtek",
        "Dell Inc.", "Dell", "Hewlett-Packard", "HP Inc.", "HP",
        "Logitech", "Synaptics", "Synaptics Incorporated"
    };

    /// <summary>
    /// Reduces the scan payload before sending to Claude:
    /// - Groups TCP/UDP listeners by port (collapsing per-interface duplicates)
    /// - Pre-correlates each port with matching Windows Firewall inbound rules
    /// - Drops uninteresting system software, keeping only a count
    /// - Drops full ACE lists for folders without concerns
    /// - Strips noisy fields (InstallDate, ACE for healthy folders)
    /// </summary>
    // UDP listeners are dominated by short-lived application sockets (mDNS, SSDP,
    // ephemeral source ports) that don't represent exposed services. Including
    // them blows the prompt past the 200K token limit. Keep TCP only — that's
    // where the actual exposure question lives.
    private static ScanSummary Summarize(ScanResult s)
    {
        var groupedPorts = s.OpenPorts
            .Where(p => p.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            .GroupBy(p => (p.Protocol, p.LocalPort))
            .Select(g => new PortGroup(
                g.Key.Protocol,
                g.Key.LocalPort,
                CompactAddresses(g.Select(p => p.LocalAddress).Distinct()),
                MatchRulesForPort(g.Key.Protocol, g.Key.LocalPort, s.FirewallRules)))
            .OrderBy(g => g.Port)
            .ToList();

        int udpCount = s.OpenPorts.Count(p => p.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase));

        var (notable, systemCount) = SplitSoftware(s.InstalledSoftware);

        var folders = s.FolderPermissions.Select(f => new FolderSummary(
            f.Path,
            f.Exists,
            f.Aces.Count,
            f.Concerns,
            // Only include ACE detail when there are concerns to investigate
            f.Concerns.Count > 0 ? f.Aces : null
        )).ToList();

        return new ScanSummary(
            s.TimestampUtc,
            s.MachineName,
            s.OsVersion,
            groupedPorts,
            udpCount,
            notable,
            systemCount,
            folders,
            s.Defender,
            s.Firewall,
            s.InstalledUpdates,
            s.LocalUsers,
            s.Administrators,
            s.Errors);
    }

    /// <summary>
    /// Collapses IPv6 link-locals into a single "[IPv6]" marker and dedupes.
    /// Keeps full info for the canonical "any" addresses (0.0.0.0, ::, 127.0.0.1)
    /// and explicit non-loopback IPv4s.
    /// </summary>
    private static List<string> CompactAddresses(IEnumerable<string> addrs)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool hasV6 = false;
        foreach (var a in addrs)
        {
            if (a.Contains(':'))
            {
                // IPv6: collapse all into one marker except the well-known "::"
                if (a == "::") result.Add("::");
                else hasV6 = true;
            }
            else
            {
                result.Add(a);
            }
        }
        if (hasV6) result.Add("[IPv6:other]");
        return result.OrderBy(x => x).ToList();
    }

    private static (List<SoftwareSummary> Notable, int SystemCount) SplitSoftware(List<SoftwareEntry> all)
    {
        var notable = new List<SoftwareSummary>();
        int systemCount = 0;
        foreach (var sw in all)
        {
            if (!string.IsNullOrWhiteSpace(sw.Publisher) && SystemPublishers.Contains(sw.Publisher))
            {
                systemCount++;
                continue;
            }
            notable.Add(new SoftwareSummary(sw.Name, sw.Version, sw.Publisher));
        }
        return (notable.OrderBy(n => n.Name).ToList(), systemCount);
    }

    private const int MaxRemoteAddressesChars = 120;
    private const int MaxMatchedRulesPerPort = 5;

    /// <summary>
    /// For the "is this port exposed?" question, only BLOCK rules add signal —
    /// they tell us traffic is rejected. Allow rules don't change exposure
    /// status, so they're skipped to keep the prompt small.
    /// </summary>
    private static List<MatchedRule>? MatchRulesForPort(string protocol, int port, List<FirewallRule> rules)
    {
        if (rules.Count == 0) return null;

        var matched = new List<MatchedRule>();
        foreach (var r in rules)
        {
            // Only Block rules answer the exposure question.
            if (!r.Action.Equals("Block", StringComparison.OrdinalIgnoreCase)) continue;

            if (!r.Protocol.Equals(protocol, StringComparison.OrdinalIgnoreCase) &&
                !r.Protocol.Equals("Any", StringComparison.OrdinalIgnoreCase))
                continue;

            bool isWildcardPort = string.IsNullOrEmpty(r.LocalPorts) ||
                                   r.LocalPorts == "*" ||
                                   r.LocalPorts.Equals("Any", StringComparison.OrdinalIgnoreCase);

            if (!isWildcardPort && !PortInRange(port, r.LocalPorts)) continue;

            matched.Add(new MatchedRule(
                r.Name,
                r.Action,
                r.RemoteAddresses.Length > MaxRemoteAddressesChars
                    ? r.RemoteAddresses[..MaxRemoteAddressesChars] + "..."
                    : r.RemoteAddresses,
                r.Profiles));

            if (matched.Count >= MaxMatchedRulesPerPort) break;
        }
        return matched.Count > 0 ? matched : null;
    }

    private static bool PortInRange(int port, string spec)
    {
        if (string.IsNullOrWhiteSpace(spec)) return false;

        foreach (var part in spec.Split(','))
        {
            var p = part.Trim();
            if (p.Length == 0) continue;

            if (p.Contains('-'))
            {
                var range = p.Split('-', 2);
                if (range.Length == 2 &&
                    int.TryParse(range[0], out int lo) &&
                    int.TryParse(range[1], out int hi) &&
                    port >= lo && port <= hi)
                    return true;
            }
            else if (int.TryParse(p, out int single) && port == single)
            {
                return true;
            }
        }
        return false;
    }
}

public record ScanSummary(
    DateTime TimestampUtc,
    string MachineName,
    string OsVersion,
    List<PortGroup> ListeningPortsTcp,
    int UdpListenerCount,
    List<SoftwareSummary> NotableSoftware,
    int SystemSoftwareCount,
    List<FolderSummary> FolderPermissions,
    DefenderStatus? Defender,
    FirewallStatus? Firewall,
    List<UpdateEntry> InstalledUpdates,
    List<UserAccount> LocalUsers,
    List<string> Administrators,
    List<CollectorError> Errors
);

public record PortGroup(string Protocol, int Port, List<string> Addresses, List<MatchedRule>? InboundRules);

public record MatchedRule(string Name, string Action, string RemoteAddresses, List<string> Profiles);

public record SoftwareSummary(string Name, string? Version, string? Publisher);

public record FolderSummary(
    string Path,
    bool Exists,
    int AceCount,
    List<string> Concerns,
    List<AceEntry>? AcesIfConcerned
);
