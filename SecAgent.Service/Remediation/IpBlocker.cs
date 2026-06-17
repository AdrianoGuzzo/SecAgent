using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecAgent.Service.Remediation;

/// <summary>
/// Blocks/unblocks a remote IP address by creating a pair of Windows Firewall
/// rules (inbound + outbound) via the HNetCfg.FwPolicy2 COM interface — the same
/// API surface used (read-only) by <c>FirewallRulesCollector</c>. Runs as
/// LocalSystem inside the Service, so it has the privilege to add/remove rules.
///
/// State is mirrored to <c>C:\ProgramData\SecAgent\blocked.json</c> after every
/// change (and rebuilt from the existing SecAgent-Block-* rules on startup, so it
/// survives reboots). The Tray reads that file to render the "blocked" list.
/// </summary>
public class IpBlocker
{
    private const int NetFwRuleDirectionIn  = 1;
    private const int NetFwRuleDirectionOut = 2;
    private const int NetFwActionBlock      = 0;
    private const int NetFwProfileAll       = 0x7FFFFFFF;
    private const int NetFwIpProtocolAny    = 256;

    private const string RulePrefix  = "SecAgent-Block-";
    private const string BlockedPath = @"C:\ProgramData\SecAgent\blocked.json";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly ILogger<IpBlocker> _logger;
    private readonly object _lock = new();

    public IpBlocker(ILogger<IpBlocker> logger)
    {
        _logger = logger;
        // Reconcile blocked.json with whatever rules already exist (post-reboot).
        try { WriteBlockedFile(); } catch (Exception ex) { _logger.LogError(ex, "IpBlocker startup reconcile failed"); }
    }

    /// <summary>Creates inbound+outbound block rules for <paramref name="ip"/>. Idempotent.</summary>
    public void Block(string ip)
    {
        if (!IPAddress.TryParse(ip, out var parsed))
        {
            _logger.LogWarning("IpBlocker.Block ignored invalid IP {Ip}", ip);
            return;
        }
        var canonical = parsed.ToString();

        lock (_lock)
        {
            dynamic? policy = CreatePolicy();
            if (policy is null) return;

            // Remove any stale rules of the same name first (idempotent).
            RemoveRules(policy, canonical);
            AddRule(policy, canonical, NetFwRuleDirectionIn);
            AddRule(policy, canonical, NetFwRuleDirectionOut);
            _logger.LogInformation("Blocked IP {Ip} (inbound+outbound firewall rules)", canonical);

            WriteBlockedFile(policy);
        }
    }

    /// <summary>Removes the block rules for <paramref name="ip"/>. Idempotent.</summary>
    public void Unblock(string ip)
    {
        if (!IPAddress.TryParse(ip, out var parsed))
        {
            _logger.LogWarning("IpBlocker.Unblock ignored invalid IP {Ip}", ip);
            return;
        }
        var canonical = parsed.ToString();

        lock (_lock)
        {
            dynamic? policy = CreatePolicy();
            if (policy is null) return;

            RemoveRules(policy, canonical);
            _logger.LogInformation("Unblocked IP {Ip}", canonical);

            WriteBlockedFile(policy);
        }
    }

    private dynamic? CreatePolicy()
    {
        var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        if (t is null) { _logger.LogError("HNetCfg.FwPolicy2 not available"); return null; }
        try { return Activator.CreateInstance(t); }
        catch (Exception ex) { _logger.LogError(ex, "Failed to create HNetCfg.FwPolicy2"); return null; }
    }

    private void AddRule(dynamic policy, string ip, int direction)
    {
        try
        {
            var rt = Type.GetTypeFromProgID("HNetCfg.FWRule");
            if (rt is null) return;
            dynamic rule = Activator.CreateInstance(rt)!;
            rule.Name = RuleName(ip, direction);
            rule.Description = "Bloqueado pelo SecAgent";
            rule.Direction = direction;
            rule.Action = NetFwActionBlock;
            rule.Protocol = NetFwIpProtocolAny;
            rule.RemoteAddresses = ip;
            rule.Profiles = NetFwProfileAll;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add firewall rule for {Ip} dir {Dir}", ip, direction);
        }
    }

    private void RemoveRules(dynamic policy, string ip)
    {
        foreach (var dir in new[] { NetFwRuleDirectionIn, NetFwRuleDirectionOut })
        {
            try { policy.Rules.Remove(RuleName(ip, dir)); }
            catch { /* rule may not exist — fine */ }
        }
    }

    private static string RuleName(string ip, int direction)
        => $"{RulePrefix}{ip}-{(direction == NetFwRuleDirectionIn ? "In" : "Out")}";

    /// <summary>Rebuilds blocked.json from the live SecAgent-Block-* rules.</summary>
    private void WriteBlockedFile(dynamic? policy = null)
    {
        policy ??= CreatePolicy();
        if (policy is null) return;

        var ips = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (dynamic rule in policy.Rules)
            {
                try
                {
                    string name = (string?)rule.Name ?? "";
                    if (!name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase)) continue;
                    // Strip prefix and the -In/-Out suffix to recover the IP.
                    var core = name.Substring(RulePrefix.Length);
                    int dash = core.LastIndexOf('-');
                    if (dash > 0) core = core.Substring(0, dash);
                    if (core.Length > 0) ips.Add(core);
                }
                catch { /* skip legacy/orphan rule */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to enumerate firewall rules for blocked.json");
            return;
        }

        var list = new BlockedList(DateTime.UtcNow, ips.Select(i => new BlockedIp(i)).ToList());
        try
        {
            var dir = Path.GetDirectoryName(BlockedPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = BlockedPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(list, JsonOpts));
            File.Move(tmp, BlockedPath, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write blocked.json");
        }
    }

    private record BlockedList(DateTime UpdatedUtc, List<BlockedIp> Blocked);
    private record BlockedIp(string Ip);
}
