using Microsoft.Extensions.Options;
using SecAgent.Service.Collectors;
using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service;

public interface ISecurityScanner
{
    ScanResult RunFullScan();
}

/// <summary>
/// Roda os 8 coletores em sequência. Cada um é isolado por <see cref="Safe{T}"/>:
/// uma falha vira <see cref="CollectorError"/> e não derruba o scan inteiro.
/// </summary>
public class SecurityScanner : ISecurityScanner
{
    private readonly ILogger<SecurityScanner> _logger;
    private readonly ScannerOptions _options;
    private readonly TimeProvider _time;
    private readonly ISystemEnvironment _env;
    private readonly OpenPortsCollector _ports;
    private readonly InstalledSoftwareCollector _software;
    private readonly FolderPermissionsCollector _folders;
    private readonly DefenderStatusCollector _defender;
    private readonly FirewallStatusCollector _firewall;
    private readonly FirewallRulesCollector _firewallRules;
    private readonly InstalledUpdatesCollector _updates;
    private readonly UserAccountsCollector _users;

    public SecurityScanner(
        ILogger<SecurityScanner> logger,
        IOptions<ScannerOptions> options,
        TimeProvider time,
        ISystemEnvironment env,
        OpenPortsCollector ports,
        InstalledSoftwareCollector software,
        FolderPermissionsCollector folders,
        DefenderStatusCollector defender,
        FirewallStatusCollector firewall,
        FirewallRulesCollector firewallRules,
        InstalledUpdatesCollector updates,
        UserAccountsCollector users)
    {
        _logger = logger;
        _options = options.Value;
        _time = time;
        _env = env;
        _ports = ports;
        _software = software;
        _folders = folders;
        _defender = defender;
        _firewall = firewall;
        _firewallRules = firewallRules;
        _updates = updates;
        _users = users;
    }

    public ScanResult RunFullScan()
    {
        var errors = new List<CollectorError>();

        var ports         = Safe("OpenPorts",     () => _ports.Collect(),                           errors) ?? new();
        var software      = Safe("Software",      () => _software.Collect(),                        errors) ?? new();
        var folders       = Safe("Folders",       () => _folders.Collect(_options.CriticalFolders), errors) ?? new();
        var defender      = Safe("Defender",      () => _defender.Collect(),                        errors);
        var firewall      = Safe("Firewall",      () => _firewall.Collect(),                        errors);
        var firewallRules = Safe("FirewallRules", () => _firewallRules.Collect(),                   errors) ?? new();
        var updates       = Safe("Updates",       () => _updates.Collect(),                         errors) ?? new();
        var accounts      = Safe("Users",         () => new UserAccountsResult(_users.Collect()),   errors);

        return new ScanResult(
            TimestampUtc: _time.GetUtcNow().UtcDateTime,
            MachineName: _env.MachineName,
            OsVersion: _env.OsVersion,
            OpenPorts: ports,
            InstalledSoftware: software,
            FolderPermissions: folders,
            Defender: defender,
            Firewall: firewall,
            FirewallRules: firewallRules,
            InstalledUpdates: updates,
            LocalUsers: accounts?.Value.Users ?? new(),
            Administrators: accounts?.Value.Administrators ?? new(),
            Errors: errors
        );
    }

    private sealed record UserAccountsResult((List<UserAccount> Users, List<string> Administrators) Value);

    private T? Safe<T>(string name, Func<T> action, List<CollectorError> errors) where T : class
    {
        try { return action(); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Collector {Name} failed", name);
            errors.Add(new CollectorError(name, $"{ex.GetType().Name}: {ex.Message}"));
            return null;
        }
    }
}
