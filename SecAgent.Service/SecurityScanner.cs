using Microsoft.Extensions.Options;
using SecAgent.Service.Collectors;
using SecAgent.Service.Models;

namespace SecAgent.Service;

public class SecurityScanner
{
    private readonly ILogger<SecurityScanner> _logger;
    private readonly ScannerOptions _options;
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
        var (users, admins) = SafeTuple("Users",  () => _users.Collect(),                           errors);

        return new ScanResult(
            TimestampUtc: DateTime.UtcNow,
            MachineName: Environment.MachineName,
            OsVersion: Environment.OSVersion.VersionString,
            OpenPorts: ports,
            InstalledSoftware: software,
            FolderPermissions: folders,
            Defender: defender,
            Firewall: firewall,
            FirewallRules: firewallRules,
            InstalledUpdates: updates,
            LocalUsers: users,
            Administrators: admins,
            Errors: errors
        );
    }

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

    private (List<UserAccount>, List<string>) SafeTuple(string name,
        Func<(List<UserAccount>, List<string>)> action, List<CollectorError> errors)
    {
        try { return action(); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Collector {Name} failed", name);
            errors.Add(new CollectorError(name, $"{ex.GetType().Name}: {ex.Message}"));
            return (new(), new());
        }
    }
}
