namespace SecAgent.Service.Models;

public record ScanResult(
    DateTime TimestampUtc,
    string MachineName,
    string OsVersion,
    List<OpenPort> OpenPorts,
    List<SoftwareEntry> InstalledSoftware,
    List<FolderAcl> FolderPermissions,
    DefenderStatus? Defender,
    FirewallStatus? Firewall,
    List<FirewallRule> FirewallRules,
    List<UpdateEntry> InstalledUpdates,
    List<UserAccount> LocalUsers,
    List<string> Administrators,
    List<CollectorError> Errors
);

public record FirewallRule(
    string Name,
    string Action,           // "Allow" | "Block"
    string Protocol,         // "TCP" | "UDP" | "ICMP" | "Any" | "IP<n>"
    string LocalPorts,       // "3389" or "80,443" or "3000-3010" or "*" / "Any"
    string RemoteAddresses,  // "*", "Internet", IP/CIDR list
    List<string> Profiles,   // ["Domain","Private","Public"] or ["All"]
    bool Enabled
);

public record OpenPort(
    string Protocol,         // "TCP" | "UDP"
    string LocalAddress,
    int LocalPort,
    string? ProcessName,
    int? ProcessId
);

public record SoftwareEntry(
    string Name,
    string? Version,
    string? Publisher,
    string? InstallDate,
    string Source            // "HKLM64" | "HKLM32" | "HKCU"
);

public record FolderAcl(
    string Path,
    bool Exists,
    List<AceEntry> Aces,
    List<string> Concerns    // human-readable flags, e.g. "Everyone has FullControl"
);

public record AceEntry(
    string Identity,
    string Rights,
    string AccessControlType // "Allow" | "Deny"
);

public record DefenderStatus(
    bool? AntivirusEnabled,
    bool? RealTimeProtectionEnabled,
    bool? IsTamperProtected,
    string? AntivirusSignatureVersion,
    DateTime? AntivirusSignatureLastUpdated,
    string? EngineVersion
);

public record FirewallStatus(
    ProfileStatus? Domain,
    ProfileStatus? Private,
    ProfileStatus? Public
);

public record ProfileStatus(bool Enabled, string? DefaultInboundAction, string? DefaultOutboundAction);

public record UpdateEntry(
    string HotFixId,
    string? Description,
    DateTime? InstalledOn,
    string? InstalledBy
);

public record UserAccount(
    string Name,
    string? FullName,
    bool Disabled,
    bool PasswordRequired,
    bool LocalAccount,
    string? SID
);

public record CollectorError(string Collector, string Message);
