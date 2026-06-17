namespace SecAgent.Tray;

/// <summary>
/// Helpers for the Claude OAuth token (CLAUDE_CODE_OAUTH_TOKEN) used by the
/// Service to invoke the Claude CLI. The Tray runs as the logged-in user and can
/// READ the Machine-scope env var without admin; WRITING it (and restarting the
/// service) needs elevation — see <see cref="TokenSetupForm"/>.
/// </summary>
public static class TokenSetup
{
    public const string TokenVar = "CLAUDE_CODE_OAUTH_TOKEN";
    public const string TokenPrefix = "sk-ant-oat";

    /// <summary>
    /// True when a token that looks valid (non-empty + expected prefix) is present
    /// in Machine scope (preferred) or User scope. This only checks presence/shape;
    /// real validity (expiry) is only known when the Service runs an analysis.
    /// </summary>
    public static bool IsConfigured()
    {
        var token = ReadToken();
        return !string.IsNullOrWhiteSpace(token) &&
               token.StartsWith(TokenPrefix, StringComparison.Ordinal);
    }

    /// <summary>Reads the token from Machine scope, falling back to User scope.</summary>
    public static string? ReadToken()
    {
        var machine = SafeGet(EnvironmentVariableTarget.Machine);
        if (!string.IsNullOrWhiteSpace(machine)) return machine;
        return SafeGet(EnvironmentVariableTarget.User);
    }

    private static string? SafeGet(EnvironmentVariableTarget target)
    {
        try { return Environment.GetEnvironmentVariable(TokenVar, target); }
        catch { return null; }
    }

    /// <summary>
    /// Locates claude.exe the same way the installer does: the standard Claude Code
    /// Windows install path, then a PATH search. Returns null if not found.
    /// </summary>
    public static string? DetectClaudeExe()
    {
        try
        {
            var profile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (!string.IsNullOrEmpty(profile))
            {
                var candidate = Path.Combine(profile, ".local", "bin", "claude.exe");
                if (File.Exists(candidate)) return candidate;
            }

            var path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    var candidate = Path.Combine(dir.Trim(), "claude.exe");
                    if (File.Exists(candidate)) return candidate;
                }
                catch { /* malformed PATH entry — skip */ }
            }
        }
        catch { /* best effort */ }
        return null;
    }
}
