namespace SecAgent.Tray;

/// <summary>
/// Token OAuth do Claude (CLAUDE_CODE_OAUTH_TOKEN) usado pelo Service. O Tray roda
/// como o usuário logado e consegue LER a env var de máquina sem admin; GRAVAR
/// (e reiniciar o serviço) exige elevação — ver <see cref="TokenSetupForm"/>.
///
/// As fontes (env var / existência de arquivo) são injetáveis para teste; as
/// sobrecargas sem parâmetros usam o ambiente real.
/// </summary>
public static class TokenSetup
{
    public const string TokenVar = "CLAUDE_CODE_OAUTH_TOKEN";
    public const string TokenPrefix = "sk-ant-oat";

    /// <summary>Lê uma env var num escopo (null em erro).</summary>
    public delegate string? EnvironmentReader(string name, EnvironmentVariableTarget target);

    internal static readonly EnvironmentReader RealEnvironment = (name, target) =>
    {
        try { return Environment.GetEnvironmentVariable(name, target); }
        catch { return null; }
    };

    public static bool IsConfigured() => IsConfigured(RealEnvironment);

    /// <summary>
    /// True quando há um token com cara de válido (não vazio + prefixo esperado)
    /// no escopo Machine (preferido) ou User. Só checa forma; validade real só é
    /// conhecida quando o Service roda uma análise.
    /// </summary>
    public static bool IsConfigured(EnvironmentReader env)
    {
        var token = ReadToken(env);
        return !string.IsNullOrWhiteSpace(token) && token.StartsWith(TokenPrefix, StringComparison.Ordinal);
    }

    public static string? ReadToken(EnvironmentReader env)
    {
        var machine = env(TokenVar, EnvironmentVariableTarget.Machine);
        if (!string.IsNullOrWhiteSpace(machine)) return machine;
        return env(TokenVar, EnvironmentVariableTarget.User);
    }

    public static string? DetectClaudeExe()
        => DetectClaudeExe(name => RealEnvironment(name, EnvironmentVariableTarget.Process), File.Exists);

    /// <summary>
    /// Localiza o claude.exe como o instalador: caminho padrão do Claude Code
    /// (%USERPROFILE%\.local\bin) e depois o PATH. Null se não achar.
    /// </summary>
    public static string? DetectClaudeExe(Func<string, string?> getEnv, Func<string, bool> fileExists)
    {
        var profile = getEnv("USERPROFILE");
        if (!string.IsNullOrEmpty(profile))
        {
            var candidate = Path.Combine(profile, ".local", "bin", "claude.exe");
            if (fileExists(candidate)) return candidate;
        }

        foreach (var dir in (getEnv("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim().Trim('"'), "claude.exe");
                if (fileExists(candidate)) return candidate;
            }
            catch (ArgumentException) { /* entrada malformada no PATH */ }
        }
        return null;
    }
}
