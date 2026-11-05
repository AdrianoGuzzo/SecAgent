namespace SecAgent.Service.Analysis;

/// <summary>Seção "Claude".</summary>
public class ClaudeOptions
{
    // O instalador grava o caminho real em appsettings.json; o default é o
    // local padrão do Claude Code no Windows para o perfil do usuário.
    public string ExePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "claude.exe");
    public string TokenEnvVarName { get; set; } = "CLAUDE_CODE_OAUTH_TOKEN";
    public string Model { get; set; } = "haiku";
    // Esforço de raciocínio padrão (--effort). Fallback para scheduled/incidente
    // e quando o trigger não traz uma escolha. Ignorado quando o modelo é Haiku.
    public string Effort { get; set; } = AiModels.DefaultEffort;
    public int TimeoutSeconds { get; set; } = 300;
    public string ReportsDirectory { get; set; } = AgentPaths.Default.ReportsDir;
    // Controls ONLY scheduled scans. false = scheduled scans are free (scan-only);
    // the manual "scan + análise" button always analyzes regardless.
    public bool AnalyzeAfterScan { get; set; } = false;
}
