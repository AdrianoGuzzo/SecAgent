namespace SecAgent.Service.Analysis;

public class ClaudeOptions
{
    public string ExePath { get; set; } = @"C:\Users\adria\.local\bin\claude.exe";
    public string TokenEnvVarName { get; set; } = "CLAUDE_CODE_OAUTH_TOKEN";
    public string Model { get; set; } = "sonnet";
    public int TimeoutSeconds { get; set; } = 300;
    public string ReportsDirectory { get; set; } = @"C:\ProgramData\SecAgent\reports";
    // Controls ONLY scheduled scans. false = scheduled scans are free (scan-only);
    // the manual "scan + análise" button always analyzes regardless.
    public bool AnalyzeAfterScan { get; set; } = false;
}
