namespace SecAgent.Service.Analysis;

public class ClaudeOptions
{
    public string ExePath { get; set; } = @"C:\Users\adria\.local\bin\claude.exe";
    public string TokenEnvVarName { get; set; } = "CLAUDE_CODE_OAUTH_TOKEN";
    public string Model { get; set; } = "sonnet";
    public int TimeoutSeconds { get; set; } = 300;
    public string ReportsDirectory { get; set; } = @"C:\ProgramData\SecAgent\reports";
    public bool AnalyzeAfterScan { get; set; } = true;
}
