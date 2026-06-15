namespace SecAgent.Spike;

public class ClaudeOptions
{
    public string ExePath { get; set; } = @"C:\Users\adria\.local\bin\claude.exe";
    public string TokenEnvVarName { get; set; } = "CLAUDE_CODE_OAUTH_TOKEN";
    public string Model { get; set; } = "sonnet";
    public int TimeoutSeconds { get; set; } = 120;
}

public class SpikeOptions
{
    public string LogPath { get; set; } = @"C:\ProgramData\SecAgent\spike.log";
    public int RunIntervalSeconds { get; set; } = 300;
    public string TestPrompt { get; set; } =
        "Respond with a single short JSON-safe sentence confirming you are alive. No code blocks.";
}
