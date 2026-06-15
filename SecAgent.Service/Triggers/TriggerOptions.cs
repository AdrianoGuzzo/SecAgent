namespace SecAgent.Service.Triggers;

public class TriggerOptions
{
    public string TriggersDirectory { get; set; } = @"C:\ProgramData\SecAgent\triggers";
    public int DebounceSeconds { get; set; } = 30;
    public bool Enabled { get; set; } = true;
}
