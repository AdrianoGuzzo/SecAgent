namespace SecAgent.Service;

public class ScannerOptions
{
    public string OutputDirectory { get; set; } = @"C:\ProgramData\SecAgent\scans";
    public int ScanIntervalHours { get; set; } = 24;
    public bool RunOnStartup { get; set; } = true;
    public List<string> CriticalFolders { get; set; } = new();
}
