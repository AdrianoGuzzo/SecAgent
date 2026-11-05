namespace SecAgent.Service;

/// <summary>Seção "Agent": raiz dos arquivos de IPC (default C:\ProgramData\SecAgent).</summary>
public class AgentOptions
{
    public string DataRoot { get; set; } = AgentPaths.DefaultDataRoot;
}

/// <summary>Seção "Scanner".</summary>
public class ScannerOptions
{
    public string OutputDirectory { get; set; } = AgentPaths.Default.ScansDir;
    public int ScanIntervalHours { get; set; } = 24;
    public bool RunOnStartup { get; set; } = true;
    public List<string> CriticalFolders { get; set; } = new();
}
