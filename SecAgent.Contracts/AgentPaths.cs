namespace SecAgent.Contracts;

/// <summary>
/// Fonte única dos caminhos do IPC por arquivos em <c>C:\ProgramData\SecAgent</c>.
/// Service e Tray derivam tudo de <see cref="DataRoot"/>; os testes passam um
/// diretório temporário. Antes estes caminhos estavam espalhados em ~10 lugares.
/// </summary>
public sealed class AgentPaths
{
    public const string DefaultDataRoot = @"C:\ProgramData\SecAgent";

    public static AgentPaths Default { get; } = new(DefaultDataRoot);

    public AgentPaths(string dataRoot)
    {
        if (string.IsNullOrWhiteSpace(dataRoot))
            throw new ArgumentException("DataRoot não pode ser vazio.", nameof(dataRoot));
        DataRoot = dataRoot;
    }

    public string DataRoot { get; }

    public string StatusFile => Path.Combine(DataRoot, "status.json");
    public string ProgressFile => Path.Combine(DataRoot, "progress.json");
    public string NetworkFile => Path.Combine(DataRoot, "network.json");
    public string BlockedFile => Path.Combine(DataRoot, "blocked.json");
    public string TraceFile => Path.Combine(DataRoot, "trace.log");

    public string ReportsDir => Path.Combine(DataRoot, "reports");
    public string ScansDir => Path.Combine(DataRoot, "scans");
    public string EventsDir => Path.Combine(DataRoot, "events");
    public string AlertsDir => Path.Combine(DataRoot, "alerts");
    public string TriggersDir => Path.Combine(DataRoot, "triggers");

    /// <summary>Arquivo JSONL de eventos do dia (UTC) de <paramref name="utc"/>.</summary>
    public string EventsFileFor(DateTime utc) => Path.Combine(EventsDir, ReportNames.EventsJsonl(utc));
}
