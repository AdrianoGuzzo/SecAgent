namespace SecAgent.Service.Triggers;

/// <summary>Seção "Triggers".</summary>
public class TriggerOptions
{
    public string TriggersDirectory { get; set; } = AgentPaths.Default.TriggersDir;
    public int DebounceSeconds { get; set; } = 30;
    public bool Enabled { get; set; } = true;

    // O watcher dispara Created antes do Tray terminar de gravar o conteúdo.
    // Espera curta antes de ler (o conteúdo carrega IP / modelo+esforço).
    public int SettleMilliseconds { get; set; } = 250;
}
