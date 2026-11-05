using System.Diagnostics.CodeAnalysis;
using System.Management;

namespace SecAgent.Service.Platform;

/// <summary>Dados de um processo recém-criado (Win32_Process).</summary>
public record ProcessStartData(
    string Name,
    string? ExecutablePath,
    string? ProcessId,
    string? ParentProcessId,
    string? CommandLine);

/// <summary>Fonte push de criação de processos.</summary>
public interface IProcessStartSource : IDisposable
{
    event Action<ProcessStartData>? ProcessStarted;
    void Start();
    void Stop();
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de WMI (__InstanceCreationEvent)")]
internal sealed class WmiProcessStartSource : IProcessStartSource
{
    private ManagementEventWatcher? _watcher;

    public event Action<ProcessStartData>? ProcessStarted;

    public void Start()
    {
        var query = new WqlEventQuery(
            "SELECT TargetInstance FROM __InstanceCreationEvent WITHIN 2 " +
            "WHERE TargetInstance ISA 'Win32_Process'");
        _watcher = new ManagementEventWatcher(query);
        _watcher.EventArrived += OnEventArrived;
        _watcher.Start();
    }

    private void OnEventArrived(object? sender, EventArrivedEventArgs e)
    {
        try
        {
            using var instance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            ProcessStarted?.Invoke(new ProcessStartData(
                Name: instance["Name"] as string ?? "",
                ExecutablePath: instance["ExecutablePath"] as string,
                ProcessId: instance["ProcessId"]?.ToString(),
                ParentProcessId: instance["ParentProcessId"]?.ToString(),
                CommandLine: instance["CommandLine"] as string));
        }
        catch { /* evento malformado — ignora */ }
    }

    public void Stop()
    {
        try { _watcher?.Stop(); } catch { }
    }

    public void Dispose()
    {
        Stop();
        try { _watcher?.Dispose(); } catch { }
        _watcher = null;
    }
}
