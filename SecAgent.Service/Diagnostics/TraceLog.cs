using System.Globalization;

namespace SecAgent.Service.Diagnostics;

/// <summary>
/// Log de diagnóstico do pipeline scan→Claude em <c>trace.log</c>. O EventLog do
/// Windows só recebe Warning+; este arquivo é a melhor janela de debug.
/// </summary>
public interface ITraceLog
{
    void Write(string category, string message);
}

/// <summary>Grava em <see cref="AgentPaths.TraceFile"/>; falhas de I/O são engolidas (best effort).</summary>
public sealed class FileTraceLog : ITraceLog
{
    private readonly string _path;
    private readonly TimeProvider _time;
    private readonly object _lock = new();

    public FileTraceLog(AgentPaths paths, TimeProvider time)
    {
        _path = paths.TraceFile;
        _time = time;
    }

    public void Write(string category, string message)
    {
        try
        {
            var stamp = _time.GetLocalNow().ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
            var line = $"[{stamp}] [{category}] {message}{Environment.NewLine}";
            lock (_lock)
            {
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.AppendAllText(_path, line);
            }
        }
        catch { /* trace nunca derruba o pipeline */ }
    }
}
