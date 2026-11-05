using System.Text;

namespace SecAgent.Tray.Core;

/// <summary>
/// "tail -f" do JSONL diário de eventos (events_yyyy-MM-dd.jsonl, dia UTC):
/// offset em bytes, só linhas completas, reset em truncamento e virada de dia.
///
/// T2: o offset avançava por <c>GetByteCount(GetString(bytes))</c> — com UTF-8
/// inválido/partido a contagem divergia dos bytes lidos e o tail perdia ou
/// repetia dados; e o preload consumia uma última linha ainda incompleta,
/// que nunca mais era lida. Agora o offset avança exatamente até o último '\n'.
/// </summary>
internal sealed class EventsTail
{
    private readonly AgentPaths _paths;
    private readonly TimeProvider _time;
    private readonly object _lock = new();
    private string? _path;
    private long _offset;

    public EventsTail(AgentPaths paths, TimeProvider time)
    {
        _paths = paths;
        _time = time;
    }

    internal long Offset => _offset;

    private string TodaysPath() => _paths.EventsFileFor(_time.GetUtcNow().UtcDateTime);

    /// <summary>Lê o arquivo de hoje do início; devolve as últimas <paramref name="maxLines"/> linhas completas.</summary>
    public List<string> Preload(int maxLines)
    {
        lock (_lock)
        {
            _path = TodaysPath();
            _offset = 0;
            var lines = ReadCompleteLines();
            return lines.Count > maxLines ? lines.GetRange(lines.Count - maxLines, maxLines) : lines;
        }
    }

    /// <summary>Linhas completas escritas desde a última leitura.</summary>
    public List<string> ReadNew()
    {
        lock (_lock)
        {
            var path = TodaysPath();
            if (!string.Equals(path, _path, StringComparison.OrdinalIgnoreCase))
            {
                _path = path;   // virada de dia UTC → arquivo novo
                _offset = 0;
            }
            return ReadCompleteLines();
        }
    }

    private List<string> ReadCompleteLines()
    {
        var result = new List<string>();
        try
        {
            if (_path is null || !File.Exists(_path)) return result;
            using var fs = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length < _offset) _offset = 0;   // truncado/rotacionado
            if (fs.Length == _offset) return result;

            fs.Seek(_offset, SeekOrigin.Begin);
            var buffer = new byte[fs.Length - _offset];
            int read = 0;
            while (read < buffer.Length)
            {
                int n = fs.Read(buffer, read, buffer.Length - read);
                if (n == 0) break;
                read += n;
            }
            if (read == 0) return result;

            int lastNl = Array.LastIndexOf(buffer, (byte)'\n', read - 1);
            if (lastNl < 0) return result;   // nenhuma linha completa ainda

            _offset += lastNl + 1;
            var text = Encoding.UTF8.GetString(buffer, 0, lastNl + 1);
            foreach (var line in text.Split('\n'))
            {
                var l = line.Trim();
                if (l.Length > 0) result.Add(l);
            }
        }
        catch (IOException) { /* escrita em andamento — próxima rodada */ }
        catch (UnauthorizedAccessException) { }
        return result;
    }
}
