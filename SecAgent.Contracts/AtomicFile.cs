using System.Text;

namespace SecAgent.Contracts;

/// <summary>
/// Escrita atômica (tmp + <see cref="File.Move(string,string,bool)"/>): quem lê
/// (o Tray, por polling/watcher) nunca vê um JSON pela metade. No Windows o
/// leitor recebe um evento <c>Renamed</c> — os watchers do Tray assinam esse evento.
/// </summary>
public static class AtomicFile
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    public static void WriteAllText(string path, string contents)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(tmp, contents, Utf8NoBom);
            File.Move(tmp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* best effort */ }
        }
    }
}
