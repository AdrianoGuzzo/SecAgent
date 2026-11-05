using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace SecAgent.Tray.Core;

/// <summary>
/// Monta o HTML do painel a partir dos recursos embutidos. NavigateToString não
/// tem base URI, então &lt;link&gt;/&lt;script src&gt; não resolvem sozinhos: cada
/// referência é lida do recurso embutido e inlinada em &lt;style&gt;/&lt;script&gt;.
/// </summary>
internal static class DashboardAssets
{
    private static readonly Regex CssLink = new("<link[^>]*?href=\"([^\"]+\\.css)\"[^>]*?>", RegexOptions.IgnoreCase);
    private static readonly Regex JsScript = new("<script[^>]*?src=\"([^\"]+\\.js)\"[^>]*?>\\s*</script>", RegexOptions.IgnoreCase);

    public const string MissingHtml = "<html><body style='font-family:sans-serif'>dashboard.html não encontrado.</body></html>";

    public static string LoadHtml() => LoadHtml(reference => ReadEmbedded(typeof(DashboardAssets).Assembly, reference));

    public static string LoadHtml(Func<string, string?> readAsset)
    {
        var html = readAsset("dashboard.html");
        if (html is null) return MissingHtml;

        // O replacement é um delegate (MatchEvaluator): '$' no conteúdo JS não é interpretado.
        html = CssLink.Replace(html, m =>
            $"<style>\n{readAsset(m.Groups[1].Value) ?? "/* " + m.Groups[1].Value + " não encontrado */"}\n</style>");
        html = JsScript.Replace(html, m =>
            $"<script>\n{readAsset(m.Groups[1].Value) ?? "/* " + m.Groups[1].Value + " não encontrado */"}\n</script>");
        return html;
    }

    /// <summary>
    /// Nome do recurso para uma referência do HTML ("js/core.js" → "...Assets.js.core.js").
    /// T6: o fallback antigo <c>EndsWith(fileName)</c> casava "xcore.js" com "core.js";
    /// agora só casa com '.' + nome do arquivo.
    /// </summary>
    public static string? FindResourceName(IEnumerable<string> resourceNames, string reference)
    {
        var fileName = reference.Replace('\\', '/').Split('/').Last();
        if (fileName.Length == 0) return null;
        return resourceNames.FirstOrDefault(n => n.EndsWith("." + fileName, StringComparison.OrdinalIgnoreCase));
    }

    public static string? ReadEmbedded(Assembly asm, string reference)
    {
        var name = FindResourceName(asm.GetManifestResourceNames(), reference);
        if (name is null) return null;
        using var stream = asm.GetManifestResourceStream(name);
        if (stream is null) return null;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
