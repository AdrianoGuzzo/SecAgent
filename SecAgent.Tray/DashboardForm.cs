using System.Collections.Concurrent;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace SecAgent.Tray;

/// <summary>
/// The friendly dashboard window. Hosts a WebView2 rendering an embedded
/// single-page app. The C# host does all file reads (via DataPump) and pushes
/// JSON messages to the page; the page posts scan commands back.
/// </summary>
public sealed class DashboardForm : Form
{
    private readonly WebView2 _web;
    private readonly DataPump _pump;
    private readonly Action<string> _onCommand;       // "scanOnly" | "scanAndAnalyze"
    private readonly ConcurrentQueue<string> _pending = new();
    private bool _ready;

    public DashboardForm(DataPump pump, Action<string> onCommand)
    {
        _pump = pump;
        _onCommand = onCommand;

        Text = "SecAgent — Painel de Segurança";
        Width = 1100;
        Height = 760;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(720, 520);
        try { Icon = SystemIcons.Shield; } catch { }

        _web = new WebView2 { Dock = DockStyle.Fill };
        Controls.Add(_web);

        _pump.Message += OnPumpMessage;
        Load += async (_, _) => await InitAsync();
        FormClosed += (_, _) => _pump.Message -= OnPumpMessage;
    }

    private async Task InitAsync()
    {
        // Runtime check — degrade gracefully if WebView2 Runtime is absent.
        try
        {
            var ver = CoreWebView2Environment.GetAvailableBrowserVersionString();
            if (string.IsNullOrEmpty(ver)) throw new InvalidOperationException("Runtime ausente");
        }
        catch
        {
            MessageBox.Show(
                "O componente WebView2 do Windows não está instalado, então o painel " +
                "não pode ser exibido.\n\nVou abrir o último relatório no formato de texto.\n\n" +
                "Para habilitar o painel, instale o 'Microsoft Edge WebView2 Runtime'.",
                "SecAgent", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            FallbackToReport();
            Close();
            return;
        }

        try
        {
            var userData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecAgent", "WebView2");
            Directory.CreateDirectory(userData);

            var env = await CoreWebView2Environment.CreateAsync(null, userData);
            await _web.EnsureCoreWebView2Async(env);

            var s = _web.CoreWebView2.Settings;
            s.AreDefaultContextMenusEnabled = false;
            s.IsStatusBarEnabled = false;
            s.AreDevToolsEnabled = false;
            s.IsZoomControlEnabled = false;

            _web.CoreWebView2.WebMessageReceived += OnWebMessage;
            _web.CoreWebView2.NavigationCompleted += (_, _) =>
            {
                _ready = true;
                FlushPending();
            };

            _web.CoreWebView2.NavigateToString(LoadHtml());
        }
        catch (Exception ex)
        {
            MessageBox.Show("Falha ao iniciar o painel: " + ex.Message, "SecAgent",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            Close();
        }
    }

    private void OnPumpMessage(string type, string payloadJson)
    {
        // DataPump raises on worker threads; marshal to the UI thread.
        if (InvokeRequired) { BeginInvoke(() => OnPumpMessage(type, payloadJson)); return; }

        var envelope = "{\"type\":\"" + type + "\",\"payload\":" + payloadJson + "}";
        if (_ready && _web.CoreWebView2 is not null)
        {
            try { _web.CoreWebView2.PostWebMessageAsJson(envelope); }
            catch { _pending.Enqueue(envelope); }
        }
        else
        {
            _pending.Enqueue(envelope);
        }
    }

    private void FlushPending()
    {
        while (_pending.TryDequeue(out var env))
        {
            try { _web.CoreWebView2.PostWebMessageAsJson(env); } catch { }
        }
    }

    private void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            using var doc = JsonDocument.Parse(e.WebMessageAsJson);
            if (doc.RootElement.TryGetProperty("cmd", out var cmd))
                _onCommand(cmd.GetString() ?? "");
        }
        catch { /* ignore malformed messages from the page */ }
    }

    private void FallbackToReport()
    {
        try
        {
            const string reportsDir = @"C:\ProgramData\SecAgent\reports";
            var last = new DirectoryInfo(reportsDir).GetFiles("report_*.md")
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault();
            if (last is not null)
                System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo(last.FullName) { UseShellExecute = true });
        }
        catch { /* nothing else to do */ }
    }

    /// <summary>
    /// Loads dashboard.html and inlines its external CSS/JS into a single string.
    /// NavigateToString renders without a base URI, so &lt;link&gt;/&lt;script src&gt;
    /// can't resolve on their own — we read each referenced embedded resource and
    /// splice it into a &lt;style&gt;/&lt;script&gt; tag. Keeps the source split across
    /// files while still shipping a single embedded payload.
    /// </summary>
    private static string LoadHtml()
    {
        var html = ReadAsset("dashboard.html");
        if (html is null) return "<html><body style='font-family:sans-serif'>dashboard.html não encontrado.</body></html>";

        // Inline <link rel="stylesheet" href="X"> -> <style>...</style>
        html = Regex.Replace(html,
            "<link[^>]*?href=\"([^\"]+\\.css)\"[^>]*?>",
            m => $"<style>\n{ReadAsset(m.Groups[1].Value) ?? "/* " + m.Groups[1].Value + " não encontrado */"}\n</style>",
            RegexOptions.IgnoreCase);

        // Inline <script src="Y"></script> -> <script>...</script>
        html = Regex.Replace(html,
            "<script[^>]*?src=\"([^\"]+\\.js)\"[^>]*?>\\s*</script>",
            m => $"<script>\n{ReadAsset(m.Groups[1].Value) ?? "/* " + m.Groups[1].Value + " não encontrado */"}\n</script>",
            RegexOptions.IgnoreCase);

        return html;
    }

    /// <summary>
    /// Reads an embedded asset by its file name (ignoring the path in the href/src,
    /// e.g. "js/core.js" matches resource "...Assets.js.core.js"). Returns null if absent.
    /// </summary>
    private static string? ReadAsset(string reference)
    {
        var fileName = reference.Replace('\\', '/').Split('/').Last();
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("." + fileName, StringComparison.OrdinalIgnoreCase)
                              || n.EndsWith(fileName, StringComparison.OrdinalIgnoreCase));
        if (name is null) return null;
        using var stream = asm.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
