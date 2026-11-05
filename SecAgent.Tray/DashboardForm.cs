using System.Diagnostics.CodeAnalysis;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using SecAgent.Tray.Core;

namespace SecAgent.Tray;

/// <summary>
/// The friendly dashboard window. Hosts a WebView2 rendering an embedded
/// single-page app. The C# host does all file reads (via DataPump) and pushes
/// JSON messages to the page; the page posts scan commands back.
/// Glue de UI: a lógica (envelope, fila, comando, inline de assets) está em Core.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Glue de WinForms/WebView2; lógica em Core")]
public sealed class DashboardForm : Form
{
    private readonly WebView2 _web;
    private readonly DataPump _pump;
    private readonly Action<string> _onCommand;       // "scanOnly" | "scanAndAnalyze"
    private readonly WebMessageQueue _queue = new();
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
                _queue.Flush(TryPost);
                _ = _pump.RequestInitialSnapshotAsync();
            };

            _web.CoreWebView2.NavigateToString(DashboardAssets.LoadHtml());
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
        // DataPump dispara em threads de worker; marshal para a UI thread.
        if (IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => OnPumpMessage(type, payloadJson)); return; }
        _queue.Post(WebMessage.Envelope(type, payloadJson), _ready && _web.CoreWebView2 is not null, TryPost);
    }

    private bool TryPost(string envelope)
    {
        if (_web.CoreWebView2 is null) return false;
        _web.CoreWebView2.PostWebMessageAsJson(envelope);
        return true;
    }

    private void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        if (WebMessage.TryGetCommand(e.WebMessageAsJson) is { } cmd) _onCommand(cmd);
    }

    private void FallbackToReport()
    {
        try
        {
            var last = new DirectoryInfo(AgentPaths.Default.ReportsDir).GetFiles("report_*.md")
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault();
            if (last is not null)
                System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo(last.FullName) { UseShellExecute = true });
        }
        catch { /* nothing else to do */ }
    }
}
