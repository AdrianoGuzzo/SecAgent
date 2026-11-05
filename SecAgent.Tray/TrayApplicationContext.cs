using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using SecAgent.Tray.Core;

namespace SecAgent.Tray;

/// <summary>
/// Dono do ciclo de vida do Tray: NotifyIcon, menu, timers e watchers. É só glue —
/// as regras (ícone, tooltips, toasts, triggers, comandos do painel) estão em
/// <see cref="TrayStatePresenter"/>, <see cref="TriggerRequester"/> e
/// <see cref="DashboardCommandParser"/>, que são testadas.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Glue de WinForms (NotifyIcon/menu/watchers); lógica em Core")]
public class TrayApplicationContext : ApplicationContext
{
    private readonly AgentPaths _paths = AgentPaths.Default;
    private readonly TriggerRequester _triggers;
    private readonly AiPrefsStore _prefs = AiPrefsStore.Default;

    private readonly NotifyIcon _icon;
    private readonly System.Windows.Forms.Timer _statusTimer;
    private readonly System.Windows.Forms.Timer _progressTimer;
    private readonly List<FileSystemWatcher> _watchers = new();

    // Geolocalização compartilhada e sempre ativa (alertas + painel).
    private readonly GeoLookup _geo = new();

    private AgentStatus? _status;
    private AnalysisProgress? _currentProgress;
    // Ícone "ocioso" (severidade do status.json) quando não há trabalho em andamento.
    private TrayIconKind _severityIcon = TrayIconKind.Busy;

    private DataPump? _dataPump;
    private DashboardForm? _dashboard;

    public TrayApplicationContext()
    {
        _triggers = new TriggerRequester(_paths, TimeProvider.System);
        foreach (var dir in new[] { _paths.DataRoot, _paths.ReportsDir, _paths.EventsDir, _paths.ScansDir, _paths.AlertsDir })
            try { Directory.CreateDirectory(dir); } catch { /* o Service cria; usuário pode não ter permissão */ }

        _icon = new NotifyIcon
        {
            Icon = SystemIcons.Information,
            Text = "SecAgent (carregando...)",
            Visible = true,
            ContextMenuStrip = BuildMenu()
        };
        _icon.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) ShowDashboard(); };
        _icon.MouseDoubleClick += (_, _) => ShowDashboard();

        _statusTimer = new System.Windows.Forms.Timer { Interval = 10_000 };
        _statusTimer.Tick += (_, _) => _ = RefreshStatusAsync();
        _statusTimer.Start();
        _ = RefreshStatusAsync();

        _progressTimer = new System.Windows.Forms.Timer { Interval = 2_000 };
        _progressTimer.Tick += (_, _) => UpdateProgressTooltip();

        Watch(_paths.ReportsDir, "*.md", created: OnNewReport);
        Watch(_paths.ScansDir, "scan_*.json", created: OnNewScan);
        // progress.json é gravado por escrita atômica (File.Move) → chega como Renamed.
        Watch(_paths.DataRoot, "progress.json", created: e => { _ = OnProgressChangedAsync(); },
            changed: true, deleted: _ => OnUi(OnProgressDeleted));
        // Sempre ativo: toast imediato de alerta de entrada, mesmo com o painel fechado.
        Watch(_paths.AlertsDir, "alert_*.json", created: e => _ = OnNewAlertAsync(e.FullPath));

        // Se o Service já estava no meio de um scan quando o Tray subiu.
        _ = OnProgressChangedAsync();
    }

    // ---- UI helpers ---------------------------------------------------------

    private void OnUi(Action action)
    {
        var host = _icon.ContextMenuStrip;
        if (host is { InvokeRequired: true }) host.BeginInvoke(action);
        else action();
    }

    private static Icon ToIcon(TrayIconKind kind) => kind switch
    {
        TrayIconKind.Error => SystemIcons.Error,
        TrayIconKind.Warning => SystemIcons.Warning,
        TrayIconKind.Shield => SystemIcons.Shield,
        _ => SystemIcons.Information
    };

    private void ShowToast(TrayToast? t, int ms = 5000)
    {
        if (t is null) return;
        OnUi(() => _icon.ShowBalloonTip(ms, t.Title, t.Text,
            t.IsError ? ToolTipIcon.Error : t.IsWarning ? ToolTipIcon.Warning : ToolTipIcon.Info));
    }

    private void Info(string text, bool error = false)
        => ShowToast(new TrayToast(TrayStatePresenter.AppName, text, IsError: error), 4000);

    private void Watch(string dir, string filter, Action<FileSystemEventArgs> created,
        bool changed = false, Action<FileSystemEventArgs>? deleted = null)
    {
        try
        {
            var w = new FileSystemWatcher(dir, filter)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            w.Created += (_, e) => created(e);
            w.Renamed += (_, e) => created(e);
            if (changed) w.Changed += (_, e) => created(e);
            if (deleted is not null) w.Deleted += (_, e) => deleted(e);
            w.EnableRaisingEvents = true;
            _watchers.Add(w);
        }
        catch { /* pasta pode não existir — o timer de status cobre */ }
    }

    // ---- menu ---------------------------------------------------------------

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Abrir painel", null, (_, _) => ShowDashboard());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Forçar scan agora (sem Claude — grátis)", null,
            (_, _) => RequestTrigger(TriggerNames.ScanOnly, "Scan iniciado, aguarde ~5s..."));
        menu.Items.Add("Forçar scan + análise Claude (último modelo escolhido)", null,
            (_, _) => RequestAnalyze(_prefs.Load()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Abrir último relatório de scan", null, (_, _) => OpenLast("report_*.md"));
        menu.Items.Add("Abrir último relatório de incidente", null, (_, _) => OpenLast("incident_*.md"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Pasta de relatórios", null, (_, _) => OpenFolder(_paths.ReportsDir));
        menu.Items.Add("Pasta de eventos", null, (_, _) => OpenFolder(_paths.EventsDir));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Atualizar status", null, (_, _) => _ = RefreshStatusAsync());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Remover SecAgent deste usuário", null, (_, _) => RemoveForCurrentUser());
        menu.Items.Add("Sair", null, (_, _) => ExitThread());
        return menu;
    }

    // Remoção por usuário (sem admin): tira o Tray e o início automático só da
    // conta atual. O serviço (machine-wide) continua. Desinstalação completa é
    // em "Aplicativos e recursos" (admin).
    private void RemoveForCurrentUser()
    {
        var answer = MessageBox.Show(
            "Isto remove o ícone do SecAgent e o início automático apenas da SUA conta de usuário.\n\n" +
            "O serviço de monitoramento continua rodando para a máquina. Para desinstalar o SecAgent " +
            "por completo (todos os usuários), use \"Aplicativos e recursos\" do Windows (requer admin).\n\n" +
            "Remover o SecAgent da sua conta agora?",
            "Remover SecAgent deste usuário",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (answer != DialogResult.Yes) return;

        UserInstall.DisableForCurrentUser();
        ExitThread();
    }

    // ---- triggers / comandos ------------------------------------------------

    private void RequestAnalyze((string Model, string Effort) choice)
        => RequestTrigger(TriggerNames.ScanAndAnalyze,
            $"Varredura + análise ({choice.Model}) iniciadas, aguarde ~1-2 min...",
            TriggerRequester.AnalyzeContent(choice.Model, choice.Effort));

    private void RequestTrigger(string fileName, string okMessage, string? content = null)
    {
        var r = _triggers.Request(fileName, content);
        Info(_triggers.Describe(r, okMessage), error: r.Status is TriggerRequestStatus.Denied or TriggerRequestStatus.Failed);
    }

    private void OnDashboardCommand(string raw)
    {
        var cmd = DashboardCommandParser.Parse(raw);
        switch (cmd.Kind)
        {
            case DashboardCommandKind.ScanOnly:
                RequestTrigger(TriggerNames.ScanOnly, "Varredura iniciada, aguarde ~5s...");
                break;
            case DashboardCommandKind.ConfigureToken:
                OpenTokenSetup();
                break;
            case DashboardCommandKind.ScanAndAnalyze when cmd.Model is null:
                RequestAnalyze(_prefs.Load());
                break;
            case DashboardCommandKind.ScanAndAnalyze:
                _prefs.Save(cmd.Model, cmd.Effort);   // lembra para a próxima vez (painel + menu)
                RequestAnalyze((cmd.Model!, cmd.Effort!));
                break;
            case DashboardCommandKind.BlockIp:
                // O nome do arquivo leva o IP sanitizado; o IP cru vai no conteúdo.
                RequestTrigger(TriggerNames.BlockIp(cmd.Ip!), $"Bloqueando {cmd.Ip} (entrada e saída)…", cmd.Ip);
                break;
            case DashboardCommandKind.UnblockIp:
                RequestTrigger(TriggerNames.UnblockIp(cmd.Ip!), $"Desbloqueando {cmd.Ip}…", cmd.Ip);
                break;
        }
    }

    private void ShowDashboard()
    {
        if (_dashboard is { IsDisposed: false })
        {
            if (_dashboard.WindowState == FormWindowState.Minimized)
                _dashboard.WindowState = FormWindowState.Normal;
            _dashboard.Show();
            _dashboard.Activate();
            _dashboard.BringToFront();
            return;
        }

        _dataPump = new DataPump(_geo);
        _dashboard = new DashboardForm(_dataPump, OnDashboardCommand);
        _dashboard.FormClosed += (_, _) =>
        {
            _dataPump?.Dispose();
            _dataPump = null;
            _dashboard = null;
        };
        _dataPump.Start();
        _dashboard.Show();
        _dashboard.Activate();
    }

    // Janela nativa de token sobre o painel; após salvar, atualiza a página para
    // o botão de IA substituir o "Configurar IA".
    private void OpenTokenSetup()
    {
        using var form = new TokenSetupForm();
        var result = _dashboard is { IsDisposed: false } ? form.ShowDialog(_dashboard) : form.ShowDialog();
        if (result == DialogResult.OK) _dataPump?.EmitTokenStatus();
    }

    // ---- status / progresso -------------------------------------------------

    private async Task RefreshStatusAsync()
    {
        var status = await JsonFileReader.ReadAsync<AgentStatus>(_paths.StatusFile);
        OnUi(() =>
        {
            _status = status;
            _severityIcon = TrayStatePresenter.SeverityIcon(status);
            // Só troca o ícone sem progresso ativo; senão mantém o "ocupado".
            if (_currentProgress is null) ShowIdle();
        });
    }

    private void ShowIdle()
    {
        _icon.Icon = ToIcon(_severityIcon);
        _icon.Text = TrayStatePresenter.StatusTooltip(_status);
    }

    private async Task OnProgressChangedAsync()
    {
        var progress = await JsonFileReader.ReadAsync<AnalysisProgress>(_paths.ProgressFile);
        if (progress is null) return;
        OnUi(() =>
        {
            // T3: progress.json órfão (Service caiu no meio do scan) não prende o ícone.
            if (TrayStatePresenter.IsStale(progress, DateTime.UtcNow)) { OnProgressDeleted(); return; }

            var previous = _currentProgress?.State;
            _currentProgress = progress;
            _icon.Icon = ToIcon(TrayIconKind.Busy);
            ShowToast(TrayStatePresenter.TransitionToast(previous, progress), 4000);
            if (!_progressTimer.Enabled) _progressTimer.Start();
            UpdateProgressTooltip();
        });
    }

    private void OnProgressDeleted()
    {
        _currentProgress = null;
        _progressTimer.Stop();
        ShowIdle();
    }

    private void UpdateProgressTooltip()
    {
        if (_currentProgress is null) return;
        if (TrayStatePresenter.IsStale(_currentProgress, DateTime.UtcNow)) { OnProgressDeleted(); return; }
        _icon.Text = TrayStatePresenter.ProgressTooltip(_currentProgress, DateTime.UtcNow);
    }

    // ---- watchers -----------------------------------------------------------

    private void OnNewReport(FileSystemEventArgs e)
    {
        ShowToast(TrayStatePresenter.ReportToast(e.Name), 7000);
        _ = RefreshStatusAsync();
    }

    private void OnNewScan(FileSystemEventArgs e)
        => OnUi(() => ShowToast(TrayStatePresenter.ScanToast(e.Name, _currentProgress), 4000));

    private async Task OnNewAlertAsync(string path)
    {
        try
        {
            var alert = await JsonFileReader.ReadAsync<NetworkAlert>(path);
            if (alert is null) return;
            // País: cache = instantâneo; senão timeout curto.
            var geo = await _geo.ResolveNowAsync(alert.RemoteAddress);
            ShowToast(TrayStatePresenter.AlertToast(alert, geo?.Country, geo?.CountryCode), 8000);
        }
        catch { /* toast é best effort */ }
    }

    // ---- abrir arquivos -----------------------------------------------------

    private void OpenLast(string pattern)
    {
        try
        {
            var last = new DirectoryInfo(_paths.ReportsDir).GetFiles(pattern)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault();
            if (last is null) { Info($"Nenhum arquivo encontrado para padrão {pattern}"); return; }
            Process.Start(new ProcessStartInfo(last.FullName) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Info($"Erro abrindo último relatório: {ex.Message}", error: true);
        }
    }

    private static void OpenFolder(string path)
    {
        Directory.CreateDirectory(path);
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _icon.Visible = false;
            _icon.Dispose();
            _statusTimer.Dispose();
            _progressTimer.Dispose();
            foreach (var w in _watchers) w.Dispose();
            _dataPump?.Dispose();
            _dashboard?.Dispose();
            _geo.Dispose();
        }
        base.Dispose(disposing);
    }
}
