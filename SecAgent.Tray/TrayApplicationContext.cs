using System.Diagnostics;
using System.Text;
using System.Text.Json;
using SecAgent.Tray.Models;

namespace SecAgent.Tray;

public class TrayApplicationContext : ApplicationContext
{
    private const string DataDir = @"C:\ProgramData\SecAgent";
    private const string StatusPath = @"C:\ProgramData\SecAgent\status.json";
    private const string ProgressPath = @"C:\ProgramData\SecAgent\progress.json";
    private const string ReportsDir = @"C:\ProgramData\SecAgent\reports";
    private const string EventsDir = @"C:\ProgramData\SecAgent\events";
    private const string ScansDir = @"C:\ProgramData\SecAgent\scans";
    private const string TriggersDir = @"C:\ProgramData\SecAgent\triggers";
    private const string AlertsDir = @"C:\ProgramData\SecAgent\alerts";

    private const string ScanOnlyTrigger = "scan-only.trigger";
    private const string ScanAndAnalyzeTrigger = "scan-and-analyze.trigger";
    private const int TriggerDebounceSeconds = 30;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly NotifyIcon _icon;
    private readonly System.Windows.Forms.Timer _statusTimer;
    private readonly System.Windows.Forms.Timer _progressTimer;
    private readonly FileSystemWatcher? _reportWatcher;
    private readonly FileSystemWatcher? _scanWatcher;
    private readonly FileSystemWatcher? _progressWatcher;
    private readonly FileSystemWatcher? _alertWatcher;
    private readonly Dictionary<string, DateTime> _lastTriggerClickUtc = new();

    // Shared, always-on geolocation client (used by alerts + the dashboard pump).
    private readonly GeoLookup _geo = new();

    private AgentStatus? _status;
    private AnalysisProgress? _currentProgress;
    private string? _previousProgressState;
    // The icon to show when no work is in progress (driven by status.json severity).
    private Icon _severityIcon = SystemIcons.Information;

    private DataPump? _dataPump;
    private DashboardForm? _dashboard;

    public TrayApplicationContext()
    {
        Directory.CreateDirectory(DataDir);
        Directory.CreateDirectory(ReportsDir);
        Directory.CreateDirectory(EventsDir);
        Directory.CreateDirectory(ScansDir);
        Directory.CreateDirectory(AlertsDir);

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
        _statusTimer.Tick += (_, _) => RefreshStatus();
        _statusTimer.Start();
        RefreshStatus();

        _progressTimer = new System.Windows.Forms.Timer { Interval = 2_000 };
        _progressTimer.Tick += (_, _) => UpdateProgressTooltip();

        try
        {
            _reportWatcher = new FileSystemWatcher(ReportsDir, "*.md")
            {
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
            };
            _reportWatcher.Created += OnNewReport;
        }
        catch { }

        try
        {
            _scanWatcher = new FileSystemWatcher(ScansDir, "scan_*.json")
            {
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
            };
            _scanWatcher.Created += OnNewScan;
        }
        catch { }

        try
        {
            _progressWatcher = new FileSystemWatcher(DataDir, "progress.json")
            {
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            _progressWatcher.Created += OnProgressFileEvent;
            _progressWatcher.Changed += OnProgressFileEvent;
            _progressWatcher.Deleted += OnProgressFileDeleted;
        }
        catch { }

        // Always-on: toast immediately when the Service writes an inbound alert,
        // even with the dashboard closed.
        try
        {
            _alertWatcher = new FileSystemWatcher(AlertsDir, "alert_*.json")
            {
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
            };
            _alertWatcher.Created += OnNewAlert;
        }
        catch { }

        // If a progress file is already on disk when the tray starts (service
        // was mid-scan when tray launched), pick it up.
        OnProgressFileEvent(this, null!);
    }

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Abrir painel", null, (_, _) => ShowDashboard());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Forçar scan agora (sem Claude — grátis)", null,
            (_, _) => RequestTrigger(ScanOnlyTrigger, "Scan iniciado, aguarde ~5s..."));
        menu.Items.Add("Forçar scan + análise Claude (~$0.16)", null,
            (_, _) => RequestTrigger(ScanAndAnalyzeTrigger, "Scan + análise iniciados, aguarde ~1-2 min..."));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Abrir último relatório de scan", null, (_, _) => OpenLast("report_*.md"));
        menu.Items.Add("Abrir último relatório de incidente", null, (_, _) => OpenLast("incident_*.md"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Pasta de relatórios", null, (_, _) => OpenFolder(ReportsDir));
        menu.Items.Add("Pasta de eventos", null, (_, _) => OpenFolder(EventsDir));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Atualizar status", null, (_, _) => RefreshStatus());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Remover SecAgent deste usuário", null, (_, _) => RemoveForCurrentUser());
        menu.Items.Add("Sair", null, (_, _) => ExitThread());
        return menu;
    }
        
    // Remoção por usuário (sem admin): tira o Tray e o início automático apenas
    // da conta atual. O serviço de monitoramento (machine-wide) continua. A
    // desinstalação completa é feita em "Aplicativos e recursos" (admin).
    private void RemoveForCurrentUser()
    {
        var answer = MessageBox.Show(
            "Isto remove o ícone do SecAgent e o início automático apenas da SUA conta de usuário.\n\n" +
            "O serviço de monitoramento continua rodando para a máquina. Para desinstalar o SecAgent " +
            "por completo (todos os usuários), use \"Aplicativos e recursos\" do Windows (requer admin).\n\n" +
            "Remover o SecAgent da sua conta agora?",
            "Remover SecAgent deste usuário",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (answer != DialogResult.Yes)
            return;

        UserInstall.DisableForCurrentUser();
        ExitThread();
    }

    private void RequestTrigger(string fileName, string okMessage, string? content = null)
    {
        if (_lastTriggerClickUtc.TryGetValue(fileName, out var last) &&
            DateTime.UtcNow - last < TimeSpan.FromSeconds(TriggerDebounceSeconds))
        {
            var wait = TriggerDebounceSeconds - (int)(DateTime.UtcNow - last).TotalSeconds;
            _icon.ShowBalloonTip(3000, "SecAgent",
                $"Aguarde {wait}s entre solicitações.", ToolTipIcon.Info);
            return;
        }

        try
        {
            Directory.CreateDirectory(TriggersDir);
            var path = Path.Combine(TriggersDir, fileName);
            File.WriteAllText(path, content ?? DateTime.UtcNow.ToString("o"));
            _lastTriggerClickUtc[fileName] = DateTime.UtcNow;
            _icon.ShowBalloonTip(4000, "SecAgent", okMessage, ToolTipIcon.Info);
        }
        catch (UnauthorizedAccessException)
        {
            _icon.ShowBalloonTip(5000, "SecAgent",
                "Sem permissão para escrever em " + TriggersDir +
                ". O serviço talvez não esteja rodando — reinstale com deploy.ps1.",
                ToolTipIcon.Error);
        }
        catch (Exception ex)
        {
            _icon.ShowBalloonTip(5000, "SecAgent",
                "Falha ao solicitar trigger: " + ex.Message, ToolTipIcon.Error);
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

    private void OnDashboardCommand(string cmd)
    {
        switch (cmd)
        {
            case "scanOnly":
                RequestTrigger(ScanOnlyTrigger, "Varredura iniciada, aguarde ~5s...");
                return;
            case "scanAndAnalyze":
                RequestTrigger(ScanAndAnalyzeTrigger, "Varredura + análise iniciadas, aguarde ~1-2 min...");
                return;
        }

        if (cmd.StartsWith("blockIp:", StringComparison.Ordinal))
        {
            var ip = cmd.Substring("blockIp:".Length).Trim();
            RequestTrigger($"block-ip-{SanitizeIp(ip)}.trigger",
                $"Bloqueando {ip} (entrada e saída)…", ip);
        }
        else if (cmd.StartsWith("unblockIp:", StringComparison.Ordinal))
        {
            var ip = cmd.Substring("unblockIp:".Length).Trim();
            RequestTrigger($"unblock-ip-{SanitizeIp(ip)}.trigger",
                $"Desbloqueando {ip}…", ip);
        }
    }

    // IPv6 addresses carry ':' / '%', which are illegal in Windows filenames.
    // The sanitized form is only for the trigger NAME; the raw IP rides in the
    // file content (the Service parses/validates that).
    private static string SanitizeIp(string ip)
        => ip.Replace(':', '-').Replace('%', '-').Replace('/', '-');

    private void RefreshStatus()
    {
        if (!File.Exists(StatusPath))
        {
            _severityIcon = SystemIcons.Information;
            if (_currentProgress is null)
            {
                _icon.Icon = _severityIcon;
                _icon.Text = "SecAgent (sem status ainda)";
            }
            return;
        }

        try
        {
            var json = File.ReadAllText(StatusPath);
            _status = JsonSerializer.Deserialize<AgentStatus>(json, JsonOpts);
            if (_status is null) return;

            var sev = (_status.OverallSeverity ?? "green").ToLowerInvariant();
            _severityIcon = sev switch
            {
                "red" => SystemIcons.Error,
                "yellow" => SystemIcons.Warning,
                _ => SystemIcons.Shield
            };

            // Only swap to the severity icon when no progress is active.
            // Otherwise leave the busy icon in place; OnProgressFileDeleted
            // will restore _severityIcon when work completes.
            if (_currentProgress is null)
            {
                _icon.Icon = _severityIcon;
                _icon.Text = BuildStatusTooltip(_status);
            }
        }
        catch
        {
            // Status file may be mid-write; try again on next tick.
        }
    }

    private static string BuildStatusTooltip(AgentStatus s)
    {
        var sb = new StringBuilder("SecAgent");
        if (s.LastScan is { } scan)
            sb.Append($"\nScan: {scan.RiskLevel} ({scan.FindingsCount} findings, {scan.TimestampUtc.ToLocalTime():HH:mm})");
        if (s.LastIncident is { } inc)
            sb.Append($"\nIncidente: {inc.Severity} ({inc.TimestampUtc.ToLocalTime():HH:mm})");
        var t = sb.ToString();
        return t.Length > 127 ? t[..127] : t;
    }

    private void OnProgressFileEvent(object? sender, FileSystemEventArgs? e)
    {
        if (_icon.ContextMenuStrip?.InvokeRequired == true)
        {
            _icon.ContextMenuStrip.BeginInvoke(() => OnProgressFileEvent(sender, e));
            return;
        }

        if (!File.Exists(ProgressPath))
        {
            return;
        }

        AnalysisProgress? progress = null;
        // Retry briefly — file may be mid-write when watcher fires.
        for (int attempt = 0; attempt < 3 && progress is null; attempt++)
        {
            try
            {
                var json = File.ReadAllText(ProgressPath);
                if (!string.IsNullOrWhiteSpace(json))
                    progress = JsonSerializer.Deserialize<AnalysisProgress>(json, JsonOpts);
            }
            catch
            {
                Thread.Sleep(80);
            }
        }
        if (progress is null) return;

        var previousState = _currentProgress?.State;
        _currentProgress = progress;

        // Swap to busy icon
        _icon.Icon = SystemIcons.Information;

        // Transition toast: scanning → analyzing
        if (previousState == "scanning" && progress.State == "analyzing")
        {
            _icon.ShowBalloonTip(4000, "SecAgent",
                $"Scan concluído. {progress.Step}, aguarde ~1 min...",
                ToolTipIcon.Info);
        }

        _previousProgressState = progress.State;

        if (!_progressTimer.Enabled) _progressTimer.Start();
        UpdateProgressTooltip();
    }

    private void OnProgressFileDeleted(object? sender, FileSystemEventArgs e)
    {
        if (_icon.ContextMenuStrip?.InvokeRequired == true)
        {
            _icon.ContextMenuStrip.BeginInvoke(() => OnProgressFileDeleted(sender, e));
            return;
        }

        _currentProgress = null;
        _previousProgressState = null;
        _progressTimer.Stop();

        // Restore severity icon and normal tooltip
        _icon.Icon = _severityIcon;
        if (_status is not null) _icon.Text = BuildStatusTooltip(_status);
        else _icon.Text = "SecAgent";
    }

    private void UpdateProgressTooltip()
    {
        if (_currentProgress is null) return;
        var elapsed = (int)(DateTime.UtcNow - _currentProgress.StartedAtUtc).TotalSeconds;
        if (elapsed < 0) elapsed = 0;

        var label = _currentProgress.State == "analyzing"
            ? $"SecAgent — {_currentProgress.Step}... {elapsed}s"
            : $"SecAgent — {_currentProgress.Step}... {elapsed}s";

        _icon.Text = label.Length > 127 ? label[..127] : label;
    }

    private void OpenLast(string pattern)
    {
        try
        {
            var last = new DirectoryInfo(ReportsDir).GetFiles(pattern)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault();
            if (last is null)
            {
                _icon.ShowBalloonTip(3000, "SecAgent",
                    $"Nenhum arquivo encontrado para padrão {pattern}", ToolTipIcon.Info);
                return;
            }
            OpenFile(last.FullName);
        }
        catch (Exception ex)
        {
            _icon.ShowBalloonTip(3000, "SecAgent", $"Erro abrindo último relatório: {ex.Message}", ToolTipIcon.Error);
        }
    }

    private static void OpenFile(string path)
        => Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });

    private static void OpenFolder(string path)
    {
        Directory.CreateDirectory(path);
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    private void OnNewReport(object sender, FileSystemEventArgs e)
    {
        if (_icon.ContextMenuStrip?.InvokeRequired == true)
        {
            _icon.ContextMenuStrip.BeginInvoke(() => OnNewReport(sender, e));
            return;
        }

        var name = e.Name ?? "";
        bool isIncident = name.StartsWith("incident_", StringComparison.OrdinalIgnoreCase);
        var title = isIncident ? "SecAgent: novo incidente detectado" : "SecAgent: novo relatório de scan";
        _icon.ShowBalloonTip(7000, title, name, isIncident ? ToolTipIcon.Warning : ToolTipIcon.Info);
        RefreshStatus();
    }

    private async void OnNewAlert(object sender, FileSystemEventArgs e)
    {
        var alert = ReadAlert(e.FullPath);
        if (alert is null) return;

        // Enrich with country (cache hit = instant; bounded timeout otherwise).
        GeoLookup.GeoInfo? geo = null;
        try { geo = await _geo.ResolveNowAsync(alert.RemoteAddress); } catch { }

        var loc = geo is not null
            ? $"{Flag(geo.CountryCode)} {geo.Country}".Trim() + " · "
            : "";
        var text = loc + alert.Message;
        var icon = string.Equals(alert.Severity, "critical", StringComparison.OrdinalIgnoreCase)
            ? ToolTipIcon.Error : ToolTipIcon.Warning;

        void Show() => _icon.ShowBalloonTip(8000, "SecAgent: " + alert.Title, text, icon);
        if (_icon.ContextMenuStrip?.InvokeRequired == true)
            _icon.ContextMenuStrip.BeginInvoke(Show);
        else
            Show();
    }

    private static NetworkAlert? ReadAlert(string path)
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, Encoding.UTF8);
                var json = sr.ReadToEnd();
                if (!string.IsNullOrWhiteSpace(json))
                    return JsonSerializer.Deserialize<NetworkAlert>(json, JsonOpts);
            }
            catch { }
            Thread.Sleep(80);
        }
        return null;
    }

    private static string Flag(string? cc)
    {
        if (string.IsNullOrEmpty(cc) || cc.Length != 2) return "🌐";
        cc = cc.ToUpperInvariant();
        return char.ConvertFromUtf32(0x1F1E6 + (cc[0] - 'A')) +
               char.ConvertFromUtf32(0x1F1E6 + (cc[1] - 'A'));
    }

    private void OnNewScan(object sender, FileSystemEventArgs e)
    {
        if (_icon.ContextMenuStrip?.InvokeRequired == true)
        {
            _icon.ContextMenuStrip.BeginInvoke(() => OnNewScan(sender, e));
            return;
        }

        // Only surface scan-only completions to avoid double-toast with reports.
        // Heuristic: if progress is null (scan-only finished and cleared its progress),
        // or if currentProgress state was "scanning" (no analyze coming), this is a
        // scan-only run. For scan+analyze the progress will transition to "analyzing"
        // and the final report toast handles it.
        if (_currentProgress is null || _currentProgress.State == "scanning")
        {
            _icon.ShowBalloonTip(4000, "SecAgent",
                "Snapshot capturado: " + (e.Name ?? ""),
                ToolTipIcon.Info);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _icon.Visible = false;
            _icon.Dispose();
            _statusTimer.Dispose();
            _progressTimer.Dispose();
            _reportWatcher?.Dispose();
            _scanWatcher?.Dispose();
            _progressWatcher?.Dispose();
            _alertWatcher?.Dispose();
            _dataPump?.Dispose();
            _dashboard?.Dispose();
            _geo.Dispose();
        }
        base.Dispose(disposing);
    }
}
