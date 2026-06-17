using System.ComponentModel;
using System.Diagnostics;

namespace SecAgent.Tray;

/// <summary>
/// Native window to configure the Claude OAuth token from the dashboard. Mirrors
/// the installer's wizard page: detect claude.exe, generate the token in a real
/// terminal (claude setup-token), paste it, validate the prefix, and save.
///
/// Saving needs admin (Machine-scope env var + service restart), which the Tray
/// lacks — so <see cref="SaveTokenElevated"/> spawns one elevated PowerShell
/// (single UAC prompt), mirroring update-token.ps1.
/// </summary>
public sealed class TokenSetupForm : Form
{
    private readonly TextBox _claudePath;
    private readonly TextBox _tokenBox;
    private readonly Button _generateBtn;

    public TokenSetupForm()
    {
        Text = "SecAgent — Configurar IA (token do Claude)";
        Width = 640;
        Height = 360;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        try { Icon = SystemIcons.Shield; } catch { }

        const int margin = 16;
        int width = ClientSize.Width - margin * 2;

        var intro = new Label
        {
            Left = margin, Top = margin, Width = width, Height = 36,
            Text = "A análise com IA usa o Claude Code. Gere um token (login no navegador) " +
                   "e cole abaixo. Salvar exige confirmação de administrador (UAC)."
        };

        var lblClaude = new Label
        {
            Left = margin, Top = intro.Bottom + 8, Width = width, Height = 18,
            Text = "Caminho do claude.exe:"
        };
        _claudePath = new TextBox
        {
            Left = margin, Top = lblClaude.Bottom + 2, Width = width - 90,
            Text = TokenSetup.DetectClaudeExe() ?? ""
        };
        var browseBtn = new Button
        {
            Left = _claudePath.Right + 8, Top = _claudePath.Top - 1, Width = 82,
            Text = "Procurar..."
        };
        browseBtn.Click += (_, _) => Browse();

        _generateBtn = new Button
        {
            Left = margin, Top = _claudePath.Bottom + 14, Width = 160, Height = 30,
            Text = "1) Gerar token…"
        };
        _generateBtn.Click += (_, _) => GenerateToken();

        var genHint = new Label
        {
            Left = _generateBtn.Right + 12, Top = _generateBtn.Top + 6,
            Width = width - _generateBtn.Width - 12, Height = 18,
            ForeColor = SystemColors.GrayText,
            Text = "Abre um terminal. Faça o login e copie o token (sk-ant-oat…)."
        };

        var lblToken = new Label
        {
            Left = margin, Top = _generateBtn.Bottom + 16, Width = width, Height = 18,
            Text = "2) Cole o token aqui:"
        };
        _tokenBox = new TextBox
        {
            Left = margin, Top = lblToken.Bottom + 2, Width = width,
            UseSystemPasswordChar = true
        };

        var saveBtn = new Button
        {
            Left = ClientSize.Width - margin - 120, Top = _tokenBox.Bottom + 20,
            Width = 120, Height = 32, Text = "Salvar"
        };
        saveBtn.Click += (_, _) => Save();

        var cancelBtn = new Button
        {
            Left = saveBtn.Left - 110, Top = saveBtn.Top, Width = 100, Height = 32,
            Text = "Cancelar", DialogResult = DialogResult.Cancel
        };

        AcceptButton = saveBtn;
        CancelButton = cancelBtn;

        Controls.AddRange(new Control[]
        {
            intro, lblClaude, _claudePath, browseBtn,
            _generateBtn, genHint, lblToken, _tokenBox, saveBtn, cancelBtn
        });

        UpdateGenerateEnabled();
        _claudePath.TextChanged += (_, _) => UpdateGenerateEnabled();
    }

    private void UpdateGenerateEnabled()
        => _generateBtn.Enabled = _claudePath.Text.Trim().Length > 0;

    private void Browse()
    {
        using var dlg = new OpenFileDialog
        {
            Title = "Selecione o claude.exe",
            Filter = "Executável (*.exe)|*.exe|Todos (*.*)|*.*",
            FileName = _claudePath.Text
        };
        if (dlg.ShowDialog(this) == DialogResult.OK)
            _claudePath.Text = dlg.FileName;
    }

    private void GenerateToken()
    {
        var claude = _claudePath.Text.Trim();
        if (claude.Length == 0)
        {
            MessageBox.Show(this, "Informe o caminho do claude.exe primeiro.",
                "SecAgent", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        try
        {
            // 'cmd /k' keeps the window open so the user can read/copy the token and
            // see any errors. The Tray already runs in the user's session, so a plain
            // Process.Start gives a real TTY + the user's browser/credentials (no
            // ExecAsOriginalUser needed, unlike the elevated installer).
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/k \"\"{claude}\" setup-token\"",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Não foi possível abrir o terminal: " + ex.Message,
                "SecAgent", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        MessageBox.Show(this,
            "Um terminal foi aberto para o login do Claude.\n\n" +
            "Conclua o login no navegador, copie o token exibido (sk-ant-oat…) " +
            "e cole no campo \"2) Cole o token aqui\" desta janela. Depois clique em Salvar.",
            "SecAgent", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void Save()
    {
        var token = _tokenBox.Text.Trim();
        if (token.Length == 0)
        {
            MessageBox.Show(this, "Cole o token antes de salvar.",
                "SecAgent", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (!token.StartsWith(TokenSetup.TokenPrefix, StringComparison.Ordinal))
        {
            var ok = MessageBox.Show(this,
                "O token não começa com \"sk-ant-oat\" (formato esperado de OAuth). Usar mesmo assim?",
                "SecAgent", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (ok != DialogResult.Yes) return;
        }

        try
        {
            if (!SaveTokenElevated(token)) return;   // user cancelled UAC / save failed
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Falha ao salvar o token: " + ex.Message,
                "SecAgent", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        MessageBox.Show(this,
            "Token salvo e serviço reiniciado. A análise com IA já pode ser usada.",
            "SecAgent", MessageBoxButtons.OK, MessageBoxIcon.Information);
        DialogResult = DialogResult.OK;
        Close();
    }

    /// <summary>
    /// Writes the token (Machine + User scope) and restarts the Service via one
    /// elevated PowerShell. The token is passed through a temp file readable only
    /// by the current user, so it never appears on the process command line.
    /// Returns false if the user declined the UAC prompt or the helper failed.
    /// </summary>
    private bool SaveTokenElevated(string token)
    {
        var tempFile = Path.Combine(Path.GetTempPath(), "secagent-token-" + Guid.NewGuid().ToString("N") + ".tmp");
        File.WriteAllText(tempFile, token);
        try
        {
            // Restrict the temp file to the current user.
            try
            {
                var fi = new FileInfo(tempFile);
                var sec = fi.GetAccessControl();
                sec.SetAccessRuleProtection(true, false);
                var me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
                sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    me, System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));
                fi.SetAccessControl(sec);
            }
            catch { /* best effort — ACL hardening only */ }

            var escaped = tempFile.Replace("'", "''");
            var script =
                $"$f='{escaped}'; " +
                "$t=(Get-Content -LiteralPath $f -Raw).Trim(); " +
                "Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue; " +
                $"[Environment]::SetEnvironmentVariable('{TokenSetup.TokenVar}',$t,'Machine'); " +
                $"[Environment]::SetEnvironmentVariable('{TokenSetup.TokenVar}',$t,'User'); " +
                "Restart-Service SecAgent -ErrorAction SilentlyContinue";

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"" +
                            script.Replace("\"", "\\\"") + "\"",
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            };

            Process proc;
            try
            {
                proc = Process.Start(psi)!;
            }
            catch (Win32Exception)
            {
                // 1223 = ERROR_CANCELLED — user dismissed the UAC prompt.
                MessageBox.Show(this,
                    "A elevação foi cancelada. O token não foi salvo.",
                    "SecAgent", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            proc.WaitForExit();
            if (proc.ExitCode != 0)
            {
                MessageBox.Show(this,
                    "O salvamento elevado terminou com erro (código " + proc.ExitCode + ").",
                    "SecAgent", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            return true;
        }
        finally
        {
            // The elevated script deletes the temp file; this is a fallback if it
            // never ran (e.g. UAC cancelled).
            try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
        }
    }
}
