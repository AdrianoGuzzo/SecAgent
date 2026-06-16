using Microsoft.Win32;

namespace SecAgent.Tray;

/// <summary>
/// Habilitação do Tray por usuário. O autostart é registrado machine-wide
/// (HKLM\...\Run) pelo instalador, então TODOS os usuários recebem o Tray por
/// padrão (padrão de mercado para "serviço LocalSystem + UI por usuário").
/// Cada usuário pode remover apenas a sua cópia — sem admin — pelo menu
/// "Remover SecAgent deste usuário", que grava o opt-out honrado aqui no
/// startup. O serviço LocalSystem é machine-wide e não é afetado; a
/// desinstalação completa (todos os usuários) é feita em "Aplicativos e
/// recursos" do Windows (requer admin).
/// </summary>
internal static class UserInstall
{
    private const string SettingsKey = @"Software\SecAgent";
    private const string DisabledValue = "TrayDisabled";
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValue = "SecAgentTray";

    /// <summary>True se o usuário atual desativou o Tray na própria conta.</summary>
    public static bool IsDisabledForCurrentUser()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(SettingsKey);
            return key?.GetValue(DisabledValue) is int v && v == 1;
        }
        catch { return false; }
    }

    /// <summary>
    /// Remove o Tray apenas para o usuário atual: grava o opt-out e apaga
    /// qualquer autostart per-user legado. O serviço machine-wide e os demais
    /// usuários ficam intactos.
    /// </summary>
    public static void DisableForCurrentUser()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(SettingsKey);
            key?.SetValue(DisabledValue, 1, RegistryValueKind.DWord);
        }
        catch { }
        RemoveLegacyAutostart();
    }

    /// <summary>
    /// Apaga o valor de autostart legado em HKCU\...\Run (instalações
    /// anteriores ao modelo HKLM). Evita o Tray subir duas vezes — uma pelo
    /// HKLM, outra pelo HKCU obsoleto.
    /// </summary>
    public static void RemoveLegacyAutostart()
    {
        try
        {
            using var run = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
            if (run?.GetValue(RunValue) != null)
                run.DeleteValue(RunValue, throwOnMissingValue: false);
        }
        catch { }
    }
}
