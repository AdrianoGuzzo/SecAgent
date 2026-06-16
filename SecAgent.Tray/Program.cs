namespace SecAgent.Tray;

static class Program
{
    [STAThread]
    static void Main()
    {
        // O autostart é machine-wide (HKLM). Honra o opt-out por usuário para
        // que alguém possa remover o Tray da própria conta sem admin.
        if (UserInstall.IsDisabledForCurrentUser())
            return;

        // Limpa o autostart per-user legado (instalações anteriores ao HKLM)
        // para o Tray não ser iniciado duas vezes.
        UserInstall.RemoveLegacyAutostart();

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayApplicationContext());
    }
}
