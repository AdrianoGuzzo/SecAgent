using System.Text;

namespace SecAgent.Tray.Core;

/// <summary>
/// Script do PowerShell elevado que grava o token (Machine + User) e reinicia o serviço.
///
/// T1: o script antigo usava a preferência de erro padrão — se a leitura do
/// arquivo temporário falhasse, <c>$t</c> ficava null e
/// <c>SetEnvironmentVariable(null)</c> APAGAVA o token existente, e o processo
/// saía com 0 ("Token salvo"). Agora: <c>$ErrorActionPreference='Stop'</c>,
/// validação de <c>$t</c> e <c>exit 1</c> em qualquer falha antes de gravar.
/// </summary>
internal static class TokenSaveScriptBuilder
{
    public const int ExitInvalidToken = 2;

    public static string Build(string tempFile, string tokenVar, string serviceName = "SecAgent")
    {
        var f = tempFile.Replace("'", "''");
        return string.Join("\n",
            "$ErrorActionPreference = 'Stop'",
            "try {",
            $"  $f = '{f}'",
            "  $t = (Get-Content -LiteralPath $f -Raw)",
            "  Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue",
            "  if ($null -eq $t) { exit " + ExitInvalidToken + " }",
            "  $t = $t.Trim()",
            "  if ([string]::IsNullOrWhiteSpace($t)) { exit " + ExitInvalidToken + " }",
            $"  [Environment]::SetEnvironmentVariable('{tokenVar}', $t, 'Machine')",
            $"  [Environment]::SetEnvironmentVariable('{tokenVar}', $t, 'User')",
            "} catch { exit 1 }",
            // O restart é best-effort: o serviço pode não estar instalado (dev).
            $"Restart-Service {serviceName} -ErrorAction SilentlyContinue",
            "exit 0");
    }

    /// <summary>
    /// Argumentos do powershell.exe com <c>-EncodedCommand</c> (UTF-16LE base64):
    /// sem escape de aspas na linha de comando.
    /// </summary>
    public static string PowerShellArguments(string script)
        => "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " +
           Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
}

/// <summary>Linha de comando do "claude setup-token" em um terminal que fica aberto.</summary>
internal static class ClaudeSetupCommand
{
    public static string CmdArguments(string claudeExe)
        => $"/k \"\"{claudeExe.Trim().Trim('"')}\" setup-token\"";
}
