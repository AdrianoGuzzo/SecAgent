# Run as Administrator. Updates CLAUDE_CODE_OAUTH_TOKEN at both User and Machine
# scope. Token is read via SecureString so it is NOT echoed to the terminal.
# After running: existing service processes need a restart to pick up the new value.

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Must run as Administrator (Machine scope requires it)."; exit 1 }

$sec = Read-Host -AsSecureString "Cole o novo token (nao sera ecoado) e aperte Enter"
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try {
    $token = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

if ([string]::IsNullOrWhiteSpace($token)) { Write-Error "Token vazio."; exit 1 }
if (-not $token.StartsWith('sk-ant-oat')) {
    Write-Warning "Token nao comeca com 'sk-ant-oat' (formato esperado de OAuth). Continuando assim mesmo."
}

[Environment]::SetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', $token, 'User')
[Environment]::SetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', $token, 'Machine')
Write-Output "Token atualizado em User e Machine scope (length=$($token.Length))"
$token = $null

# Restart the spike service so it picks up the new env var, if installed and running
$svc = Get-Service -Name SecAgentSpike -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Output "Reiniciando SecAgentSpike para usar o novo token..."
    Restart-Service -Name SecAgentSpike -Force
    Start-Sleep -Seconds 2
    Get-Service -Name SecAgentSpike | Format-Table Name, Status
}
