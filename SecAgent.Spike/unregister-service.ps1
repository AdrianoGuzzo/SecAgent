# Run as Administrator. Stops and removes the SecAgentSpike service.
# Leaves the Machine-scope CLAUDE_CODE_OAUTH_TOKEN env var in place (used by future SecAgent.Service).

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Must run as Administrator."; exit 1 }

$serviceName = 'SecAgentSpike'
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $svc) { Write-Output "$serviceName not installed. Nothing to do."; exit 0 }

if ($svc.Status -ne 'Stopped') {
    Write-Output "Stopping $serviceName"
    Stop-Service -Name $serviceName -Force
    Start-Sleep -Seconds 2
}
Write-Output "Deleting $serviceName"
& sc.exe delete $serviceName | Out-Null
Write-Output "Done."
