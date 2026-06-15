# Run as Administrator. Registers SecAgentSpike as a Windows Service under LocalSystem
# and propagates CLAUDE_CODE_OAUTH_TOKEN from the current user's env to Machine scope
# so the LocalSystem service can read it.

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$serviceName = 'SecAgentSpike'
$exePath = 'C:\Projetos\SecAgent\SecAgent.Spike\bin\publish\SecAgent.Spike.exe'

if (-not (Test-Path $exePath)) {
    Write-Error "Binary not found at $exePath. Run 'dotnet publish' first."
    exit 1
}

# Read token from the invoking user's User-scope env var. With UAC elevation
# the user identity is preserved, so HKCU of adria still works.
$token = [Environment]::GetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', 'User')
if ([string]::IsNullOrEmpty($token)) {
    Write-Error "User-scope CLAUDE_CODE_OAUTH_TOKEN is missing. Run 'claude setup-token' first and set it."
    exit 1
}

Write-Output "Setting Machine-scope CLAUDE_CODE_OAUTH_TOKEN (length=$($token.Length))"
[Environment]::SetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', $token, 'Machine')

# Tear down any previous instance
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Output "Stopping and deleting existing $serviceName"
    if ($existing.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Output "Registering service"
$scResult = & sc.exe create $serviceName binPath= "`"$exePath`"" start= demand obj= LocalSystem DisplayName= "SecAgent Spike (Claude integration test)"
$scResult | Out-Host

Write-Output "Setting service description"
& sc.exe description $serviceName "Spike for validating Claude Code CLI invocation from a LocalSystem Windows Service." | Out-Null

Write-Output "Starting service"
Start-Service -Name $serviceName
Start-Sleep -Seconds 2
Get-Service -Name $serviceName | Format-Table Name, Status, StartType
Write-Output "Done. Watch C:\ProgramData\SecAgent\spike.log for output."
