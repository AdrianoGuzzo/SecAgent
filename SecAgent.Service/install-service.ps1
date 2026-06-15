# Run as Administrator.
# - Stops/deletes the temporary SecAgentSpike (if present)
# - Ensures CLAUDE_CODE_OAUTH_TOKEN is present at Machine scope
# - Registers SecAgent as a Windows Service running under LocalSystem
# - Sets start type to 'auto' (starts at boot)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Must run as Administrator."; exit 1 }

$serviceName = 'SecAgent'
$exePath = 'C:\Projetos\SecAgent\SecAgent.Service\bin\publish\SecAgent.Service.exe'

if (-not (Test-Path $exePath)) {
    Write-Error "Binary not found at $exePath. Run 'dotnet publish' first."
    exit 1
}

# Token: prefer Machine scope; fall back to User scope and copy up to Machine
$tokenMachine = [Environment]::GetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', 'Machine')
if ([string]::IsNullOrEmpty($tokenMachine)) {
    $tokenUser = [Environment]::GetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', 'User')
    if ([string]::IsNullOrEmpty($tokenUser)) {
        Write-Error "CLAUDE_CODE_OAUTH_TOKEN missing in both User and Machine scope. Run 'claude setup-token' first."
        exit 1
    }
    Write-Output "Copying CLAUDE_CODE_OAUTH_TOKEN from User -> Machine scope (length=$($tokenUser.Length))"
    [Environment]::SetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', $tokenUser, 'Machine')
} else {
    Write-Output "Machine-scope CLAUDE_CODE_OAUTH_TOKEN already present (length=$($tokenMachine.Length))"
}

# Tear down the temporary spike if present
$spike = Get-Service -Name 'SecAgentSpike' -ErrorAction SilentlyContinue
if ($spike) {
    Write-Output "Stopping and deleting SecAgentSpike (replaced by SecAgent)"
    if ($spike.Status -ne 'Stopped') { Stop-Service -Name 'SecAgentSpike' -Force }
    & sc.exe delete 'SecAgentSpike' | Out-Null
    Start-Sleep -Seconds 2
}

# Tear down previous SecAgent if present
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Output "Stopping and deleting existing $serviceName"
    if ($existing.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Output "Registering $serviceName as Windows Service (LocalSystem, auto-start)"
$null = & sc.exe create $serviceName binPath= "`"$exePath`"" start= auto obj= LocalSystem DisplayName= "SecAgent (Security monitoring + Claude analysis)"
& sc.exe description $serviceName "Daily Windows security configuration scan with AI-driven analysis via Claude Code subscription." | Out-Null

# Failure recovery: restart on crash after 60s, three attempts within 24h
& sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

Write-Output "Starting $serviceName"
Start-Service -Name $serviceName
Start-Sleep -Seconds 3
Get-Service -Name $serviceName | Format-Table Name, Status, StartType
Write-Output ""
Write-Output "Done. Watch scans in C:\ProgramData\SecAgent\scans and reports in C:\ProgramData\SecAgent\reports"
Write-Output "First scan + Claude analysis runs immediately (~3 min). Subsequent scans every 24h."
