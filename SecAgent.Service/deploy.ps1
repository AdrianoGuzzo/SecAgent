# Run as Administrator.
# Full redeploy flow: stop service -> publish -> re-register -> start.
# Use this after any code change to ship the new binary.

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Must run as Administrator."; exit 1 }

$projectDir = 'C:\Projetos\SecAgent\SecAgent.Service'
$serviceName = 'SecAgent'

# 1. Stop the service so the published exe can be overwritten
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    Write-Output "[1/4] Stopping $serviceName"
    Stop-Service -Name $serviceName -Force
    Start-Sleep -Seconds 2
} else {
    Write-Output "[1/4] $serviceName not running, skip stop"
}

# 2. Publish (writes to bin\publish)
Write-Output "[2/4] Publishing"
Push-Location $projectDir
try {
    & dotnet publish -c Release -o bin\publish --no-self-contained --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit $LASTEXITCODE" }
} finally {
    Pop-Location
}

# 3. Re-register service (delete + create with same settings as install-service.ps1)
Write-Output "[3/4] Re-registering $serviceName"
$exePath = Join-Path $projectDir 'bin\publish\SecAgent.Service.exe'
if (-not (Test-Path $exePath)) { Write-Error "Binary missing at $exePath after publish"; exit 1 }

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
}

$null = & sc.exe create $serviceName binPath= "`"$exePath`"" start= auto obj= LocalSystem DisplayName= "SecAgent (Security monitoring + Claude analysis)"
& sc.exe description $serviceName "Daily Windows security configuration scan with AI-driven analysis via Claude Code subscription. Real-time process/network/eventlog monitoring with ad-hoc incident analysis." | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

# 4. Start
Write-Output "[4/4] Starting $serviceName"
Start-Service -Name $serviceName
Start-Sleep -Seconds 3
Get-Service -Name $serviceName | Format-Table Name, Status, StartType
Write-Output ""
Write-Output "Done. Watch C:\ProgramData\SecAgent\ for scans/, reports/, events/."
