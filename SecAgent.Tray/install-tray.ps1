# Run as the LOGGED-IN USER (no admin needed).
# - Closes any running SecAgent.Tray
# - Publishes the WinForms exe to bin\publish
# - Registers under HKCU\...\Run so it auto-starts on login
# - Launches it now

$ErrorActionPreference = 'Stop'

$projectDir = 'C:\Projetos\SecAgent\SecAgent.Tray'
$exePath = Join-Path $projectDir 'bin\publish\SecAgent.Tray.exe'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$valueName = 'SecAgentTray'

Write-Output "[1/4] Stopping any running SecAgent.Tray"
Get-Process -Name SecAgent.Tray -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Output "[2/4] Publishing"
Push-Location $projectDir
try {
    & dotnet publish -c Release -o bin\publish --no-self-contained --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit $LASTEXITCODE" }
} finally {
    Pop-Location
}
if (-not (Test-Path $exePath)) { Write-Error "Binary missing at $exePath"; exit 1 }

Write-Output "[3/4] Registering under HKCU\...\Run as '$valueName'"
if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
Set-ItemProperty -Path $runKey -Name $valueName -Value "`"$exePath`""

# Limpa um opt-out anterior ("Remover SecAgent deste usuario" no menu do Tray),
# tratando o re-install dev como "voltar ao padrao" (igual ao instalador Inno).
$settingsKey = 'HKCU:\Software\SecAgent'
if (Get-ItemProperty -Path $settingsKey -Name 'TrayDisabled' -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $settingsKey -Name 'TrayDisabled' -ErrorAction SilentlyContinue
}

Write-Output "[4/4] Launching"
Start-Process -FilePath $exePath
Start-Sleep -Seconds 1
$proc = Get-Process -Name SecAgent.Tray -ErrorAction SilentlyContinue
if ($proc) {
    Write-Output ("Tray running, PID=" + $proc.Id)
} else {
    Write-Warning "Tray process not detected. Check Windows Event Viewer for errors."
}
Write-Output ""
Write-Output "Done. Look for the SecAgent icon in the system tray (notification area)."
Write-Output "Tray will now start automatically every time you log in."
