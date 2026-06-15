# Run as the LOGGED-IN USER (no admin needed).
# Removes the HKCU Run key entry and stops the tray.

$ErrorActionPreference = 'Stop'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$valueName = 'SecAgentTray'

Get-Process -Name SecAgent.Tray -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
if (Get-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $runKey -Name $valueName
    Write-Output "Auto-start entry removed."
} else {
    Write-Output "No auto-start entry found."
}
Write-Output "Done."
