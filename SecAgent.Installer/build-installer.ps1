# build-installer.ps1
# ----------------------------------------------------------------------------
# Publica SecAgent.Service e SecAgent.Tray como self-contained win-x64 e
# compila SecAgent.iss com o Inno Setup (ISCC.exe), gerando
# output\SecAgent-Setup.exe.
#
# NAO requer admin (so build). Requer:
#   - .NET 8 SDK  (dotnet)
#   - Inno Setup 6 (ISCC.exe) -> winget install JRSoftware.InnoSetup

$ErrorActionPreference = 'Stop'

$installerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$solutionDir  = Split-Path -Parent $installerDir
$serviceProj  = Join-Path $solutionDir 'SecAgent.Service'
$trayProj     = Join-Path $solutionDir 'SecAgent.Tray'
$publishDir   = Join-Path $installerDir 'publish'
$outputDir    = Join-Path $installerDir 'output'

# 1. Limpar publish anterior (evita arrastar arquivos orfaos para o setup)
if (Test-Path $publishDir) {
    Write-Output "[1/4] Limpando $publishDir"
    Remove-Item -Recurse -Force $publishDir
}
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null
New-Item -ItemType Directory -Force -Path $outputDir  | Out-Null

# 2. Publicar Service (self-contained win-x64)
Write-Output "[2/4] Publicando SecAgent.Service (self-contained win-x64)"
& dotnet publish $serviceProj -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=false -o (Join-Path $publishDir 'Service') --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet publish (Service) falhou com exit $LASTEXITCODE" }

# 3. Publicar Tray (self-contained win-x64)
Write-Output "[3/4] Publicando SecAgent.Tray (self-contained win-x64)"
& dotnet publish $trayProj -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=false -o (Join-Path $publishDir 'Tray') --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet publish (Tray) falhou com exit $LASTEXITCODE" }

# 4. Localizar ISCC.exe e compilar o .iss
Write-Output "[4/4] Compilando o instalador com Inno Setup"
$iscc = $null
$candidates = @(
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles        'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:LOCALAPPDATA         'Programs\Inno Setup 6\ISCC.exe')
)
foreach ($c in $candidates) {
    if ($c -and (Test-Path $c)) { $iscc = $c; break }
}
if (-not $iscc) {
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { $iscc = $cmd.Source }
}
if (-not $iscc) {
    throw "ISCC.exe (Inno Setup) nao encontrado. Instale com: winget install JRSoftware.InnoSetup"
}

$iss = Join-Path $installerDir 'SecAgent.iss'
& $iscc $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC falhou com exit $LASTEXITCODE" }

$setup = Join-Path $outputDir 'SecAgent-Setup.exe'
if (Test-Path $setup) {
    Write-Output ""
    Write-Output "OK: $setup"
} else {
    throw "Compilacao terminou mas $setup nao foi gerado."
}
