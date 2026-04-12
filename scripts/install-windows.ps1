$ErrorActionPreference = "Stop"

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "install-windows.ps1 must be run as Administrator"
}

$root = Split-Path -Parent $PSScriptRoot
$windowsBuildDir = Join-Path $root "agents\windows\build\service\Release"
$programFilesDir = "C:\Program Files\RansomEye"
$programDataDir = "C:\ProgramData\RansomEye"

$serviceSrc = Join-Path $windowsBuildDir "ransomeye_service.exe"
$buildManifestSrc = Join-Path $root "agents\windows\build\build_manifest.json"
$buildManifestSigSrc = Join-Path $root "agents\windows\build\build_manifest.sig"
$agentIdPath = Join-Path $programDataDir "agent_id.bin"

if (-not (Test-Path $serviceSrc)) {
    throw "Missing build artifact: $serviceSrc"
}

New-Item -ItemType Directory -Force -Path $programFilesDir | Out-Null
New-Item -ItemType Directory -Force -Path $programDataDir | Out-Null

$serviceDst = Join-Path $programFilesDir "ransomeye_service.exe"
Move-Item -Force $serviceSrc $serviceDst

if (Test-Path $buildManifestSrc) {
    Copy-Item -Force $buildManifestSrc (Join-Path $programDataDir "build_manifest.json")
}
if (Test-Path $buildManifestSigSrc) {
    Copy-Item -Force $buildManifestSigSrc (Join-Path $programDataDir "build_manifest.sig")
}

$guidBytes = [Guid]::NewGuid().ToByteArray()
[System.IO.File]::WriteAllBytes($agentIdPath, $guidBytes)

icacls $serviceDst /inheritance:r /grant:r "Administrators:RX" "SYSTEM:RX" | Out-Null
icacls $agentIdPath /inheritance:r /grant:r "Administrators:R" "SYSTEM:R" | Out-Null

if (Get-Service -Name "RansomEyeAgent" -ErrorAction SilentlyContinue) {
    Stop-Service -Name "RansomEyeAgent" -ErrorAction SilentlyContinue
    sc.exe delete RansomEyeAgent | Out-Null
    Start-Sleep -Seconds 1
}

New-Service `
    -Name "RansomEyeAgent" `
    -BinaryPathName "`"$serviceDst`"" `
    -DisplayName "RansomEye Agent" `
    -Description "RansomEye Windows service" `
    -StartupType Automatic

Write-Host "[OK] Installed ransomeye_service.exe"
Write-Host "[NOTE] Provision core_client.pfx, core_client.pfx.pass, worm_signing.key, dek.key, core_server_cert.sha256, build_manifest.json, and build_manifest.sig under $programDataDir before starting the service."
