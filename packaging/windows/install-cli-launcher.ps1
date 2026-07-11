param(
    [string]$Version = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
if (-not $Version) {
    $packageJson = Get-Content (Join-Path $projectRoot "package.json") -Raw | ConvertFrom-Json
    $Version = [string]$packageJson.version
}

$coreRoot = Join-Path $env:LOCALAPPDATA "RookDuel\Avikal\Core\$Version"
$manifestPath = Join-Path $coreRoot "core.json"
$backendExe = Join-Path $coreRoot "backend\avikal-backend.exe"
if (-not (Test-Path $manifestPath)) {
    throw "Missing shared Avikal core manifest: $manifestPath"
}
if (-not (Test-Path $backendExe)) {
    throw "Missing shared Avikal core executable: $backendExe"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ([string]$manifest.version -ne $Version) {
    throw "Shared Avikal core version mismatch. Expected $Version, got $($manifest.version)."
}
if ([string]$manifest.executablePath -ne $backendExe) {
    throw "Shared Avikal core executable path mismatch."
}

$launcherRoot = Join-Path $env:LOCALAPPDATA "Programs\RookDuel-Avikal CLI"
New-Item -ItemType Directory -Path $launcherRoot -Force | Out-Null
$launcherPath = Join-Path $launcherRoot "avikal.cmd"
@"
@echo off
"$backendExe" %*
"@ | Set-Content -LiteralPath $launcherPath -Encoding ASCII

Write-Host "Installed Avikal CLI launcher at $launcherPath"
Write-Host "Add $launcherRoot to PATH if it is not already present."
