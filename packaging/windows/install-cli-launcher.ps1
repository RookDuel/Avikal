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

& (Join-Path $PSScriptRoot "verify-shared-core.ps1") -Version $Version
if ($LASTEXITCODE -ne 0) {
    throw "Install or verify the shared Avikal core before creating the CLI launcher."
}

$coreRoot = Join-Path $env:LOCALAPPDATA "RookDuel\Avikal\Core\$Version"
$backendExe = Join-Path $coreRoot "backend\avikal-backend.exe"
if (-not (Test-Path $backendExe)) {
    throw "Missing shared Avikal core executable: $backendExe"
}

$launcherRoot = Join-Path $env:LOCALAPPDATA "Programs\RookDuel Avikal CLI"
New-Item -ItemType Directory -Path $launcherRoot -Force | Out-Null
$launcherPath = Join-Path $launcherRoot "avikal.cmd"
@"
@echo off
"$backendExe" %*
"@ | Set-Content -LiteralPath $launcherPath -Encoding ASCII

Write-Host "Installed Avikal CLI launcher at $launcherPath"
Write-Host "Add $launcherRoot to PATH if it is not already present."
