param(
    [string]$Version = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-NativeModulePath {
    param([string]$CoreRoot)
    $candidates = @(
        (Join-Path $CoreRoot "backend\_internal\avikal_backend\_native.pyd"),
        (Join-Path $CoreRoot "backend\avikal_backend\_native.pyd")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    return $null
}

function Get-Sha256OrThrow {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) {
        throw "Missing file for hash verification: $Path"
    }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
if (-not $Version) {
    $packageJson = Get-Content (Join-Path $projectRoot "package.json") -Raw | ConvertFrom-Json
    $Version = [string]$packageJson.version
}

$coreRoot = Join-Path $env:LOCALAPPDATA "RookDuel\Avikal\Core\$Version"
$manifestPath = Join-Path $coreRoot "core.json"
$backendExe = Join-Path $coreRoot "backend\avikal-backend.exe"
$opensslPath = Join-Path $coreRoot "backend-runtime\pqc\bin\openssl.exe"
$nativePath = Get-NativeModulePath -CoreRoot $coreRoot

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
if ([string]$manifest.platform -ne "win32") {
    throw "Shared Avikal core platform mismatch. Expected win32, got $($manifest.platform)."
}
if ([string]$manifest.executablePath -ne $backendExe) {
    throw "Shared Avikal core executable path mismatch."
}
if ([string]$manifest.nativeModuleHash -ne (Get-Sha256OrThrow -Path $nativePath)) {
    throw "Shared Avikal core native module hash mismatch."
}
if ([string]$manifest.pqcRuntimeHash -ne (Get-Sha256OrThrow -Path $opensslPath)) {
    throw "Shared Avikal core PQC runtime hash mismatch."
}

& $backendExe --verify-runtime
if ($LASTEXITCODE -ne 0) {
    throw "Shared Avikal core runtime verification failed."
}

Write-Host "Shared Avikal core verified at $coreRoot"
