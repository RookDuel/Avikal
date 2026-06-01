param(
    [string]$SourceRoot = "",
    [string]$Version = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ManifestVersion {
    param([string]$ProjectRoot, [string]$ExplicitVersion)
    if ($ExplicitVersion) {
        return $ExplicitVersion
    }
    $packageJson = Get-Content (Join-Path $ProjectRoot "package.json") -Raw | ConvertFrom-Json
    return [string]$packageJson.version
}

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

function Get-PqcRuntimePath {
    param([string]$CoreRoot)
    return (Join-Path $CoreRoot "backend-runtime\pqc\bin\openssl.exe")
}

function Get-Sha256OrThrow {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) {
        throw "Missing file for hash verification: $Path"
    }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Test-SharedCore {
    param([string]$CoreRoot, [string]$Version)
    $manifestPath = Join-Path $CoreRoot "core.json"
    $backendExe = Join-Path $CoreRoot "backend\avikal-backend.exe"
    if (-not (Test-Path $manifestPath) -or -not (Test-Path $backendExe)) {
        return $false
    }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ([string]$manifest.version -ne $Version -or [string]$manifest.platform -ne "win32") {
            return $false
        }
        if ([string]$manifest.executablePath -ne $backendExe) {
            return $false
        }
        $nativePath = Get-NativeModulePath -CoreRoot $CoreRoot
        $pqcPath = Get-PqcRuntimePath -CoreRoot $CoreRoot
        if (-not $nativePath -or -not (Test-Path $pqcPath)) {
            return $false
        }
        if ([string]$manifest.nativeModuleHash -ne (Get-Sha256OrThrow -Path $nativePath)) {
            return $false
        }
        if ([string]$manifest.pqcRuntimeHash -ne (Get-Sha256OrThrow -Path $pqcPath)) {
            return $false
        }
        & $backendExe --verify-runtime | Out-Null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Version = Get-ManifestVersion -ProjectRoot $projectRoot -ExplicitVersion $Version
if (-not $SourceRoot) {
    $SourceRoot = Join-Path $projectRoot ".app-build"
}

$sourceBackend = Join-Path $SourceRoot "backend"
$sourceRuntime = Join-Path $SourceRoot "backend-runtime"
if (-not (Test-Path $sourceBackend)) {
    throw "Missing backend bundle: $sourceBackend"
}
if (-not (Test-Path $sourceRuntime)) {
    throw "Missing backend runtime: $sourceRuntime"
}

$coreRoot = Join-Path $env:LOCALAPPDATA "RookDuel\Avikal\Core\$Version"
if (Test-SharedCore -CoreRoot $coreRoot -Version $Version) {
    Write-Host "Compatible shared Avikal core already installed at $coreRoot"
    exit 0
}

$tempRoot = "$coreRoot.tmp-$PID"
$backendExe = Join-Path $tempRoot "backend\avikal-backend.exe"

if (Test-Path $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
Copy-Item -LiteralPath $sourceBackend -Destination (Join-Path $tempRoot "backend") -Recurse -Force
Copy-Item -LiteralPath $sourceRuntime -Destination (Join-Path $tempRoot "backend-runtime") -Recurse -Force

$nativePath = Get-NativeModulePath -CoreRoot $tempRoot
$opensslPath = Get-PqcRuntimePath -CoreRoot $tempRoot
$manifest = [ordered]@{
    version = $Version
    appVersion = $Version
    platform = "win32"
    arch = $env:PROCESSOR_ARCHITECTURE
    executablePath = (Join-Path $coreRoot "backend\avikal-backend.exe")
    nativeModuleHash = Get-Sha256OrThrow -Path $nativePath
    pqcRuntimeHash = Get-Sha256OrThrow -Path $opensslPath
    archiveCompatibility = "avk-v1"
    installedAt = (Get-Date).ToUniversalTime().ToString("o")
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $tempRoot "core.json") -Encoding UTF8

& $backendExe --verify-runtime
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
    throw "Shared Avikal core verification failed."
}

if (Test-Path $coreRoot) {
    Remove-Item -LiteralPath $coreRoot -Recurse -Force
}
New-Item -ItemType Directory -Path (Split-Path $coreRoot -Parent) -Force | Out-Null
Move-Item -LiteralPath $tempRoot -Destination $coreRoot
Write-Host "Installed shared Avikal core at $coreRoot"
