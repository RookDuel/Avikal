param(
    [string]$Version = "",
    [switch]$SkipRuntimeBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ProjectVersion {
    param([string]$ProjectRoot, [string]$ExplicitVersion)
    if ($ExplicitVersion) {
        return $ExplicitVersion
    }
    $packageJson = Get-Content (Join-Path $ProjectRoot "package.json") -Raw | ConvertFrom-Json
    return [string]$packageJson.version
}

function Copy-RequiredDirectory {
    param([string]$Source, [string]$Destination)
    if (-not (Test-Path -LiteralPath $Source)) {
        throw "Missing required directory: $Source"
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

function Get-Sha256Hex {
    param([string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash($stream)
            return ([System.BitConverter]::ToString($hashBytes) -replace "-", "").ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Resolve-Makensis {
    $command = Get-Command makensis.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "NSIS\makensis.exe"),
        (Join-Path $env:ProgramFiles "NSIS\makensis.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $electronBuilderNsis = Join-Path $env:LOCALAPPDATA "electron-builder\Cache\nsis"
    if (Test-Path -LiteralPath $electronBuilderNsis) {
        $cached = Get-ChildItem -LiteralPath $electronBuilderNsis -Recurse -Filter "makensis.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName |
            Select-Object -First 1
        if ($cached) {
            return $cached.FullName
        }
    }

    throw "NSIS makensis.exe was not found. Install NSIS before building the CLI installer."
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Version = Get-ProjectVersion -ProjectRoot $projectRoot -ExplicitVersion $Version

Push-Location $projectRoot
try {
    if (-not $SkipRuntimeBuild) {
        npm run build:runtime
        if ($LASTEXITCODE -ne 0) {
            throw "Runtime build failed."
        }
        npm run sign:runtime
        if ($LASTEXITCODE -ne 0) {
            throw "Runtime signing failed."
        }
    }

    $backendBundle = Join-Path $projectRoot ".app-build\backend"
    $backendRuntime = Join-Path $projectRoot ".app-build\backend-runtime"
    if (-not (Test-Path -LiteralPath (Join-Path $backendBundle "avikal-backend.exe"))) {
        throw "Missing packaged backend executable. Run npm run build:runtime first."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $backendRuntime "pqc\bin\openssl.exe"))) {
        throw "Missing bundled OpenSSL PQC runtime. Build or install runtime\pqc before packaging CLI."
    }

    $distRoot = Join-Path $projectRoot "dist"
    $workRoot = Join-Path $projectRoot ".tmp_build\windows-cli-installer"
    $payloadRoot = Join-Path $workRoot "payload"
    $installerPath = Join-Path $distRoot "RookDuel-Avikal-CLI.exe"
    $nsiPath = Join-Path $projectRoot "packaging\windows\avikal-cli-installer.nsi"

    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $distRoot -Force | Out-Null

    Copy-RequiredDirectory -Source $backendBundle -Destination (Join-Path $payloadRoot "backend")
    Copy-RequiredDirectory -Source $backendRuntime -Destination (Join-Path $payloadRoot "backend-runtime")

    if (Test-Path -LiteralPath $installerPath) {
        Remove-Item -LiteralPath $installerPath -Force
    }

    $makensis = Resolve-Makensis
    & $makensis `
        "/V2" `
        "/DOUTPUT_FILE=$installerPath" `
        "/DPAYLOAD_ROOT=$payloadRoot" `
        "/DAPP_VERSION=$Version" `
        $nsiPath
    if ($LASTEXITCODE -ne 0) {
        throw "NSIS CLI installer build failed."
    }
    if (-not (Test-Path -LiteralPath $installerPath)) {
        throw "NSIS CLI installer was not produced: $installerPath"
    }

    $hash = Get-Sha256Hex -Path $installerPath
    "$hash *$(Split-Path -Leaf $installerPath)" | Set-Content -LiteralPath "$installerPath.sha256" -NoNewline

    $metadata = [ordered]@{
        product_version = $Version
        installer_name = [System.IO.Path]::GetFileName($installerPath)
        installer_sha256 = $hash
        payload_format = "nsis-local-installer"
        install_layout = "direct-cli-runtime"
        installs_shared_core = $false
        installs_cli_launcher = $true
    }
    $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $distRoot "avikal-cli-release-metadata.json")

    Write-Host "Built self-contained NSIS Avikal CLI installer at $installerPath"
}
finally {
    Pop-Location
}
