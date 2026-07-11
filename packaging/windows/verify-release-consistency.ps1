param(
    [string]$ReleaseTag = "",
    [switch]$SkipArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Normalize-Version {
    param([string]$Value)
    return ([string]$Value).Trim() -replace '^v', ''
}

function Assert-Equal {
    param([string]$Name, [string]$Actual, [string]$Expected)
    if ($Actual -ne $Expected) {
        throw "$Name mismatch. Expected '$Expected' but found '$Actual'."
    }
}

function Read-JsonFieldWithNode {
    param([string]$JsonPath, [string]$Expression)
    $script = "const data=require(process.argv[1]); const value=($Expression); if (value === undefined || value === null) process.exit(2); console.log(String(value));"
    $value = & node -e $script $JsonPath
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read JSON field from $JsonPath using expression: $Expression"
    }
    return [string]$value
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$backendVersionFile = Get-Content -LiteralPath (Join-Path $projectRoot "backend\src\avikal_backend\version.py") -Raw

$packageJsonPath = Join-Path $projectRoot "package.json"
$packageLockPath = Join-Path $projectRoot "package-lock.json"
$packageVersion = Normalize-Version (Read-JsonFieldWithNode -JsonPath $packageJsonPath -Expression "data.version")
$lockVersion = Normalize-Version (Read-JsonFieldWithNode -JsonPath $packageLockPath -Expression "data.version")
$rootLockVersion = Normalize-Version (Read-JsonFieldWithNode -JsonPath $packageLockPath -Expression "data.packages[''].version")

if ($backendVersionFile -notmatch '__version__\s*=\s*"([^"]+)"') {
    throw "Could not read backend __version__."
}
$backendVersion = Normalize-Version $Matches[1]

Assert-Equal -Name "package-lock version" -Actual $lockVersion -Expected $packageVersion
Assert-Equal -Name "package-lock root package version" -Actual $rootLockVersion -Expected $packageVersion
Assert-Equal -Name "backend version" -Actual $backendVersion -Expected $packageVersion

if ($ReleaseTag) {
    $tagVersion = Normalize-Version $ReleaseTag
    Assert-Equal -Name "release tag version" -Actual $tagVersion -Expected $packageVersion
}

$distRoot = Join-Path $projectRoot "dist"
$guiInstaller = Join-Path $distRoot "RookDuel-Avikal.exe"
$cliInstaller = Join-Path $distRoot "RookDuel-Avikal-CLI.exe"
$releaseMetadataPath = Join-Path $distRoot "avikal-release-metadata.json"
$cliMetadataPath = Join-Path $distRoot "avikal-cli-release-metadata.json"

if ($SkipArtifacts) {
    Write-Host "Version consistency verified for Avikal $packageVersion."
    return
}

foreach ($requiredPath in @($guiInstaller, "$guiInstaller.sha256", $cliInstaller, "$cliInstaller.sha256", $releaseMetadataPath, $cliMetadataPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Missing required release artifact: $requiredPath"
    }
}

$metadata = Get-Content -LiteralPath $releaseMetadataPath -Raw | ConvertFrom-Json
Assert-Equal -Name "release metadata product_version" -Actual (Normalize-Version $metadata.product_version) -Expected $packageVersion
Assert-Equal -Name "release metadata GUI installer name" -Actual ([string]$metadata.gui_installer_name) -Expected (Split-Path -Leaf $guiInstaller)
Assert-Equal -Name "release metadata CLI installer name" -Actual ([string]$metadata.cli_installer_name) -Expected (Split-Path -Leaf $cliInstaller)

$guiHash = (Get-FileHash -LiteralPath $guiInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
$cliHash = (Get-FileHash -LiteralPath $cliInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
Assert-Equal -Name "GUI installer hash" -Actual ([string]$metadata.gui_installer_sha256).ToLowerInvariant() -Expected $guiHash
Assert-Equal -Name "CLI installer hash" -Actual ([string]$metadata.cli_installer_sha256).ToLowerInvariant() -Expected $cliHash

if ((Get-Item -LiteralPath $guiInstaller).Length -lt 50MB) {
    throw "GUI installer is too small to be a bundled local installer."
}
if ((Get-Item -LiteralPath $cliInstaller).Length -lt 25MB) {
    throw "CLI installer is too small to be a bundled local installer."
}

Write-Host "Release consistency verified for Avikal $packageVersion."
