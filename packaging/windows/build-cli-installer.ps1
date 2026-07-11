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

function ConvertTo-NsisString {
    param([string]$Value)
    return ($Value -replace '"', '$\"')
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Version = Get-ProjectVersion -ProjectRoot $projectRoot -ExplicitVersion $Version

Push-Location $projectRoot
try {
    if (-not $SkipRuntimeBuild) {
        npm run build:runtime
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
    $nsiPath = Join-Path $workRoot "avikal-cli-installer.nsi"

    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $distRoot -Force | Out-Null

    Copy-RequiredDirectory -Source $backendBundle -Destination (Join-Path $payloadRoot "backend")
    Copy-RequiredDirectory -Source $backendRuntime -Destination (Join-Path $payloadRoot "backend-runtime")
    Copy-RequiredDirectory -Source (Join-Path $projectRoot "packaging\windows") -Destination (Join-Path $payloadRoot "packaging\windows")
    Copy-Item -LiteralPath (Join-Path $projectRoot "package.json") -Destination (Join-Path $payloadRoot "package.json") -Force

    if (Test-Path -LiteralPath $installerPath) {
        Remove-Item -LiteralPath $installerPath -Force
    }

    $payloadRootForNsis = ConvertTo-NsisString -Value $payloadRoot
    $installerPathForNsis = ConvertTo-NsisString -Value $installerPath
    $versionForNsis = ConvertTo-NsisString -Value $Version
    $nsisScript = @"
Unicode true
RequestExecutionLevel user
Name "RookDuel-Avikal CLI"
OutFile "$installerPathForNsis"
InstallDir "`$LOCALAPPDATA\Programs\RookDuel-Avikal CLI"
BrandingText "RookDuel-Avikal CLI"
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "`$INSTDIR\payload"
  File /r "$payloadRootForNsis\*.*"

  DetailPrint "Installing shared Avikal core..."
  ExecWait '"`$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "`$INSTDIR\payload\packaging\windows\install-shared-core.ps1" -SourceRoot "`$INSTDIR\payload" -Version "$versionForNsis"' `$0
  `${If} `$0 != "0"
    MessageBox MB_ICONSTOP "Shared Avikal core installation failed."
    Abort
  `${EndIf}

  DetailPrint "Installing Avikal CLI launcher..."
  ExecWait '"`$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "`$INSTDIR\payload\packaging\windows\install-cli-launcher.ps1" -Version "$versionForNsis"' `$0
  `${If} `$0 != "0"
    MessageBox MB_ICONSTOP "Avikal CLI launcher installation failed."
    Abort
  `${EndIf}

  WriteUninstaller "`$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "DisplayName" "RookDuel-Avikal CLI"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "DisplayVersion" "$versionForNsis"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "Publisher" "RookDuel"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "InstallLocation" "`$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "DisplayIcon" "`$INSTDIR\payload\backend\avikal-backend.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "UninstallString" '"`$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "`$INSTDIR\avikal.cmd"
  Delete "`$INSTDIR\Uninstall.exe"
  RMDir /r "`$INSTDIR\payload"
  RMDir "`$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI"
SectionEnd
"@

    $nsisScript | Set-Content -LiteralPath $nsiPath -Encoding UTF8
    $makensis = Resolve-Makensis
    & $makensis "/V2" $nsiPath
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
        installs_shared_core = $true
        installs_cli_launcher = $true
    }
    $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $distRoot "avikal-cli-release-metadata.json")

    Write-Host "Built self-contained NSIS Avikal CLI installer at $installerPath"
}
finally {
    Pop-Location
}
