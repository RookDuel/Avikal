param(
  [string]$Version = "3.5.6",
  [switch]$Clean,
  [switch]$RunTests
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$BuildRoot = Join-Path $ProjectRoot "native\_build"
$DownloadsRoot = Join-Path $BuildRoot "downloads"
$SourceRoot = Join-Path $BuildRoot "src"
$RuntimeRoot = Join-Path $ProjectRoot "runtime\pqc"
$ArchiveName = "openssl-$Version.tar.gz"
$SourceUrl = "https://github.com/openssl/openssl/releases/download/openssl-$Version/$ArchiveName"
$Sha256Url = "$SourceUrl.sha256"
$ArchivePath = Join-Path $DownloadsRoot $ArchiveName
$Sha256Path = Join-Path $DownloadsRoot "$ArchiveName.sha256"
$ExtractedSource = Join-Path $SourceRoot "openssl-$Version"

function Find-VcVars64 {
  $candidates = @(
    "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "$env:ProgramFiles\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    "$env:ProgramFiles\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
    "$env:ProgramFiles\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
  )
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) {
      return $candidate
    }
  }
  throw "Could not find Visual Studio vcvars64.bat. Install Visual Studio Build Tools 2022 with C++ tools."
}

function Ensure-Tool($Name) {
  $tool = Get-Command $Name -ErrorAction SilentlyContinue
  if (-not $tool) {
    throw "Required tool not found on PATH: $Name"
  }
  return $tool.Source
}

function Read-Sha256FromFile($Path) {
  $content = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
  $match = [regex]::Match($content, "[A-Fa-f0-9]{64}")
  if (-not $match.Success) {
    throw "Could not parse SHA256 from $Path"
  }
  return $match.Value.ToUpperInvariant()
}

if ($Clean -and (Test-Path -LiteralPath $BuildRoot)) {
  Remove-Item -LiteralPath $BuildRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $DownloadsRoot, $SourceRoot, $RuntimeRoot | Out-Null

$vcvars64 = Find-VcVars64
Ensure-Tool "perl.exe" | Out-Null
Ensure-Tool "nasm.exe" | Out-Null

if (-not (Test-Path -LiteralPath $ArchivePath)) {
  Write-Host "Downloading $SourceUrl"
  Invoke-WebRequest -Uri $SourceUrl -OutFile $ArchivePath
}

if (-not (Test-Path -LiteralPath $Sha256Path)) {
  Write-Host "Downloading $Sha256Url"
  Invoke-WebRequest -Uri $Sha256Url -OutFile $Sha256Path
}

$expectedSha256 = Read-Sha256FromFile $Sha256Path
$actualSha256 = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actualSha256 -ne $expectedSha256) {
  throw "OpenSSL archive SHA256 mismatch. Expected $expectedSha256 but got $actualSha256"
}
Write-Host "Verified $ArchiveName SHA256: $actualSha256"

if ($Clean -and (Test-Path -LiteralPath $ExtractedSource)) {
  Remove-Item -LiteralPath $ExtractedSource -Recurse -Force
}

if (-not (Test-Path -LiteralPath $ExtractedSource)) {
  Write-Host "Extracting $ArchiveName"
  tar -xzf $ArchivePath -C $SourceRoot
} else {
  Write-Host "Reusing existing source tree at $ExtractedSource"
}

if ($Clean -and (Test-Path -LiteralPath $RuntimeRoot)) {
  Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $RuntimeRoot | Out-Null

$cmdPath = Join-Path $BuildRoot "build-openssl-$Version.cmd"
$configureArgs = "VC-WIN64A no-tests no-docs no-legacy --prefix=`"$RuntimeRoot`" --openssldir=`"$RuntimeRoot\ssl`""
$testCommand = if ($RunTests) { "nmake test" } else { "echo Skipping OpenSSL test suite" }

$cmd = @"
@echo off
setlocal
call "$vcvars64"
if errorlevel 1 exit /b %errorlevel%
set "PATH=C:\Strawberry\perl\bin;C:\Strawberry\c\bin;%PATH%"
cd /d "$ExtractedSource"
perl Configure $configureArgs
if errorlevel 1 exit /b %errorlevel%
nmake
if errorlevel 1 exit /b %errorlevel%
$testCommand
if errorlevel 1 exit /b %errorlevel%
nmake install_sw
if errorlevel 1 exit /b %errorlevel%
endlocal
"@
Set-Content -LiteralPath $cmdPath -Value $cmd -Encoding ASCII

Write-Host "Building OpenSSL $Version for Windows x64"
& cmd.exe /c $cmdPath
if ($LASTEXITCODE -ne 0) {
  throw "OpenSSL build failed with exit code $LASTEXITCODE"
}

$opensslExe = Join-Path $RuntimeRoot "bin\openssl.exe"
if (-not (Test-Path -LiteralPath $opensslExe)) {
  throw "OpenSSL build did not produce $opensslExe"
}

$versionOutput = & $opensslExe version
$manifest = [ordered]@{
  version = $Version
  source_url = $SourceUrl
  sha256 = $actualSha256
  built_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  openssl_version = $versionOutput
  runtime_root = $RuntimeRoot
}
$manifestPath = Join-Path $RuntimeRoot "avikal-openssl-runtime.json"
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Prepared OpenSSL PQC runtime at $RuntimeRoot"
Write-Host $versionOutput
