param(
  [string]$ZipPath,
  [string]$Url,
  [switch]$Clean
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$RuntimeRoot = Join-Path $ProjectRoot "runtime\pqc"
$DownloadsRoot = Join-Path $ProjectRoot "native\_build\downloads"

if (-not $ZipPath -and -not $Url) {
  throw "Provide -ZipPath path\to\avikal-openssl-pqc-runtime-win-x64.zip or -Url https://..."
}

if ($Url) {
  New-Item -ItemType Directory -Force -Path $DownloadsRoot | Out-Null
  $downloadName = Split-Path -Leaf ([Uri]$Url).AbsolutePath
  if (-not $downloadName) {
    $downloadName = "avikal-openssl-pqc-runtime-win-x64.zip"
  }
  $ZipPath = Join-Path $DownloadsRoot $downloadName
  Write-Host "Downloading PQC runtime artifact from $Url"
  Invoke-WebRequest -Uri $Url -OutFile $ZipPath
}

$ZipPath = (Resolve-Path -LiteralPath $ZipPath).Path
if ($Clean -and (Test-Path -LiteralPath $RuntimeRoot)) {
  Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $RuntimeRoot | Out-Null
$tempExtract = Join-Path ([System.IO.Path]::GetTempPath()) ("avikal-pqc-runtime-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempExtract | Out-Null
try {
  Expand-Archive -LiteralPath $ZipPath -DestinationPath $tempExtract -Force
  $opensslCandidates = Get-ChildItem -LiteralPath $tempExtract -Recurse -Force -File -Filter "openssl.exe"
  if (-not $opensslCandidates) {
    throw "Runtime artifact does not contain openssl.exe"
  }

  $artifactRoot = $opensslCandidates[0].Directory.Parent.FullName
  if ((Split-Path -Leaf $opensslCandidates[0].Directory.FullName) -ne "bin") {
    $artifactRoot = $opensslCandidates[0].Directory.FullName
  }

  Copy-Item -LiteralPath (Join-Path $artifactRoot "*") -Destination $RuntimeRoot -Recurse -Force

  $opensslExe = Join-Path $RuntimeRoot "bin\openssl.exe"
  if (-not (Test-Path -LiteralPath $opensslExe)) {
    $flatOpenSsl = Join-Path $RuntimeRoot "openssl.exe"
    if (-not (Test-Path -LiteralPath $flatOpenSsl)) {
      throw "Installed runtime does not contain bin\openssl.exe or openssl.exe"
    }
    $opensslExe = $flatOpenSsl
  }

  $versionOutput = & $opensslExe version
  Write-Host "Installed Avikal PQC runtime at $RuntimeRoot"
  Write-Host $versionOutput
} finally {
  Remove-Item -LiteralPath $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
}
