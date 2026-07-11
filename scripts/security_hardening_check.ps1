param(
  [switch]$SkipFrontend,
  [switch]$SkipBackend,
  [switch]$SkipRust
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

function Invoke-Step {
  param(
    [string]$Name,
    [scriptblock]$Command
  )
  Write-Host ""
  Write-Host "==> $Name" -ForegroundColor Cyan
  & $Command
}

function Invoke-Checked {
  param(
    [Parameter(Mandatory = $true)]
    [scriptblock]$Command
  )
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code $LASTEXITCODE"
  }
}

if (-not $SkipRust) {
  Invoke-Step "Rust native tests" {
    Push-Location "$root\backend\native\avikal_backend_native"
    try {
      Invoke-Checked { cargo test }
    } finally {
      Pop-Location
    }
  }
}

if (-not $SkipBackend) {
  Invoke-Step "Backend focused security tests" {
    Push-Location $root
    try {
      $baseTemp = Join-Path $root ".pytest-hardening-tmp"
      if (Test-Path $baseTemp) {
        Remove-Item -Recurse -Force $baseTemp
      }
      New-Item -ItemType Directory -Force $baseTemp | Out-Null
      Invoke-Checked { .\backend\venv\Scripts\python.exe -m pytest --basetemp $baseTemp `
        backend\tests\test_native_crypto.py `
        backend\tests\test_archive_security_guards.py `
        backend\tests\test_archive_fuzz_smoke.py `
        backend\tests\test_assured_archive_features.py `
        backend\tests\test_pqc_keychain_integrity.py `
        backend\tests\test_payload_streaming_native.py }
    } finally {
      Pop-Location
    }
  }
}

if (-not $SkipFrontend) {
  Invoke-Step "Frontend type and build check" {
    Push-Location "$root\frontend"
    try {
      Invoke-Checked { npm run build:check }
    } finally {
      Pop-Location
    }
  }
}

Invoke-Step "Electron syntax check" {
  Push-Location $root
  try {
    Invoke-Checked { node --check electron\main.js }
    Invoke-Checked { node --check electron\preload.js }
    Invoke-Checked { node --check scripts\afterPack.js }
  } finally {
    Pop-Location
  }
}

Write-Host ""
Write-Host "Security hardening checks completed." -ForegroundColor Green
