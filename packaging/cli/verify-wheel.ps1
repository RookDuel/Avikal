Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$python = Join-Path $projectRoot "backend\venv\Scripts\python.exe"
$wheelDir = Join-Path $projectRoot "dist\cli"
$verifyRoot = Join-Path $projectRoot ".tmp_build\cli-wheel-verify"
$verifyVenv = Join-Path $verifyRoot "venv"

New-Item -ItemType Directory -Path $wheelDir -Force | Out-Null
if (Test-Path $verifyRoot) {
    Remove-Item -LiteralPath $verifyRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $verifyRoot -Force | Out-Null

$wheel = Get-ChildItem -Path $wheelDir -Filter "avikal-*.whl" | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if (-not $wheel) {
    throw "No Avikal wheel found in $wheelDir. Run packaging/cli/build-wheel.ps1 first."
}

Push-Location $projectRoot
try {
    & $python -m venv $verifyVenv
    $verifyPython = Join-Path $verifyVenv "Scripts\python.exe"
    $verifyAvikal = Join-Path $verifyVenv "Scripts\avikal.exe"

    & $verifyPython -m pip install --upgrade pip
    & $verifyPython -m pip install $wheel.FullName
    & $verifyPython -c "from avikal_backend.runtime_requirements import ensure_native_crypto_runtime; ensure_native_crypto_runtime('CLI wheel verification')"
    & $verifyAvikal doctor --json
}
finally {
    Pop-Location
}
