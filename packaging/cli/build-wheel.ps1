Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$python = Join-Path $projectRoot "backend\venv\Scripts\python.exe"
$wheelDir = Join-Path $projectRoot "dist\cli"
$sourceDrandRuntime = Join-Path $projectRoot "backend\scripts"
$packagedDrandRuntime = Join-Path $projectRoot "backend\src\avikal_backend\runtime\scripts"

New-Item -ItemType Directory -Path $wheelDir -Force | Out-Null

Push-Location $projectRoot
try {
    $env:AVIKAL_REQUIRE_BUNDLED_PQC_RUNTIME = "1"
    if (-not (Test-Path (Join-Path $sourceDrandRuntime "node_modules\tlock-js"))) {
        Push-Location $sourceDrandRuntime
        try {
            npm ci
        }
        finally {
            Pop-Location
        }
    }
    New-Item -ItemType Directory -Path $packagedDrandRuntime -Force | Out-Null
    Copy-Item -Path (Join-Path $sourceDrandRuntime "drand_timelock_helper.mjs") -Destination $packagedDrandRuntime -Force
    Copy-Item -Path (Join-Path $sourceDrandRuntime "package.json") -Destination $packagedDrandRuntime -Force
    Copy-Item -Path (Join-Path $sourceDrandRuntime "package-lock.json") -Destination $packagedDrandRuntime -Force
    Copy-Item -Path (Join-Path $sourceDrandRuntime "node_modules") -Destination $packagedDrandRuntime -Recurse -Force
    & $python -m pip install -r .\backend\requirements-build.txt
    & $python -m pip wheel .\backend --wheel-dir $wheelDir
}
finally {
    if (Test-Path $packagedDrandRuntime) {
        Remove-Item -LiteralPath $packagedDrandRuntime -Recurse -Force
    }
    Remove-Item Env:\AVIKAL_REQUIRE_BUNDLED_PQC_RUNTIME -ErrorAction SilentlyContinue
    Pop-Location
}
