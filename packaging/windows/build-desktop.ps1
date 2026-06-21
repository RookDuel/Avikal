Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Push-Location $projectRoot
try {
    $channel = [string]$env:VITE_AVIKAL_RELEASE_CHANNEL
    if ($channel.Trim().ToLowerInvariant() -eq "production") {
        npm run package:production
    }
    else {
        npm run package:beta
    }
}
finally {
    Pop-Location
}
