Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Push-Location $projectRoot
try {
    $channel = [string]$env:VITE_AVIKAL_RELEASE_CHANNEL
    if ($channel.Trim().ToLowerInvariant() -eq "beta") {
        npm run package:beta
    }
    else {
        npm run package:production
    }
}
finally {
    Pop-Location
}
