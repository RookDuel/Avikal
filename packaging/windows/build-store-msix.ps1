param(
    [string]$IdentityName = $env:AVIKAL_STORE_IDENTITY_NAME,
    [string]$Publisher = $env:AVIKAL_STORE_PUBLISHER,
    [string]$PublisherDisplayName = $env:AVIKAL_STORE_PUBLISHER_DISPLAY_NAME
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($IdentityName)) {
    throw "AVIKAL_STORE_IDENTITY_NAME must match the Microsoft Partner Center product identity."
}
if ([string]::IsNullOrWhiteSpace($Publisher)) {
    throw "AVIKAL_STORE_PUBLISHER must match the Microsoft Partner Center publisher value."
}
if ([string]::IsNullOrWhiteSpace($PublisherDisplayName)) {
    throw "AVIKAL_STORE_PUBLISHER_DISPLAY_NAME is required."
}

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$packageJson = Get-Content -LiteralPath (Join-Path $projectRoot "package.json") -Raw | ConvertFrom-Json
$config = $packageJson.build
$config.artifactName = 'RookDuel-Avikal-Store.${ext}'
$config.win.target = @("appx")
$config.appx = [ordered]@{
    applicationId = "RookDuelAvikal"
    identityName = $IdentityName
    publisher = $Publisher
    publisherDisplayName = $PublisherDisplayName
    displayName = "RookDuel Avikal"
    languages = @("en-US")
    backgroundColor = "transparent"
}

$temporaryConfig = Join-Path $projectRoot ".tmp_build\electron-builder-store.json"
New-Item -ItemType Directory -Path (Split-Path $temporaryConfig -Parent) -Force | Out-Null
$config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $temporaryConfig -Encoding utf8

Push-Location $projectRoot
try {
    & (Join-Path $projectRoot "node_modules\.bin\electron-builder.cmd") --config $temporaryConfig --win appx --publish never
    if ($LASTEXITCODE -ne 0) {
        throw "Microsoft Store MSIX build failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
    Remove-Item -LiteralPath $temporaryConfig -Force -ErrorAction SilentlyContinue
}
