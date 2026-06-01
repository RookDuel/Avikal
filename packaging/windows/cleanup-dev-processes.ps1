Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$escapedRoot = [Regex]::Escape($projectRoot)

$processTable = @{}
Get-CimInstance Win32_Process | ForEach-Object {
    $processTable[[int]$_.ProcessId] = $_
}

$protectedIds = New-Object System.Collections.Generic.HashSet[int]
$cursor = [int]$PID
while ($cursor -gt 0 -and $processTable.ContainsKey($cursor)) {
    if (-not $protectedIds.Add($cursor)) {
        break
    }
    $cursor = [int]$processTable[$cursor].ParentProcessId
}

$killable = Get-CimInstance Win32_Process | Where-Object {
    $name = $_.Name.ToLowerInvariant()
    $exePath = if ($_.ExecutablePath) { $_.ExecutablePath } else { "" }
    $commandLine = if ($_.CommandLine) { $_.CommandLine } else { "" }
    $matchesWorkspace = ($exePath -like "$projectRoot*") -or ($commandLine -match $escapedRoot)
    $interesting = $name -in @("electron.exe", "python.exe", "node.exe", "cmd.exe")

    $interesting -and $matchesWorkspace -and (-not $protectedIds.Contains([int]$_.ProcessId))
}

foreach ($process in $killable) {
    try {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to stop process $($process.ProcessId) ($($process.Name)): $($_.Exception.Message)"
    }
}
