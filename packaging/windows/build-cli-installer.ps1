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
    $payloadZip = Join-Path $workRoot "avikal-cli-payload.zip"
    $installerPath = Join-Path $distRoot "RookDuel Avikal CLI-beta.exe"
    $markerText = "AVIKAL_CLI_INSTALLER_PAYLOAD_V1"

    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $distRoot -Force | Out-Null

    Copy-RequiredDirectory -Source $backendBundle -Destination (Join-Path $payloadRoot "backend")
    Copy-RequiredDirectory -Source $backendRuntime -Destination (Join-Path $payloadRoot "backend-runtime")
    Copy-RequiredDirectory -Source (Join-Path $projectRoot "packaging\windows") -Destination (Join-Path $payloadRoot "packaging\windows")
    Copy-Item -LiteralPath (Join-Path $projectRoot "package.json") -Destination (Join-Path $payloadRoot "package.json") -Force

    Compress-Archive -Path (Join-Path $payloadRoot "*") -DestinationPath $payloadZip -Force

    if (Test-Path -LiteralPath $installerPath) {
        Remove-Item -LiteralPath $installerPath -Force
    }

    $escapedMarker = $markerText
    $source = @"
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;

public static class AvikalCliInstaller
{
    private const string MarkerText = "$escapedMarker";

    public static int Main(string[] args)
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "avikal-cli-installer-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tempRoot);
            string exePath = Process.GetCurrentProcess().MainModule.FileName;
            byte[] allBytes = File.ReadAllBytes(exePath);
            byte[] marker = Encoding.ASCII.GetBytes(MarkerText);
            if (allBytes.Length < marker.Length + 8)
            {
                throw new InvalidOperationException("Installer payload marker is missing.");
            }

            int markerOffset = allBytes.Length - marker.Length;
            for (int i = 0; i < marker.Length; i++)
            {
                if (allBytes[markerOffset + i] != marker[i])
                {
                    throw new InvalidOperationException("Installer payload marker is invalid.");
                }
            }

            long payloadLength = BitConverter.ToInt64(allBytes, markerOffset - 8);
            long payloadOffset = markerOffset - 8 - payloadLength;
            if (payloadLength <= 0 || payloadOffset < 0)
            {
                throw new InvalidOperationException("Installer payload length is invalid.");
            }

            string zipPath = Path.Combine(tempRoot, "payload.zip");
            using (FileStream output = File.Create(zipPath))
            {
                output.Write(allBytes, (int)payloadOffset, (int)payloadLength);
            }

            string extractRoot = Path.Combine(tempRoot, "payload");
            ZipFile.ExtractToDirectory(zipPath, extractRoot);
            string installCore = Path.Combine(extractRoot, "packaging", "windows", "install-shared-core.ps1");
            string installLauncher = Path.Combine(extractRoot, "packaging", "windows", "install-cli-launcher.ps1");

            RunPowerShell(installCore, "-SourceRoot", Quote(extractRoot));
            RunPowerShell(installLauncher);

            Console.WriteLine("Avikal CLI installation completed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Avikal CLI installation failed: " + ex.Message);
            return 1;
        }
        finally
        {
            try { Directory.Delete(tempRoot, true); } catch { }
        }
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }

    private static void RunPowerShell(string scriptPath, params string[] extraArgs)
    {
        string arguments = "-NoProfile -ExecutionPolicy Bypass -File " + Quote(scriptPath);
        if (extraArgs != null && extraArgs.Length > 0)
        {
            arguments += " " + string.Join(" ", extraArgs);
        }

        ProcessStartInfo startInfo = new ProcessStartInfo("powershell.exe", arguments);
        startInfo.UseShellExecute = false;
        Process process = Process.Start(startInfo);
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException("Installer script failed: " + Path.GetFileName(scriptPath));
        }
    }
}
"@

    Add-Type `
        -TypeDefinition $source `
        -Language CSharp `
        -OutputAssembly $installerPath `
        -OutputType ConsoleApplication `
        -ReferencedAssemblies @("System.IO.Compression.dll", "System.IO.Compression.FileSystem.dll")

    $payloadStream = [System.IO.File]::OpenRead($payloadZip)
    $installerStream = [System.IO.File]::Open($installerPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
    try {
        $payloadStream.CopyTo($installerStream)
        $lengthBytes = [System.BitConverter]::GetBytes([Int64]$payloadStream.Length)
        $markerBytes = [System.Text.Encoding]::ASCII.GetBytes($markerText)
        $installerStream.Write($lengthBytes, 0, $lengthBytes.Length)
        $installerStream.Write($markerBytes, 0, $markerBytes.Length)
    }
    finally {
        $installerStream.Dispose()
        $payloadStream.Dispose()
    }

    $hash = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash *$(Split-Path -Leaf $installerPath)" | Set-Content -LiteralPath "$installerPath.sha256" -NoNewline

    $metadata = [ordered]@{
        product_version = $Version
        installer_name = [System.IO.Path]::GetFileName($installerPath)
        installer_sha256 = $hash
        payload_format = "embedded-zip"
        installs_shared_core = $true
        installs_cli_launcher = $true
    }
    $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $distRoot "avikal-cli-release-metadata.json")

    Write-Host "Built self-contained Avikal CLI installer at $installerPath"
}
finally {
    Pop-Location
}
