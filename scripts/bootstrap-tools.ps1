# Install Trivy, Grype, Syft and Dive into .\.tools\bin on Windows.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\bootstrap-tools.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\bootstrap-tools.ps1 -Tools trivy,grype -Force
param(
    [string]$Dir = "",
    [string]$Tools = "trivy,grype,syft,dive",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Dir) { $Dir = Join-Path $Root ".tools\bin" }
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$archArm = $env:PROCESSOR_ARCHITECTURE -match "ARM64"
if ($archArm) { $arch = "arm64" }

function Get-LatestVersion([string]$Repo) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "layersecops-bootstrap" }
    return $release.tag_name.TrimStart("v")
}

function Install-Tool([string]$Name, [string]$Version, [string]$Url) {
    $target = Join-Path $Dir "$Name.exe"
    if ((Test-Path $target) -and -not $Force) {
        Write-Host "  $Name`: already installed at $target"
        return
    }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("layersecops-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        $zip = Join-Path $tmp "archive.zip"
        Write-Host "  $Name`: downloading $Url"
        Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $binary = Get-ChildItem -Path $tmp -Recurse -Filter "$Name.exe" | Select-Object -First 1
        if (-not $binary) { throw "Could not find $Name.exe in the downloaded archive" }
        Copy-Item $binary.FullName $target -Force
        Write-Host "  $Name`: installed $Version at $target"
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

Write-Host "Installing tools into $Dir (windows/$arch)"
foreach ($tool in ($Tools -split ",")) {
    $name = $tool.Trim().ToLower()
    switch ($name) {
        "trivy" {
            $v = if ($env:TRIVY_VERSION) { $env:TRIVY_VERSION } else { Get-LatestVersion "aquasecurity/trivy" }
            $assetArch = if ($arch -eq "arm64") { "ARM64" } else { "64bit" }
            Install-Tool "trivy" $v "https://github.com/aquasecurity/trivy/releases/download/v$v/trivy_${v}_Windows-${assetArch}.zip"
        }
        "grype" {
            $v = if ($env:GRYPE_VERSION) { $env:GRYPE_VERSION } else { Get-LatestVersion "anchore/grype" }
            Install-Tool "grype" $v "https://github.com/anchore/grype/releases/download/v$v/grype_${v}_windows_${arch}.zip"
        }
        "syft" {
            $v = if ($env:SYFT_VERSION) { $env:SYFT_VERSION } else { Get-LatestVersion "anchore/syft" }
            Install-Tool "syft" $v "https://github.com/anchore/syft/releases/download/v$v/syft_${v}_windows_${arch}.zip"
        }
        "dive" {
            $v = if ($env:DIVE_VERSION) { $env:DIVE_VERSION } else { Get-LatestVersion "wagoodman/dive" }
            Install-Tool "dive" $v "https://github.com/wagoodman/dive/releases/download/v$v/dive_${v}_windows_${arch}.zip"
        }
        default { throw "Unknown tool: $name" }
    }
}

Write-Host ""
Write-Host "Done. Use .\.tools\bin\trivy.exe (or add it to PATH) and run:"
Write-Host "  python -m layersecops tools"
