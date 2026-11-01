#requires -Version 5.1
<#
.SYNOPSIS
    Downloads and installs the latest LiveAppInspector release.

.DESCRIPTION
    Verifies the published SHA-256 before running anything, installs to
    %LOCALAPPDATA%\Programs\LiveAppInspector and optionally adds it to the user PATH.

.EXAMPLE
    iwr https://raw.githubusercontent.com/horizonbymuneeb/liveappinspector/main/scripts/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Version 1.0.0 -AddToPath
#>
[CmdletBinding()]
param(
    [string]$Version = 'latest',
    [string]$Repo = 'horizonbymuneeb/liveappinspector',
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\LiveAppInspector'),
    [switch]$AddToPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($Version -eq 'latest') {
    Write-Host "Resolving latest release of $Repo..." -ForegroundColor Cyan
    $rel = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $rel.tag_name.TrimStart('v')
}
$asset = "lai-$Version-win64.zip"
$base = "https://github.com/$Repo/releases/download/v$Version"
$tmp = Join-Path $env:TEMP ("lai-install-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    Write-Host "Downloading $asset ..." -ForegroundColor Cyan
    $zip = Join-Path $tmp $asset
    Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile $zip

    Write-Host 'Verifying SHA-256 ...' -ForegroundColor Cyan
    $sums = (Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS.txt").Content
    $expected = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($asset) }) -replace '\s+.*$', ''
    $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if (-not $expected) { throw "no checksum published for $asset - refusing to install" }
    if ($expected.Trim().ToLower() -ne $actual) { throw "checksum mismatch: expected $expected, got $actual" }
    Write-Host "  ok $actual" -ForegroundColor Green

    Write-Host "Installing to $InstallDir ..." -ForegroundColor Cyan
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $inner = Join-Path $tmp "lai-$Version-win64"
    if (-not (Test-Path $inner)) { throw 'unexpected archive layout' }
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    New-Item -ItemType Directory -Path (Split-Path $InstallDir) -Force | Out-Null
    Move-Item $inner $InstallDir

    $exe = Join-Path $InstallDir 'lai.exe'
    & $exe --version

    if ($AddToPath) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if ($userPath -notlike "*$InstallDir*") {
            [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDir", 'User')
            Write-Host "Added $InstallDir to the user PATH (restart your shell)." -ForegroundColor Yellow
        }
    }

    Write-Host ''
    Write-Host "Installed: $exe" -ForegroundColor Green
    Write-Host ''
    Write-Host 'Start the dashboard:' -ForegroundColor Cyan
    Write-Host "  & '$InstallDir\Start LiveAppInspector.cmd'"
    Write-Host 'Or drive it from a shell:'
    Write-Host "  & '$exe' serve --open"
    Write-Host "  & '$exe' inspect --window --json case.json --html case.html"
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
