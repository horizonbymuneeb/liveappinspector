#requires -Version 5.1
<#
    Builds the release assets for LiveAppInspector.

    Outputs into dist\:
        lai.exe                        standalone engine (same bytes as the zip)
        lai-<version>-win64.zip        portable bundle: binary, launchers, docs, tests
        SHA256SUMS.txt                 sha256 of every asset, for verification

    Usage:
        .\scripts\package.ps1 -Version 1.0.0
        .\scripts\package.ps1                                   # version from Cargo.toml
        .\scripts\package.ps1 -Version 1.0.1 -NoBuild           # use an existing binary
#>
[CmdletBinding()]
param(
    [string]$Version,
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$engine = Join-Path $root 'engine'
$dist = Join-Path $root 'dist'

# --- resolve version ---------------------------------------------------------
if (-not $Version) {
    $line = Select-String -Path (Join-Path $engine 'Cargo.toml') -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $line) { throw 'cannot read version from engine/Cargo.toml' }
    $Version = $line.Matches[0].Groups[1].Value
}
if ($Version -notmatch '^\d+\.\d+\.\d+([-+].*)?$') { throw "invalid version '$Version'" }
Write-Host "Packaging LiveAppInspector $Version" -ForegroundColor Cyan

# rustup installs to %USERPROFILE%\.cargoin; make the script work even when the
# current shell did not inherit that PATH entry.
$candidates = @()
if ($env:CARGO_HOME) { $candidates += (Join-Path $env:CARGO_HOME 'bin') }
if ($env:USERPROFILE) { $candidates += (Join-Path (Join-Path $env:USERPROFILE '.cargo') 'bin') }
foreach ($candidate in $candidates) {
    if ((Test-Path $candidate) -and (Test-Path (Join-Path $candidate 'cargo.exe'))) {
        if ($env:Path -notlike "*$candidate*") { $env:Path = "$candidate;$env:Path" }
        break
    }
}

# --- build -------------------------------------------------------------------
$exe = Join-Path $engine 'target\release\lai.exe'
if (-not $NoBuild) {
    Write-Host 'Building release binary...' -ForegroundColor Cyan
    Push-Location $engine
    try {
        & cargo build --release
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    }
    finally { Pop-Location }
}
if (-not (Test-Path $exe)) { throw "binary not found: $exe" }

$reported = (& $exe --version) -replace '^LiveAppInspector\s+', ''
if ($reported.Trim() -ne $Version) {
    Write-Warning "binary reports $reported but packaging as $Version (rebuild without -NoBuild?)"
}

# --- stage bundle ------------------------------------------------------------
$stage = Join-Path $env:TEMP ("lai-pkg-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$bundle = Join-Path $stage "lai-$Version-win64"
New-Item -ItemType Directory -Path $bundle -Force | Out-Null

Copy-Item $exe (Join-Path $bundle 'lai.exe') -Force
foreach ($f in @('README.md', 'ARCHITECTURE.md', 'CHANGELOG.md', 'CODE_OF_CONDUCT.md',
                 'CONTRIBUTING.md', 'SECURITY.md', 'LICENSE')) {
    Copy-Item (Join-Path $root $f) $bundle -Force
}
Copy-Item (Join-Path $root 'schema') $bundle -Recurse -Force
New-Item -ItemType Directory -Path (Join-Path $bundle 'samples') -Force | Out-Null
Copy-Item (Join-Path $root 'samples\README.md') (Join-Path $bundle 'samples') -Force
Copy-Item (Join-Path $root 'scripts') $bundle -Recurse -Force
Get-ChildItem (Join-Path $root '*.cmd') | ForEach-Object { Copy-Item $_.FullName $bundle -Force }
New-Item -ItemType Directory -Path (Join-Path $bundle 'docs') -Force | Out-Null
Copy-Item (Join-Path $root 'docs\*.md') (Join-Path $bundle 'docs') -Force
Copy-Item (Join-Path $root 'docs\screenshots') (Join-Path $bundle 'docs') -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path (Join-Path $bundle 'tests') -Force | Out-Null
Get-ChildItem (Join-Path $root 'tests\*') -File | ForEach-Object { Copy-Item $_.FullName (Join-Path $bundle 'tests') -Force }

# A version stamp so an operator can tell what is in the zip without running it.
@"
LiveAppInspector $Version
built: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
binary sha256: $((Get-FileHash (Join-Path $bundle 'lai.exe') -Algorithm SHA256).Hash.ToLower())
platform: Windows 10/11 x64 (server 2016+)
"@ | Set-Content (Join-Path $bundle 'VERSION.txt') -Encoding utf8

# --- zip ---------------------------------------------------------------------
if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }
$zipName = "lai-$Version-win64.zip"
$zipPath = Join-Path $dist $zipName
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $bundle -DestinationPath $zipPath -CompressionLevel Optimal
Copy-Item $exe (Join-Path $dist 'lai.exe') -Force

# --- checksums ---------------------------------------------------------------
$sums = Join-Path $dist 'SHA256SUMS.txt'
$lines = @()
foreach ($asset in @($zipName, 'lai.exe')) {
    $path = Join-Path $dist $asset
    $hash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
    $lines += "$hash  $asset"
}
$lines | Set-Content $sums -Encoding ascii

# --- package-manager manifests (scoop / winget) -----------------------------
# Generated with the real hash so they can be published as-is.
$repoSlug = 'horizonbymuneeb/liveappinspector'
$url = "https://github.com/$repoSlug/releases/download/v$Version/$zipName"
$zipHash = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()

$scoopDir = Join-Path $dist 'packaging\scoop'
New-Item -ItemType Directory -Path $scoopDir -Force | Out-Null
@"
{
  "`$schema": "https://raw.githubusercontent.com/ScoopInstaller/Scoop/master/schema.json",
  "version": "$Version",
  "description": "Point-and-shoot live application forensics for Windows (DFIR)",
  "homepage": "https://github.com/$repoSlug",
  "license": "MIT",
  "url": "$url",
  "hash": "$zipHash",
  "extract_dir": "lai-$Version-win64",
  "bin": [["lai.exe", "lai"]],
  "shortcuts": [["Start LiveAppInspector.cmd", "LiveAppInspector"]],
  "checkver": { "github": "https://github.com/$repoSlug" },
  "autoupdate": {
    "url": "https://github.com/$repoSlug/releases/download/v`$version/lai-`$version-win64.zip"
  }
}
"@ | Set-Content (Join-Path $scoopDir 'liveappinspector.json') -Encoding utf8

$wingetDir = Join-Path $dist 'packaging\winget'
New-Item -ItemType Directory -Path $wingetDir -Force | Out-Null
@"
PackageIdentifier: LiveAppInspector.LiveAppInspector
PackageVersion: $Version
PackageLocale: en-US
Publisher: Muneeb Anjum
PublisherUrl: https://github.com/$repoSlug
PackageName: LiveAppInspector
PackageUrl: https://github.com/$repoSlug
License: MIT
LicenseUrl: https://github.com/$repoSlug/blob/main/LICENSE
ShortDescription: Point-and-shoot live application forensics for Windows (DFIR).
Description: Click any window and get a sealed forensic report about the process behind it - identity, token, ancestry, sockets, modules, handles, registry and persistence artefacts, plus the on-disk image SHA-256 and its Authenticode/catalog trust.
Moniker: lai
Tags: dfir, forensics, incident-response, triage, windows, security
ManifestType: defaultLocale
ManifestVersion: 1.6.0
"@ | Set-Content (Join-Path $wingetDir 'LiveAppInspector.LiveAppInspector.locale.en-US.yaml') -Encoding utf8
@"
PackageIdentifier: LiveAppInspector.LiveAppInspector
PackageVersion: $Version
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
  - RelativeFilePath: lai-$Version-win64\lai.exe
    PortableCommandAlias: lai
Installers:
  - Architecture: x64
    InstallerUrl: $url
    InstallerSha256: $zipHash
ManifestType: installer
ManifestVersion: 1.6.0
"@ | Set-Content (Join-Path $wingetDir 'LiveAppInspector.LiveAppInspector.installer.yaml') -Encoding utf8
@"
PackageIdentifier: LiveAppInspector.LiveAppInspector
PackageVersion: $Version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"@ | Set-Content (Join-Path $wingetDir 'LiveAppInspector.LiveAppInspector.yaml') -Encoding utf8

Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host 'Assets:' -ForegroundColor Green
Get-ChildItem (Join-Path $dist 'lai*'), $sums | ForEach-Object {
    Write-Host ("  {0,-28} {1,10:N0} bytes" -f $_.Name, $_.Length)
}
Write-Host ''
Get-Content $sums | ForEach-Object { Write-Host "  $_" }
Write-Host ''
Write-Host 'Package-manager manifests (generated with the published hash):' -ForegroundColor Cyan
Get-ChildItem (Join-Path $dist 'packaging') -Recurse -File | ForEach-Object { Write-Host ("  " + $_.FullName.Replace($dist + '', '')) }
Write-Host ''
Write-Host 'Verify an asset with:' -ForegroundColor Cyan
Write-Host '  (Get-FileHash .\lai.exe -Algorithm SHA256).Hash.ToLower()' -ForegroundColor DarkGray
