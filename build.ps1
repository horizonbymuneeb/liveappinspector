#requires -Version 5.1
<#
    LiveAppInspector - release build script.

    Produces dist\lai.exe: a single self-contained executable (no runtime
    dependencies, no MSVC needed when using the *-pc-windows-gnu toolchain).

    Usage:
        .\build.ps1                 # build + test + stage to dist\
        .\build.ps1 -SkipTests      # skip cargo test
        .\build.ps1 -Clean          # cargo clean first
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$engine = Join-Path $root 'engine'
$dist = Join-Path $root 'dist'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

Write-Step 'Checking toolchain'
# rustup normally adds this to PATH; probe the default location anyway so a
# --no-modify-path install (or a stale PowerShell environment) still builds.
$candidates = @()
if ($env:CARGO_HOME) { $candidates += (Join-Path $env:CARGO_HOME 'bin') }
if ($env:USERPROFILE) { $candidates += (Join-Path (Join-Path $env:USERPROFILE '.cargo') 'bin') }
foreach ($candidate in $candidates) {
    if ((Test-Path $candidate) -and (Test-Path (Join-Path $candidate 'cargo.exe'))) {
        if ($env:Path -notlike "*$candidate*") { $env:Path = "$candidate;$env:Path" }
        break
    }
}
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    Fail @"
cargo was not found on PATH.

Install a Rust toolchain (MSVC is not required):

    winget install Rustlang.Rustup
    rustup default stable-x86_64-pc-windows-gnu

or see https://rustup.rs
"@
}
$version = (& cargo --version) 2>&1
Write-Host "    $version"
Write-Host "    toolchain: $((& rustup show active-toolchain) 2>&1)"

if ($Clean) {
    Write-Step 'cargo clean'
    Push-Location $engine
    & cargo clean
    Pop-Location
}

Push-Location $engine
try {
    if (-not $SkipTests) {
        Write-Step 'Running tests'
        # Native stderr must not become a terminating PowerShell error, and the
        # exit code has to be inspected by hand.
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $testLog = (cargo test --quiet 2>&1 | Out-String)
        $testCode = $LASTEXITCODE
        if ($testCode -ne 0 -and ($testLog -match 'Application Control policy|os error 4551')) {
            # Smart App Control / WDAC can block a freshly built *unsigned* debug
            # test binary. Retry in the release profile - the one we ship.
            Write-Host '    debug test binary blocked by an Application Control policy; retrying with --release' -ForegroundColor Yellow
            $testLog = (cargo test --release --quiet 2>&1 | Out-String)
            $testCode = $LASTEXITCODE
        }
        $ErrorActionPreference = $prev
        if ($testCode -ne 0) {
            ($testLog -split "`n" | Select-Object -Last 25) | Write-Host
            Fail 'tests failed'
        }
        $m = [regex]::Match($testLog, '(\d+) passed')
        if ($m.Success) { Write-Host ("    {0} tests passed" -f $m.Groups[1].Value) }
        else { Write-Host '    tests passed' }
    }

    Write-Step 'Building release binary'
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $buildLog = (cargo build --release 2>&1 | Out-String)
    $buildCode = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($buildCode -ne 0) {
        ($buildLog -split "`n" | Select-Object -Last 30) | Write-Host
        Fail 'build failed'
    }
}
finally {
    Pop-Location
}

Write-Step 'Staging artifacts'
if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }

$exe = Join-Path $engine 'target\release\lai.exe'
if (-not (Test-Path $exe)) { Fail "built binary not found at $exe" }
Copy-Item $exe (Join-Path $dist 'lai.exe') -Force

# Acceptance tests travel with the build so an operator can prove the binary.
$testDir = Join-Path $dist 'tests'
if (-not (Test-Path $testDir)) { New-Item -ItemType Directory -Path $testDir | Out-Null }
Get-ChildItem (Join-Path $root 'tests\*.ps1') -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName $testDir -Force }
Get-ChildItem (Join-Path $root 'tests\*.js') -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName $testDir -Force }

# One-click launchers (double-click friendly for a responder on a live box).
Get-ChildItem (Join-Path $root '*.cmd') -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName $dist -Force }

# Ship the complete documentation set next to the binary so an operator on a
# response laptop has the interpretation notes (and the schema) available offline,
# and every relative link in the copied README still resolves.
foreach ($doc in @('README.md', 'ARCHITECTURE.md', 'CHANGELOG.md', 'CODE_OF_CONDUCT.md',
                   'CONTRIBUTING.md', 'SECURITY.md', 'LICENSE')) {
    Copy-Item (Join-Path $root $doc) $dist -Force
}
Copy-Item (Join-Path $root 'schema') $dist -Recurse -Force
New-Item -ItemType Directory -Path (Join-Path $dist 'samples') -Force | Out-Null
Copy-Item (Join-Path $root 'samples\README.md') (Join-Path $dist 'samples') -Force
Copy-Item (Join-Path $root 'scripts') $dist -Recurse -Force
$docDir = Join-Path $dist 'docs'
if (-not (Test-Path $docDir)) { New-Item -ItemType Directory -Path $docDir | Out-Null }
Copy-Item (Join-Path $root 'docs\*.md') $docDir -Force
if (Test-Path (Join-Path $root 'docs\screenshots')) {
    Copy-Item (Join-Path $root 'docs\screenshots') $docDir -Recurse -Force
}

$size = [math]::Round((Get-Item (Join-Path $dist 'lai.exe')).Length / 1MB, 2)
Write-Host ''
Write-Host "Built: dist\lai.exe ($size MB)" -ForegroundColor Green
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  .\dist\lai.exe serve --open          # dashboard + Ctrl+Alt+F picker'
Write-Host '  .\dist\lai.exe inspect --window      # headless interactive pick'
Write-Host '  .\dist\lai.exe self-check            # elevation / privilege diagnostics'
Write-Host ''
Write-Host 'Run elevated for SYSTEM/protected processes:' -ForegroundColor Yellow
Write-Host '  Start-Process .\dist\lai.exe -Verb RunAs -ArgumentList "serve","--open"'
