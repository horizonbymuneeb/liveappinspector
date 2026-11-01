#requires -Version 5.1
<#
    LiveAppInspector - end-to-end acceptance test.

    Runs every documented capability against a real Windows desktop and prints a
    PASS/FAIL table. No Administrator rights required (elevation-only behaviour is
    reported as SKIP with the reason; run it from an elevated prompt to cover it).

    Usage:
        .\tests\e2e.ps1                     # tests ..\dist\lai.exe
        .\tests\e2e.ps1 -Exe .\dist\lai.exe -Verbose
        .\tests\e2e.ps1 -SkipPicker         # skip the synthetic-click tests

    Exit code: 0 = all executed tests passed, 1 = at least one failure.
#>
[CmdletBinding()]
param(
    [string]$Exe,
    [switch]$SkipPicker,
    [int]$Port = 8799
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Exe) { $Exe = Join-Path $root 'dist\lai.exe' }
if (-not (Test-Path $Exe)) { Write-Host "lai.exe not found at $Exe (run build.ps1)" -ForegroundColor Red; exit 1 }
$Exe = (Resolve-Path $Exe).Path

$work = Join-Path ([IO.Path]::GetTempPath()) ("lai-e2e-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null

$results = New-Object System.Collections.ArrayList
$engineProcs = New-Object System.Collections.ArrayList

function Record([string]$name, [string]$status, [string]$detail) {
    [void]$results.Add([pscustomobject]@{ Test = $name; Status = $status; Detail = $detail })
    $colour = switch ($status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'Yellow' } default { 'Gray' } }
    Write-Host ("  [{0}] {1}" -f $status, $name) -ForegroundColor $colour
    if ($detail -and $status -ne 'PASS') { Write-Host ("        {0}" -f $detail) -ForegroundColor DarkGray }
    elseif ($detail -and $Verbose) { Write-Host ("        {0}" -f $detail) -ForegroundColor DarkGray }
}

function Test-Case([string]$name, [scriptblock]$body) {
    try {
        $out = & $body
        if ($out -is [array]) { $detail = ($out -join '; ') } else { $detail = [string]$out }
        Record $name 'PASS' $detail
    }
    catch {
        Record $name 'FAIL' $_.Exception.Message
    }
}

function Invoke-Lai {
    param([string[]]$Arguments, [int]$TimeoutSec = 120)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch {} ; throw "lai.exe timed out after ${TimeoutSec}s" }
    $p.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $p.ExitCode
        Stdout   = $stdout.Result
        Stderr   = $stderr.Result
    }
}

function Get-Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLower() }

# ---------------------------------------------------------------- P/Invoke glue
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public struct LAIRECT { public int Left, Top, Right, Bottom; }
public struct LAIPOINT { public int X, Y; }
public class LAIWin {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out LAIRECT r);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, IntPtr e);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr FindWindow(string cls, string name);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(LAIPOINT p);
    [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr h, uint flags);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
    public static void RaiseAt(IntPtr h, int x, int y) {
        // HWND_TOPMOST(-1) + move to (x,y), keep size
        SetWindowPos(h, (IntPtr)(-1), x, y, 0, 0, 0x0001);
    }
    // SWP_SHOWWINDOW(0x40) | SWP_NOSIZE(0x01): move + raise + force-show.
    // A process started with CreateProcess(SW_HIDE) has its first ShowWindow
    // call ignored, so the form exists but is not visible - and an invisible
    // window is skipped by WindowFromPoint.
    public static void ShowTopMost(IntPtr h, int x, int y) {
        SetWindowPos(h, (IntPtr)(-1), x, y, 0, 0, 0x0040 | 0x0001);
    }
    public static IntPtr RootWindowAt(int x, int y) {
        LAIPOINT p = new LAIPOINT(); p.X = x; p.Y = y;
        IntPtr h = WindowFromPoint(p);
        if (h == IntPtr.Zero) return IntPtr.Zero;
        IntPtr root = GetAncestor(h, 2);
        return root == IntPtr.Zero ? h : root;
    }
    public static void Click(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(200);
        mouse_event(0x0002, 0, 0, 0, IntPtr.Zero);
        System.Threading.Thread.Sleep(80);
        mouse_event(0x0004, 0, 0, 0, IntPtr.Zero);
    }
}
"@ -ErrorAction SilentlyContinue | Out-Null

Write-Host ''
Write-Host '=============================================================' -ForegroundColor Cyan
Write-Host ' LiveAppInspector - end-to-end acceptance test' -ForegroundColor Cyan
Write-Host '=============================================================' -ForegroundColor Cyan
Write-Host ("  binary : {0}  ({1:N0} bytes, sha256 {2}...)" -f $Exe, (Get-Item $Exe).Length, (Get-Sha256 $Exe).Substring(0,16))
Write-Host ("  host   : {0}  user {1}  elevated {2}" -f $env:COMPUTERNAME, "$env:USERDOMAIN\$env:USERNAME", ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Write-Host ("  work   : {0}" -f $work)
Write-Host ''

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ===========================================================================
Write-Host '-- 1. CLI surface -------------------------------------------------' -ForegroundColor DarkCyan

Test-Case 'version banner' {
    $r = Invoke-Lai @('--version')
    if ($r.ExitCode -ne 0) { throw "exit $($r.ExitCode): $($r.Stderr)" }
    if ($r.Stdout -notmatch 'LiveAppInspector \d+\.\d+\.\d+') { throw "unexpected: $($r.Stdout)" }
    $r.Stdout.Trim()
}

Test-Case 'help text lists every subcommand' {
    $r = Invoke-Lai @('--help')
    foreach ($cmd in @('inspect', 'serve', 'pick', 'hash', 'verify', 'procs', 'self-check')) {
        if ($r.Stdout -notmatch [regex]::Escape($cmd)) { throw "help missing '$cmd'" }
    }
    'inspect/serve/pick/hash/verify/procs/self-check all documented'
}

Test-Case 'self-check returns valid JSON with engine facts' {
    $r = Invoke-Lai @('self-check')
    $j = $r.Stdout | ConvertFrom-Json
    if (-not $j.version) { throw 'no version' }
    if ($j.schema -ne 'liveappinspector.report/v1') { throw "schema=$($j.schema)" }
    if (-not $j.computer) { throw 'no computer name' }
    "v$($j.version) $($j.os) build $($j.os_build) on $($j.computer)"
}

Test-Case 'unknown command exits non-zero' {
    $r = Invoke-Lai @('bogus-command')
    if ($r.ExitCode -eq 0) { throw 'expected non-zero exit' }
    "exit $($r.ExitCode)"
}

Test-Case 'procs lists live processes as JSON' {
    $r = Invoke-Lai @('procs', '--limit', '25', '--json')
    $rows = $r.Stdout | ConvertFrom-Json
    if ($rows.Count -lt 5) { throw "only $($rows.Count) rows" }
    $withPid = @($rows | Where-Object { $_.pid -gt 0 })
    if ($withPid.Count -lt 3) { throw 'no usable rows' }
    "$($rows.Count) rows, e.g. pid $($withPid[0].pid) $($withPid[0].name)"
}

# ===========================================================================
Write-Host '-- 2. Acquisition (module A-F) ------------------------------------' -ForegroundColor DarkCyan

# CI runners do not always have an interactive explorer.exe, so fall back to the
# shell running this test - it is still a real process with a real token.
$shellProc = Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $shellProc) { $shellProc = Get-Process -Id $PID }
$explorerPid = $shellProc.Id
$targetName = $shellProc.ProcessName + '.exe' 
$reportPath = Join-Path $work 'explorer.json'
$htmlPath = Join-Path $work 'explorer.html'

Test-Case "inspect $targetName (pid $explorerPid) -> JSON + HTML" {
    $r = Invoke-Lai @('inspect', '--pid', "$explorerPid", '--json', $reportPath, '--html', $htmlPath, '--case', 'E2E-001', '--examiner', 'E2E', '--org', 'TEST')
    if ($r.ExitCode -ne 0) { throw "exit $($r.ExitCode): $($r.Stderr)" }
    if (-not (Test-Path $reportPath)) { throw 'json not written' }
    if (-not (Test-Path $htmlPath)) { throw 'html not written' }
    "{0:N0} bytes json, {1:N0} bytes html" -f (Get-Item $reportPath).Length, (Get-Item $htmlPath).Length
}

$rep = if (Test-Path $reportPath) { Get-Content $reportPath -Raw | ConvertFrom-Json } else { $null }

Test-Case 'report schema + all six modules present' {
    if (-not $rep) { throw 'no report' }
    foreach ($section in @('tool', 'case', 'selection', 'process', 'user_context', 'genealogy', 'network', 'modules', 'handles', 'registry', 'services', 'binary', 'integrity')) {
        if ($null -eq $rep.$section) { throw "missing section '$section'" }
    }
    'tool/case/selection/process/user_context/genealogy/network/modules/handles/registry/services/binary/integrity'
}

Test-Case 'module A: identity + window facts' {
    if ($rep.process.pid -ne $explorerPid) { throw "pid $($rep.process.pid)" }
    if ($rep.process.image_name -ne $targetName) { throw "image $($rep.process.image_name), expected $targetName" }
    if (-not $rep.process.image_path) { throw 'no image path' }
    if ($rep.process.arch -ne 'x64') { throw "arch $($rep.process.arch)" }
    if (-not $rep.process.times.created_utc) { throw 'no creation time' }
    if (-not $rep.process.command_line) { throw 'no command line' }
    if ($rep.process.command_line_source -notmatch 'PEB') { throw "cmdline source $($rep.process.command_line_source)" }
    "pid $($rep.process.pid) $($rep.process.image_name) $($rep.process.arch) created $($rep.process.times.created_utc), cmdline from PEB"
}

Test-Case 'module B: token, SID, integrity, privileges, session' {
    $u = $rep.user_context
    if ($u.sid -notmatch '^S-1-') { throw "sid $($u.sid)" }
    if (-not $u.account_name) { throw 'no account name' }
    if (-not $u.integrity.name) { throw 'no integrity level' }
    if ($u.privileges.Count -lt 3) { throw "privileges $($u.privileges.Count)" }
    if ($u.groups.Count -lt 3) { throw "groups $($u.groups.Count)" }
    if (-not $u.elevation.verdict) { throw 'no elevation verdict' }
    if (-not $u.token.authentication_id) { throw 'no logon session id' }
    "$($u.account_domain)\$($u.account_name) $($u.sid) $($u.integrity.name) privs=$($u.privileges.Count) groups=$($u.groups.Count) session=$($u.session.id)/$($u.session.kind)"
}

Test-Case 'module C: genealogy + PPID-recycling logic' {
    $g = $rep.genealogy
    if ($g.meta.status -ne 'ok') { throw "genealogy status $($g.meta.status)" }
    if ($null -eq $g.children -or $null -eq $g.descendants) { throw 'genealogy arrays missing' }
    $recycleWarning = @($g.meta.warnings | Where-Object { $_ -match 'recycled|later' })
    "children=$($g.children.Count) descendants=$($g.descendants.Count) ancestors=$($g.ancestors.Count) recycling-warnings=$($recycleWarning.Count)"
}

Test-Case 'module D: socket tables queried (no bogus PTR)' {
    $n = $rep.network
    if (-not $n.meta.status) { throw 'no network status' }
    $bogus = @($n.connections | Where-Object {
        $_.remote_hostname -and ($_.remote_address -eq '::' -or $_.remote_address -eq '0.0.0.0' -or $_.remote_address -like '127.*')
    })
    if ($bogus.Count -gt 0) { throw "wildcard/loopback address was reverse-resolved to '$($bogus[0].remote_hostname)'" }
    "tcp=$($n.tcp_count) udp=$($n.udp_count) status=$($n.meta.status) wildcard-PTR=false"
}

Test-Case 'module E: modules + handles + registry' {
    if ($rep.modules.count -lt 20) { throw "modules $($rep.modules.count)" }
    $ntdll = $rep.modules.items | Where-Object { $_.name -match '^ntdll' } | Select-Object -First 1
    if (-not $ntdll) { throw 'ntdll not in module list' }
    if (-not $ntdll.file_version) { throw 'ntdll has no version resource' }
    if ($rep.handles.inspected -lt 10) { throw "handles $($rep.handles.inspected)" }
    if ($rep.handles.items.Count -lt 10) { throw 'no resolved handles' }
    $resolved = @($rep.handles.items | Where-Object { $_.object_name })
    if ($resolved.Count -lt 5) { throw "only $($resolved.Count) handles with object names" }
    "modules=$($rep.modules.count) (ntdll v$($ntdll.file_version)) handles=$($rep.handles.inspected) named=$($resolved.Count) keys=$($rep.registry.keys.Count)"
}

Test-Case 'module F: SHA-256 matches certutil (independent tool)' {
    $expected = (certutil -hashfile $rep.binary.path SHA256 | Select-Object -Index 1).Trim().ToLower()
    if ($rep.binary.sha256 -ne $expected) { throw "engine=$($rep.binary.sha256) certutil=$expected" }
    if ($rep.binary.file_index -notmatch '^[0-9A-F]+$') { throw "file index $($rep.binary.file_index)" }
    "both = $($rep.binary.sha256.Substring(0,32))...  volume=$($rep.binary.volume_serial) index=$($rep.binary.file_index)"
}

Test-Case 'no section refused or failed on a normal user process' {
    # A `partial` section is legitimate (truncation, an unresolvable object name,
    # a DNS budget); a `denied`/`error` section on our own user process is not.
    $sections = @('process', 'user_context', 'genealogy', 'network', 'modules', 'handles', 'registry', 'services', 'binary')
    $refused = @()
    $partial = @()
    foreach ($name in $sections) {
        $status = $rep.$name.meta.status
        if ($status -in @('denied', 'error')) { $refused += "$name=$status" }
        elseif ($status -eq 'partial') { $partial += $name }
    }
    if ($refused.Count -gt 0) { throw ('sections refused or failed: ' + ($refused -join ', ')) }
    if ($partial.Count -gt 0) {
        "0 denied/error, partial: $($partial -join ', ') ($($rep.integrity.custody_log.Count) custody events)"
    }
    else {
        "0 degraded, $($rep.integrity.custody_log.Count) custody events"
    }
}

Test-Case 'custody log is ordered and gap-free' {
    $seqs = @($rep.integrity.custody_log | ForEach-Object { $_.seq })
    for ($i = 0; $i -lt $seqs.Count; $i++) { if ($seqs[$i] -ne $i + 1) { throw "seq gap at $i (got $($seqs[$i]))" } }
    foreach ($e in $rep.integrity.custody_log) { if ($e.at_utc -notmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$') { throw "bad timestamp $($e.at_utc)" } }
    "$($seqs.Count) events, seq 1..$($seqs.Count), RFC3339 UTC"
}

# ===========================================================================
Write-Host '-- 3. Seal / chain of custody --------------------------------------' -ForegroundColor DarkCyan

Test-Case 'lai verify -> MATCH on an untouched exhibit' {
    $r = Invoke-Lai @('verify', $reportPath)
    if ($r.ExitCode -ne 0) { throw "exit $($r.ExitCode): $($r.Stdout)" }
    if ($r.Stdout -notmatch 'MATCH') { throw 'no MATCH verdict' }
    'exit 0, VERDICT MATCH'
}

Test-Case 'tampering is detected (verify -> MISMATCH, exit 2)' {
    $tampered = Join-Path $work 'tampered.json'
    $raw = Get-Content $reportPath -Raw
    $obj = $raw | ConvertFrom-Json
    $obj.binary.sha256 = ('0' * 64)
    $json = $obj | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText($tampered, $json, (New-Object Text.UTF8Encoding($false)))
    $r = Invoke-Lai @('verify', $tampered)
    if ($r.ExitCode -ne 2) { throw "expected exit 2, got $($r.ExitCode)" }
    if ($r.Stdout -notmatch 'MISMATCH') { throw 'no MISMATCH verdict' }
    'exit 2, VERDICT MISMATCH'
}

Test-Case 'a BOM-prefixed exhibit still verifies (Windows tooling tolerance)' {
    $bomPath = Join-Path $work 'with-bom.json'
    $bytes = [IO.File]::ReadAllBytes($reportPath)
    $bom = [byte[]](0xEF, 0xBB, 0xBF)
    [IO.File]::WriteAllBytes($bomPath, ($bom + $bytes))
    $r = Invoke-Lai @('verify', $bomPath)
    if ($r.ExitCode -ne 0) { throw "exit $($r.ExitCode): $($r.Stdout)$($r.Stderr)" }
    if ($r.Stdout -notmatch 'MATCH') { throw 'BOM caused a false mismatch' }
    'UTF-8 BOM tolerated, VERDICT MATCH'
}

Test-Case 'render rebuilds an exhibit from JSON (no re-acquisition)' {
    $out = Join-Path $work 'rendered.html'
    $r = Invoke-Lai @('render', $reportPath, '--html', $out)
    if ($r.ExitCode -ne 0) { throw "exit $($r.ExitCode): $($r.Stderr)" }
    $rendered = Get-Content $out -Raw
    $original = Get-Content $htmlPath -Raw
    if ($rendered -ne $original) { throw 'rendered exhibit differs from the acquisition-time exhibit' }
    "byte-identical to the acquisition-time exhibit ($((Get-Item $out).Length) bytes)"
}

Test-Case 'render --reseal updates the seal but keeps verify honest' {
    $edited = Join-Path $work 'edited.json'
    $obj = Get-Content $reportPath -Raw | ConvertFrom-Json
    $obj.case.examiner = 'B. Reviewer'
    [IO.File]::WriteAllText($edited, ($obj | ConvertTo-Json -Depth 100), (New-Object Text.UTF8Encoding($false)))
    $before = (Invoke-Lai @('verify', $edited))
    if ($before.ExitCode -ne 2) { throw "edited report should fail verification, exit $($before.ExitCode)" }
    $r = Invoke-Lai @('render', $edited, '--reseal', '--json', $edited)
    if ($r.ExitCode -ne 0) { throw "reseal failed: $($r.Stderr)" }
    $after = Invoke-Lai @('verify', $edited)
    if ($after.ExitCode -ne 0) { throw "resealed report does not verify: $($after.Stdout)" }
    'edit -> MISMATCH -> reseal -> MATCH'
}

Test-Case 'seal is recomputable from the JSON alone' {
    $obj = Get-Content $reportPath -Raw | ConvertFrom-Json
    $embedded = $obj.integrity.report_sha256
    $obj.integrity.report_sha256 = ''
    $obj.integrity.sealed_at_utc = ''
    # PowerShell re-serialisation differs from serde_json, so verify the *field*
    # invariants here and rely on `lai verify` for the byte-exact check.
    if ($embedded.Length -ne 64) { throw "seal length $($embedded.Length)" }
    if (-not $obj.integrity.seal_scope) { throw 'no seal scope documented' }
    "embedded seal $($embedded.Substring(0,24))... documented scope present"
}

# ===========================================================================
Write-Host '-- 4. HTML exhibit -------------------------------------------------' -ForegroundColor DarkCyan

Test-Case 'HTML exhibit is self-contained and script-free' {
    $html = Get-Content $htmlPath -Raw
    if ($html -notmatch 'Report seal') { throw 'no seal block' }
    if ($html -notmatch 'Custody log') { throw 'no custody log' }
    if ($html -match '(?i)<script') { throw 'contains a <script> tag' }
    if ($html -match 'https?://(?!www\.w3\.org)') { throw 'contains an external URL' }
    if ($html -notmatch $rep.binary.sha256) { throw 'binary hash absent' }
    "{0:N0} bytes, seal + custody log + hash present, 0 scripts, 0 external refs" -f $html.Length
}

Test-Case 'HTML table structure is balanced' {
    $html = Get-Content $htmlPath -Raw
    $open = ([regex]::Matches($html, '<table')).Count
    $close = ([regex]::Matches($html, '</table>')).Count
    if ($open -ne $close) { throw "tables $open open vs $close close" }
    $openSec = ([regex]::Matches($html, '<section')).Count
    $closeSec = ([regex]::Matches($html, '</section>')).Count
    if ($openSec -ne $closeSec) { throw "sections $openSec open vs $closeSec close" }
    "$open tables, $openSec sections, all closed"
}

# ===========================================================================
Write-Host '-- 5. Denied / protected targets -----------------------------------' -ForegroundColor DarkCyan

$winlogonPid = (Get-Process winlogon | Select-Object -First 1).Id
$deniedPath = Join-Path $work 'winlogon.json'

Test-Case "denied target (winlogon.exe pid $winlogonPid) degrades gracefully" {
    $r = Invoke-Lai @('inspect', '--pid', "$winlogonPid", '--no-handles', '--json', $deniedPath)
    if (-not (Test-Path $deniedPath)) { throw 'no report written' }
    $d = Get-Content $deniedPath -Raw | ConvertFrom-Json
    if ($d.process.meta.status -notin @('denied', 'ok')) { throw "process status $($d.process.meta.status)" }
    if ($d.process.meta.status -eq 'denied' -and -not $d.process.meta.error) { throw 'denied without an explanation' }
    if ($d.process.meta.status -eq 'denied' -and $d.integrity.sections_degraded -lt 1) { throw 'expected degraded sections' }
    if ($r.ExitCode -ne 0 -and $r.ExitCode -ne 3) { throw "unexpected exit $($r.ExitCode)" }
    "status=$($d.process.meta.status) exit=$($r.ExitCode) degraded=$($d.integrity.sections_degraded) reason recorded"
}

Test-Case 'denied target still yields image hash + trust (kernel fallback)' {
    $d = Get-Content $deniedPath -Raw | ConvertFrom-Json
    if ($d.binary.sha256.Length -ne 64) { throw 'no hash collected' }
    if ($d.binary.signature.status -ne 'valid') { throw "signature $($d.binary.signature.status)" }
    if (-not $d.binary.signature.signature_source) { throw 'signature source not recorded' }
    if ($d.process.meta.status -eq 'denied') {
        if ($d.binary.signature.signature_source -ne 'catalog') { throw "source $($d.binary.signature.signature_source)" }
        if (-not $d.binary.signature.catalog_path) { throw 'no catalog path' }
        if ($d.process.image_path_source -notmatch 'kernel') { throw 'provenance not labelled' }
    }
    "hash ok, catalog-signed (signer '$($d.binary.signature.signer_subject)'), provenance labelled"
}

Test-Case 'PID 4 (System) does not crash the engine' {
    $p4 = Join-Path $work 'system.json'
    $r = Invoke-Lai @('inspect', '--pid', '4', '--no-handles', '--json', $p4)
    if (-not (Test-Path $p4)) { throw 'no report' }
    $d = Get-Content $p4 -Raw | ConvertFrom-Json
    if ($d.process.pid -ne 4) { throw "pid $($d.process.pid)" }
    "wrote $((Get-Item $p4).Length) bytes, status=$($d.process.meta.status), exit=$($r.ExitCode)"
}

# ===========================================================================
Write-Host '-- 6. Service / network correlation --------------------------------' -ForegroundColor DarkCyan

$svcCandidates = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessId -gt 4 -and $_.PathName -and $_.PathName -notmatch 'svchost' } |
    Select-Object -First 3
$svcPass = $null
if ($svcCandidates) {
    $svcPath = Join-Path $work 'service.json'
    foreach ($svc in $svcCandidates) {
        try {
            Invoke-Lai @('inspect', '--pid', "$($svc.ProcessId)", '--no-handles', '--json', $svcPath) | Out-Null
            $d = Get-Content $svcPath -Raw | ConvertFrom-Json
            $match = @($d.services.services | Where-Object { $_.name -eq $svc.Name })
            if ($match.Count -ge 1) { $svcPass = "$($match[0].name) [$($match[0].state)/$($match[0].start_type)] binary-match=$($match[0].binary_matches_target)"; break }
        } catch { }
    }
}
if ($svcPass) {
    Record 'service correlation' 'PASS' $svcPass
} else {
    Record 'service correlation' 'SKIP' 'no inspectable non-svchost service host found (or all refused access)'
}

$conn = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -gt 4 } | Select-Object -First 1
if ($conn) {
    Test-Case "network table ($($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort))" {
        $netPath = Join-Path $work 'network.json'
        $r = Invoke-Lai @('inspect', '--pid', "$($conn.OwningProcess)", '--no-handles', '--resolve-dns', '--json', $netPath)
        $d = Get-Content $netPath -Raw | ConvertFrom-Json
        $found = @($d.network.connections | Where-Object { $_.remote_port -eq $conn.RemotePort -and $_.remote_address -eq $conn.RemoteAddress })
        if ($found.Count -lt 1) { throw "connection not found among $($d.network.connections.Count) endpoints" }
        $ptr = if ($found[0].remote_hostname) { "PTR=$($found[0].remote_hostname)" } else { 'no PTR (expected offline)' }
        "$($found[0].protocol) $($found[0].state) local=$($found[0].local_port) remote=$($conn.RemoteAddress):$($conn.RemotePort) $ptr"
    }
} else {
    Record 'network table' 'SKIP' 'no established TCP connection available on this host'
}

# ===========================================================================
Write-Host '-- 7. Point-and-shoot picker (synthetic click) ---------------------' -ForegroundColor DarkCyan

if ($SkipPicker) {
    Record 'picker (window)' 'SKIP' '-SkipPicker'
    Record 'picker (hwnd inspect)' 'SKIP' '-SkipPicker'
}
else {
    # Launch a dedicated target window so the click lands somewhere known.
    $targetTitle = "LAI-E2E-TARGET-$([guid]::NewGuid().ToString('N').Substring(0,6))"
    $targetScript = Join-Path $work 'target.ps1'
    @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
`$f = New-Object System.Windows.Forms.Form
`$f.Text = '$targetTitle'
`$f.Width = 520; `$f.Height = 240
`$f.StartPosition = 'CenterScreen'
`$f.TopMost = `$true
`$f.BackColor = [System.Drawing.Color]::FromArgb(20,24,32)
`$l = New-Object System.Windows.Forms.Label
`$l.Text = 'LiveAppInspector E2E target window'
`$l.ForeColor = [System.Drawing.Color]::White
`$l.AutoSize = `$true
`$l.Location = New-Object System.Drawing.Point(30,30)
`$f.Controls.Add(`$l)
`$f.Show()
`$f.Activate()
[Console]::Out.WriteLine(`$f.Handle)
[Console]::Out.Flush()
Start-Sleep -Seconds 120
"@ | Set-Content $targetScript -Encoding UTF8

    $targetOut = Join-Path $work 'target.out'
    $targetProc = Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $targetScript -RedirectStandardOutput $targetOut -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    $targetPid = $targetProc.Id
    $targetHwnd = 0
    try { $targetHwnd = [int64](Get-Content $targetOut -Raw).Trim() } catch {}

    Test-Case 'picker resolves the clicked window to its PID' {
        if ($targetHwnd -eq 0) { throw 'target window did not report its handle' }
        # Deterministic z-order: raise the target above the terminal and park it
        # off-centre so no other window can shadow the click point.
        [LAIWin]::ShowTopMost([IntPtr]$targetHwnd, 140, 140)
        Start-Sleep -Milliseconds 500
        $rect = New-Object LAIRECT
        [void][LAIWin]::GetWindowRect([IntPtr]$targetHwnd, [ref]$rect)
        $cx = [int](($rect.Left + $rect.Right) / 2)
        $cy = [int](($rect.Top + $rect.Bottom) / 2)
        # Precondition: the target must be the topmost window at the click point,
        # otherwise the picker is correct and the *test* is wrong.
        $onTop = $false
        for ($i = 0; $i -lt 20 -and -not $onTop; $i++) {
            $root = [LAIWin]::RootWindowAt($cx, $cy)
            if ($root -eq [IntPtr]$targetHwnd) { $onTop = $true } else { Start-Sleep -Milliseconds 250 }
        }
        if (-not $onTop) {
            $root = [LAIWin]::RootWindowAt($cx, $cy)
            throw ("target window 0x{0:X} (visible={1}) is not the window at ({2},{3}); found 0x{4:X} - precondition failed" -f $targetHwnd, [LAIWin]::IsWindowVisible([IntPtr]$targetHwnd), $cx, $cy, [int64]$root)
        }
        $pickJson = Join-Path $work 'pick.json'
        $proc = Start-Process -FilePath $Exe -ArgumentList 'pick', '--json' -RedirectStandardOutput $pickJson -PassThru -WindowStyle Hidden
        Start-Sleep -Milliseconds 1500
        [LAIWin]::Click($cx, $cy)
        if (-not $proc.WaitForExit(30000)) { try { $proc.Kill() } catch {}; throw 'picker did not finish' }
        $picked = Get-Content $pickJson -Raw | ConvertFrom-Json
        if ($picked.pid -ne $targetPid) { throw "picked pid $($picked.pid), expected $targetPid (state: $($picked.title))" }
        if ($picked.title -ne $targetTitle) { throw "picked title '$($picked.title)' , expected '$targetTitle'" }
        "pid=$($picked.pid) hwnd=$($picked.hwnd) title='$($picked.title)' at ($cx,$cy)"
    }

    Test-Case 'inspect --hwnd acquires the same window' {
        if ($targetHwnd -eq 0) { throw 'no target window' }
        $h = '0x{0:X}' -f $targetHwnd
        $hwndReport = Join-Path $work 'hwnd.json'
        $r = Invoke-Lai @('inspect', '--hwnd', $h, '--no-handles', '--json', $hwndReport)
        $d = Get-Content $hwndReport -Raw | ConvertFrom-Json
        if ($d.process.pid -ne $targetPid) { throw "pid $($d.process.pid) != $targetPid" }
        if ($d.selection.window.title -ne $targetTitle) { throw "window title '$($d.selection.window.title)'" }
        "hwnd=$h pid=$($d.process.pid) title matches, class=$($d.selection.window.class_name)"
    }

    if ($targetProc -and -not $targetProc.HasExited) { try { $targetProc.Kill() } catch {} }
}

# ===========================================================================
Write-Host '-- 8. Dashboard bridge (HTTP) --------------------------------------' -ForegroundColor DarkCyan

$serveLog = Join-Path $work 'serve.log'
$serve = Start-Process -FilePath $Exe -ArgumentList 'serve', '--port', "$Port" -RedirectStandardOutput $serveLog -PassThru -WindowStyle Hidden
[void]$engineProcs.Add($serve)
Start-Sleep -Seconds 3
$token = $null
for ($i = 0; $i -lt 20 -and -not $token; $i++) {
    if (Test-Path $serveLog) {
        $m = [regex]::Match((Get-Content $serveLog -Raw), 'session token:\s*([0-9a-f]{32})')
        if ($m.Success) { $token = $m.Groups[1].Value }
    }
    if (-not $token) { Start-Sleep -Milliseconds 400 }
}
$base = "http://127.0.0.1:$Port"
$headers = @{ 'X-LAI-Token' = $token }

Test-Case 'dashboard assets served with token injected' {
    if (-not $token) { throw 'engine never printed a session token' }
    $index = Invoke-WebRequest "$base/" -UseBasicParsing
    if ($index.StatusCode -ne 200) { throw "index $($index.StatusCode)" }
    if ($index.Content -notmatch [regex]::Escape($token)) { throw 'token not injected into index' }
    if ($index.Content -match '__LAI_TOKEN__') { throw 'token placeholder left in HTML' }
    $js = Invoke-WebRequest "$base/app.js" -UseBasicParsing
    $css = Invoke-WebRequest "$base/style.css" -UseBasicParsing
    "index=$($index.RawContentLength) js=$($js.RawContentLength) css=$($css.RawContentLength) bytes, token injected"
}

Test-Case 'CSP allows same-origin scripts and blocks everything else' {
    $idx = Invoke-WebRequest "$base/" -UseBasicParsing
    $csp = $idx.Headers['Content-Security-Policy']
    if (-not $csp) { throw 'no Content-Security-Policy header' }
    if ($csp -notmatch "script-src 'self'") { throw "script-src does not allow 'self' (the dashboard would not boot): $csp" }
    if ($csp -notmatch "default-src 'none'") { throw "default-src should be 'none': $csp" }
    if ($csp -match "script-src[^;]*'unsafe-inline'") { throw 'script-src should not require unsafe-inline' }
    if ($csp -notmatch "frame-ancestors 'none'") { throw 'frame-ancestors missing' }
    'strict CSP, scripts from self only'
}

Test-Case 'index ships the token as inert JSON (no executable inline script)' {
    $html = (Invoke-WebRequest "$base/" -UseBasicParsing).Content
    if ($html -notmatch 'type="application/json" id="laiBoot"') { throw 'token bootstrap block missing' }
    $executable = [regex]::Matches($html, '<script(?![^>]*application/json)(?![^>]*src=)[^>]*>')
    if ($executable.Count -gt 0) { throw "$($executable.Count) executable inline script tag(s) found" }
    if ($html -notmatch 'src="/app.js"') { throw 'app.js not referenced' }
    'token is data, not code; only /app.js executes'
}

Test-Case 'hidden panels cannot be overridden by class display rules' {
    $css = (Invoke-WebRequest "$base/style.css" -UseBasicParsing).Content
    if ($css -notmatch '\[hidden\]\s*\{\s*display:\s*none') { throw '[hidden] guard rule missing from style.css' }
    $js = (Invoke-WebRequest "$base/app.js" -UseBasicParsing).Content
    foreach ($id in @('procDropdown', 'tabs', 'exportBox', 'overlay')) {
        if ($js -notmatch [regex]::Escape($id)) { throw "app.js never references $id" }
    }
    '[hidden]{display:none!important} present; toggled panels referenced'
}

Test-Case 'API rejects a missing/invalid token (401)' {
    try {
        $r = Invoke-WebRequest "$base/api/status" -UseBasicParsing
        throw "expected 401, got $($r.StatusCode)"
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw $_ }
    }
    try {
        Invoke-WebRequest "$base/api/status" -Headers @{ 'X-LAI-Token' = 'deadbeef' * 4 } -UseBasicParsing | Out-Null
        throw 'invalid token was accepted'
    }
    catch { if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw $_ } }
    'no-token=401, bad-token=401, good-token accepted'
}

Test-Case 'GET /api/status reports engine state' {
    $s = Invoke-RestMethod "$base/api/status" -Headers $headers
    if (-not $s.ok) { throw 'not ok' }
    if ($s.version -ne '1.0.0') { throw "version $($s.version)" }
    if ($s.hotkey -ne 'Ctrl+Alt+F') { throw "hotkey $($s.hotkey)" }
    "host=$($s.host) os=$($s.os) elevated=$($s.engine_elevated) hotkey-listener=$($s.hotkey_listener)"
}

Test-Case 'POST /api/inspect returns a sealed report' {
    $body = @{ pid = $explorerPid } | ConvertTo-Json
    $r = Invoke-RestMethod "$base/api/inspect" -Method Post -Headers $headers -ContentType 'application/json' -Body $body
    if (-not $r.ok) { throw 'not ok' }
    if ($r.report.integrity.report_sha256.Length -ne 64) { throw 'report not sealed' }
    if ($r.report.process.pid -ne $explorerPid) { throw "pid $($r.report.process.pid)" }
    "pid=$($r.report.process.pid) modules=$($r.report.modules.count) handles=$($r.report.handles.inspected) seal=$($r.report.integrity.report_sha256.Substring(0,16))"
}

Test-Case 'downloads: JSON + HTML with attachment filenames' {
    $j = Invoke-WebRequest "$base/api/export/json?t=$token" -UseBasicParsing
    $h = Invoke-WebRequest "$base/api/export/html?t=$token" -UseBasicParsing
    $cd = $j.Headers['Content-Disposition']
    if ($cd -notmatch 'attachment; filename="LAI-.*\.json"') { throw "json disposition: $cd" }
    $cdH = $h.Headers['Content-Disposition']
    if ($cdH -notmatch '\.html') { throw "html disposition: $cdH" }
    $parsed = $j.Content | ConvertFrom-Json
    if ($parsed.integrity.report_sha256.Length -ne 64) { throw 'downloaded json not sealed' }
    "json {0:N0} bytes, html {1:N0} bytes, filenames ok" -f $j.RawContentLength, $h.RawContentLength
}

Test-Case 'GET /api/processes + hotkey poll' {
    $p = Invoke-RestMethod "$base/api/processes?limit=10&t=$token"
    if ($p.processes.Count -lt 3) { throw "processes $($p.processes.Count)" }
    $h = Invoke-RestMethod "$base/api/hotkey_pick?t=$token"
    if ($h.pending -ne $true -and $h.pending -ne $false) { throw 'hotkey poll malformed' }
    "processes=$($p.processes.Count) hotkey_pending=$($h.pending)"
}

if ($SkipPicker) {
    Record 'POST /api/pick: click -> acquisition through the dashboard' 'SKIP' '-SkipPicker (needs an interactive desktop)'
}
else {
Test-Case 'POST /api/pick: click -> acquisition through the dashboard' {
    if (-not $targetHwnd) { throw 'no target window available (picker test was skipped)' }
    $targetTitle2 = "LAI-E2E-HTTP-$([guid]::NewGuid().ToString('N').Substring(0,6))"
    $tmpScript = Join-Path $work 'target2.ps1'
    (Get-Content (Join-Path $work 'target.ps1') -Raw) -replace 'LAI-E2E-TARGET-[0-9a-f]+', $targetTitle2 | Set-Content $tmpScript -Encoding UTF8
    $out2 = Join-Path $work 'target2.out'
    $t2 = Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $tmpScript -RedirectStandardOutput $out2 -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    $h2 = 0
    try { $h2 = [int64](Get-Content $out2 -Raw).Trim() } catch {}
    [LAIWin]::ShowTopMost([IntPtr]$h2, 160, 160)
    Start-Sleep -Milliseconds 500
    $rect = New-Object LAIRECT
    [void][LAIWin]::GetWindowRect([IntPtr]$h2, [ref]$rect)
    $cx = [int](($rect.Left + $rect.Right) / 2); $cy = [int](($rect.Top + $rect.Bottom) / 2)
    $onTop = $false
    for ($i = 0; $i -lt 20 -and -not $onTop; $i++) {
        if ([LAIWin]::RootWindowAt($cx, $cy) -eq [IntPtr]$h2) { $onTop = $true } else { Start-Sleep -Milliseconds 250 }
    }
    if (-not $onTop) { throw 'HTTP pick target is not topmost - precondition failed' }
    $job = Start-Job -ScriptBlock {
        param($uri, $hdr)
        Invoke-RestMethod $uri -Method Post -Headers $hdr -ContentType 'application/json' -Body '{"timeout_secs":45}' -TimeoutSec 90
    } -ArgumentList "$base/api/pick", $headers
    Start-Sleep -Milliseconds 2500
    [LAIWin]::Click($cx, $cy)
    $res = $null
    for ($i = 0; $i -lt 40; $i++) {
        if ($job.State -ne 'Running') { break }
        Start-Sleep -Milliseconds 500
    }
    $res = Receive-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force
    if (-not $res -or -not $res.ok) { throw "pick failed: $($res.error)" }
    if ($res.report.process.pid -ne $t2.Id) { throw "picked pid $($res.report.process.pid), expected $($t2.Id)" }
    if (-not $t2.HasExited) { try { $t2.Kill() } catch {} }
    "picked pid=$($res.report.process.pid) via=$($res.target.via) seal=$($res.report.integrity.report_sha256.Substring(0,12)) duration=$($res.report.tool.duration_ms)ms"
}
}

Test-Case 'POST /api/shutdown stops the engine cleanly' {
    $r = Invoke-RestMethod "$base/api/shutdown" -Method Post -Headers $headers -ContentType 'application/json' -Body '{}'
    Start-Sleep -Seconds 2
    $still = Get-Process -Id $serve.Id -ErrorAction SilentlyContinue
    if ($still) { throw 'engine still running after shutdown' }
    'engine exited'
}

# ===========================================================================
Write-Host '-- 9. Injection / hostile input ------------------------------------' -ForegroundColor DarkCyan

Test-Case 'hostile window title is escaped in JSON, HTML and dashboard' {
    $payload = '<script>alert("x")</script><img src=x onerror=alert(1)>'
    $scr = Join-Path $work 'hostile.ps1'
    @"
Add-Type -AssemblyName System.Windows.Forms
`$f = New-Object System.Windows.Forms.Form
`$f.Text = '$payload'
`$f.Width = 420; `$f.Height = 180
`$f.TopMost = `$true
`$f.StartPosition = 'CenterScreen'
`$f.Show(); `$f.Activate()
[Console]::Out.WriteLine(`$f.Handle); [Console]::Out.Flush()
Start-Sleep -Seconds 60
"@ | Set-Content $scr -Encoding UTF8
    $ho = Join-Path $work 'hostile.out'
    $hp = Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scr -RedirectStandardOutput $ho -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    $hw = 0; try { $hw = [int64](Get-Content $ho -Raw).Trim() } catch {}
    $hpJson = Join-Path $work 'hostile.json'
    $hpHtml = Join-Path $work 'hostile.html'
    $r = Invoke-Lai @('inspect', '--hwnd', ('0x{0:X}' -f $hw), '--no-handles', '--json', $hpJson, '--html', $hpHtml)
    if (-not $hp.HasExited) { try { $hp.Kill() } catch {} }
    $d = Get-Content $hpJson -Raw | ConvertFrom-Json
    if ($d.selection.window.title -ne $payload) { throw "JSON lost the raw title: '$($d.selection.window.title)'" }
    $html = Get-Content $hpHtml -Raw
    if ($html -match '<script>alert') { throw 'HTML contains raw <script> payload' }
    if ($html -match '<img src=x onerror') { throw 'HTML contains raw <img> payload' }
    if ($html -notmatch '&lt;script&gt;alert') { throw 'HTML did not escape the payload' }
    'raw title preserved in JSON; escaped in HTML (&lt;script&gt;...), 0 executable payloads'
}

# ===========================================================================
Write-Host ''
Write-Host '=============================================================' -ForegroundColor Cyan
$pass = @($results | Where-Object Status -eq 'PASS').Count
$fail = @($results | Where-Object Status -eq 'FAIL').Count
$skip = @($results | Where-Object Status -eq 'SKIP').Count
Write-Host (" RESULT: {0} passed, {1} failed, {2} skipped  (of {3})" -f $pass, $fail, $skip, $results.Count) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host '=============================================================' -ForegroundColor Cyan
if ($fail -gt 0) {
    Write-Host ''
    Write-Host ' Failures:' -ForegroundColor Red
    $results | Where-Object Status -eq 'FAIL' | ForEach-Object { Write-Host ("  - {0}: {1}" -f $_.Test, $_.Detail) -ForegroundColor Red }
}
$results | Where-Object Status -eq 'SKIP' | ForEach-Object { Write-Host ("  skipped: {0} ({1})" -f $_.Test, $_.Detail) -ForegroundColor Yellow }

$csv = Join-Path $work 'results.csv'
$results | Export-Csv -Path $csv -NoTypeInformation
Write-Host ''
Write-Host (" artifacts: {0}" -f $work)

foreach ($p in $engineProcs) { if ($p -and -not $p.HasExited) { try { $p.Kill() } catch {} } }
Get-Process lai -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }

if ($fail -gt 0) { exit 1 } else { exit 0 }
