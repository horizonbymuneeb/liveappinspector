# Deployment & troubleshooting

## 1. One-click usage (normal workstation)

Nothing needs to be compiled — ship `dist\` as-is:

```
dist\
├── lai.exe
├── Start LiveAppInspector.cmd                  <- double-click
├── Start LiveAppInspector (Administrator).cmd  <- double-click for full coverage
├── README.md
└── docs\
```

1. Double-click **`Start LiveAppInspector.cmd`** → a console shows the engine URL
   and your default browser opens the dashboard automatically.
2. Press **Ctrl+Alt+F** (or click the crosshair button), then click the target
   application.
3. Use **Export → JSON report / HTML exhibit** (the JSON is sealed).
4. Close the console window (or Ctrl+C) to stop the engine.

For SYSTEM/service/protected targets use
**`Start LiveAppInspector (Administrator).cmd`** — it raises the UAC prompt and
then runs the same dashboard with an elevated token.

From a terminal, the equivalent is:

```powershell
.\lai.exe serve --open                 # dashboard + hotkey, ephemeral port
.\lai.exe serve --open --port 8787     # fixed port
.\lai.exe inspect --window --json c.json --html c.html
```

---

## 2. "Windows blocked the app" — Smart App Control / WDAC / AppLocker

If double-clicking produces **exit code 126** in a shell, or Windows shows
*"was blocked by your organization's Device Guard policy"*, the binary is being
stopped by **code integrity**, not by a bug. Confirm with:

```powershell
# SAC state: Off / On / Evaluation
(Get-MpComputerStatus).SmartAppControlState
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState

# the blocked file will be named here (event 3077)
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 20 |
  Where-Object Id -in 3077,3033 | ForEach-Object { $_.Message }
```

Typical message:

```
Code Integrity determined that a process (...) attempted to load ...\lai.exe
that did not meet the Enterprise signing level requirements or violated code
integrity policy (Policy ID:{0283ac0f-fff1-49ae-ada1-8a933130cad6}).
```

`{0283ac0f-fff1-49ae-ada1-8a933130cad6}` is the **Smart App Control** policy.
SAC blocks unsigned executables that the Microsoft Intelligent Security Graph has
no reputation for — including a binary you just compiled yourself. A *self-signed*
certificate does **not** satisfy it (verified: signature `Valid`, still blocked);
SAC wants a trusted-publisher chain with cloud reputation.

Observed behaviour worth knowing: a freshly built binary may run for a while and
then start being blocked once SAC finishes evaluating it, so "it worked
yesterday" is not evidence that it will work today.

### Options

| Option | How | Notes |
|---|---|---|
| **Run it on a normal host / VM** | copy `dist\` to a test VM | Recommended for DFIR work anyway: triage tools belong on a controlled fly-away laptop, not the examiner's daily box |
| **Turn Smart App Control off** | Settings → Privacy & security → Windows Security → App & browser control → Smart App Control → **Off**, then reboot | **One-way on this Windows install** — SAC cannot be re-enabled without a Windows reset. This is a security decision for the device owner, not something a tool should do silently |
| **Code-sign with a real certificate** | OV/EV code-signing cert + timestamping (see README) | May need some time to accumulate ISG reputation before SAC stops blocking; not guaranteed on day one |
| **Managed fleet (WDAC/AppLocker)** | add the publisher or file hash to your own policy | The policy owner controls this; `lai.exe` is a normal Win64 PE, so hash/publisher rules both work |

> The registry equivalent of the SAC switch is
> `HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy\VerifiedAndReputablePolicyState = 0`
> followed by a reboot.

---

## 3. Other runtime notes

| Symptom | Cause | Fix |
|---|---|---|
| Sections show `denied` on a SYSTEM/protected target | engine not elevated | run the **Administrator** launcher; `lai.exe self-check` reports `elevated: false` |
| `handles` shows `type_56`-style names | `PROCESS_DUP_HANDLE` refused (typical when unelevated against a service) | elevate; the report says this explicitly |
| Browser does not open | no default browser association in that session | copy the printed `http://127.0.0.1:<port>/` URL manually |
| Dashboard cannot reach the engine | engine stopped or port changed | the console prints the exact URL and session token |
| `lai verify` says MISMATCH | the JSON was edited after sealing | use the original exhibit; a mismatch means the report is not trustworthy |
| Antivirus flags the tool | unsigned DFIR binary that enumerates processes/handles | expected for this class of tool: sign it, or add an exclusion for the tool directory in the AV console |

---

## 3b. Acceptance test (do this before trusting a build)

```powershell
.	ests\e2e.ps1 -Verbose
```

37 checks, no mocks: it inspects a real process, hashes it and cross-checks the
SHA-256 against `certutil`, seals/verifies/tampers an exhibit, exercises the
loopback API with and without a token, resolves a synthetic click through the
crosshair picker, and throws a `<script>` payload at the renderers. Exit code 0
means every executed check passed; `-SkipPicker` skips the two synthetic-click
checks on a headless/Session-0 host (they will report SKIP, not FAIL).

For the UI layer specifically (HTTP checks cannot prove that a browser booted the
page), run the Chromium-driven smoke test:

```powershell
.\lai.exe serve --port 8787                    # note the printed session token
start msedge --app=http://127.0.0.1:8787/ --remote-debugging-port=9222 --user-data-dir=%TEMP%/lai-ui --no-first-run
node tests/ui-smoke.js . <target-pid> <session-token>
```

It runs an acquisition from the page's own JavaScript, asserts the DOM rendered
(tab bar visible, cards present, hash shown, no leaked dropdown), verifies
`typeof api === 'function'`, and writes reference screenshots.

If a check fails with *"blocked by your organization's Device Guard policy"*, see
section 2 - the test harness is telling you the binary cannot execute on that
host, not that the code is wrong.

---

## 4. Building on another machine

```powershell
winget install Rustlang.Rustup
rustup default stable-x86_64-pc-windows-gnu
.\build.ps1
```

`build.ps1` finds `cargo` even if it is not on `PATH`, runs the test suite
(falling back to `cargo test --release` when a code-integrity policy blocks the
freshly built debug harness), builds `dist\lai.exe`, and stages the launchers and
documentation next to it.
