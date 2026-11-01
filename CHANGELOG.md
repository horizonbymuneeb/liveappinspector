# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [1.0.0] - 2026-11-01

First public release: a single self-contained `lai.exe` (no runtime, no MSVC
required) plus an embedded dark dashboard served over loopback.

### Added

- **Point-and-shoot selection** — crosshair overlay picker, global `Ctrl+Alt+F`
  hotkey on a message-only window, `WindowFromPoint` → `GA_ROOT` →
  `GetWindowThreadProcessId` resolution, keyword arguments for `--pid`,
  `--window`, `--hwnd`, plus a foreground-window default.
- **Module A — identity**: image path/name/directory, x86/x64/ARM64 + WOW64,
  creation/exit/kernel/user times, working set, handle/thread counts, priority,
  PS_PROTECTION (PPL) level and signer, DWM-cloaked window state, window class,
  DPI, style bits, rectangles.
- **Module B — user context**: SID, account name/domain/type, integrity level
  (with RID), elevation + elevation type with a human verdict, session id/kind
  (console/RDP/service/kernel), session user and RDP client, token id, logon
  session LUID, token type, owner SID, AppContainer and virtualization flags,
  full privilege list with attributes, full group list.
- **Module C — genealogy**: kernel-verified parent, ancestor chain, children,
  breadth-first descendants, live command line / working directory / environment
  from the PEB (native *and* WOW64 layouts), CIM fallback labelled as such, and a
  **PPID-recycling detector** (parent created after child).
- **Module D — network**: owner-PID TCP/UDP tables for IPv4 and IPv6 with state,
  endpoints, optional bounded reverse DNS (wildcard/loopback/link-local
  addresses are never resolved).
- **Module E — modules, handles, registry, services**: module list with version
  resources, base/size and *missing-on-disk* detection; system handle table
  filtered to the PID with object type/name resolution on a watchdog worker
  (150 ms budget, wedged workers abandoned), `Process`-type handles resolved to
  target PIDs, registry keys mapped to `HKLM\…`/`HKU\…`, autostart correlation
  (`Run`, `RunOnce`, `RunServices`, `Winlogon`), SCM service registrations.
- **Module F — integrity & chain of custody**: streamed SHA-256 with an
  independent second read pass (tamper-during-collection detection), NTFS volume
  serial + file index, file attributes/timestamps/hard links, PE header parse,
  Authenticode **and security-catalog** trust with signer attribution, ordered
  custody log, and a SHA-256 report seal with `lai verify`.
- **Kernel-table fallback**: when `OpenProcess` is refused (PPL/SYSTEM), image
  name, start time, parent, thread count still come from
  `NtQuerySystemInformation(SystemProcessInformation)` so the on-disk image can
  still be hashed and trust-checked — with explicit provenance labelling.
- **Dashboard**: nine tabs with live counts, per-section health table, sidebar
  target card and seal, JSON/HTML export buttons, process picker, reverse-DNS and
  skip-handles toggles, in-app elevation, strict CSP, per-run session token.
- **Exhibits**: sealed JSON plus a self-contained, script-free HTML report.
- **Tests**: 12 unit/integration tests, a 40-check end-to-end acceptance suite
  (`tests/e2e.ps1`) and a Chromium-driven UI smoke test (`tests/ui-smoke.js`).
- **Packaging**: `build.ps1`, `scripts/package.ps1` (portable ZIP + SHA-256
  sums), one-click launchers, Scoop and winget manifests, GitHub Actions CI and
  release workflows. The portable bundle ships the complete documentation set
  (`docs/`, `schema/`, `samples/`, `scripts/`, licence and contributor files) so
  every link in the bundled README resolves offline.
- **Documentation**: `docs/README.md` index, `docs/FAQ.md` for the questions that
  actually come up (code-integrity blocks, `denied` sections, catalog vs embedded
  signing, hash mismatches), `docs/SCHEMA.md` + generated JSON Schema, and a
  CI-enforced link/anchor check (`scripts/check-docs.py`).

### Fixed

Bugs found by the acceptance suite before the first release:

- **Wrong window could be reported on scaled or multi-monitor desktops.** The
  engine was DPI-unaware, so `GetCursorPos`/`WindowFromPoint` operated in a
  virtualised coordinate space; a click at `(400,260)` resolved to `(-1848,-190)`
  and attributed the report to the wrong process. The engine now opts into
  per-monitor-v2 DPI awareness before creating any window and records
  `tool.dpi_awareness` in every report.
- **`lai verify` rejected BOM-prefixed exhibits.** Files that passed through
  Windows tooling (`Set-Content -Encoding UTF8`, Excel, case management) carry a
  UTF-8 BOM; verification now strips it, with a regression test.
- **The dashboard could not boot.** The CSP was `script-src 'unsafe-inline'`
  without `'self'`, so browsers downloaded `/app.js` and refused to execute it.
  The token now ships as inert `application/json` and the policy is strict.
- **Hidden panels rendered anyway.** `.dropdown { display: flex }` overrode the
  UA `[hidden]` rule, so the process picker covered the tab bar; `[hidden]` is now
  forced with `!important` and guarded by a test.
- Handle object types that cannot be duplicated out of their process (common for
  unelevated SYSTEM targets) are now explained instead of surfacing as opaque
  `type_N` values.
- `::`/`0.0.0.0` endpoints are no longer reverse-resolved into the local
  hostname, which would have put fabricated evidence in a report.

### Security

- Loopback-only HTTP bridge, per-run 128-bit session token required on every
  `/api/*` call, exact-match routing (no filesystem surface), request header and
  body caps, strict CSP, and read-only collection (no memory writes, no
  registry/service mutations, nothing injected or suspended).
- Every collected value is HTML-escaped before it reaches an exhibit; window
  titles, paths and registry keys are attacker-controlled strings.

[Unreleased]: https://github.com/horizonbymuneeb/liveappinspector/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/horizonbymuneeb/liveappinspector/releases/tag/v1.0.0
