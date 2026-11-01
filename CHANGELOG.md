# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [1.1.0] - 2026-11-02

### Added

- **Module G - address space and memory anomalies.** A read-only `VirtualQueryEx`
  walk of the target classifies every committed region (image-backed, file-mapped,
  private), counts executable, executable-private and writable+executable regions
  with their byte totals, and lists the largest anomalies with base address,
  protection and region type. Executable private memory (no image backing on disk)
  and W+X regions are the cheapest high-signal triage leads for injected or
  manually mapped code. The section states facts and explicitly does not claim a
  verdict: CLR/JIT, browser, Go and Java runtimes create such regions normally.
  Reported as `memory` in JSON, a *Memory* tab in the dashboard, and a section in
  the HTML exhibit; bounded to 200k regions and the 250 largest anomalies.
- **Documentation website** at <https://horizonbymuneeb.github.io/liveappinspector/>
  (MkDocs Material, dark/light, full-text search). It is generated from the
  repository markdown by `scripts/build-docs-site.py`, so there is a single source
  of truth, and `.github/workflows/docs.yml` builds it with `mkdocs build --strict`
  so a broken link or nav entry fails the deploy.
- Unit tests for protection-flag decoding and the executable/writable predicates.

### Changed

- Default handle-resolution cap raised from 5000 to 8000: modern browsers and the
  shell routinely hold 4-6k handles, so the old default truncated exactly the
  processes examiners care about (~1.4 s end-to-end, `--handle-cap` overrides).
- Handle sections no longer degrade to `partial` for a handful of unresolvable
  object names or object types; a material share (>=5% of names, >=25% of types)
  is still a warning, and every case is recorded as a note on the section.

### Changed

- Report schema gained an additive section (`memory`); `liveappinspector.report/v1`
  is unchanged and existing consumers are unaffected (see `docs/SCHEMA.md`).

## [1.0.1] - 2026-11-01

Documentation and distribution patch. No changes to collection code, report
format or the schema: a 1.0.0 report verifies and parses identically.

### Added

- `docs/README.md` - documentation entry point routing each audience (operator,
  examiner, parser author, contributor) to the right document.
- `docs/FAQ.md` - the questions that actually come up: code-integrity blocks,
  `denied` sections, `type_N` handles, hash mismatches, catalog vs embedded
  signing, AV quarantine, "does it phone home".
- `scripts/check-docs.py`, wired into CI: relative links and heading anchors are
  validated on every push, so documentation cannot rot silently.
- README: documentation map table.

### Fixed

- **Portable bundle now ships the complete documentation set** (`docs/`,
  `schema/`, `samples/`, `scripts/`, licence and contributor files). Previously the
  bundled `README.md` linked to files that were not in the zip (16 dead links);
  the bundle is verified to have 0 broken relative links.
- `scripts/install.ps1`: an install no longer fails when a code-integrity policy
  blocks execution of the just-installed binary; it installs, then explains the
  block.
- `scripts/install.ps1`: checksum lookup now works when Windows PowerShell returns
  `SHA256SUMS.txt` as `byte[]` instead of a string (previously "no checksum
  published - refusing to install").
- release workflow: publishing is idempotent (refresh notes/assets when the
  release exists), `workflow_dispatch` checks out the tag instead of the default
  branch, and every asset now carries a build provenance attestation.

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

[Unreleased]: https://github.com/horizonbymuneeb/liveappinspector/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/horizonbymuneeb/liveappinspector/releases/tag/v1.1.0
[1.0.1]: https://github.com/horizonbymuneeb/liveappinspector/releases/tag/v1.0.1
[1.0.0]: https://github.com/horizonbymuneeb/liveappinspector/releases/tag/v1.0.0
