# Contributing to LiveAppInspector

Thanks for helping. This is a Windows forensics tool, so correctness and
evidentiary honesty matter more than features: **a wrong field in a report is a
worse outcome than a missing one.**

## 1. Set up

```powershell
winget install Rustlang.Rustup
rustup default stable-x86_64-pc-windows-gnu     # MSVC is not required
rustup component add rustfmt clippy

git clone https://github.com/horizonbymuneeb/liveappinspector.git
cd liveappinspector
.\build.ps1                                     # builds dist\lai.exe, runs the tests
```

Optional but recommended before a PR:

```powershell
cd engine
cargo fmt --all
cargo clippy --release --all-targets -- -D warnings
cargo test --release
cd ..
.\tests\e2e.ps1                                 # 40 acceptance checks on a live desktop
```

`tests/e2e.ps1 -SkipPicker` skips the two synthetic-click checks (use it on a
headless or Session-0 host). `tests/ui-smoke.js` needs Edge and a running engine;
it drives a real Chromium over the DevTools protocol and is the only layer that
can prove the dashboard actually boots.

## 2. Project map

| Area | Where |
|---|---|
| Report schema (the contract) | `engine/src/model.rs` |
| Collection orchestrator (per-module isolation) | `engine/src/engine.rs` |
| One module per forensic concern | `engine/src/win/*.rs` |
| Win32/NT prototypes and structs | `engine/src/win/ffi.rs` |
| Seal / verification | `engine/src/report/json.rs` |
| HTML exhibit | `engine/src/report/html.rs` |
| Loopback HTTP bridge | `engine/src/server.rs` |
| Dashboard | `ui/index.html`, `ui/app.js`, `ui/style.css` |
| Design notes | `ARCHITECTURE.md`, `docs/FORENSIC_NOTES.md` |

Adding an artifact section means touching five places: `model.rs` (struct +
`Report` field), a collector under `win/`, one `guard(...)` call plus a
`sections[]` entry in `engine.rs`, a renderer branch in `report/html.rs`, and a
tab panel in `ui/app.js`. Update `docs/SCHEMA.md` and `CHANGELOG.md` in the same
PR.

## 3. Rules that are not negotiable

1. **Never commit real evidence.** No report JSON, no HTML exhibits, no
   screenshots of a real examination. `samples/` and `.gitignore` are set up
   accordingly; use the sanitising helper in `samples/README.md` if you must
   share a shape.
2. **Every new artifact needs provenance.** State where the value came from
   (live process, kernel table, CIM fallback, …) and record it in the report
   (`*_source` fields) — reviewers must be able to disagree with an inference.
3. **Never hard-fail a section.** Collectors return a populated struct with
   `meta.status` (`ok` / `partial` / `denied` / `error` / `skipped` / `timeout`)
   plus the Win32 error; a refusal is evidence, a crash is a lost acquisition.
4. **Bound every loop and every blocking call.** Iteration caps, buffer caps and
   timeouts (see `win/handles.rs` for the watchdog pattern).
5. **Read-only.** No writes into the target: no memory writes, no registry or
   service changes, no suspend/inject/terminate. File handles use
   `FILE_SHARE_READ|WRITE|DELETE` with `GENERIC_READ` only.
6. **No new network egress.** The engine only binds `127.0.0.1`. Reverse DNS is
   opt-in, bounded, and never resolves wildcard/loopback addresses.
7. **Escape attacker-controlled strings.** Window titles, paths, registry keys
   and command lines are hostile input; they must pass through the HTML/JS
   escapers before rendering.

## 4. Code style

- `rustfmt` defaults, `clippy -D warnings`. `unsafe` blocks need a `// SAFETY:`
  comment stating the invariant that makes them sound.
- FFI lives in `win/ffi.rs`. Do not pull in a bindings crate: the point is that
  the ABI surface this tool touches is auditable in-repo. Document any struct
  truncation or union aliasing where it happens.
- Prefer returning `WResult<T>` from leaf functions and translating to a report
  `status` at the module boundary.
- Public behaviour changes need a test. Report-shape changes need a
  `schema`-version discussion first.

## 5. Commits and pull requests

- Conventional-ish prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `perf:`, `chore:`.
- One logical change per PR; include the *why* in the description and note any
  effect on evidence interpretation.
- PR checklist: `fmt` · `clippy -D warnings` · `cargo test` · `tests/e2e.ps1` ·
  docs/CHANGELOG updated · no evidence or host data committed · no new
  dependencies without justification (four runtime deps today: `serde`,
  `serde_json`, `sha2`, and the standard library).
- Security-relevant changes (FFI, token handling, HTTP bridge, escaping) will be
  reviewed twice.

## 6. Reporting bugs

Open an issue with `lai self-check` output, the exact command, the section
`status`/`error` pair from the report (redacted), and whether the engine was
elevated. For anything that could be a vulnerability, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.
