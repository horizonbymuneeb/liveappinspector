# Architecture

## 1. Shape of the system

```
                 ┌──────────────────────────── ui/ (HTML + JS + CSS) ────────────────────────────┐
                 │  dashboard: pick button, hotkey poller, tabbed report view, export buttons   │
                 └───────────────────────────────▲───────────────────────────────────────────────┘
                                                 │  HTTP on 127.0.0.1 + X-LAI-Token
┌────────────────────────────────────────────────┴──────────────────────────────────────────────┐
│ engine (single static .exe, no runtime dependencies)                                          │
│                                                                                               │
│  main.rs ── CLI ──────────────┐                                                               │
│  server.rs ── routes ─────────┤                                                               │
│                               ▼                                                               │
│                        engine.rs  (orchestrator)                                              │
│      ┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐           │
│      ▼          ▼          ▼          ▼          ▼          ▼          ▼          ▼           │
│   window.rs process.rs  token.rs   tree.rs     net.rs   modules.rs handles.rs  binary.rs      │
│      │          │          │          │          │          │          │          │           │
│      └──────────┴──────────┴───── ffi.rs (all Win32/NT prototypes) ─────┴──────────┘          │
│                                    │            │            │                                │
│                               kernel.rs      catalog.rs    paths.rs                           │
│                                                                                               │
│  model.rs  = the report schema           report/json.rs = seal + verify                       │
│  win/dpi.rs = per-monitor-v2 coordinate fidelity (must run before any window)                   │
│  util.rs   = marshalling/time/errors     report/html.rs = self-contained exhibit              │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Acquisition pipeline

```
select target ─► open process (full ▸ limited ▸ kernel table)
                      │
                      ├─► identity (image path, arch, protection, times, memory)
                      ├─► token (SID, integrity, elevation, privileges, groups, session)
                      ├─► PEB read (cmdline, cwd, environment)      [fallback: CIM]
                      ├─► genealogy (kernel parent ▸ ancestors ▸ children ▸ descendants)
                      ├─► network (owner-PID TCP/UDP tables)
                      ├─► modules (EnumProcessModulesEx + version resources)
                      ├─► handles (system handle table ▸ duplicate ▸ type/name)
                      │      └─► registry view + Process-handle correlation
                      ├─► persistence (Run/RunOnce/RunServices/Winlogon + SCM services)
                      └─► binary (SHA-256 ×2 reads, NTFS identity, PE, Authenticode+catalog)
                      │
                      ▼
                 seal (SHA-256 over canonical JSON) ─► JSON / HTML / dashboard
```

Each collector returns a **populated section struct**, never an error to the
caller. A section that cannot be collected is returned with
`meta.status = denied|error|skipped|timeout`, `meta.error = <Win32 text>`,
`meta.win32_error = <code>` and one or more `meta.warnings`.

## 3. Failure philosophy

| Hazard | Handling |
|---|---|
| `OpenProcess` denied (PPL, SYSTEM, higher IL) | four-step degradation: full access → `PROCESS_QUERY_LIMITED_INFORMATION` → kernel process table → CIM; the report states which tier was used |
| A collector panics | `catch_unwind` in `engine::guard()` isolates it; that section becomes `Status::Error`, the rest of the report survives |
| `NtQueryObject` blocks (named pipes, hung drivers) | handle-name resolution runs on a watchdog worker thread with a 150 ms budget; a wedged worker is abandoned, a fresh one is spawned, and the handle is annotated `name query timed out` |
| Handle duplication refused (`ERROR_NOT_SUPPORTED`) | object name is marked unavailable, type resolution falls back to any other process holding the same type index; failures are never cached |
| `NtQuerySystemInformation` buffer races | the documented grow-and-retry loop with a hard ceiling (256 MiB handles / 512 MiB process table) |
| Enumeration never terminates | every loop has an iteration/row cap (`handle_cap`, 64 service pages, 512 descendants, 2 M handle entries) and records truncation in the report |
| Network table changes between size query and read | `ERROR_INSUFFICIENT_BUFFER` retry with headroom, bounded to 64 MiB |
| File locked by the running process | hashing uses `FILE_SHARE_READ|WRITE|DELETE` |
| File mutates during the hash | second independent read pass (`std::fs`) compared against the native pass; mismatch raises a warning |
| Exit code lies | `process.accessible` drives the CLI exit code (3 = access denied) |

## 4. Threading model

* **Main thread** — CLI parsing, or `serve()`'s accept loop.
* **HTTP** — one thread per connection (short-lived, `Connection: close`).
  `/api/pick` blocks its connection thread while the operator aims, which is why
  the design is thread-per-connection rather than a single-threaded reactor.
* **Picker** — a dedicated thread runs the overlay message loop; the caller waits
  on a channel with the same deadline the picker enforces.
* **Hotkey listener** — one persistent thread owning a message-only window and a
  `RegisterHotKey(Ctrl+Alt+F)` registration; hotkey picks are parked in a
  `Mutex<Option<PickResult>>` that the dashboard drains via `/api/hotkey_pick`.
* **Handle name resolver** — one worker thread (replaced if it wedges) consumes
  `NtQueryObject` requests, so the collection thread never blocks unboundedly.
* **Reverse DNS** — one throwaway thread per endpoint with a 700 ms budget.

All shared state is `Mutex`-guarded; the only `static mut`-like construct is a
`Mutex<PickState>`, and all Win32 handles are RAII-wrapped (`Process`, `Token`)
so they are closed on every path, including unwinds.

## 5. Why the FFI layer is hand-written

`win/ffi.rs` declares every prototype, struct and constant the collection path
uses (about 1 400 lines). Trade-off accepted deliberately:

* **Auditable ABI surface** — an examiner/reviewer sees exactly which kernel
  objects the tool touches; no opaque third-party binding crate re-declares them.
* **Layout control** — the truncation/union tricks (`SYSTEM_PROCESS_INFORMATION`,
  `WINTRUST_DATA.pFile` aliasing `WINTRUST_CATALOG_INFO`) are documented in place
  with the reason, which is impossible with a binding generator.
* **Optional DLLs loaded at runtime** (`dwmapi`, `wtsapi32`, `wintrust`,
  `version`) so a missing/SKU-trimmed DLL degrades one field instead of breaking
  the load, and the project builds without those import libraries.

## 6. Extension points

| Want to add | Touch |
|---|---|
| A new artifact section | `model.rs` (struct + field on `Report`), a collector in `win/`, one `guard(...)` call + one `sections[]` entry in `engine.rs`, a renderer branch in `report/html.rs` and a tab in `ui/app.js` |
| A new trust provider (e.g. WDAC/CI policy) | `win/catalog.rs` (same "verify then explain" shape) |
| A new end-to-end check | `tests/e2e.ps1` - add a `Test-Case 'name' { ... }` block; it records PASS/FAIL/SKIP and sets the exit code |
| Signed detection of “image on disk ≠ mapped image” | `win/binary.rs`: hash the mapped sections via `ReadProcessMemory` and compare to the PE file's sections |
| YARA/PE-sieve style scanning | new `win/scan.rs`, invoked from `engine.rs`, output as its own section so it cannot break collection |
| JSON → Elastic/CEF | consume `report/json.rs` output; the schema is versioned (`liveappinspector.report/v1`) |

## 7. Determinism & the seal

`report/json.rs` computes the seal over `serde_json::to_string_pretty` of the
report struct. Determinism relies on two properties:

1. struct field order is fixed by `model.rs` (serialized in declaration order),
2. the model contains no `HashMap`/`Map` fields — only `Vec` and `BTree`-free
   ordered collections.

Those constraints are deliberate and documented in the module; changing them
requires bumping `SCHEMA_VERSION` (the verification path refuses foreign
schemas).
