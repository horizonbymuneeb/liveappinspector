# FAQ / troubleshooting

Real questions that came up while building and testing this tool. Each answer
says what the tool does and *why*, because a forensic tool that hides its
reasoning is not usable in an investigation.

---

### "Windows blocked it — 'blocked by your organization's Device Guard policy'"

Not a bug. The binary is unsigned and Smart App Control (`{0283ac0f-fff1-49ae-ada1-8a933130cad6}`)
or a WDAC/AppLocker policy refuses to load it. A self-signed certificate does not
help: SAC requires a trusted-publisher chain with cloud reputation.

Diagnose and fix: [DEPLOYMENT.md](DEPLOYMENT.md) (section 2, "Windows blocked the app").
Options: run on a test VM / a host without SAC, sign with a real code-signing
certificate, or disable SAC (one-way, device-owner decision).

---

### "Half the sections say `denied`. Is the tool broken?"

No — the process refused a handle. Typical targets: PPL/PP processes (AV/EDR),
`MsMpEng.exe`, LSA, or any SYSTEM process when the engine is not elevated.

- `process.meta.status = denied` with the exact Win32 error,
- `tool.running_elevated` / `tool.debug_privilege_held` record what the engine was
  allowed to do,
- the kernel process table still supplies image name, start time, parent and
  thread count, so the **on-disk image is still hashed, PE-parsed and
  trust-checked**, with `process.image_path_source` saying it came from the kernel.

Re-run from the *Administrator* launcher for full coverage. A `denied` section is
never "nothing happened" — read `meta.status` before concluding anything.

---

### "Handles show `type_56` / `type_21` instead of a real object type"

`PROCESS_DUP_HANDLE` was refused, so the object could not be duplicated into the
engine to ask for its type. The section warns when this affects ≥25% of handles.
Elevate the engine and the names resolve (type indices are stable per boot, so
they are cached for the process lifetime).

---

### "Why is the handle count lower than Task Manager?"

`handles.inspected` is the number of handle-table entries the kernel returned for
that PID; `handles.items` is the subset resolved within the cap
(`--handle-cap`, default 5000) and the per-object time budget (150 ms). Truncation
is recorded (`handles.truncated`, plus a warning). Nothing is silently dropped.

---

### "The SHA-256 differs from what my EDR/vendor says"

Three possibilities, all visible in the report:

1. `binary.meta.warnings` contains a **hash-mismatch** note → the file changed
   between the two read passes (live update, or tampering during acquisition).
2. `binary.path` shows a different path than expected (`process.image_path_source`
   tells you whether it came from the live handle, the kernel table, or a verified
   name search).
3. The process is hollowed/injected: the mapped image is not the file on disk.
   Look for `modules.missing_on_disk`, and prefer `process.image_path_source` =
   `live process` reports.

---

### "PE timestamp is in 2071 — is that timestomping?"

Almost certainly not. Microsoft and other vendors use deterministic builds
(`/Brepro`) that put a hash in `TimeDateStamp`. The report explicitly labels this
instead of raising a false timestomping warning. Only a timestamp that is *newer
than the file's last-write time but still in the past* produces a warning.

---

### "Is `winlogon.exe` unsigned? The report says `valid` with source `catalog`"

Most of `System32` has **no embedded Authenticode signature**; it is signed by a
security catalog (`.cat`) that the kernel and AppLocker trust. The engine verifies
the catalog member (hash → catalog → chain) and records
`signature.signature_source = catalog` plus `catalog_path`. Reporting these as
"unsigned" would be wrong, which is why the extra pass exists.

---

### "The picker selected the wrong window"

Fixed in 1.0.0 and now guarded by a test. The cause was DPI-unaware coordinates:
a scaled or multi-monitor desktop virtualises `GetCursorPos`/`WindowFromPoint`, so
the report could describe a *different* process. The engine now opts into
per-monitor-v2 awareness before creating any window and records
`tool.dpi_awareness`. If you ever see `system_or_unaware`, trust `pid`/`hwnd` over
`selection.screen_x/y`.

---

### "Antivirus quarantined `lai.exe`"

Expected for this class of tool: it opens other processes, enumerates handles,
reads tokens and hashes images. It contains no injection, credential access or
persistence. Sign the binary and add an exclusion for the tool directory; the
source is public so the behaviour can be reviewed line by line.

---

### "Does it write anything to the target machine?"

Collection is read-only: file handles are `GENERIC_READ` with
`FILE_SHARE_READ|WRITE|DELETE`, no registry writes, no service changes, no
injection/suspend/terminate, no memory writes. The engine does write **its own**
export files (`--json`, `--html`) and binds `127.0.0.1` for the dashboard.

---

### "Does it phone home?"

No telemetry, no update check. The only outbound traffic is reverse DNS for remote
endpoints, and only with `--resolve-dns` (bounded, 700 ms per lookup, and it never
resolves wildcard/loopback/link-local addresses).

---

### "Can I run it on a server / without a desktop?"

Yes for the CLI: `lai inspect --pid … --json …` needs no window station. The
crosshair picker obviously needs an interactive desktop; `lai serve` starts the
dashboard but the hotkey and overlay will not work over a disconnected session.

---

### "`lai verify` says MISMATCH — is the report useless?"

A mismatch means the JSON was modified after sealing (an editor, a script, a
redaction tool). Do not rely on it. If you edited it deliberately, re-seal with
`lai render edited.json --reseal --json edited.json` — and keep the original
exhibit, because the reseal is a new chain of custody, not a repair of the old one.
