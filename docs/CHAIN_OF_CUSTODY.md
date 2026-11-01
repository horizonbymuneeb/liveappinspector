# Chain of custody

LiveAppInspector produces two mutually consistent exhibits per acquisition:

1. **`*.json`** — the machine-readable record, sealed with a SHA-256 that covers
   the entire report body.
2. **`*.html`** — a self-contained human-readable exhibit of the same report,
   including the seal, the custody log and the collection warnings.

Both are written atomically (`write → rename`) so a crash cannot leave a
half-written exhibit that looks complete.

---

## 1. What is recorded, and when

Every section carries `meta.collected_at_utc` (microsecond precision, UTC). In
addition, `integrity.custody_log` is an **ordered, gap-free event log**:

| `action` | Meaning |
|---|---|
| `acquisition_start` | tool version, schema, selection mode, PID |
| `privilege_state` | whether the engine was elevated and whether `SeDebugPrivilege` was enabled |
| `module_collect` | one entry per completed collector with its key metrics |
| `module_failed` | a collector panicked or was refused (with the reason) |
| `hash_computed` | path, SHA-256, byte count, duration, timestamp |
| `acquisition_complete` | total duration and number of degraded sections |

The log is append-only for the lifetime of the acquisition: `seq` increases
monotonically and each event is timestamped when it is emitted, not when the
report is written.

---

## 2. The seal

```
report_sha256 = SHA-256( canonical_json(report) )
canonical_json(report) = to_string_pretty(report) with
        integrity.report_sha256 = ""
        integrity.sealed_at_utc = ""
        integrity.hash_algorithm = "SHA-256"
        integrity.seal_scope     = <the constant string>
```

Everything else — every artifact, every warning, every custody event, the tool
version, host identity, case metadata — is inside the hash. Changing a single
byte of any collected value invalidates the seal.

Why blank those four fields: they are the seal itself and its provenance. The
scope string is a constant, so including it adds no entropy but keeps the
canonical form stable across versions that share a schema.

Why pretty-printed JSON: the seal must be recomputable by a human with standard
tools, not only by this program.

---

## 3. Verification

### Automatic

```powershell
lai verify case42.json
```

```
LiveAppInspector seal verification
  report        : case42.json
  target        : explorer.exe (pid 7616)
  sealed at     : 2026-11-01T14:50:34.369826Z
  embedded seal : 5a00763bd33bb21c29b5819af4a04851cb1ac9fb9f21b366eaef1314f06b8b5a
  recomputed    : 5a00763bd33bb21c29b5819af4a04851cb1ac9fb9f21b366eaef1314f06b8b5a
  VERDICT       : MATCH - report is intact
  binary sha256 : eee089fe6f927c7f0d51b0abd9d70c094157e33673ad760713ec7b1cea18ee11
  degraded      : 0 section(s), 12 custody events
```

Exit code `0` = intact, `2` = mismatch/parse failure. A mismatch means the JSON
was modified after sealing and the exhibit must not be relied upon.

### By hand (no tooling from this project)

```powershell
# 1. take the embedded seal out of the document
$json = Get-Content case42.json -Raw | ConvertFrom-Json
$embedded = $json.integrity.report_sha256

# 2. blank the seal fields, re-serialize with the same indentation
$json.integrity.report_sha256 = ""
$json.integrity.sealed_at_utc = ""
$json.integrity.hash_algorithm = "SHA-256"
$json.integrity.seal_scope = "SHA-256 over the UTF-8 JSON of this report with integrity.report_sha256 and integrity.sealed_at_utc emptied"
$canonical = $json | ConvertTo-Json -Depth 100

# 3. hash the canonical form (PowerShell 7 writes the same JSON shape as serde_json
#    for this schema: 2-space indent, `": "` separators, no trailing newline)
$bytes = [Text.Encoding]::UTF8.GetBytes($canonical.TrimEnd())
[BitConverter]::ToString([Security.Cryptography.SHA256]::HashData($bytes)).Replace('-','').ToLower()
```

> Note: hand verification is only byte-exact when the re-serializer matches
> `serde_json::to_string_pretty` (2-space indent, `": "`, arrays one element per
> line, no trailing newline). The `lai verify` path is authoritative; the manual
> recipe is documented so the method itself can be audited, and so the JSON can
> be inspected independently.

---

## 4. Evidence handling recommendations

1. **Capture the report and its hash at the scene.** Export JSON + HTML, then
   record the report seal in the case notes.
2. **Also record the host clock offset.** `tool.host.uptime_seconds` and
   `tool.host.boot_time_utc` let a reviewer detect a tampered system clock
   (compare against `process.times.created_utc` and known boot events).
3. **Keep the original files.** The tool writes new files with `write + rename`;
   it never rewrites an exhibit. Re-running an acquisition creates a *new*
   sealed report with a new timestamp — it does not update the old one.
4. **Treat `sha256_of_binary` separately from the report seal.** The report seal
   proves the report is unmodified; the binary hash proves what was on disk at
   acquisition time. Cross-check the binary hash with an independent tool
   (`certutil -hashfile <path> SHA256`) whenever possible — this implementation
   already performs a second internal read pass and warns on mismatch.
5. **Document the privilege level.** `tool.running_elevated` and
   `tool.debug_privilege_held` bound what the acquisition *could* have seen;
   `integrity.sections_degraded` plus per-section `status` bound what it *did*
   see. A "clean" report from an unelevated run is not evidence of absence.

---

## 5. What the seal does not prove

* It does not prove the **collection was complete** — check
  `integrity.sections_degraded` and each section's `status`.
* It does not prove the **host was truthful** — a kernel-mode rootkit can lie to
  every user-mode API this tool calls. Presence of such a rootkit is itself a
  finding; the seal only proves the report was not edited after the fact.
* It is **not a digital signature.** It is an integrity checksum, not proof of
  authorship: an attacker with write access can recompute a matching seal. For
  court-facing work, additionally sign the exported file with your
  organisation's key (GPG / Authenticode timestamped signature) and record that
  signature hash in the case file.
