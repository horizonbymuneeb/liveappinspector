# Forensic notes — provenance and interpretation of each artifact

This file exists so an examiner can defend every field in the report. Each entry
states **where the data came from**, **what can make it wrong**, and **what it
does not mean**.

---

## A. Selection & window

| Field | Source | Caveats |
|---|---|---|
| `tool.dpi_awareness` | `SetProcessDpiAwarenessContext` result | `per_monitor` means the window geometry and pick coordinates are physical pixels. If a build ever reports `system_or_unaware`, treat `selection.screen_x/y` and `window.rect` as virtualised and prefer the HWND/PID for identification. |
| `selection.hwnd`, `window.*` | `WindowFromPoint` + `GetAncestor(GA_ROOT)`, `GetWindowTextW`, `GetClassNameW`, `GetWindowRect`, `GetWindowLongPtrW`, `GetDpiForWindow` | Titles are attacker-controlled strings and may contain misleading text or RTL-override characters. `is_cloaked` (DWM) marks UWP windows that are "visible" but not composited. A child window is normalised to its root window; the *clicked* child is not recorded. |
| `process.pid` | `GetWindowThreadProcessId` | Correct by definition of the click; if the window belongs to a broker/host (`RuntimeBroker.exe`, `svchost.exe`), the *hosting* process is reported — that is the process with the window, not necessarily the code you visually identify. |

## B. Identity & token

| Field | Source | Caveats |
|---|---|---|
| `user_context.*` | `OpenProcessToken` + `GetTokenInformation` classes 1, 2, 3, 4, 10, 12, 18, 20, 24, 25, 29 | Authoritative for "what the process is running as". `LookupAccountSidW` needs a reachable DC for domain SIDs; when offline you get the SID with an empty name — that is normal, not a failure. |
| `integrity.name` | Token integrity SID (S-1-16-*), RID mapped to a label | `medium_plus` = UIAccess. `protected_process` (0x5000) is rare outside PPL contexts. |
| `elevation.verdict` | `TokenElevation` + `TokenElevationType` | `is_elevated=false` with `elevation_type=limited` means a UAC split token (standard user context) — the same user may own a second, elevated process elsewhere. Compare `token.authentication_id` (logon session LUID) across processes to prove they share a logon. |
| `session.*` | `WTSQuerySessionInformationW` | `kind=service` means session 0. `client_address` is only populated for RDP. The *session* user can differ from the *token* user (e.g. a service in an interactive session). |
| `privileges[]` | Token privilege list | "Enabled" is a point-in-time attribute. `SeDebugPrivilege` present-but-disabled is still a privilege-escalation capability for an administrator. |

## C. Genealogy

| Field | Source | Caveats |
|---|---|---|
| `genealogy.parent` | `NtQueryInformationProcess(ProcessBasicInformation).InheritedFromUniqueProcessId` | Modern Windows *reparents*: a process whose launcher exited is reparented, and the PID may then be reused. Two safeguards are recorded: `parent.is_alive` and a warning when the parent's creation time is **later** than the child's (impossible for a real ancestor = PID recycling). |
| `genealogy.ancestors` | Toolhelp `th32ParentProcessID` walk | After the first hop this uses Toolhelp, which is best-effort. Treat deep ancestry as indicative. |
| `process.command_line` | Read from the target's PEB (`RTL_USER_PROCESS_PARAMETERS.CommandLine`) | Live memory: reflects the actual launch line, and can differ from what an event log recorded. When the PEB is unreadable, the value comes from `Win32_Process.CommandLine` and `command_line_source` says so. A CIM value can be stale or suppressed. |
| `process.environment` | PEB environment block | Same provenance caveat; extremely useful for spotting injected `PATH`/`TEMP`/`APPDATA` redirection. |

## D. Network

| Field | Source | Caveats |
|---|---|---|
| `network.connections[]` | `GetExtendedTcpTable`/`GetExtendedUdpTable` (`TCP_TABLE_OWNER_PID_ALL`, `UDP_TABLE_OWNER_PID`) | Endpoint ownership is kernel-provided and reliable. UDP tables have no remote address or state — `remote_address` is `*` and `state` is `OPEN`. Connections opened and closed between collection and reading are invisible; this is a snapshot, not a flow log. |
| `remote_hostname` | `getnameinfo` (opt-in, 700 ms budget) | Absence of a hostname proves nothing (DNS may be blocked). Never treat a resolved name as attribution. |

## E. Modules, handles, registry, services

| Field | Source | Caveats |
|---|---|---|
| `modules.items[]` | `EnumProcessModulesEx(LIST_MODULES_ALL)` + `GetModuleFileNameExW` + version resources | Includes both 32- and 64-bit modules of a WOW64 target. `missing_on_disk=true` means the image is mapped but no file exists at that path — a strong indicator of manual mapping, process hollowing, or a deleted DLL. Version strings come from the file, so they can be forged by a packed binary. |
| `handles.items[]` | `NtQuerySystemInformation(SystemExtendedHandleInformation)` filtered to the PID, then `DuplicateHandle` + `NtQueryObject` | Named pipes are deliberately not name-resolved (the query blocks). Windows 11 redacts object addresses, so `object_address` is usually empty. Handles that cannot be duplicated report why. `Process`-type handles are resolved to target PIDs — a valuable "who can this process touch" signal (e.g. LSASS handles from an unknown binary). |
| `registry.keys[]` | `Key`-type handle names, mapped `\REGISTRY\MACHINE\… → HKLM\…`, `\REGISTRY\USER\<SID> → HKU\<SID>` | Only keys the process *currently holds open*. Absence ≠ the process never touched the registry. |
| `registry.autoruns[]` | `Run`, `RunOnce`, `RunServices`, `RunServicesOnce` (HKLM + HKCU + WOW6432Node) and the `Winlogon` execution values | Only entries whose command references this image are included. `REG_EXPAND_SZ` values are expanded. This is a *correlation*, not proof the entry is malicious. |
| `services.services[]` | `EnumServicesStatusExW(SC_ENUM_PROCESS_INFO)` + `QueryServiceConfigW` | Two matchers, both recorded: services whose hosted process is this PID, and services whose configured image path is this binary (persistence even when dormant). Service binary paths often include arguments; they are stripped before comparison and the raw value is preserved. |

## G. Address space / memory anomalies

| Field | Source | Caveats |
|---|---|---|
| `memory.regions_scanned`, `committed_*`, `image_bytes`, `mapped_bytes`, `private_bytes` | `VirtualQueryEx` walk of the target's address space | A snapshot: regions can be allocated/freed between the walk and the report. `image_bytes` counts mapped PE images (modules), not file-backed data. |
| `memory.executable_regions`, `private_executable_regions`, `writable_executable_regions` (+ byte totals) | Same walk, decoded from `Protect` | `PAGE_GUARD` and `PAGE_NOACCESS` regions are excluded. Private executable memory is **normal** for CLR/JIT, browser, Go and Java runtimes — see FAQ. Counters are complete even when the anomaly list is truncated. |
| `memory.anomalies[]` | Regions that are executable **and** (private or writable), largest first, capped at 250 | Facts only: base address, size, protection, region type. No verdict is claimed, because a verdict needs relocation-aware comparison of mapped bytes against the on-disk image, which this tool deliberately does not do. Use the addresses with a memory-imaging tool. |
| `memory.meta.status = denied` | Handle lacks `PROCESS_QUERY_INFORMATION` + `PROCESS_VM_READ` | Elevated engine or `SeDebugPrivilege` needed; protected processes refuse even that. |

## F. Binary integrity

| Field | Source | Caveats |
|---|---|---|
| `binary.sha256` | Streamed `ReadFile` (1 MiB chunks) over a share-read/write/delete handle | Verified by a second independent read pass; a mismatch during collection raises a warning. If the file is replaced between the two passes, both hashes are reported and the section is marked `partial`. |
| `binary.volume_serial`, `file_index` | `GetFileInformationByHandle` | NTFS file identity — the correct way to prove *which* file object was hashed (a copy elsewhere has the same hash but not the same file index). |
| `binary.pe.*` | Manual PE header parse | `compile_timestamp_utc` is only meaningful when it is in the past and not equal to a deterministic-build marker; Microsoft binaries routinely report a **future** stamp (`/Brepro`), which the report labels rather than flagging as timestomping. `is_dotnet` is derived from data directory 14 (CLR header). |
| `binary.signature.status` | `WinVerifyTrust(WTD_CHOICE_FILE)`, then `CryptCATAdmin*` + `WinVerifyTrust(WTD_CHOICE_CATALOG)` when no embedded signature exists | `signature_source` distinguishes `embedded` from `catalog`. Most of `System32` is catalog-signed, so "no embedded signature" would be a false alarm on its own. `valid` means the chain verified against local trust policy **without online revocation checking** (`WTD_CACHE_ONLY_URL_RETRIEVAL`) — offline acquisition must not stall on a CRL fetch. `CERT_E_REVOCATION_FAILURE` is surfaced as `valid` with an explicit message. |
| `binary.meta.warnings` | provenance checks | When the path was recovered from the kernel table or a name search, the report says the hash covers *the file at that path*, which was not verified against the process's mapped image. That distinction matters: hollowed processes do not run the bytes on disk. |

---

## Interpreting degraded sections

| Status | Meaning | What to do |
|---|---|---|
| `ok` | full fidelity | — |
| `partial` | collected, but sub-items unresolved (timeouts, unresolvable names, truncation) | read `meta.warnings`; the missing items are named |
| `denied` | the OS refused access | re-run elevated; if still denied the target is protected/PPL (see `process.protection_*`) |
| `error` | unexpected failure, Win32 code recorded | report it; the rest of the report is still valid |
| `skipped` | not applicable or disabled (`--no-handles`) | expected |
| `timeout` | a bounded operation gave up | re-run with a longer budget or accept the gap |

## Things this tool deliberately does NOT do

* It does not dump memory or scan for injected code regions (PE-sieve territory).
* It does not read registry hive files, event logs, or `$MFT` — those are disk
  artifacts and belong to a full image.
* Exhibit verification tolerates a UTF-8 BOM (Windows tooling adds them); a BOM is
  an encoding artefact and never a tamper indicator.
* It does not attribute behaviour; it records state. Every inference in a report
  (PID recycling, timestomping, missing-on-disk modules, catalog vs embedded
  signing) is stated with its rule and its caveat so a reviewer can disagree.
