# samples/

Reference exhibits are **not** committed: a real report contains host names,
SIDs, account names, file paths and socket endpoints, which is exactly the data a
forensic tool must not leak into a repository.

Generate your own on a lab machine:

```powershell
# a complete, sealed, human-readable exhibit set
.\dist\lai.exe inspect --window `
    --case "LAB-001" --examiner "Your Name" --org "Lab" `
    --json samples\lab-001.json --html samples\lab-001.html

# verify it, the way a reviewer would
.\dist\lai.exe verify samples\lab-001.json
```

Recommended lab matrix (each produces a *different* interesting report shape):

| Scenario | Target | What it demonstrates |
|---|---|---|
| Interactive GUI app | `notepad.exe`, a browser | full fidelity: modules, handles, sockets, window facts |
| WOW64 process | 32-bit `cmd.exe` on x64, `SysWOW64\notepad.exe` | `is_wow64=true`, mixed-architecture module list, 32-bit PEB read |
| SYSTEM service host | `svchost.exe`, `winlogon.exe` | service registration correlation, catalog-signed trust, kernel-table fallback when unelevated |
| Protected process | an EDR/AV process, `MsMpEng.exe` | `denied` sections, `protection_level`, hash still collected |
| Elevation contrast | run the same target unelevated, then elevated | `tool.running_elevated`, `sections_degraded` differences |
| Persistence | a test binary registered under `HKCU\...\Run` and as a service | `registry.autoruns[]`, `services.services[]` |
| Network | a small tool holding a TCP listener + outbound connection | `network.connections[]` with `LISTEN`/`ESTABLISHED`, `--resolve-dns` variant |
| Prompt injection attempt | rename a window title to `<script>alert(1)</script>` | escaping in both the dashboard and the HTML exhibit |

When you file a bug or a report about this tool, attach a **redacted** JSON: strip
`tool.host.*`, `user_context.account_*`, `user_context.sid`, `process.image_path`,
`registry.*`, and `network.connections[].remote_address`. Re-seal the redacted copy
or simply mark it as redacted so nobody mistakes it for a sealed original.
