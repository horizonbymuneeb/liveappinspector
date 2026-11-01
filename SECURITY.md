# Security policy

## Supported versions

`main` and the latest tagged release receive security fixes. Older tags do not.

## Reporting a vulnerability

Please **do not** open a public issue for anything that could be exploited.
Use GitHub's private reporting flow:

> Security → Advisories → *Report a vulnerability*

or e-mail the maintainer listed on the GitHub profile. Include the version
(`lai --version`), the target type, and — if you can — a redacted report section.
Expect an acknowledgement within 72 hours and a coordinated disclosure timeline.

## Threat model

LiveAppInspector runs **on** the machine it examines, as the person doing the
examination. That shapes what is and is not in scope.

**In scope**

- Escape from attacker-controlled strings: window titles, process/module paths,
  registry keys, command lines and service names flowing into the JSON, the HTML
  exhibit or the dashboard DOM.
- Weaknesses in the loopback bridge: authentication bypass on `/api/*`, path
  traversal, request-smuggling, unbounded request handling.
- Logic that could put **wrong** information into a report: misresolved target
  PID/HWND, hash attributed to the wrong file, stale or mislabelled provenance.
- Memory-safety defects in the FFI layer (struct layout, bounds checks on
  buffers returned by the kernel).
- Denial of service against the acquisition itself (a hostile process making the
  engine hang or crash instead of degrading).

**Out of scope / by design**

- The tool is not sandboxed from the target: a kernel-mode attacker can lie to
  every user-mode API it calls. Detecting that is a finding, not a bug here.
- `denied` sections for PPL/protected processes, or `type_N` handle names when
  unelevated: these are documented degradations, not defects.
- The report seal is an integrity checksum, **not** a signature. Anyone with
  write access can recompute it; sign exhibits with your own key for court use.
- Code-integrity policy blocking an unsigned build (Smart App Control, WDAC,
  AppLocker) — sign the binary; see `docs/DEPLOYMENT.md`.
- Running the engine as Administrator gives it broad read access by design.

## Defensive properties to preserve in review

- HTTP binds `127.0.0.1` only; every `/api/*` call needs the per-run session
  token; assets are compiled in (no filesystem surface); headers and bodies are
  capped.
- Strict CSP: `default-src 'none'; script-src 'self'; …`; the token is delivered
  as inert `application/json`, never as executable script.
- Collection is read-only: `GENERIC_READ` file handles, no registry writes, no
  service changes, no injection/suspension/termination of the target.
- No telemetry, no update check, no network egress except opt-in bounded reverse
  DNS.
- All output escaping is centralised (`util::html_escape`, `esc()` in the
  dashboard); new sinks must use it.

## Dual use

This is a forensic/incident-response tool. It deliberately enumerates processes,
tokens, handles and sockets on the local machine and produces a detailed report
about them. It contains no offensive capability (no injection, no credential
access, no persistence, no evasion), but it does reveal a lot about a host — so
handle reports as sensitive case material.
