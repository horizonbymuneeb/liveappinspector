## What changed

<!-- One or two sentences. What behaviour is different after this PR? -->

## Why

<!-- The investigative or engineering reason. Link the issue: Fixes #123 -->

## Evidence impact

<!--
Does this change what a report says? Forensics tools are judged on accuracy:
- new field(s) and their provenance (authoritative / best-effort / inference)?
- any interpretation rule added or changed (e.g. a new warning heuristic)?
- does any existing field change meaning? (then bump SCHEMA_VERSION and say so)
- degradation behaviour when access is denied?
-->

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --release --all-targets -- -D warnings` passes
- [ ] `cargo test --release` passes
- [ ] `tests/e2e.ps1` passes (or `-SkipPicker` with a note why)
- [ ] New/changed behaviour has a test
- [ ] `docs/` + `CHANGELOG.md` updated (`docs/SCHEMA.md` for report fields)
- [ ] No real case data, exhibits, or host-identifying screenshots committed
- [ ] No new dependency (or: justified in the description — today the runtime set is serde, serde_json, sha2)
- [ ] Unsafe/FFI additions have a `// SAFETY:` justification and bounds checks
- [ ] Collection remains read-only and loopback-only
