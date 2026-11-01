# Documentation

**Website version (searchable):** <https://horizonbymuneeb.github.io/liveappinspector/>

Everything an operator, an examiner, a reviewer and a contributor needs. Start
where you are:

| If you want to… | Read |
|---|---|
| **Use it in 2 minutes** | [README → Install / Quick start](../README.md#install) |
| Understand what each report field *means* and where it came from | [FORENSIC_NOTES.md](FORENSIC_NOTES.md) |
| Consume reports in a pipeline / write a parser | [SCHEMA.md](SCHEMA.md) + [schema/report-v1.schema.json](../schema/report-v1.schema.json) |
| Defend the report in court / prove it was not edited | [CHAIN_OF_CUSTODY.md](CHAIN_OF_CUSTODY.md) |
| Deploy on a fleet, behind SAC/WDAC/AppLocker, or debug a block | [DEPLOYMENT.md](DEPLOYMENT.md) |
| Troubleshoot the common "why is this denied / blocked" questions | [FAQ.md](FAQ.md) |
| Contribute code, a module or a test | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Understand the design before changing it | [ARCHITECTURE.md](../ARCHITECTURE.md) |
| Cut and publish a release | [RELEASING.md](RELEASING.md) |
| Report a vulnerability | [SECURITY.md](../SECURITY.md) |

## Reading order for a new examiner

1. **README §1 — what it collects** maps every module (A–F) to the artifacts and
   the Win32/NT API that produces them.
2. **FORENSIC_NOTES.md** — per-field provenance, caveats, and the two rules that
   matter: *a `denied` section is not an empty result* and *an inference is
   labelled as one*.
3. **CHAIN_OF_CUSTODY.md** — how the seal is computed and re-verified, including
   the manual recipe and the honest limits ("the seal is not a signature").
4. **SCHEMA.md** — the machine contract, `status` semantics and versioning policy.

## Documentation guarantees

- Every relative link and heading anchor is checked in CI
  (`python scripts/check-docs.py`), so links cannot rot silently.
- The report schema is generated from a real capture with
  `scripts/gen-schema.py`, not hand-maintained.
- Screenshots in this directory are generated from a **redacted** report
  (`scripts/sanitize-report.py` → `lai render --reseal` → `scripts/gen-screenshots.js`),
  so no case data is published.
- Release notes are extracted from [CHANGELOG.md](../CHANGELOG.md) by CI, so the
  changelog and the release page cannot diverge.
