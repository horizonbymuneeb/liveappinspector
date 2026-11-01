# Releasing

Releases are built and published by GitHub Actions (`.github/workflows/release.yml`).
A maintainer only bumps the version, updates the changelog, and pushes a tag.

## 1. Prepare

```powershell
# 1. bump the version in exactly one place
#    engine/Cargo.toml -> version = "1.1.0"
# 2. move CHANGELOG.md "Unreleased" entries under a new "## [1.1.0] - YYYY-MM-DD"
# 3. refresh the links at the bottom of CHANGELOG.md
# 4. make sure everything is green locally
cd engine; cargo fmt --all -- --check; cargo clippy --release --all-targets -- -D warnings; cargo test --release
cd ..; .\tests\e2e.ps1
```

If the report shape changed, regenerate the schema and commit it together:

```powershell
.\dist\lai.exe inspect --pid 1234 --json $env:TEMP\sample.json
python scripts\gen-schema.py $env:TEMP\sample.json schema\report-v1.schema.json
```

## 2. Tag

The workflow refuses to publish when the tag and `engine/Cargo.toml` disagree, so
they cannot drift.

```powershell
git add -A
git commit -m "chore(release): 1.1.0"
git tag -a v1.1.0 -m "LiveAppInspector 1.1.0"
git push origin main --follow-tags
```

## 3. What CI does

| Stage | Command |
|---|---|
| verify | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --release` |
| acceptance | `tests/e2e.ps1 -SkipPicker` against the release binary |
| package | `scripts/package.ps1 -Version <v>` → `lai-<v>-win64.zip`, `lai.exe`, `SHA256SUMS.txt`, scoop/winget manifests |
| publish | `gh release create` with notes taken from the matching `CHANGELOG.md` section |

Assets published per release:

```
lai-1.1.0-win64.zip     portable bundle: lai.exe, launchers, docs/, tests/, VERSION.txt
lai.exe                 standalone engine (identical bytes to the one in the zip)
SHA256SUMS.txt          lower-case sha256 of both assets
```

## 4. Verify the published release

```powershell
# from the release page, or:
$v = '1.1.0'
Invoke-WebRequest "https://github.com/horizonbymuneeb/liveappinspector/releases/download/v$v/SHA256SUMS.txt"
(Get-FileHash .\lai.exe -Algorithm SHA256).Hash.ToLower()   # must match the file above
.\lai.exe --version                                          # must print 1.1.0
.\lai.exe self-check
```

Then smoke-test the installer path (it re-verifies the checksum itself):

```powershell
iwr https://raw.githubusercontent.com/horizonbymuneeb/liveappinspector/main/scripts/install.ps1 | iex
```

## 5. Package managers

`scripts/package.ps1` writes ready-to-submit manifests into `dist/packaging/` with
the *published* hash baked in:

- **Scoop** — `dist/packaging/scoop/liveappinspector.json`
  Publish by opening a PR against a Scoop bucket (e.g. `ScoopInstaller/Extras`) or
  by hosting your own bucket and documenting `scoop bucket add`.
- **winget** — `dist/packaging/winget/*.yaml`
  Publish with `wingetcreate submit --token <PAT> dist/packaging/winget` (or open a
  PR against `microsoft/winget-pkgs` with those three files).

Both are portable installers: no MSI, no registry writes, `lai` on `PATH`.

## 6. If a release is bad

1. **Do not delete the tag** if anyone may have downloaded it — mark the release
   as pre-release and add a warning at the top of the notes.
2. Cut a patch release with the fix; note the regression in `CHANGELOG.md`
   ("### Fixed").
3. If the artifact itself was wrong (bad build, not bad code), replace the assets
   with `gh release upload v1.1.0 <files> --clobber` **and** bump `SHA256SUMS.txt`
   in the same upload, then post a comment explaining the replacement. A replaced
   asset must never keep the old checksum.
4. If a report format changed in a way that could mislead a reader, bump the
   schema version and document the migration — a silent semantic change in a
   forensic tool is worse than a breaking one.

## 7. Repository settings worth enabling (one-time, in the GitHub UI)

- Branch protection on `main`: require the `ci` workflow, require review, no force
  pushes.
- Private vulnerability reporting (Security → Advisories) — `SECURITY.md` points
  there.
- Dependabot alerts + the `dependabot.yml` in this repo.
- Releases: keep `Immutable releases` on so published assets cannot be silently
  replaced.
- Actions: allow only the actions used here (`actions/*`) if your org wants a
  tighter allow-list.
