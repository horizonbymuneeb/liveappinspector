//! JSON serialisation plus the tamper-evident report seal.
//!
//! Seal design
//! -----------
//! The seal is a SHA-256 over the *canonical JSON rendering* of the report with
//! `integrity.report_sha256` and `integrity.sealed_at_utc` emptied. Because the
//! serializer emits struct fields in a fixed declaration order and the report
//! model contains no unordered maps, that rendering is byte-for-byte
//! reproducible - so a third party can re-verify the exhibit later with
//! `lai verify <report.json>`, or by hand with any JSON + SHA-256 tool.

use sha2::{Digest, Sha256};

use crate::model::Report;
use crate::util;

pub const SEAL_SCOPE: &str =
    "SHA-256 over the UTF-8 JSON of this report with integrity.report_sha256 and integrity.sealed_at_utc emptied";

/// Canonical JSON rendering used for hashing (pretty printed for readability).
pub fn canonical(report: &Report) -> String {
    let mut clone = report.clone();
    clone.integrity.report_sha256.clear();
    clone.integrity.sealed_at_utc.clear();
    clone.integrity.hash_algorithm = "SHA-256".to_string();
    clone.integrity.seal_scope = SEAL_SCOPE.to_string();
    serde_json::to_string_pretty(&clone).unwrap_or_else(|_| "{}".to_string())
}

/// Computes and embeds the seal. Call this last, immediately before delivery.
pub fn seal(report: &mut Report) -> String {
    report.integrity.hash_algorithm = "SHA-256".into();
    report.integrity.seal_scope = SEAL_SCOPE.into();
    report.integrity.report_sha256.clear();
    report.integrity.sealed_at_utc.clear();

    let body = canonical(report);
    let digest = Sha256::digest(body.as_bytes());
    let hex = util::hex_lower(&digest);
    report.integrity.report_sha256 = hex.clone();
    report.integrity.sealed_at_utc = util::rfc3339_of(util::UnixTime::now()).unwrap_or_default();
    hex
}

pub fn to_pretty(report: &Report) -> String {
    serde_json::to_string_pretty(report)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialisation failed: {e}\"}}"))
}

#[derive(Debug, Clone)]
pub struct Verification {
    pub computed: String,
    pub embedded: String,
    pub matches: bool,
    pub target: String,
    pub sealed_at: String,
    pub sha256_of_binary: String,
    pub sections_degraded: u32,
    pub custody_events: usize,
}

/// Re-computes the seal from a report file on disk.
///
/// Tolerates a UTF-8 BOM: exhibits routinely travel through Windows tooling
/// (PowerShell `Set-Content -Encoding UTF8`, Excel, case-management imports)
/// that prepends one, and an encoding artefact must never be mistaken for
/// tampering - or worse, make a genuine exhibit unverifiable.
pub fn verify_file(path: &str) -> Result<Verification, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let text = String::from_utf8_lossy(strip_bom(&bytes)).into_owned();
    verify_str(&text)
}

/// Strips a leading UTF-8 BOM (EF BB BF) if present.
fn strip_bom(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    }
}

pub fn verify_str(text: &str) -> Result<Verification, String> {
    // Tolerate a BOM that arrived as a char (e.g. pasted through a pipeline).
    let text = text.trim_start_matches('\u{feff}');
    let report: Report =
        serde_json::from_str(text).map_err(|e| format!("not a LiveAppInspector report: {e}"))?;
    let embedded = report.integrity.report_sha256.clone();
    let computed = {
        let body = canonical(&report);
        util::hex_lower(&Sha256::digest(body.as_bytes()))
    };
    Ok(Verification {
        matches: !embedded.is_empty() && computed.eq_ignore_ascii_case(&embedded),
        computed,
        embedded,
        target: format!(
            "{} (pid {})",
            if report.process.image_name.is_empty() {
                "<unknown image>"
            } else {
                &report.process.image_name
            },
            report.process.pid
        ),
        sealed_at: report.integrity.sealed_at_utc.clone(),
        sha256_of_binary: report.binary.sha256.clone(),
        sections_degraded: report.integrity.sections_degraded,
        custody_events: report.integrity.custody_log.len(),
    })
}

pub fn write_atomic(path: &str, contents: &str) -> std::io::Result<()> {
    let final_path = std::path::Path::new(path);
    if let Some(dir) = final_path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let tmp = path.to_string() + ".tmp";
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, final_path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{self, Options, Target};

    fn sample_report() -> Report {
        // A real acquisition of our own engine process: exercises the whole
        // collection pipeline rather than a hand-built fixture.
        let mut r = engine::inspect(&Target::from_pid(std::process::id()), &Options::default());
        seal(&mut r);
        r
    }

    #[test]
    fn seal_is_deterministic_and_verifiable() {
        let report = sample_report();
        assert_eq!(report.integrity.report_sha256.len(), 64);
        assert!(!report.integrity.sealed_at_utc.is_empty());

        let text = to_pretty(&report);
        let v = verify_str(&text).expect("verification must parse our own output");
        assert!(v.matches, "recomputed seal must match the embedded one");
        assert_eq!(v.computed, report.integrity.report_sha256);

        // Recomputing must be stable across runs of the canonicalisation.
        assert_eq!(
            util::hex_lower(&Sha256::digest(canonical(&report).as_bytes())),
            report.integrity.report_sha256
        );
    }

    #[test]
    fn bom_prefixed_report_still_verifies() {
        let report = sample_report();
        let text = to_pretty(&report);
        let with_bom = format!("\u{feff}{text}");
        let v = verify_str(&with_bom).expect("a BOM must not break verification");
        assert!(v.matches, "a BOM is an encoding artefact, not tampering");
    }

    #[test]
    fn tampering_breaks_the_seal() {
        let report = sample_report();
        let mut value: serde_json::Value =
            serde_json::from_str(&to_pretty(&report)).expect("report json");
        // Forge an innocuous-looking change: swap the recorded image hash.
        value["binary"]["sha256"] =
            serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
        let tampered = serde_json::to_string_pretty(&value).unwrap();
        let v = verify_str(&tampered).expect("still a valid report document");
        assert!(!v.matches, "a modified report must never verify");
        assert_ne!(v.computed, v.embedded);
    }

    #[test]
    fn self_inspection_collects_core_artifacts() {
        let report = sample_report();
        let pid = std::process::id();
        assert_eq!(report.process.pid, pid);
        assert!(
            report.process.accessible,
            "we must be able to open ourselves"
        );
        assert!(!report.process.image_path.is_empty());
        assert_eq!(report.binary.sha256.len(), 64);
        assert!(
            report.modules.count > 0,
            "a process always has ntdll loaded"
        );
        assert!(report.handles.inspected > 0);
        assert!(!report.integrity.custody_log.is_empty());
        assert!(report.user_context.sid.starts_with("S-1-"));
        // Cross-check the streamed hash against an independent read path.
        if let Some(reference) = crate::win::binary::hash_file_reference(&report.binary.path) {
            assert_eq!(reference, report.binary.sha256);
        }
    }
}
