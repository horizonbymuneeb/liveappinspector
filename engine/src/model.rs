//! Forensic report data model — the single source of truth for every artifact
//! LiveAppInspector collects.  Field names are stable and versioned by
//! `SCHEMA_VERSION`; downstream SIEM/IR pipelines can key off them directly.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "liveappinspector.report/v1";
pub const TOOL_NAME: &str = "LiveAppInspector";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Section outcome handling
// ---------------------------------------------------------------------------

/// Every collection module reports one of these so a partially-privileged run
/// still produces a court-defensible report instead of a crash or a blank page.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Status {
    /// Full fidelity collection.
    #[default]
    Ok,
    /// Collected, but one or more sub-items could not be resolved.
    Partial,
    /// The OS refused access (protected process / insufficient integrity).
    Denied,
    /// Unexpected failure; `error` carries the Win32 detail.
    Error,
    /// Not applicable for this target (e.g. network module on session 0).
    Skipped,
    /// An operation exceeded its defensive time budget.
    Timeout,
}

impl Status {
    pub fn is_ok(self) -> bool {
        matches!(self, Status::Ok)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Partial => "partial",
            Status::Denied => "denied",
            Status::Error => "error",
            Status::Skipped => "skipped",
            Status::Timeout => "timeout",
        }
    }
}

/// Common metadata attached to every collected section.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SectionMeta {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub win32_error: Option<u32>,
    pub collected_at_utc: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

impl Default for SectionMeta {
    fn default() -> Self {
        Self {
            status: Status::Ok,
            error: None,
            win32_error: None,
            collected_at_utc: crate::util::rfc3339_of(crate::util::UnixTime::now())
                .unwrap_or_default(),
            warnings: Vec::new(),
        }
    }
}

impl SectionMeta {
    pub fn ok() -> Self {
        Self::default()
    }
    pub fn with(status: Status, error: impl Into<String>) -> Self {
        let mut m = Self::default();
        m.status = status;
        m.error = Some(error.into());
        m
    }
    pub fn denied(error: impl Into<String>) -> Self {
        Self::with(Status::Denied, error)
    }
    pub fn error(error: impl Into<String>) -> Self {
        Self::with(Status::Error, error)
    }
    pub fn partial(error: impl Into<String>) -> Self {
        Self::with(Status::Partial, error)
    }
    /// Records an observation that does *not* degrade the section status.
    pub fn note(&mut self, w: impl Into<String>) {
        self.warnings.push(w.into());
    }
    pub fn warn(&mut self, w: impl Into<String>) {
        self.warnings.push(w.into());
        if self.status == Status::Ok {
            self.status = Status::Partial;
        }
    }
}

// ---------------------------------------------------------------------------
// Root report
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Report {
    pub schema: String,
    pub tool: ToolInfo,
    pub case: CaseInfo,
    pub selection: Selection,
    pub process: ProcessInfo,
    pub user_context: UserContext,
    pub genealogy: Genealogy,
    pub network: NetworkInfo,
    pub modules: ModuleList,
    pub handles: HandleList,
    pub registry: RegistryInfo,
    pub services: ServiceList,
    pub memory: MemoryReport,
    pub binary: BinaryInfo,
    pub integrity: ReportIntegrity,
}

// ---------------------------------------------------------------------------
// Tool / host / case
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub schema: String,
    pub build_profile: String,
    pub arch: String,
    pub os: OsInfo,
    pub host: HostInfo,
    pub running_elevated: bool,
    pub debug_privilege_held: bool,
    /// Screen-coordinate awareness of the engine (`per_monitor` etc.), because it
    /// determines whether the picked window coordinates are physical pixels.
    pub dpi_awareness: String,
    pub started_at_utc: String,
    pub completed_at_utc: String,
    pub duration_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OsInfo {
    pub product_name: String,
    pub version: String,
    pub build: u32,
    pub native_arch: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HostInfo {
    pub computer_name: String,
    pub dns_hostname: String,
    pub dns_domain: String,
    pub uptime_seconds: u64,
    pub boot_time_utc: Option<String>,
    pub timezone_bias_minutes: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CaseInfo {
    pub case_id: String,
    pub examiner: String,
    pub organization: String,
    pub notes: String,
}

// ---------------------------------------------------------------------------
// Module A - selection, window, process identity
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Selection {
    /// `interactive_pick` | `hotkey_pick` | `explicit_hwnd` | `explicit_pid`
    pub mode: String,
    pub picked_at_utc: String,
    pub screen_x: i32,
    pub screen_y: i32,
    pub hwnd: String,
    pub window: WindowInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WindowInfo {
    pub title: String,
    pub class_name: String,
    pub process_id: u32,
    pub thread_id: u32,
    pub root_hwnd: String,
    pub owner_hwnd: String,
    pub rect: RectInfo,
    pub client_rect: RectInfo,
    pub dpi: u32,
    pub is_visible: bool,
    pub is_cloaked: bool,
    pub style_hex: String,
    pub ex_style_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
pub struct RectInfo {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ProcessInfo {
    pub meta: SectionMeta,
    pub pid: u32,
    pub image_name: String,
    pub image_path: String,
    pub image_dir: String,
    /// Where `image_path` came from: the live process, or the kernel table.
    pub image_path_source: String,
    pub arch: String,
    pub is_wow64: bool,
    pub session_id: u32,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub handle_count: u32,
    pub protection_level: String,
    pub protection_signer: String,
    pub is_elevated_process: bool,
    pub command_line: Option<String>,
    pub command_line_source: String,
    pub current_directory: Option<String>,
    pub dll_path: Option<String>,
    pub environment: Vec<String>,
    pub environment_source: String,
    pub times: ProcessTimes,
    pub memory: MemoryInfo,
    pub priority_class: String,
    pub accessible: bool,
    pub access_error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ProcessTimes {
    pub created_utc: Option<String>,
    pub created_unix_ms: i64,
    pub created_filetime_raw: u64,
    pub exited_utc: Option<String>,
    pub elapsed_ms: u64,
    pub kernel_time_ms: u64,
    pub user_time_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MemoryInfo {
    pub working_set_bytes: u64,
    pub peak_working_set_bytes: u64,
    pub pagefile_usage_bytes: u64,
    pub private_bytes: u64,
    pub page_faults: u32,
}

// ---------------------------------------------------------------------------
// Module B - user, token, session context
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UserContext {
    pub meta: SectionMeta,
    pub sid: String,
    pub account_name: String,
    pub account_domain: String,
    pub account_type: String,
    pub integrity: IntegrityInfo,
    pub elevation: ElevationInfo,
    pub session: SessionInfo,
    pub token: TokenInfo,
    pub privileges: Vec<PrivilegeInfo>,
    pub groups: Vec<GroupInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct IntegrityInfo {
    pub rid: u32,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ElevationInfo {
    pub is_elevated: bool,
    /// `default` | `full` | `limited`
    pub elevation_type: String,
    pub verdict: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SessionInfo {
    pub id: u32,
    /// `console` | `rdp` | `service` | `other`
    pub kind: String,
    pub username: String,
    pub domain: String,
    pub client_name: String,
    pub client_address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TokenInfo {
    pub authentication_id: String,
    pub token_id: String,
    pub logon_session: u32,
    pub token_type: String,
    pub impersonation_level: String,
    pub is_app_container: bool,
    pub virtualization_enabled: bool,
    pub privilege_count: u32,
    pub group_count: u32,
    pub owner_sid: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PrivilegeInfo {
    pub name: String,
    pub enabled: bool,
    pub enabled_by_default: bool,
    pub removed: bool,
    pub used_for_access: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct GroupInfo {
    pub sid: String,
    pub name: String,
    pub domain: String,
    pub enabled: bool,
    pub mandatory: bool,
    pub deny_only: bool,
    pub integrity: bool,
    pub logon_id: bool,
    pub resource: bool,
}

// ---------------------------------------------------------------------------
// Module C - genealogy
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Genealogy {
    pub meta: SectionMeta,
    pub parent: Option<ProcessRef>,
    pub ancestors: Vec<ProcessRef>,
    pub children: Vec<ProcessRef>,
    pub descendants: Vec<ProcessRef>,
    pub living_processes_total: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ProcessRef {
    pub pid: u32,
    pub name: String,
    pub image_path: Option<String>,
    pub created_utc: Option<String>,
    pub is_alive: bool,
    pub depth: u32,
    pub session_id: u32,
}

// ---------------------------------------------------------------------------
// Module D - network
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NetworkInfo {
    pub meta: SectionMeta,
    pub connections: Vec<Connection>,
    pub tcp_count: u32,
    pub udp_count: u32,
    pub listening_count: u32,
    pub established_count: u32,
    pub unique_remote_endpoints: u32,
    pub resolve_dns: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Connection {
    /// `tcp` | `tcp6` | `udp` | `udp6`
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub state_code: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_hostname: Option<String>,
}

// ---------------------------------------------------------------------------
// Module E - modules, handles, registry, services
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ModuleList {
    pub meta: SectionMeta,
    pub count: u32,
    pub items: Vec<ModuleInfo>,
    pub target_image_index: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: String,
    pub size_bytes: u64,
    pub entry_point: String,
    pub company: String,
    pub product: String,
    pub file_version: String,
    pub description: String,
    pub is_target_image: bool,
    pub on_disk_modified_utc: Option<String>,
    /// True when the DLL no longer exists on disk (process-hollowing / unlinked).
    pub missing_on_disk: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HandleList {
    pub meta: SectionMeta,
    pub inspected: u32,
    pub truncated: bool,
    pub limit: u32,
    pub counts_by_type: Vec<TypeCount>,
    pub items: Vec<HandleInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TypeCount {
    pub type_name: String,
    pub count: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HandleInfo {
    pub handle: String,
    pub type_name: String,
    /// `file` | `registry` | `process` | `thread` | `section` | `sync` | `ipc` | `other`
    pub classifier: String,
    pub object_name: Option<String>,
    pub granted_access: String,
    pub object_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RegistryInfo {
    pub meta: SectionMeta,
    pub keys: Vec<RegistryKeyRef>,
    pub autoruns: Vec<AutorunEntry>,
    pub autorun_scan_notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RegistryKeyRef {
    pub path: String,
    pub native_path: String,
    pub handle: String,
    pub granted_access: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AutorunEntry {
    pub hive: String,
    pub key: String,
    pub value_name: String,
    pub command: String,
    pub matches_target: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ServiceList {
    pub meta: SectionMeta,
    pub services: Vec<ServiceInfo>,
    pub loaded_drivers_match: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub binary_path: String,
    pub start_type: String,
    pub service_type: String,
    pub account: String,
    pub state: String,
    pub pid: u32,
    pub binary_matches_target: bool,
}

// ---------------------------------------------------------------------------
// Module G - memory anomalies (address-space triage)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MemoryReport {
    pub meta: SectionMeta,
    pub pid: u32,
    pub regions_scanned: u32,
    pub committed_regions: u32,
    pub committed_bytes: u64,
    pub image_bytes: u64,
    pub mapped_bytes: u64,
    pub private_bytes: u64,
    pub executable_regions: u32,
    pub executable_bytes: u64,
    pub private_executable_regions: u32,
    pub private_executable_bytes: u64,
    pub writable_executable_regions: u32,
    pub writable_executable_bytes: u64,
    /// Largest anomalies first; `anomalies_shown` / counters say if truncated.
    pub anomalies_shown: u32,
    pub anomalies: Vec<MemoryAnomaly>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MemoryAnomaly {
    pub base_address: String,
    pub size_bytes: u64,
    pub protection: String,
    /// `private` | `mapped` | `image`
    pub region_type: String,
    pub note: String,
}

// ---------------------------------------------------------------------------
// Module F - binary integrity / chain of custody
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BinaryInfo {
    pub meta: SectionMeta,
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub volume_serial: String,
    pub file_index: String,
    pub file_attributes: String,
    pub hard_link_count: u32,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub accessed_utc: Option<String>,
    pub sha256: String,
    pub hash_algorithm: String,
    pub hashed_at_utc: String,
    pub hash_duration_ms: u64,
    pub bytes_read: u64,
    pub pe: PeInfo,
    pub signature: SignatureInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PeInfo {
    pub machine: String,
    pub compile_timestamp_utc: Option<String>,
    pub subsystem: String,
    pub linker_version: String,
    pub is_dotnet: bool,
    pub characteristics: String,
    pub note: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SignatureInfo {
    /// `valid` | `unsigned` | `invalid` | `untrusted_root` | `expired` | `revoked` | `error`
    pub status: String,
    pub trust_status_hex: String,
    pub message: String,
    pub signer_subject: String,
    pub signer_issuer: String,
    pub certificates_in_store: u32,
    /// `embedded` when the signature lives in the PE, `catalog` when it comes
    /// from a security catalog (`System32\CatRoot`), empty when unsigned.
    pub signature_source: String,
    pub catalog_path: String,
    pub catalog_member_tag: String,
}

// ---------------------------------------------------------------------------
// Report integrity / chain of custody
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ReportIntegrity {
    pub report_sha256: String,
    pub hash_algorithm: String,
    pub seal_scope: String,
    pub sealed_at_utc: String,
    pub artifact_sections: u32,
    pub sections_degraded: u32,
    pub warnings: Vec<String>,
    pub custody_log: Vec<CustodyEvent>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CustodyEvent {
    pub seq: u32,
    pub at_utc: String,
    pub action: String,
    pub detail: String,
}
