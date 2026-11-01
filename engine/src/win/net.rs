//! Module D: active socket enumeration for the target PID.
//!
//! Uses the IP Helper owner-PID tables (GetExtendedTcpTable / GetExtendedUdpTable),
//! which are serviced by the kernel and therefore far harder to hide than a
//! userspace netstat-style scrape.
//!
//! Reverse DNS is opt-in because lookups can block; every lookup runs on a
//! watchdog thread with a hard time budget.

use std::collections::HashSet;
use std::sync::mpsc;
use std::time::Duration;

use super::ffi;
use crate::model::*;
use crate::util;

const MAX_TABLE_BYTES: u32 = 64 * 1024 * 1024;
const DNS_TIMEOUT_MS: u64 = 700;
const DNS_BUDGET: u32 = 48;

fn tcp_state_name(code: u32) -> &'static str {
    match code {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn ipv4_str(raw: u32) -> String {
    let b = raw.to_ne_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// RFC 5952-ish IPv6 rendering with longest zero-run compression.
fn ipv6_str(raw: &[u8; 16]) -> String {
    let mut groups = [0u16; 8];
    for i in 0..8 {
        groups[i] = u16::from_be_bytes([raw[i * 2], raw[i * 2 + 1]]);
    }
    let (mut best_start, mut best_len) = (usize::MAX, 0usize);
    let mut i = 0usize;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            if i - start > best_len && i - start > 1 {
                best_start = start;
                best_len = i - start;
            }
        } else {
            i += 1;
        }
    }
    let mut out = String::new();
    let mut idx = 0usize;
    while idx < 8 {
        if idx == best_start {
            out.push_str("::");
            idx += best_len;
            if idx >= 8 {
                break;
            }
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", groups[idx]));
        idx += 1;
    }
    if out.is_empty() {
        "::".into()
    } else {
        out
    }
}

fn port_of(dw_port: u32) -> u16 {
    u16::from_be((dw_port & 0xFFFF) as u16)
}

struct TableError {
    code: u32,
}

impl std::fmt::Display for TableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", util::format_message(self.code))
    }
}

/// Fetch a raw owner-PID table with a growing buffer (the API's documented
/// two-call pattern, made idempotent so a racing socket cannot cause a spin).
fn fetch_table(tcp: bool, family: u32) -> Result<Vec<u8>, TableError> {
    let mut size: u32 = 16 * 1024;
    for _ in 0..8 {
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe {
            if tcp {
                ffi::GetExtendedTcpTable(
                    buf.as_mut_ptr() as *mut _,
                    &mut size,
                    ffi::FALSE,
                    family,
                    ffi::TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            } else {
                ffi::GetExtendedUdpTable(
                    buf.as_mut_ptr() as *mut _,
                    &mut size,
                    ffi::FALSE,
                    family,
                    ffi::UDP_TABLE_OWNER_PID,
                    0,
                )
            }
        };
        if rc == ffi::NO_ERROR {
            buf.truncate(size as usize);
            return Ok(buf);
        }
        if rc == ffi::ERROR_INSUFFICIENT_BUFFER {
            if size > MAX_TABLE_BYTES {
                break;
            }
            // `size` now carries the required length; add headroom for churn.
            size = (size + 8192).min(MAX_TABLE_BYTES);
            continue;
        }
        return Err(TableError { code: rc });
    }
    Err(TableError {
        code: ffi::ERROR_INSUFFICIENT_BUFFER,
    })
}

/// Parses the `<count><rows...>` layout returned by the IP Helper tables.
fn rows<T: Copy>(buf: &[u8], row_size: usize) -> Vec<T> {
    if buf.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut out = Vec::with_capacity(count.min(65_536));
    let mut off = 4usize;
    for _ in 0..count {
        if off + row_size > buf.len() {
            break;
        }
        out.push(unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const T) });
        off += row_size;
    }
    out
}

// ---------------------------------------------------------------------------
// Reverse DNS (bounded)
// ---------------------------------------------------------------------------

/// Wildcard, loopback, link-local and multicast addresses have no meaningful
/// PTR record - `getnameinfo` on `::` happily returns the *local* hostname,
/// which would be actively misleading in a report.
fn worth_resolving(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        return !(v4.is_unspecified()
            || v4.is_loopback()
            || v4.is_link_local()
            || v4.is_broadcast()
            || v4.is_multicast()
            || v4.octets()[0] == 0);
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        let seg0 = v6.segments()[0];
        return !(v6.is_unspecified()
            || v6.is_loopback()
            || v6.is_multicast()
            || (seg0 & 0xffc0) == 0xfe80); // link-local fe80::/10
    }
    false
}

fn reverse_dns(ip: &str) -> Option<String> {
    if !worth_resolving(ip) {
        return None;
    }
    let ip_owned = ip.to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(getnameinfo_blocking(&ip_owned));
    });
    rx.recv_timeout(Duration::from_millis(DNS_TIMEOUT_MS))
        .ok()
        .flatten()
}

fn getnameinfo_blocking(ip: &str) -> Option<String> {
    static WSA: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    WSA.get_or_init(|| unsafe {
        let mut data = [0u8; 512];
        ffi::WSAStartup(0x0202, data.as_mut_ptr() as *mut _);
    });

    let mut host = [0i8; 256];
    let rc = unsafe {
        if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
            let sa = ffi::SOCKADDR_IN {
                sin_family: ffi::AF_INET as u16,
                sin_port: 0,
                sin_addr: u32::from_ne_bytes(v4.octets()),
                sin_zero: [0; 8],
            };
            ffi::getnameinfo(
                &sa as *const ffi::SOCKADDR_IN as *const _,
                std::mem::size_of::<ffi::SOCKADDR_IN>() as i32,
                host.as_mut_ptr(),
                host.len() as u32,
                std::ptr::null_mut(),
                0,
                ffi::NI_NAMEREQD,
            )
        } else if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
            let sa = ffi::SOCKADDR_IN6 {
                sin6_family: ffi::AF_INET6 as u16,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: v6.octets(),
                sin6_scope_id: 0,
            };
            ffi::getnameinfo(
                &sa as *const ffi::SOCKADDR_IN6 as *const _,
                std::mem::size_of::<ffi::SOCKADDR_IN6>() as i32,
                host.as_mut_ptr(),
                host.len() as u32,
                std::ptr::null_mut(),
                0,
                ffi::NI_NAMEREQD,
            )
        } else {
            -1
        }
    };
    if rc != 0 {
        return None;
    }
    let bytes: Vec<u8> = host
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    let s = String::from_utf8_lossy(&bytes).into_owned();
    if s.is_empty() || s == ip {
        None
    } else {
        Some(s)
    }
}

// ---------------------------------------------------------------------------
// Public collection
// ---------------------------------------------------------------------------

/// Collects every TCP/UDP endpoint owned by `pid`.
pub fn collect(pid: u32, resolve_names: bool) -> NetworkInfo {
    let mut info = NetworkInfo {
        resolve_dns: resolve_names,
        ..Default::default()
    };
    let mut failures: Vec<String> = Vec::new();

    // ---- TCP IPv4 ----
    match fetch_table(true, ffi::AF_INET) {
        Ok(buf) => {
            for row in rows::<ffi::MIB_TCPROW_OWNER_PID>(
                &buf,
                std::mem::size_of::<ffi::MIB_TCPROW_OWNER_PID>(),
            ) {
                if row.dwOwningPid != pid {
                    continue;
                }
                info.tcp_count += 1;
                if row.dwState == 2 {
                    info.listening_count += 1;
                }
                if row.dwState == 5 {
                    info.established_count += 1;
                }
                info.connections.push(Connection {
                    protocol: "tcp".into(),
                    local_address: ipv4_str(row.dwLocalAddr),
                    local_port: port_of(row.dwLocalPort),
                    remote_address: ipv4_str(row.dwRemoteAddr),
                    remote_port: port_of(row.dwRemotePort),
                    state: tcp_state_name(row.dwState).into(),
                    state_code: row.dwState,
                    remote_hostname: None,
                });
            }
        }
        Err(e) => failures.push(format!("TCP/IPv4 table: {e}")),
    }

    // ---- TCP IPv6 ----
    match fetch_table(true, ffi::AF_INET6) {
        Ok(buf) => {
            for row in rows::<ffi::MIB_TCP6ROW_OWNER_PID>(
                &buf,
                std::mem::size_of::<ffi::MIB_TCP6ROW_OWNER_PID>(),
            ) {
                if row.dwOwningPid != pid {
                    continue;
                }
                info.tcp_count += 1;
                if row.dwState == 2 {
                    info.listening_count += 1;
                }
                if row.dwState == 5 {
                    info.established_count += 1;
                }
                info.connections.push(Connection {
                    protocol: "tcp6".into(),
                    local_address: ipv6_str(&row.ucLocalAddr),
                    local_port: port_of(row.dwLocalPort),
                    remote_address: ipv6_str(&row.ucRemoteAddr),
                    remote_port: port_of(row.dwRemotePort),
                    state: tcp_state_name(row.dwState).into(),
                    state_code: row.dwState,
                    remote_hostname: None,
                });
            }
        }
        Err(e) => failures.push(format!("TCP/IPv6 table: {e}")),
    }

    // ---- UDP IPv4 / IPv6 ----
    match fetch_table(false, ffi::AF_INET) {
        Ok(buf) => {
            for row in rows::<ffi::MIB_UDPROW_OWNER_PID>(
                &buf,
                std::mem::size_of::<ffi::MIB_UDPROW_OWNER_PID>(),
            ) {
                if row.dwOwningPid != pid {
                    continue;
                }
                info.udp_count += 1;
                info.connections.push(Connection {
                    protocol: "udp".into(),
                    local_address: ipv4_str(row.dwLocalAddr),
                    local_port: port_of(row.dwLocalPort),
                    remote_address: "*".into(),
                    remote_port: 0,
                    state: "OPEN".into(),
                    state_code: 0,
                    remote_hostname: None,
                });
            }
        }
        Err(e) => failures.push(format!("UDP/IPv4 table: {e}")),
    }

    match fetch_table(false, ffi::AF_INET6) {
        Ok(buf) => {
            for row in rows::<ffi::MIB_UDP6ROW_OWNER_PID>(
                &buf,
                std::mem::size_of::<ffi::MIB_UDP6ROW_OWNER_PID>(),
            ) {
                if row.dwOwningPid != pid {
                    continue;
                }
                info.udp_count += 1;
                info.connections.push(Connection {
                    protocol: "udp6".into(),
                    local_address: ipv6_str(&row.ucLocalAddr),
                    local_port: port_of(row.dwLocalPort),
                    remote_address: "*".into(),
                    remote_port: 0,
                    state: "OPEN".into(),
                    state_code: 0,
                    remote_hostname: None,
                });
            }
        }
        Err(e) => failures.push(format!("UDP/IPv6 table: {e}")),
    }

    info.connections.sort_by(|a, b| {
        established_rank(&b.state)
            .cmp(&established_rank(&a.state))
            .then(a.local_port.cmp(&b.local_port))
            .then(a.remote_address.cmp(&b.remote_address))
    });

    let mut uniq = HashSet::new();
    for c in &info.connections {
        if c.remote_address != "*" && !c.remote_address.is_empty() {
            uniq.insert(format!("{}:{}", c.remote_address, c.remote_port));
        }
    }
    info.unique_remote_endpoints = uniq.len() as u32;

    if resolve_names {
        let mut cache: std::collections::HashMap<String, Option<String>> = Default::default();
        let mut budget = DNS_BUDGET;
        for c in info.connections.iter_mut() {
            if budget == 0 {
                break;
            }
            let remote = c.remote_address.clone();
            if remote == "*" || remote.is_empty() || !worth_resolving(&remote) {
                continue;
            }
            let host = cache
                .entry(remote.clone())
                .or_insert_with(|| reverse_dns(&remote))
                .clone();
            if let Some(h) = host {
                c.remote_hostname = Some(h);
                budget -= 1;
            }
        }
        info.meta
            .note("reverse DNS ran under a per-lookup 700 ms budget; unresolved names are expected offline");
    }

    if !failures.is_empty() {
        info.meta = SectionMeta::partial(failures.join("; "));
        info.meta.warnings = failures;
    } else if info.connections.is_empty() {
        // Not an error: idle GUI applications genuinely own no sockets.
        info.meta
            .note("no TCP/UDP endpoints owned by this PID at collection time");
    }
    info
}

fn established_rank(state: &str) -> u8 {
    match state {
        "ESTABLISHED" => 3,
        "LISTEN" => 2,
        "OPEN" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_rendering_uses_network_order() {
        // 127.0.0.1 as stored by the IP Helper API (network byte order).
        assert_eq!(ipv4_str(u32::from_ne_bytes([127, 0, 0, 1])), "127.0.0.1");
        assert_eq!(
            ipv4_str(u32::from_ne_bytes([192, 168, 1, 40])),
            "192.168.1.40"
        );
    }

    #[test]
    fn port_decoding_is_big_endian() {
        // 443 == 0x01BB stored big-endian in the low 16 bits.
        assert_eq!(port_of(0x0000_BB01), 443);
        assert_eq!(port_of(0x0000_5000), 80);
    }

    #[test]
    fn ipv6_compression() {
        let mut raw = [0u8; 16];
        raw[15] = 1; // ::1
        assert_eq!(ipv6_str(&raw), "::1");
        let loopback_full = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(ipv6_str(&loopback_full), "::1");
        // 2001:db8::1
        let mut doc = [0u8; 16];
        doc[0] = 0x20;
        doc[1] = 0x01;
        doc[2] = 0x0d;
        doc[3] = 0xb8;
        doc[15] = 1;
        assert_eq!(ipv6_str(&doc), "2001:db8::1");
    }
}
