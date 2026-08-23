//! What the gateway refuses before it dials: blocked address ranges,
//! forbidden headers, and the egress audit record.

use super::*;

pub(crate) fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ─── SSRF / private-address protection ──────────────────────────────────────

/// True if `ip` must never be reached via the egress proxy: loopback, private,
/// link-local (incl. the cloud metadata endpoint 169.254.169.254), CGNAT,
/// unspecified, multicast/broadcast, and the IPv6 equivalents (ULA fc00::/7,
/// link-local fe80::/10, IPv4 mapped/compatible forms, and transition ranges
/// that can tunnel an otherwise blocked IPv4 destination (NAT64, 6to4,
/// Teredo). Transition mechanisms are refused wholesale: the gateway cannot
/// safely prove which final IPv4 address a downstream translator will reach.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()          // 127.0.0.0/8
                || v4.is_private()    // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local() // 169.254/16 (incl. 169.254.169.254 metadata)
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0                                   // 0.0.0.0/8 "this host"
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => {
            if let Some(embedded) = v6.to_ipv4() {
                return is_blocked_ip(IpAddr::V4(embedded));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0 && seg[3] == 0) // NAT64 64:ff9b::/96
                || seg[0] == 0x2002 // 6to4 2002::/16
                || (seg[0] == 0x2001 && seg[1] == 0) // Teredo 2001::/32
        }
    }
}

/// Resolve `host:port` and vet EVERY resolved address. Denies if the host does
/// not resolve or if ANY resolved address is blocked (a name that resolves to
/// both a public and a private/metadata IP is treated as hostile). Returns the
/// vetted addresses so the caller can PIN the connection to one of them,
/// closing the DNS-rebinding window between check and connect.
pub(crate) async fn resolve_and_vet(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("dns resolution failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("host did not resolve to any address".to_string());
    }
    for a in &addrs {
        if is_blocked_ip(a.ip()) {
            return Err(format!(
                "target resolves to a blocked address ({}) — private/loopback/link-local/metadata ranges are refused",
                a.ip()
            ));
        }
    }
    Ok(addrs)
}

/// Headers the caller may NOT set on the forwarded request. Blocks allowlist
/// bypass via `Host`, hop-by-hop smuggling, forwarded-for spoofing, and
/// reflection of our own internal `x-sauron-*` auth headers. Matched
/// case-insensitively; the `x-sauron-`/`proxy-` prefixes are also blocked.
const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "proxy-authorization",
    "proxy-connection",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

pub(crate) fn header_forbidden(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    FORBIDDEN_HEADERS.iter().any(|h| *h == n)
        || n.starts_with("x-sauron-")
        || n.starts_with("proxy-")
}

/// Record one egress event to the audit trail. Shared by the voluntary
/// `/agent/egress/log` endpoint and the enforcing proxy so both log identically
/// and both remain queryable. Capability issuance already commits the signed
/// action receipt that the anchor batch seals. Creating a second synthetic
/// receipt here would have no signed action-envelope preimage and would make a
/// complete transparent-proof batch impossible. Returns the egress row id.
#[allow(clippy::too_many_arguments)]
pub fn record_egress(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    agent_id: &str,
    target_host: &str,
    target_path: &str,
    method: &str,
    body_hash_hex: &str,
    status_code: i64,
    allowed: bool,
    now: i64,
) -> Result<i64, String> {
    // `RETURNING id` rather than `last_insert_rowid()`: the rowid accessor is a
    // rusqlite method with no Postgres equivalent, and the id is returned to the
    // caller of POST /agent/egress/report, so it cannot just be dropped.
    let egress_id = db.query_row(
        "INSERT INTO agent_egress_log
         (tenant_id, agent_id, target_host, target_path, method, body_hash_hex, status_code, ts, allowed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) RETURNING id",
        sql_params![
            &tenant_id,
            &agent_id,
            &target_host,
            &target_path,
            &method,
            &body_hash_hex,
            &status_code,
            &now,
            allowed as i64
        ],
        |r| r.get_i64(0),
    )
    .map_err(|e| format!("insert agent_egress_log: {e}"))?
    .ok_or_else(|| "insert agent_egress_log returned no id".to_string())?;

    Ok(egress_id)
}
