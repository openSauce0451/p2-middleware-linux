// ps3_tunnel.rs — bridge-core: user-space VPN-style tunnel between two
// middleware instances. Pure std threads, no new dependencies, crypto
// reuses channel::Envelope (AES-256-CBC + HMAC-SHA1).
//
// REV 6.1 — DUAL-PORT DATA FRAMES (full tuple reconstruction)
//
//   * New flag 0x03: [3][dst_port BE][src_port BE][payload]. dst = the
//     port the datagram is addressed to on the RECEIVING console; src =
//     the port the SENDING console sent from. The receiver delivers to
//     local_ps3:dst from an alias socket bound at remote_ps3:src, so the
//     console sees the exact peer tuple a direct LAN would show.
//   * Legacy [0][dst][payload] frames are still accepted (old peers keep
//     working, degraded to Rev 6 behavior). Outbound frames switch to
//     0x03; set P2_LEGACY_FRAMES=1 to emit Rev 6 frames for A/B tests
//     against an unpatched peer.
//   * In practice the src alias port is usually ALREADY bound: the two
//     consoles use symmetric candidate ports (our console dials the very
//     ports the far console sends from), so the outbound worker/catch-all
//     has bound that alias already. bind_on_demand covers the remainder.
//   * STUN txid routing (FIX 7) runs upstream of delivery, unchanged.
// REV 7 — IP:PORT ANNOUNCEMENTS + ADVERTISED PORT (VPN port-forwarding)
//
//   * Flag-2 announcements now carry "public-ip:port" instead of a bare IP.
//     Rationale: Proton VPN's NAT-PMP port forwarding assigns an exit-side
//     port that differs from our local bind (0.0.0.0:27050). The peer must
//     dial exit_ip:forwarded_port, so the announcement must carry the port.
//   * New optional TunnelConfig.advertised_port (CLI --tunnel-advertised-port,
//     settings key advertised_port): the PUBLIC port the peer should dial.
//     None = announce wire_port (unchanged behaviour for direct-ISP peers).
//   * Receiver compares BOTH ip and port against the configured wire_peer
//     (bare-IP Rev 5/6 announcements still accepted; ip-only comparison then).
//   * tunnel_peer_config_stale hint now names the full corrected endpoint.
//
// REV 6 recap — FRAME-PORT FIX: forwarded frames encode the ALIAS PORT the
// datagram ARRIVED on (the console's DESTINATION port), not the SOURCE port.
//
// REV 5 recap — AUTHENTICATE-THEN-LEARN + ANNOUNCEMENTS: PSK-valid datagrams
// from new sources are adopted (tunnel_peer_learned); each side announces its
// public endpoint inside an authenticated keepalive variant every 4th
// keepalive (~32 s) so a stale configured wire_peer is DETECTED and named.
//
// REV 3 recap (port-band alias listener): bind a band of alias sockets so
// every port candidate in the console's advertisement sweep finds a live
// socket; TPROXY catch-all (Linux) / raw-socket sniffer (Windows) extends
// coverage beyond the static band.
//
// MODEL (validated topology):
//
//   Console L 192.168.0.242 ─ gw: Linux PC ══tunnel══ Windows PC :gw ─ Console W 10.0.0.182
//
//   Each middleware holds a /32 alias for the REMOTE console's IP and binds
//   sockets on (remote_ip : remote_port) plus every port in the optional
//   band. Outbound console traffic lands on some bound socket by normal
//   routing; replies carry the exact source tuple the console expects.
//
// STARTUP ORDERING: the app waits for serve()'s "listening" event before
// applying network settings; the privileged helper creates the /32 alias only
// during that apply. The bind loops RETRY in a background thread until the
// alias appears. spawn() never blocks.
//
// WIRE FORMAT (inside Envelope encryption, 16-byte block padded):
//   [u8 flag][u16 src_port BE][payload]   (flag 0 = data; src_port = the
//                                         port the datagram ARRIVED on
//                                         at the forwarding side, i.e.
//                                         the receiving console's port)
//   [u8 flag]                             (flag 1 = keepalive)
//   [u8 flag][ascii "ip:port"]            (flag 2 = endpoint announcement;
//                                          a bare "ip" (no colon) is a
//                                          Rev 5/6 legacy announcement and
//                                          is still accepted)
//
// EVENTS:
//   tunnel_wire_listening   — wire socket bound, awaiting the peer and alias
//   tunnel_started          — PRIMARY alias socket (remote_port) bound
//   tunnel_band_ready       — every requested port is bound (or skipped-busy)
//   tunnel_band_partial     — deadline hit; some band ports never bound
//   tunnel_alias_absent     — deadline hit and the primary never bound
//   tunnel_port_busy        — another process owns one band port (skipped)
//   tunnel_decrypt_rejected — undecodable datagram from a relevant address
//   tunnel_peer_learned     — PSK-valid datagram from a NEW source adopted
//   tunnel_keepalive_in     — inbound keepalive received (the key liveness sign)
//   tunnel_keepalive_out    — outbound keepalive sent (every 8 s)
//   tunnel_public_detected  — own public IPv4 detected (changed:true on rotation)
//   tunnel_public_detect_failed — HTTP echo unreachable; announcements deferred
//   tunnel_peer_public      — peer's self-reported ip(:port) vs observed source
//   tunnel_peer_config_stale — configured endpoint disagrees with peer report
//   tunnel_announce_invalid — flag-2 payload that is not a valid ip(:port)
//   tunnel_flow_rejected    — console traffic from an address other than ours
//   tunnel_wire_short / tunnel_wire_flag_unknown — malformed tunnel frames
//   tunnel_in_dropped       — inbound payload with no alias socket to use
//   tunnel_stun_*           — STUN responder activity
//   tunnel_dynamic_*        — catch-all port activity
//   tunnel_in / tunnel_out  — per-datagram counters (always logged)
// =============================================================================

use crate::{bad, channel::Envelope, gateway::event};
use crate::stun::{
    build_allocate_success, hex, send_stun_response_advertised, stun_attr, stun_classify, StunKind,
};
use crate::udp_relay::bind_udp_reuse;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

// Linux-only machinery: handle_dynamic + the TPROXY thread's dyn_opened
// counter. Unused (and correctly absent) on the Windows build.
#[cfg(target_os = "linux")]
use crate::catch_all;
use std::{
    net::SocketAddrV4,
};

const MAX_PAYLOAD: usize = 1400; // stay under wire MTU after envelope padding
const KEEPALIVE: Duration = Duration::from_secs(8);
const POLL: Duration = Duration::from_millis(200);
/// Every Nth keepalive carries the public-endpoint announcement (N * 8 s).
const ANNOUNCE_EVERY: u32 = 4;
/// Side-thread re-detection cadence for the public IP (VPN exit rotation).
const PUBLIC_RECHECK: Duration = Duration::from_secs(256);
/// Hard cap on band sockets so a fat-fingered range can't fork 65k threads.
const MAX_BAND_SOCKETS: usize = 512;
pub(crate) const MAX_DYNAMIC_SOCKETS: usize = 256;
/// STUN binding-error tripwire, shared by every tunnel_stun_other site.
static STUN_REJECTS: AtomicUsize = AtomicUsize::new(0);
/// Experimental: suppress relaying error-430 responses so the peer's
/// transport times out and renegotiates. Set once in Ps3Tunnel::spawn().
static STUN_DROP_REJECTS: AtomicBool = AtomicBool::new(false);
const MAX_PENDING_PER_PORT: usize = 64;
const PENDING_TTL: Duration = Duration::from_secs(5);



// ---------------------------------------------------------------------------
// Divert readiness gate (Linux). Lives in bridge-core so the lobby relay
// (gateway.rs) can assert divert-up before releasing 5434 offers to the
// console; the app crate's tunnel_setup delegates here too (single source).
// ---------------------------------------------------------------------------

/// MUST match the app crate's tunnel_setup (TPROXY_MARK / TPROXY_TABLE):
/// these are protocol constants of our own divert machinery, in effect.
#[cfg(target_os = "linux")]
const TPROXY_MARK: &str = "0x1";
#[cfg(target_os = "linux")]
const TPROXY_TABLE: &str = "100";

#[derive(Debug, Clone)]
pub struct WirePeerState {
    /// Current effective peer address (starts as the configured value,
    /// updated by learning when a PSK-valid datagram arrives from elsewhere).
    pub addr: SocketAddr,
    /// Value read from settings.toml, kept for diagnostics.
    pub configured: SocketAddr,
}

pub struct PendingFrame {
    payload: Vec<u8>,   // plain[3..] — the console-facing datagram
    received: Instant,  // for expiry
}

pub type WirePeer = Arc<Mutex<WirePeerState>>;

/// Parse a flag-2 announcement payload: "ip:port" (Rev 7) or bare "ip"
/// (Rev 5/6 legacy). Returns the IPv4 and, when present, the advertised
/// PUBLIC port the announcing side expects to be dialed on.
fn parse_announcement(text: &str) -> Option<(Ipv4Addr, Option<u16>)> {
    if let Some((ip_part, port_part)) = text.rsplit_once(':') {
        let ip = ip_part.parse::<Ipv4Addr>().ok()?;
        let port = port_part.parse::<u16>().ok()?;
        return Some((ip, Some(port)));
    }
    let ip = text.parse::<Ipv4Addr>().ok()?;
    Some((ip, None))
}

/// Best-effort self public-IPv4 discovery over plain HTTP: std only — no
/// TLS stack, no new dependencies. Both endpoints answer plain-text
/// requests on port 80. The reply's LAST IPv4-parseable token is the
/// CALLER's IPv4 as the Internet sees it — through CGNAT or the VPN exit,
/// which is exactly the address the peer should be told to use.
///
/// Scans tokens BACKWARD so chunked-transfer tails ("0\r\n") and trailing
/// junk never shadow the address.
fn fetch_public_ipv4() -> Option<String> {
    for host in ["api.ipify.org", "checkip.amazonaws.com"] {
        let addr = match (host, 80).to_socket_addrs() {
            Ok(mut iter) => iter.next(),
            Err(_) => None,
        };
        let addr = match addr {
            Some(a) => a,
            None => continue,
        };
        let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(4)) else {
            continue;
        };
        let _ = s.set_read_timeout(Some(Duration::from_secs(4)));
        let _ = s.set_write_timeout(Some(Duration::from_secs(4)));
        if s.write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: p2-bridge\r\n\r\n")
                .as_bytes(),
        )
            .is_err()
            {
                continue;
            }
            let mut buf: Vec<u8> = Vec::with_capacity(1024);
            let mut chunk = [0u8; 512];
            loop {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.len() > 8192 {
                            break; // pathological server; we only need the tail
                        }
                    }
                }
            }
            let text = String::from_utf8_lossy(&buf);
            // Take the BODY if the headers are present, else the whole text.
            let body = match text.find("\r\n\r\n") {
                Some(pos) => &text[pos + 4..],
                None => text.as_ref(),
            };
            // Backward scan: first token (from the end) that parses as IPv4.
            for token in body.split_whitespace().rev() {
                if token.parse::<Ipv4Addr>().is_ok() {
                    return Some(token.to_string());
                }
            }
    }
    None
}

/// Verified readiness: alias assigned AND the divert triplet can match
/// THIS session's traffic. Distinguishes "installed" from "can fire" —
/// frame 3262 proved they diverge (an -i-scoped rule that never matched
/// passed the old coarse check while checks died as ICMP).
#[cfg(target_os = "linux")]
pub fn divert_ready(alias: Ipv4Addr, catch_all: u16) -> bool {
    use std::process::Command;

    // 1. The /32 alias must be assigned (any interface).
    let assigned = Command::new("ip")
    .args(["addr", "show"])
    .output()
    .map(|o| {
        String::from_utf8_lossy(&o.stdout)
        .lines()
        .any(|l| l.contains(&format!("{alias}/32")))
    })
    .unwrap_or(false);
    if !assigned {
        return false;
    }

    // 2. fwmark policy rule exists.
    let ruled = Command::new("ip")
    .args(["rule", "show"])
    .output()
    .map(|o| {
        String::from_utf8_lossy(&o.stdout)
        .lines()
        .any(|l| {
            let l = l.to_lowercase();
            l.contains("fwmark") && l.contains(TPROXY_MARK) && l.contains("lookup")
        })
    })
    .unwrap_or(false);
    if !ruled {
        return false;
    }

    // 3. Local route in the policy table. RENDERING TRAP: `ip route show`
    //    normalizes "0.0.0.0/0" to "default" — the literal CIDR never
    //    appears in the listing. Accept both spellings (same fix the app
    //    crate's tproxy_route_exists already carries).
    let routed = Command::new("ip")
    .args(["route", "show", "table", TPROXY_TABLE])
    .output()
    .map(|o| {
        String::from_utf8_lossy(&o.stdout)
        .lines()
        .any(|l| {
            let l = l.to_lowercase();
            l.contains("local")
            && (l.contains("0.0.0.0/0") || l.contains("default"))
        })
    })
    .unwrap_or(false);
    if !routed {
        return false;
    }

    // 4. A PREROUTING TPROXY rule naming THIS alias and THIS catch-all
    //    port exists (not merely "some TPROXY rule").
    Command::new("iptables")
    .args(["-t", "mangle", "-S", "PREROUTING"])
    .output()
    .map(|o| {
        String::from_utf8_lossy(&o.stdout)
        .lines()
        .any(|l| {
            l.contains("TPROXY")
            && l.contains(&alias.to_string())
            && l.contains(&format!("--on-port {catch_all}"))
        })
    })
    .unwrap_or(false)
}

/// Block until divert_ready or deadline. Emits the gate receipt events
/// (tunnel_divert_gate_passed / tunnel_divert_gate_failed) so startup
/// ordering is observable in every log.
#[cfg(target_os = "linux")]
pub fn await_divert(alias: Ipv4Addr, catch_all: u16, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs.max(1));
    loop {
        if divert_ready(alias, catch_all) {
            event(
                "tunnel_divert_gate_passed",
                json!({"alias": alias.to_string(), "catch_all_port": catch_all}),
            );
            return true;
        }
        if Instant::now() >= deadline {
            event(
                "tunnel_divert_gate_failed",
                json!({"alias": alias.to_string(), "catch_all_port": catch_all,
                    "waited_secs": secs}),
            );
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// REV 9 MAP-UDP via the WIRE SOCKET. Gateways bind the mapping to the
/// SOURCE port of the request, so it must originate from the socket
/// that owns internal_port — the wire. The reply therefore lands on the
/// wire socket; thread 3 deposits PMP-shaped replies into pmp_reply and
/// this polls for them. NEVER set sockopts on the shared socket here —
/// thread 3's blocking recv_from depends on them staying default.
/// Every failure mode is reported; no silent None paths remain.
fn nat_pmp_request_via_wire(
    wire: &UdpSocket,
    reply_slot: &Mutex<Option<[u8; 16]>>,
    gw: Ipv4Addr,
    internal_port: u16,
) -> Option<u16> {
    // Drop any stale reply before sending.
    *reply_slot.lock().unwrap() = None;

    let lifetime: u32 = 3600; // > PUBLIC_RECHECK (256 s): renewal is safe
    let mut req = [0u8; 12];
    req[1] = 1; // opcode 1: MAP-UDP
    req[4] = (internal_port >> 8) as u8;
    req[5] = internal_port as u8;
    req[8..12].copy_from_slice(&lifetime.to_be_bytes());

    if let Err(e) = wire.send_to(&req, SocketAddrV4::new(gw, 5351)) {
        event("tunnel_nat_pmp_send_failed", json!({
            "error": e.to_string(),
        }));
        return None;
    }

    // Thread 3 deposits the reply; poll until the deadline.
    let deadline = Instant::now() + Duration::from_secs(2);
    let resp = loop {
        if let Some(r) = reply_slot.lock().unwrap().take() {
            break r;
        }
        if Instant::now() >= deadline {
            event("tunnel_nat_pmp_timeout", json!({
                "gateway": gw.to_string(),
            }));
            return None;
        }
        thread::sleep(Duration::from_millis(25));
    };

    // [ver][0x81][result u16][epoch u32][int port 2][ext port 2][lifetime 4]
    if resp[0] != 0 || resp[1] == 129 {
        event("tunnel_nat_pmp_malformed", json!({
            "resp_head": format!("{:02x}{:02x}", resp[0], resp[1]),
        }));
        return None;
    }
    let result = u16::from_be_bytes([resp[2], resp[3]]);
    if result != 0 {
        event("tunnel_nat_pmp_denied", json!({
            "gateway": gw.to_string(),
                                             "result": result,
        }));
        return None;
    }
    if u16::from_be_bytes([resp[8], resp[9]]) != internal_port {
        event("tunnel_nat_pmp_port_mismatch", json!({
            "requested": internal_port,
            "echoed": u16::from_be_bytes([resp[8], resp[9]]),
        }));
        return None;
    }
    let ext = u16::from_be_bytes([resp[10], resp[11]]);
    if ext == 0 {
        event("tunnel_nat_pmp_ext_zero", json!({}));
        return None;
    }
    Some(ext)
}

// ---------------------------------------------------------------------------
// REV 8 — NAT-PMP PER-SERVER SERVICE DISCOVERY + MAP-UDP CORRECTNESS
//
// Replaces the old single-function nat_pmp_request(keep) with a discovery
// suite. Fixes vs the previous body:
//   * result code parsed as u16 BE and compared to 0. The old check
//     rejected resp[3] == 0 — the HIGH byte of the SUCCESS code — so every
//     genuine success was discarded.
//   * positive requested lifetime (3600 s): RFC 6886 says lifetime 0 in
//     a MAP-UDP request DELETES a mapping; the old body renewed by deleting.
//   * internal-port echo verified, external port 0 rejected.
//   * gateway discovered per-session instead of hard-coded 10.2.255.254.
// ---------------------------------------------------------------------------

/// Every DEFAULT route's (interface, gateway) from /proc/net/route.
/// Columns: Iface Dest Gateway Flags ...; Dest "00000000" = default.
/// Numbers are little-endian hex u32 (0100A8C0 = 192.168.0.1).
#[cfg(target_os = "linux")]
fn default_gateways() -> Vec<(String, Ipv4Addr)> {
    let Ok(text) = std::fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 || cols[1] != "00000000" {
            continue;
        }
        let Ok(raw) = u32::from_str_radix(cols[2], 16) else { continue };
        out.push((cols[0].to_string(), Ipv4Addr::from(raw.swap_bytes())));
    }
    out
}

/// Every DEFAULT route's (interface, gateway) from the IPv4 route table.
/// Windows analogue of /proc/net/route: spawn `route.exe PRINT -4` and
/// parse the Active Routes table structurally.
///
/// Relevant rows look like:
///   Network Destination  Netmask       Gateway       Interface    Metric
///            0.0.0.0      0.0.0.0   192.168.1.1   192.168.1.10      25
///
/// Parsing is locale-independent by design: non-English Windows translates
/// the headers and the word "On-link", so we never match on words — only
/// on structural columns (Destination "0.0.0.0", Netmask "0.0.0.0", and a
/// Gateway that parses as an IPv4 literal).
#[cfg(target_os = "windows")]
fn default_gateways() -> Vec<(String, Ipv4Addr)> {
    use std::process::Command;

    let Ok(output) = Command::new("route").args(["print", "-4"]).output() else {
        return Vec::new();
    };
    // route.exe emits in the OEM code page; lossy conversion may mangle
    // localized headers, but every line we match on is pure-ASCII
    // addresses, so the interesting rows survive intact.
    let table = String::from_utf8_lossy(&output.stdout);

    let mut out = Vec::new();
    for line in table.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        // Structural match for a DEFAULT route, regardless of locale.
        if cols[0] != "0.0.0.0" || cols[1] != "0.0.0.0" {
            continue;
        }
        // Localized "On-link" gateways fail this parse and are skipped —
        // as is the unspecified address. Neither is a gateway a NAT-PMP
        // daemon could plausibly answer from, so losing them costs nothing.
        let Ok(gw) = cols[2].parse::<Ipv4Addr>() else { continue };
        if gw.is_unspecified() {
            continue;
        }
        // cols[3] is the interface's LOCAL IP (route.exe doesn't print
        // interface names here). Callers only consume the gateway, but we
        // keep the column for signature parity — and an interface's own
        // address is a perfectly usable interface identifier on Windows.
        out.push((cols[3].to_string(), gw));
    }
    out
}

/// Ordered candidate gateways for this session's VPN exit.
/// LAN routers (192.168/16, 172.16-31/12) are excluded outright: the
/// NAT-PMP service lives on the VPN tunnel's gateway, which Proton
/// provisions inside 10/8. Derived a.b.255.254 and a.b.255.255 patterns
/// are appended because Proton commonly places the NAT-PMP listener at
/// one of the two final addresses of the tunnel network.
#[cfg(target_os = "linux")]
fn nat_pmp_candidates() -> Vec<Ipv4Addr> {
    let mut cands: Vec<Ipv4Addr> = Vec::new();
    let push = |ip: Ipv4Addr, cands: &mut Vec<Ipv4Addr>| {
        if !cands.contains(&ip) {
            cands.push(ip);
        }
    };
    for (_iface, gw) in default_gateways() {
        let [a, b, _, _] = gw.octets();
        let is_lan = (a == 192 && b == 168) || (a == 172 && (16..=31).contains(&b));
        if is_lan {
            continue;
        }
        push(gw, &mut cands);
        // Pattern candidates next to the observed gateway. Both final
        // octet variants are observed in the wild; probing both costs
        // one 2-byte datagram each.
        push(Ipv4Addr::new(a, b, 255, 254), &mut cands);
        push(Ipv4Addr::new(a, b, 255, 255), &mut cands);
        push(Ipv4Addr::new(a, b, 0, 1), &mut cands);
    }
    // Sort so 10/8 candidates are probed before anything else.
    cands.sort_by_key(|ip| if ip.octets()[0] == 10 { 0 } else { 1 });
    // Known Proton constants, last resort: neither surfaces as a route
    // gateway, so both finals are hard-coded.
    push(Ipv4Addr::new(10, 2, 255, 254), &mut cands);
    push(Ipv4Addr::new(10, 2, 255, 255), &mut cands);
    cands
}

#[cfg(target_os = "windows")]
fn nat_pmp_candidates() -> Vec<Ipv4Addr> {
    // Raw-ISP host (no VPN exit): the consumer router IS the mapping
    // gateway, so the default route's gateway is the candidate — the
    // LAN exclusion applies only to VPN-tunnel setups.
    let mut cands: Vec<Ipv4Addr> = Vec::new();
    for (_iface, gw) in default_gateways() {
        if !cands.contains(&gw) {
            cands.push(gw);
        }
    }
    cands
}

/// Platform-neutral PMP discovery driver: probe the route-derived
/// candidate list, and on the first live gateway request a MAP-UDP
/// mapping for the wire socket's own port. Returns the winning
/// (gateway, session-current external port), or None when no
/// candidate answered.
fn nat_pmp_discover(
    wire: &UdpSocket,
    pmp_reply: &Arc<Mutex<Option<[u8; 16]>>>,
) -> Option<(Ipv4Addr, u16)> {
    // Gateways bind the mapping to the request's source port, so the
    // internal side must be the wire socket's actual local port.
    let internal_port: u16 = wire
    .local_addr()
    .map(|a| a.port())
    .unwrap_or(0);
    let cands = nat_pmp_candidates();
    event("tunnel_nat_pmp_scan_done", json!({
        "candidates": cands.len(), "found": null,
    }));
    for gw in cands {
        if !nat_pmp_alive(wire, pmp_reply, gw) {
            continue;
        }
        event("tunnel_nat_pmp_gateway", json!({ "gateway": gw.to_string() }));
        if let Some(ext) = nat_pmp_request_via_wire(wire, pmp_reply, gw, internal_port) {
            event("tunnel_nat_pmp_mapped", json!({
                "internal": internal_port, "external": ext,
            }));
            return Some((gw, ext as u16));
        }
    }
    None
}

/// Cheap validity probe: opcode 0 (GET external address). Creates NO
/// mapping, so it is safe to fire at arbitrary candidates. A working
/// NAT-PMP gateway answers with result 0 in ~0 RTTs worth of traffic.
///
/// Adapted for the wire-socket origin requirement (REV 9): gateways bind
/// replies to the request's source port, and thread 3 is the sole reader
/// of the wire socket — it fishes ver-0 answers into the shared pmp_reply
/// slot before Envelope authentication. This function therefore POLLS the
/// slot instead of recv'ing directly; a direct recv_from on a socket clone
/// would race thread 3 for every datagram on the port.
fn nat_pmp_alive(
    wire: &UdpSocket,
    pmp_reply: &Arc<Mutex<Option<[u8; 16]>>>,
    gw: Ipv4Addr,
) -> bool {
    // Drain any stale deposit so we only judge THIS probe's answer.
    *pmp_reply.lock().unwrap() = None;
    if wire
        .send_to(&[0u8, 0], SocketAddrV4::new(gw, 5351))
        .is_err()
        {
            return false;
        }
        // Live daemons answer immediately; a short poll window keeps
        // discovery snappy (worst case ~600 ms per dead candidate, same
        // budget as the original read timeout).
        for _ in 0..12 {
            thread::sleep(Duration::from_millis(50));
            if let Some(resp) = *pmp_reply.lock().unwrap() {
                // [ver 0][opcode 0x80][result u16][epoch u32][ext IPv4 u32]
                return resp[0] == 0 && resp[1] == 128 && resp[2] == 0 && resp[3] == 0;
            }
        }
        false
}

/// Adopt a NAT-PMP-observed external port into the announcement slot.
/// Emits `tunnel_nat_pmp_adopted` only on CHANGE, so a stable mapping
/// renews silently. The configured pin, if any, is reported for contrast.
fn adopt_ext(slot: &Arc<Mutex<u16>>, ext: u16, pinned: Option<u16>) {
    let mut ap = slot.lock().unwrap();
    if *ap != ext {
        let was = *ap;
        *ap = ext;
        drop(ap);
        event("tunnel_nat_pmp_adopted", json!({
            "was": was, "active": ext, "pinned_seed": pinned,
        }));
        // The endpoint announcer reads announced_port each ANNOUNCE_EVERY
        // tick, so the next authenticated announce frame carries the
        // truthful port; the peer adopts it via REV 5 validation.
    }
}

/// STUN configuration — minimal, no external dependencies.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StunCfg {
    pub enabled: bool,
    pub probe_ports: Vec<u16>,
    /// Answer TURN Allocate requests (0x0003) with a relay allocation
    /// Default ON: the console solicits allocations continuously
    /// during the gameplay transition and stalls without them.
    #[serde(default = "default_true")]
    pub relay_allocations: bool,
}

impl Default for StunCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            probe_ports: vec![3478, 4379, 4380],
            relay_allocations: true,
        }
    }
}

fn default_true() -> bool { true }

#[derive(Clone)]
pub struct TunnelConfig {
    /// This side's console (the only accepted source on the alias sockets).
    pub local_ps3: Ipv4Addr,
    pub remote_pc: Ipv4Addr,
    /// The remote console's private IP — the address OUR console dials.
    /// This PC must hold a /32 alias for it (privileged helper's job).
    pub remote_ps3: Ipv4Addr,
    /// The remote console's PRIMARY advertised port. Always bound first
    /// and doubles as the fallback delivery socket.
    pub remote_port: u16,
    /// Own wire listener, e.g. 0.0.0.0:27050.
    pub wire_bind: SocketAddr,
    /// The other middleware's public endpoint. STARTING POINT only — the
    /// effective peer is learned at runtime (see WirePeerState).
    pub wire_peer: SocketAddr,
    /// Pre-shared session key (paired setup).
    pub key: [u8; 32],
    /// Startup grace period for the alias to appear, in seconds.
    pub seconds: u64,
    /// STUN responder configuration.
    pub stun: StunCfg,
    /// OPTIONAL inclusive band of extra alias ports to bind, (first, last).
    /// None = legacy single-port behaviour (remote_port only).
    ///
    /// Each side should derive its band from ITS OWN capture (the tuple
    /// their console observes for us): tcpdump "udp and dst host <remote>"
    /// on this machine shows the candidate ports OUR console dials.
    pub port_band: Option<(u16, u16)>,
    pub catch_all_port: Option<u16>,
    /// REV 7: the PUBLIC UDP port this side's peer should dial — the VPN
    /// provider's assigned forwarded port when NAT-PMP/port-forwarding is
    /// in play (it almost never equals wire_port there). None = announce
    /// wire_port, i.e. direct-ISP behaviour, identical to Rev 6.
    pub advertised_port: Option<u16>,
    /// Optional pinned endpoint advertised in STUN Binding Responses
    /// None = auto-detect (echo IP + advertised_port/NAT-PMP).
    pub stun_advertise: Option<SocketAddr>,
}

impl TunnelConfig {
    /// Full sorted set of alias ports to bind: primary + optional band,
    /// capped at MAX_BAND_SOCKETS, remote_port always included.
    fn listen_set(&self) -> Vec<u16> {
        let mut ports = vec![self.remote_port];
        if let Some((a, b)) = self.port_band {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            for p in lo..=hi {
                if ports.len() >= MAX_BAND_SOCKETS {
                    break;
                }
                if p != self.remote_port {
                    ports.push(p);
                }
            }
        }
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

/// Bound alias sockets keyed by port, plus the learned reply-routing map:
/// console source port -> alias socket port. The route map is what keeps
/// reply fidelity when the console sweeps candidates: a datagram that
/// arrived on alias port P from console source port S is answered from
/// port P, so the console sees a coherent peer tuple.
#[derive(Default)]
pub(crate) struct AliasTable {
    sockets: Mutex<HashMap<u16, Arc<UdpSocket>>>,
    routes: Mutex<HashMap<u16, u16>>,
}

impl AliasTable {
    pub(crate) fn insert(&self, port: u16, socket: Arc<UdpSocket>) {
        self.sockets.lock().unwrap().insert(port, socket);
    }

    pub(crate) fn get(&self, port: u16) -> Option<Arc<UdpSocket>> {
        self.sockets.lock().unwrap().get(&port).cloned()
    }

    /// Learn (or refresh) which alias port this console source port last
    /// talked to. Latest candidate wins, matching first-responsive-wins.
    fn learn(&self, console_src: u16, alias_port: u16) {
        let mut routes = self.routes.lock().unwrap();
        if routes.get(&console_src) != Some(&alias_port) {
            routes.insert(console_src, alias_port);
        }
    }

    /// The socket to REPLY through for traffic involving console_src:
    /// the learned alias port if present, else the primary, else nothing.
    fn route_socket(&self, console_src: u16, primary: u16) -> Option<Arc<UdpSocket>> {
        let port = {
            let routes = self.routes.lock().unwrap();
            *routes.get(&console_src).unwrap_or(&primary)
        };
        self.get(port).or_else(|| self.get(primary))
    }

    /// Bind-on-demand: the inbound path's counterpart of the catch-all
    /// binder. When the far console answers a port our side never
    /// dialed, we materialize the alias socket so the answer reaches
    /// the console from the tuple it expects.
    ///
    /// Returns the existing socket when already bound (race-safe),
    /// Ok(Some) when freshly bound, Ok(None) when alias not up yet,
    /// Err on a hard bind error. Mirrors handle_dynamic's policy.
    pub(crate) fn bind_on_demand(
        &self,
        port: u16,
        alias_ip: Ipv4Addr,
        dyn_opened: &AtomicUsize,
        max_dynamic: usize,
    ) -> io::Result<Option<Arc<UdpSocket>>> {
        if let Some(s) = self.get(port) {
            return Ok(Some(s));
        }
        if dyn_opened.load(Ordering::Relaxed) >= max_dynamic {
            return Ok(None);
        }
        match bind_udp_reuse(SocketAddrV4::new(alias_ip, port)) {
            Ok(s) => {
                let s = Arc::new(s);
                self.insert(port, s.clone());
                dyn_opened.fetch_add(1, Ordering::Relaxed);
                event("tunnel_dynamic_bound", json!({ "port": port, "path": "inbound" }));
                Ok(Some(s))
            }
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                event("tunnel_port_busy", json!({ "port": port, "path": "inbound" }));
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

pub(crate) fn alias_addr(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(std::net::IpAddr::V4(ip), port)
}

pub struct Ps3Tunnel {
    stop: Arc<AtomicBool>,
    shared: Option<Arc<TunnelShared>>,
}

/// Arc bundle of everything the UDP-relay hooks need. Kept by Ps3Tunnel
/// after spawn so the relay can be wired in later (Fixes 1+2).
pub(crate) struct TunnelShared {
    pub stop: Arc<AtomicBool>,
    pub table: Arc<AliasTable>,
    pub wire: Arc<UdpSocket>,
    pub wire_peer: WirePeer,
    pub announced_endpoint: Arc<Mutex<Option<SocketAddr>>>,
    pub dyn_opened: Arc<AtomicUsize>,
    pub local_ps3: Ipv4Addr,
    pub remote_ps3: Ipv4Addr,
    pub key: [u8; 32],
    pub relay_allocations: bool,
    /// Frames waiting for their alias socket to come up. Keyed by
    /// alias port. Bounded; oldest frames per port are dropped when
    /// the cap is hit (UDP semantics preserved — no head-of-line stall).
    pub pending: Mutex<HashMap<u16, VecDeque<PendingFrame>>>,
    // FIX 7: STUN txid -> requesting console address. Outbound requests are
    // indexed by the worker/catch-all; thread 3 routes inbound responses by
    // the txid they echo, delivering to the console SOURCE port that probed,
    // from the alias socket at the probed tuple (frame tag).
    // Edit 1 (revised): value becomes (console source, probed candidate port)
    pub txid_routes: Mutex<HashMap<[u8; 16], (SocketAddr, u16)>>,
}

// ---- delivery core: used by thread 3 ----

/// Park a datagram for retry when the alias socket isn't ready yet.
fn park_frame(shared: &Arc<TunnelShared>, port: u16, payload: &[u8]) {
    let mut pending = shared.pending.lock().unwrap();
    let q = pending.entry(port).or_default();
    if q.len() >= MAX_PENDING_PER_PORT {
        q.pop_front(); // oldest first
    }
    q.push_back(PendingFrame { payload: payload.to_vec(), received: Instant::now() });
}

/// Try to flush everything parked for `port`. Called after each inbound
/// frame for that port, after any successful bind, and by the janitor.
fn flush_pending(shared: &Arc<TunnelShared>, local_ps3: Ipv4Addr, port: u16) {
    let mut parked: Vec<Vec<u8>> = Vec::new();
    {
        let mut pending = shared.pending.lock().unwrap();
        if let Some(q) = pending.get_mut(&port) {
            let now = Instant::now();
            // collect frames still in TTL; expired ones die here
            q.retain(|f| now.duration_since(f.received) < PENDING_TTL);
            parked = q.drain(..).map(|f| f.payload).collect();
        }
    }
    if parked.is_empty() {
        return;
    }
    if let Some(sock) = shared.table.get(port) {
        let dst = alias_addr(local_ps3, port);
        for payload in &parked {
            if let Err(e) = sock.send_to(payload, dst) {
                if !transient(&e) {
                    event("tunnel_wire_error", json!({
                        "kind": format!("{:?}", e.kind()), "flush": true,
                    }));
                    break;
                }
            }
        }
        event("tunnel_pending_flushed", json!({ "port": port, "count": parked.len() }));
    } else {
        // still no socket: put them back (front), keeping TTL order
        let mut pending = shared.pending.lock().unwrap();
        let q = pending.entry(port).or_default();
        for payload in parked.into_iter().rev() {
            q.push_front(PendingFrame { payload, received: Instant::now() });
        }
    }
}


impl TunnelShared {
    /// Hook: acquire a relay alias port for a TURN Allocate requester.
    pub fn allocate_relay_fn(self: &Arc<Self>)
    -> Arc<dyn Fn(SocketAddrV4) -> Option<SocketAddrV4> + Send + Sync> {
        let s = Arc::clone(self);
        Arc::new(move |_requester| {
            let env = Envelope::modern(s.key);
            acquire_relay_port(&s, &env)
            .map(|p| SocketAddrV4::new(s.remote_ps3, p))
        })
    }

    /// Hook: current advertised endpoint for Binding Responses.
    pub fn advertise_fn(self: &Arc<Self>)
    -> Arc<dyn Fn() -> Option<SocketAddr> + Send + Sync> {
        let slot = Arc::clone(&self.announced_endpoint);
        Arc::new(move || *slot.lock().unwrap())
    }
}

impl Ps3Tunnel {
    /// Ready-made hooks for the legacy UDP relay (wire after spawn).
    pub fn relay_hooks(&self) -> crate::udp_relay::UdpRelayHooks {
        match &self.shared {
            Some(s) => crate::udp_relay::UdpRelayHooks {
                relay_allocations: s.relay_allocations,
                allocate_relay: Some(s.allocate_relay_fn()),
                stun_advertise: Some(s.advertise_fn()),
            },
            None => Default::default(),
        }
    }
    /// Non-blocking: returns as soon as the wire socket is bound. Alias
    /// sockets are bound later by the retrying binder thread (see module
    /// header for why this must never block). `stop()` terminates workers.
    pub fn spawn(config: TunnelConfig) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(config.seconds.max(1));

        // PC<->PC wire socket: no alias involved, bind immediately.
        let wire = Arc::new(UdpSocket::bind(config.wire_bind)?);

        // Shared learned-peer state. Starts at the configured address;
        // thread 3 adopts a PSK-valid sender when it differs. Every
        // sender resolves the CURRENT address through the mutex at send
        // time, so nobody caches a stale copy.
        let wire_peer: WirePeer = Arc::new(Mutex::new(WirePeerState {
            addr: config.wire_peer,
            configured: config.wire_peer,
        }));

        let table = Arc::new(AliasTable::default());
        let ports = config.listen_set();

        // 0 = no truthful endpoint yet. Operator pin seeds directly;
        // unpinned starts at 0 and fills on a NAT-PMP grant
        // (side thread never updates while pinned, so a pin wins).
        let announced_port = Arc::new(Mutex::new(config.advertised_port.unwrap_or(0)));
        // REV 9: landing zone for NAT-PMP replies fished off the wire socket by
        // thread 3; the side thread polls it after sending a MAP-UDP request FROM
        // the wire (gateways bind the mapping to the request's SOURCE port, so the
        // request must originate on the socket that owns internal_port).
        let pmp_reply: Arc<Mutex<Option<[u8; 16]>>> = Arc::new(Mutex::new(None));
        // Created once, near the top of the tunnel constructor:
        let announced_endpoint: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        // a pinned advertisement wins over auto-detection. The
        // `pinned_stun` guard below (thread 4) respects this; the flag-2
        // announcer may still publish its live-detected endpoint to the
        // PEER — only the STUN slot is frozen.
        let pinned_stun = config.stun_advertise;
        if let Some(sa) = pinned_stun {
            *announced_endpoint.lock().unwrap() = Some(sa);
        }
        event("tunnel_stun_advertise_mode", json!({
            "mode": if pinned_stun.is_some() { "pinned" } else { "auto" },
                                                  "value": pinned_stun.map(|s| s.to_string()),
        }));

        let shared = Arc::new(TunnelShared {
            stop: stop.clone(),
                              table: table.clone(),
                              wire: wire.clone(),
                              wire_peer: wire_peer.clone(),
                              announced_endpoint: announced_endpoint.clone(), // the Fix 2b slot
                              dyn_opened: Arc::new(AtomicUsize::new(0)),     // persistent budget for relay allocations
                              local_ps3: config.local_ps3,
                              remote_ps3: config.remote_ps3,
                              key: config.key,
                              relay_allocations: config.stun.relay_allocations,
                              pending: Mutex::new(HashMap::new()),
                              txid_routes: Mutex::new(HashMap::new()),
        });

        event("tunnel_wire_listening", json!({
            "wire": config.wire_bind.to_string(),
                                             "peer": config.wire_peer.to_string(),
                                             "remote_ps3": config.remote_ps3.to_string(),
                                             "remote_port": config.remote_port,
                                             "alias_ports": ports.len(),
                                             "announced_port": *announced_port.lock().unwrap(),
        }));

        // ---- thread 0: dynamic catch-all (Linux TPROXY) ----
        //
        // Acquires alias ports the console invents mid-session (599xx/649xx
        // sweeps in the live captures — no static band can ever match).
        // Costs nothing when the band is also live and rescues the session
        // when the sweep escapes the band.
        #[cfg(target_os = "linux")]
        if let Some(catch_port) = config.catch_all_port {
            let stop = stop.clone();
            let table = table.clone();
            let wire = wire.clone();
            let wire_peer = wire_peer.clone();
            let envelope = Envelope::modern(config.key);
            let local_ps3 = config.local_ps3;
            let remote_ps3 = config.remote_ps3;
            let stun_enabled = config.stun.enabled;
            let shared_h = shared.clone();
            thread::spawn(move || {
                let result = catch_all::serve_until(
                    catch_port,
                    stop.clone(),
                                                    |orig, src, data| {
                                                        handle_dynamic(
                                                            &stop, &table, &wire, &wire_peer, &envelope,
                                                            local_ps3, remote_ps3, stun_enabled,
                                                            &shared_h, orig, src, data,
                                                        );
                                                    },
                );
                if let Err(e) = result {
                    // TPROXY unavailable (module/rule missing, non-root):
                    // the band path remains the fallback. Loud, not fatal.
                    event("tunnel_catchall_failed", json!({
                        "error": e.to_string(),
                                                          "fallback": "port_band",
                    }));
                }
            });
            event("tunnel_catchall_listening", json!({
                "port": catch_port,
                "alias": config.remote_ps3.to_string(),
                                                     "budget": MAX_DYNAMIC_SOCKETS,
            }));
        }

        // ---- thread 0 (Windows twin): dynamic catch-all via raw-socket sniffer ----
        // No TPROXY on Windows: the sniffer observes datagrams to the alias,
        // eagerly binds each unseen candidate port, and hands it to the
        // standard worker. The ICMP shield hides the first probe's
        // port-unreachable while the bind lands.
        #[cfg(target_os = "windows")]
        {
            let remote_ps3 = config.remote_ps3;

            let on_new_flow = crate::win_catch_all::make_on_new_flow(
                shared.clone(),
                                                                     Envelope::modern(config.key),
                                                                     config.local_ps3,
                                                                     config.stun.enabled,
            );
            let shield_ok = match crate::win_catch_all::install_icmp_shield() {
                Ok(()) => true,
                Err(e) => {
                    event("icmp_shield_failed", json!({ "error": e.to_string() }));
                    thread::sleep(Duration::from_secs(3));
                    match crate::win_catch_all::install_icmp_shield() {
                        Ok(()) => {
                            event("icmp_shield_retry_ok", json!({}));
                            true
                        }
                        Err(e2) => {
                            event("icmp_shield_failed_final", json!({
                                "error": e2.to_string(),
                                                                    "consequence": "catch-all sniffer disabled; falling back to port_band only",
                            }));
                            false
                        }
                    }
                }
            };
            if shield_ok {
                let cfg = crate::win_catch_all::SnifferConfig {
                    adapter_ip: adapter_toward(config.local_ps3)?,
                    alias: remote_ps3,
                    protected_ports: config.stun.probe_ports.clone(),
                        band: config.port_band,
                };
                let handle = crate::win_catch_all::spawn_sniffer(cfg, on_new_flow);
                match handle {
                    Ok(_) => {
                        event("tunnel_catchall_listening", json!({
                            "mode": "sniffer",
                            "alias": remote_ps3.to_string(),
                        }));
                    }
                    Err(e) => {
                        event("tunnel_catchall_failed", json!({
                            "error": e.to_string(),
                                                            "fallback": "port_band",
                        }));
                    }
                }
            } else {
                event("tunnel_catchall_failed", json!({
                    "error": "icmp_shield_unavailable",
                    "fallback": "port_band",
                }));
            }
        }

        // ---- thread 1: band binder (retry until the helper creates the alias) ----
        //
        // Iterates the port set every POLL, binding anything not yet bound.
        // AddrNotAvailable => alias not up yet, retry. AddrInUse => another
        // process owns that port, skip permanently. Emits tunnel_started when
        // the PRIMARY socket lands.
        {
            let stop = stop.clone();
            let table = table.clone();
            let remote_ps3 = config.remote_ps3;
            let local_ps3 = config.local_ps3;
            let key = config.key;
            let stun_enabled = config.stun.enabled;
            let primary = config.remote_port;
            let ports = ports.clone();
            let deadline = deadline;
            let shared_b = shared.clone();
            thread::spawn(move || {
                let mut skipped: HashSet<u16> = HashSet::new();
                let mut announced_start = false;
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut pending = 0usize;
                    for &p in &ports {
                        if skipped.contains(&p) || table.get(p).is_some() {
                            continue;
                        }
                        match bind_udp_reuse(SocketAddrV4::new(remote_ps3, p)) {
                            Ok(s) => {
                                let s = Arc::new(s);
                                table.insert(p, s.clone());
                                if p == primary && !announced_start {
                                    announced_start = true;
                                    event("tunnel_started", json!({
                                        "alias": alias_addr(remote_ps3, primary).to_string(),
                                    }));
                                }
                                spawn_console_worker(
                                    shared_b.clone(), Envelope::modern(key),
                                                     local_ps3, stun_enabled, p, s,
                                );
                            }
                            // Alias does not exist yet — the helper hasn't
                            // finished. Expected during startup; keep polling.
                            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                                pending += 1;
                            }
                            // Someone else owns this port. Skip it; the
                            // sweep will pass it by.
                            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                                event("tunnel_port_busy", json!({"port": p}));
                                skipped.insert(p);
                            }
                            // Anything else is treated as transient and retried.
                            Err(_) => pending += 1,
                        }
                    }

                    if pending == 0 {
                        event("tunnel_band_ready", json!({
                            "ports": ports.len() - skipped.len(),
                        }));
                        return;
                    }
                    if Instant::now() >= deadline {
                        if table.get(primary).is_some() {
                            event("tunnel_band_partial", json!({
                                "bound": ports.len() - skipped.len() - pending,
                                                                "total": ports.len(),
                            }));
                        } else {
                            event("tunnel_alias_absent", json!({
                                "alias": alias_addr(remote_ps3, primary).to_string(),
                            }));
                        }
                        return;
                    }
                    thread::sleep(POLL);
                }
            });
        }

        // ---- thread 2 (was): console -> tunnel — now per-socket workers
        //      spawned by the binder (see spawn_console_worker below). ----

        // ---- thread 3: wire -> console ----
        //
        // Authenticate FIRST: anything the envelope rejects is noise
        // (logged only if it claims to come from a relevant address).
        // A PSK-valid datagram from a NEW source is ADOPTED — the peer's
        // NAT/VPN rewrote it, and the PSK already proved identity.
        //
        // DISPATCH ORDER (Rev 5 fix): the flag byte is examined BEFORE the
        // length check. Keepalives are 1 byte ([flag]); only DATA frames
        // need the 3-byte header (flag + port).
        {
            let wire = wire.clone();
            let wire_peer = wire_peer.clone();
            let envelope = Envelope::modern(config.key);
            let table = table.clone();
            let local_ps3 = config.local_ps3;
            let primary = config.remote_port;
            let shared_h = shared.clone();          // pending + dyn_opened
            let remote_ps3 = config.remote_ps3;     // alias owner for bind_on_demand
            let stun_enabled = config.stun.enabled; // worker spawn on fresh bind
            let shared_worker = shared.clone();     // moved into spawn_console_worker
            // REV 9: landing zone for NAT-PMP replies fished off the wire socket
            // by thread 3; the side thread polls it after sending a MAP-UDP request
            // FROM the wire (source port = the mapped port, as gateways require).
            let pmp_reply: Arc<Mutex<Option<[u8; 16]>>> = Arc::new(Mutex::new(None));

            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let mut seen_lens: std::collections::HashSet<usize> = std::collections::HashSet::new();
                loop {
                    let (n, from) = match wire.recv_from(&mut buf) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    // REV 9: fish NAT-PMP replies off the wire socket before Envelope
                    // decoding. Nothing else in the Envelope/STUN world can look like
                    // this: STUN replies have msg-type high byte 0x01 and are >= 20
                    // bytes. Two reply shapes arrive here:
                    //   GET  (opcode 0x80): 12 bytes [ver][op][result u16][epoch u32][ext IP]
                    //   MAP  (opcode 0x81): 16 bytes [... same header ...][int port u16][ext port u16][lifetime u32]
                    // Both are ver 0, high-bit-set opcode. Read-only — we never author
                    // anything here, we merely defer a genuine gateway reply to the
                    // side thread. (Formerly n == 16 only; the 12-byte GET answers
                    // were silently dropped, making every alive-probe time out.)
                    if (n == 12 || n == 16) && buf[0] == 0 && (buf[1] == 0x80 || buf[1] == 0x81) {
                        let mut snap = [0u8; 16];
                        snap[..n].copy_from_slice(&buf[..n]);
                        *pmp_reply.lock().unwrap() = Some(snap);
                        event("tunnel_nat_pmp_reply_seen", json!({
                            "from": from.to_string(),
                                                                 "opcode": buf[1],
                                                                 "len": n,
                        }));
                        continue; // consumed; not tunnel payload
                    }

                    // 1) Authenticate FIRST.
                    let plain = match envelope.decode(&buf[..n]) {
                        Ok(p) => p,
                        Err(_) => {
                            let relevant = {
                                let ps = wire_peer.lock().unwrap();
                                from == ps.addr || from == ps.configured
                            };
                            if relevant {
                                event("tunnel_decrypt_rejected", json!({
                                    "from": from.to_string()
                                }));
                            }
                            continue;
                        }
                    };

                    // 2) PSK-valid datagram from a new source: adopt it.
                    //    Strangers cannot survive step 1, so adopting is safe.
                    {
                        let mut ps = wire_peer.lock().unwrap();
                        if from != ps.addr {
                            let was = ps.addr;
                            ps.addr = from;
                            event("tunnel_peer_learned", json!({
                                "was": was.to_string(),
                                                            "now": from.to_string()
                            }));
                        }
                    }

                    // 3) Dispatch the frame — flag byte FIRST.
                    if plain.is_empty() {
                        event("tunnel_wire_short", json!({ "len": 0 }));
                        continue;
                    }
                    let flag = plain[0];

                    if flag == 1 {
                        // Keepalive (1-byte frame). Proof of life + NAT refresh.
                        event("tunnel_keepalive_in", json!({ "from": from.to_string() }));
                        continue;
                    }

                    if flag == 2 {
                        // REV 7: endpoint announcement, payload "ip:port"
                        // (a bare "ip" is a Rev 5/6 peer and still works —
                        // the port then falls back to our configured one).
                        //   reported = what the PEER believes its public
                        //              endpoint is (their echo service +
                        //              their forwarded/advertised port);
                        //   from     = what OUR kernel saw after the path
                        //              rewrote it.
                        // A delta between the two measures the NAT rewrite.
                        // A disagreement with OUR configured wire_peer is
                        // named with a copy-pasteable correction.
                        let reported =
                        String::from_utf8_lossy(&plain[1..]).trim().to_string();
                        let Some((rip, rport)) = parse_announcement(&reported) else {
                            event("tunnel_announce_invalid", json!({
                                "from": from.to_string(),
                                                                "len": reported.len(),
                            }));
                            continue;
                        };
                        let configured = {
                            let ps = wire_peer.lock().unwrap();
                            ps.configured
                        };
                        // Full-endpoint match when the peer sent a port;
                        // ip-only match for legacy bare-IP announcements.
                        let matches = configured.ip() == std::net::IpAddr::V4(rip)
                        && rport.is_none_or(|p| p == configured.port());
                        event("tunnel_peer_public", json!({
                            "reported": reported,
                            "observed_from": from.to_string(),
                                                        "configured_matches": matches,
                        }));
                        if !matches {
                            // Build the corrected endpoint: the peer's
                            // reported port, or our configured port when
                            // the announcement was ip-only.
                            let port = rport.unwrap_or_else(|| configured.port());
                            let corrected =
                            format!("{}:{}", rip, port);
                            event("tunnel_peer_config_stale", json!({
                                "configured": configured.to_string(),
                                                                    "reported": reported,
                                                                    "hint": format!(
                                                                        "Update wire_peer to {corrected} in settings.toml"
                                                                    ),
                            }));
                        }
                        continue;
                    }

                    if flag == 3 {
                        // REV 6.1 dual-port data frame:
                        //   [3][dst_port BE][src_port BE][payload]
                        // dst = destination port on OUR console; src = the
                        // port the FAR console sent from. We deliver from
                        // an alias socket at remote_ps3:src so the console
                        // sees the true peer source tuple.
                        if plain.len() < 5 {
                            event("tunnel_wire_short", json!({ "len": plain.len() }));
                            continue;
                        }
                        let dst_port = u16::from_be_bytes([plain[1], plain[2]]);
                        let src_port = u16::from_be_bytes([plain[3], plain[4]]);
                        let payload = &plain[5..];

                        // Resolve the SOURCE alias socket. In the common
                        // case src_port is one of the candidates OUR console
                        // already dialed — the worker/catch-all bound it, so
                        // table.get() hits and the same socket now serves
                        // both directions. Otherwise bind on demand, and
                        // start the console worker so replies leave the box.
                        let src_sock: Option<Arc<UdpSocket>> = match table.get(src_port) {
                            Some(s) => Some(s),
                          None => {
                              match table.bind_on_demand(
                                  src_port,
                                  remote_ps3,
                                  &shared_h.dyn_opened,
                                  MAX_DYNAMIC_SOCKETS,
                              ) {
                                  Ok(Some(s)) => {
                                      //   tunnel_source_alias_bound — REV 6.1: receive-side alias socket bound at
                                      //                               the far console's source port (tuple rebuilt)
                                      event("tunnel_source_alias_bound", json!({
                                          "src_port": src_port,
                                          "dst_port": dst_port,
                                      }));
                                      spawn_console_worker(
                                          shared_worker.clone(),
                                                           envelope.clone(),
                                                           local_ps3,
                                                           stun_enabled,
                                                           src_port,
                                                           s.clone(),
                                      );
                                      Some(s)
                                  }
                                  // Budget exhausted or tuple owned elsewhere:
                                  // park the frame; the janitor retries.
                                  Ok(None) | Err(_) => None,
                              }
                          }
                        };

                        let Some(s) = src_sock else {
                            park_frame(&shared_h, src_port, payload);
                            event("tunnel_in_parked", json!({
                                "port": src_port,
                                "dst_port": dst_port,
                                "len": payload.len(),
                                                            "reason": "src_alias_unavailable",
                            }));
                            continue;
                        };

                        // FIX 7 upstream of delivery, unchanged: STUN
                        // responses route by txid to the console socket
                        // that asked, from the probed alias tuple.
                        if tunnel_stun_is_response(payload) {
                            if let Some(tx) = tunnel_stun_txid(payload) {
                                if let Some((console_src, probed)) =
                                    shared_h.txid_routes.lock().unwrap().get(&tx).copied()
                                    {
                                        let sock =
                                        table.get(probed).unwrap_or_else(|| s.clone());
                                        let _ = sock.send_to(payload, console_src);
                                    }
                            }
                        }

                        if let Err(e) = s.send_to(payload, alias_addr(local_ps3, dst_port)) {
                            if !transient(&e) {
                                event("tunnel_wire_error", json!({
                                    "kind": format!("{:?}", e.kind())
                                }));
                            }
                        }
                        event("tunnel_in", json!({
                            "port": dst_port,
                            "len": payload.len(),
                                                 "src_port": src_port,
                                                 "dst_port": dst_port,
                                                 "txid_routed": false,
                        }));

                        // A fresh src-alias bind may unblock parked frames.
                        flush_pending(&shared_h, local_ps3, src_port);

                        if seen_lens.insert(plain.len()) {
                            event("tunnel_in_first", json!({
                                "port": dst_port,
                                "src_port": src_port,
                                "len": payload.len(),
                                                           "payload_hex": crate::stun::hex(payload),
                            }));
                        }
                        continue;
                    }

                    if flag != 0 {
                        event("tunnel_wire_flag_unknown", json!({ "flag": flag }));
                        continue;
                    }

                    // Data frame: needs the 3-byte header (flag + port).
                    if plain.len() < 3 {
                        event("tunnel_wire_short", json!({ "len": plain.len() }));
                        continue;
                    }
                    let port = u16::from_be_bytes([plain[1], plain[2]]);
                    let payload = &plain[3..];

                    // Resolution chain (G1 + G2):
                    // learned route -> alias socket -> bind-on-demand -> park
                    let routed = table.get(port).or_else(|| table.route_socket(port, primary));

                    let target_sock: Option<Arc<UdpSocket>> = match routed {
                        Some(s) => Some(s),
                          None => match table.bind_on_demand(
                              port,
                              remote_ps3,
                              &shared_h.dyn_opened,
                              MAX_DYNAMIC_SOCKETS,
                          ) {
                              Ok(Some(s)) => {
                                  // The console -> wire half of this flow
                                  // does not exist yet either: start the
                                  // worker, exactly as handle_dynamic does,
                                  // or the console's replies to this port
                                  // never leave the machine.
                                  spawn_console_worker(
                                      shared_worker.clone(),
                                                       envelope.clone(),
                                                       local_ps3,
                                                       stun_enabled,
                                                       port,
                                                       s.clone(),
                                  );
                                  Some(s)
                              }
                              Ok(None) => {
                                  park_frame(&shared_h, port, payload);
                                  event("tunnel_in_parked", json!({
                                      "port": port, "len": payload.len(),
                                                                  "reason": "unavailable",
                                  }));
                                  None
                              }
                              Err(e) => {
                                  park_frame(&shared_h, port, payload);
                                  event("tunnel_in_parked", json!({
                                      "port": port, "len": payload.len(),
                                                                  "reason": format!("{:?}", e.kind()),
                                  }));
                                  None
                              }
                          },
                    };

                    if let Some(s) = target_sock {
                        // FIX 7: a STUN RESPONSE goes to the console SOURCE port that
                        // originated the matching request (txid lookup), sent from the
                        // alias socket at the frame-tag port — the exact tuple the
                        // console probed. Everything else keeps current behavior.
                        let dst_port = port;
                        let txid_routed = false;
                        if tunnel_stun_is_response(payload) {
                            if let Some(tx) = tunnel_stun_txid(payload) {
                                if let Some((console_src, probed)) = shared_h.txid_routes.lock().unwrap().get(&tx).copied() {
                                    // Prefer the alias socket at the tuple the console actually
                                    // probed; fall back to the tag-routed socket.
                                    let s = table.get(probed).unwrap_or_else(|| s.clone());
                                    let _ = s.send_to(payload, console_src);
                                }
                            }
                        }
                        if let Err(e) = s.send_to(payload, alias_addr(local_ps3, dst_port)) {
                            if !transient(&e) {
                                event("tunnel_wire_error", json!({
                                    "kind": format!("{:?}", e.kind())
                                }));
                            }
                        }
                        event("tunnel_in", json!({
                            "port": port,
                            "len": payload.len(),
                                                 "dst_port": dst_port,
                                                 "txid_routed": txid_routed,
                        }));
                    }

                    // Socket may exist now (fresh bind above) — retry
                    // anything parked for this port earlier.
                    flush_pending(&shared_h, local_ps3, port);

                    if seen_lens.insert(plain.len()) {
                        event("tunnel_in_first", json!({
                            "port": port,
                            "len": payload.len(),
                                                       "payload_hex": crate::stun::hex(payload),
                        }));
                    }
                }
            });
            {
                // ---- janitor thread: spawns next to thread 3 ----

                // Retries parked frames whose alias socket appeared late
                // (grace period, catch-all binder, bind-on-demand races).
                let shared_j = shared.clone();
                let local_ps3_j = local_ps3;
                thread::spawn(move || {
                    loop {
                        if shared_j.stop.load(Ordering::Relaxed) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(200));
                        let ports: Vec<u16> = {
                            let pending = shared_j.pending.lock().unwrap();
                            pending.keys().copied().collect()
                        };
                        for port in ports {
                            flush_pending(&shared_j, local_ps3_j, port);
                        }
                    }
                });
            }
        }

        // ---- thread 4: keepalive + endpoint announcer ----
        {
            let stop = stop.clone();
            let wire = wire.clone();
            let wire_peer = wire_peer.clone();
            let envelope = Envelope::modern(config.key);
            let public_ip: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let published = Arc::new(Mutex::new(String::new()));
            let announced_endpoint_ke = announced_endpoint.clone();
            // pinned_stun moved to constructor scope; captured here:
            let pinned_stun = config.stun_advertise;

            // Side thread: detect the public IP immediately, then re-check
            // every PUBLIC_RECHECK so a rotating VPN exit is picked up.
            // Cross-platform (Linux Proton VPN and Windows home router alike):
            // each cycle either RENEWS the cached NAT-PMP mapping or runs
            // DISCOVERY via nat_pmp_discover. On success the session-current
            // external port is ADOPTED into announced_port — the pin
            // (advertised_port) is a seed, never a veto: when the gateway
            // disagrees with the pin, the mapping is ground truth, because
            // the mapping is the only thing that delivers.
            {
                let stop = stop.clone();
                let public_ip = public_ip.clone();
                let announced_port = announced_port.clone();
                let wire = wire.clone();
                let pmp_reply = pmp_reply.clone();
                let pinned = config.advertised_port; // Option<u16>: seed, not gate
                let mut pmp_gw: Option<Ipv4Addr> = None;
                let wire_port: u16 = wire
                .local_addr()
                .map(|a| a.port())
                .unwrap_or(0);
                thread::spawn(move || {
                    let mut first = true;
                    let mut had_any = false;
                    let mut pin_complained = false;
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }

                        // --- NAT-PMP lifecycle (was Linux-only; now both hosts) ---
                        let mapped: Option<u16> = match pmp_gw {
                            Some(gw) => {
                                // Renewal tick: mappings carry a lifetime, and a
                                // failed renewal (rotation, daemon restart) means
                                // the cached gateway can no longer deliver.
                                match nat_pmp_request_via_wire(&wire, &pmp_reply, gw, wire_port) {
                                    Some(ext) => Some(ext as u16),
                              None => {
                                  event("tunnel_nat_pmp_renew_lost", json!({
                                      "gateway": gw.to_string(),
                                  }));
                                  pmp_gw = None;
                                  None
                              }
                                }
                            }
                            None => {
                                // Discovery tick: full scan; winner is cached so
                                // subsequent cycles renew cheaply (one request
                                // instead of a candidate sweep).
                                match nat_pmp_discover(&wire, &pmp_reply) {
                                    Some((gw, ext)) => {
                                        pmp_gw = Some(gw);
                                        Some(ext)
                                    }
                                    None => {
                                        if pinned.is_some() && !pin_complained {
                                            pin_complained = true;
                                            event("tunnel_nat_pmp_pin_unverified", json!({
                                                "pin": pinned,
                                                "reason": "no candidate answered; pin is seed-only and unverified",
                                            }));
                                        }
                                        None
                                    }
                                }
                            }
                        };
                        if let Some(ext) = mapped {
                            adopt_ext(&announced_port, ext, pinned);
                        }

                        // --- Public IP detection (unchanged) ---
                        match fetch_public_ipv4() {
                            Some(ip) => {
                                let changed = {
                                    let mut slot = public_ip.lock().unwrap();
                                    let ch = first || slot.as_deref() != Some(ip.as_str());
                                    *slot = Some(ip.clone());
                                    ch
                                };
                                if changed {
                                    event("tunnel_public_detected", json!({
                                        "ip": ip,
                                        "changed": !first || had_any,
                                    }));
                                }
                                first = false;
                                had_any = true;
                            }
                            None => {
                                if first {
                                    event("tunnel_public_detect_failed", json!({
                                        "reason": "echo services unreachable; announcements deferred"
                                    }));
                                }
                                first = false;
                            }
                        }
                        thread::sleep(PUBLIC_RECHECK);
                    }
                });
            }

            // Main keepalive cadence — never blocked on network probes.
            thread::spawn(move || {
                let mut tick: u32 = 0;
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let frame: Vec<u8> = if tick % ANNOUNCE_EVERY == 0 {
                        match public_ip.lock().unwrap().clone() {
                            Some(ip) => {
                                let port = *announced_port.lock().unwrap();
                                if port == 0 {
                                    // Fix 8: no truthful port yet (no pin, no NAT-PMP grant).
                                    // Publish nothing (STUN stays silent = the proven-safe
                                    // black-hole) and send a plain keepalive, not "ip:0".
                                    vec![1u8]
                                } else {
                                    let endpoint = format!("{ip}:{port}");
                                    let already = {
                                        let p = published.lock().unwrap();
                                        *p == endpoint
                                    };
                                    if pinned_stun.is_none() {
                                        if let Ok(sa) = endpoint.parse::<SocketAddr>() {
                                            *announced_endpoint_ke.lock().unwrap() = Some(sa);
                                        }
                                    }
                                    if already {
                                        vec![1u8]
                                    } else {
                                        *published.lock().unwrap() = endpoint.clone();
                                        let mut f = vec![2u8];
                                        f.extend_from_slice(endpoint.as_bytes());
                                        f
                                    }
                                }
                            }
                            None => vec![1u8], // plain keepalive — no IP yet
                        }
                    } else {
                        vec![1u8]
                    };
                    let target = wire_peer.lock().unwrap().addr;
                    let sealed = envelope.encode(&frame);
                    if let Err(e) = wire.send_to(&sealed, target) {
                        if !transient(&e) {
                            event("tunnel_wire_error", json!({
                                "kind": format!("{:?}", e.kind())
                            }));
                        }
                    }
                    event("tunnel_keepalive_out", json!({ "to": target.to_string() }));
                    tick = tick.wrapping_add(1);
                    thread::sleep(KEEPALIVE);
                }
            });
        }

        // ---- thread 5+: STUN probe responders (dedicated ports) ----
        //
        // Binding Requests are answered with the ADVERTISED public
        // endpoint (Fix 2); TURN Allocate requests (0x0003) are served
        // with a dynamic relay allocation (Fix 1).
        if config.stun.enabled {
            let shared_base = shared.clone();
            let envelope_base = Envelope::modern(config.key);
            let announce_slot = announced_endpoint.clone();
            for &port in &config.stun.probe_ports {
                let stop = stop.clone();
                let local_ps3 = config.local_ps3;
                let remote_ps3 = config.remote_ps3;
                let probe_port = port;
                let deadline = deadline;
                let shared_acq = shared_base.clone();
                let envelope_acq = envelope_base.clone();
                let announced_endpoint = announce_slot.clone();
                thread::spawn(move || {
                    let socket = loop {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        match bind_udp_reuse(SocketAddrV4::new(remote_ps3, probe_port)) {
                            Ok(s) => break s,
                              Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                                  if Instant::now() >= deadline {
                                      return;
                                  }
                                  thread::sleep(POLL);
                              }
                              // Should be unreachable now that SO_REUSEADDR is
                              // set (both our wildcard and this socket allow
                              // sharing). Fires only if an EXTERNAL process
                              // without SO_REUSEADDR owns the tuple.
                              Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                                  event("tunnel_probe_port_busy", json!({
                                      "probe_port": probe_port,
                                      "error": e.to_string(),
                                  }));
                                  return;
                              }
                              Err(e) => {
                                  event("tunnel_probe_bind_failed", json!({
                                      "probe_port": probe_port,
                                      "error": e.to_string(),
                                  }));
                                  return;
                              }
                        }
                    };

                    event("tunnel_stun_listening", json!({
                        "probe_port": probe_port,
                    }));

                    let mut buf = [0u8; 65536];
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        match socket.recv_from(&mut buf) {
                            Ok((n, from)) => {
                                // Peer enforcement, same rule as the alias
                                // workers: only OUR console may feed the
                                // tunnel. (Adapt field name if it differs.)
                                if from.ip() != std::net::IpAddr::V4(local_ps3) {
                                    event("tunnel_probe_source_rejected", json!({
                                        "probe_port": probe_port,
                                        "from": from.to_string(),
                                    }));
                                    continue;
                                }
                                if n > MAX_PAYLOAD {
                                    continue;
                                }
                                // Reply fidelity: delivery thread sources
                                // answers from the tuple the console dialed.
                                shared_acq.table.learn(from.port(), probe_port);

                                // Consumed locally (answered or allocated) =>
                                // do not forward. Everything else — credentialed
                                // checks, console-signed successes, 430s with
                                // the drop flag OFF, non-STUN — goes to the wire.
                                let mut forward = true;
                                match stun_classify(&buf[..n]) {
                                    StunKind::BindingRequest => {
                                        let advertised = announced_endpoint
                                        .lock().unwrap().unwrap_or(from);
                                        match send_stun_response_advertised(&socket, from, &buf[..n], advertised) {
                                            Ok(resp) => {
                                                event("tunnel_stun_answered", json!({
                                                    "probe_port": probe_port,
                                                    "from": from.to_string(),
                                                                                    "advertised": advertised.to_string(),
                                                                                    "resp_hex": hex(&resp),
                                                                                    "signed": false,
                                                }));
                                            }
                                            Err(_) => {}
                                        }
                                    }
                                    StunKind::Other(0x0003) if shared_acq.relay_allocations => {
                                        let relay_port = match acquire_relay_port(&shared_acq, &envelope_acq) {
                                            Some(p) => p,
                              None => {
                                  event("tunnel_relay_exhausted", json!({
                                      "from": from.to_string(),
                                                                        "probe_port": probe_port,
                                  }));
                                  continue;
                              }
                                        };
                                        let relayed = SocketAddrV4::new(remote_ps3, relay_port);
                                        let requester = match from { SocketAddr::V4(v4) => v4, SocketAddr::V6(_) => continue };
                                        match build_allocate_success(&buf[..n], requester, relayed) {
                                            Some(resp) => match socket.send_to(&resp, from) {
                                                Ok(_) => event("tunnel_relay_allocated", json!({
                                                    "from": from.to_string(),
                                                                                               "probe_port": probe_port,
                                                                                               "relayed": relayed.to_string(),
                                                                                               "dynamic": true,
                                                })),
                                                Err(e) if !transient(&e) => event("tunnel_relay_error", json!({
                                                    "kind": format!("{:?}", e.kind()),
                                                                                                              "probe_port": probe_port,
                                                                                                              "dynamic": true,
                                                })),
                                                Err(_) => {}
                                            },
                                            None => event("tunnel_relay_error", json!({
                                                "kind": "request_shorter_than_header",
                                                "probe_port": probe_port,
                                                "dynamic": true,
                                            })),
                                        }
                                        forward = false; // allocation answered locally
                                    }
                                    StunKind::Other(msg_type) => {
                                        if msg_type == 0x0101 {
                                            // Console-signed SUCCESS response — our
                                            // own answers never reach this arm, so
                                            // this is genuine accepted material.
                                            event("tunnel_stun_success", json!({
                                                "probe_port": probe_port,
                                                "from": from.to_string(),
                                                                               "len": n,
                                                                               "signed": stun_attr(&buf[..n], 0x0008).is_some(),
                                                                               "hex": hex(&buf[..n]),
                                            }));
                                        } else if msg_type == 0x0111 && note_stun_error(&buf[..n], probe_port) {
                                            // Suppress relay of this one frame ONLY.
                                            // `return` here would kill the whole
                                            // responder thread for the session.
                                            continue;
                                        }
                                        event("tunnel_stun_other", json!({
                                            "type": format!("{msg_type:#06x}"),
                                                                         "len": n,
                                                                         "probe_port": probe_port,
                                        }));
                                    }
                                    StunKind::NotStun => {}
                                }

                                if forward {
                                    // Seal and ship (REV 6.1), same framing
                                    // as the alias workers: dual-port frame.
                                    let frame = wire_data_frame(probe_port, from.port(), &buf[..n]);
                                    let sealed = envelope_acq.encode(&frame);
                                    let target = shared_acq.wire_peer.lock().unwrap().addr;
                                    if let Err(e) = shared_acq.wire.send_to(&sealed, target) {
                                        if !transient(&e) {
                                            event("tunnel_wire_error", json!({
                                                "kind": format!("{:?}", e.kind()),
                                                                             "probe_port": probe_port,
                                            }));
                                            return;
                                        }
                                    }
                                    event("tunnel_out", json!({
                                        "bytes": n,
                                        "src_port": from.port(),
                                                              "probe_port": probe_port,
                                    }));
                                }
                            }
                            Err(e) if transient(&e) => {}
                            Err(_) => return,
                        }
                    }
                });
            }
        }
        Ok(Self { stop, shared: Some(shared) })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        #[cfg(target_os = "windows")]
        let _ = crate::win_catch_all::remove_icmp_shield();
    }
}

impl Drop for Ps3Tunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Address of the LAN adapter facing `target` (kernel route lookup, no I/O).
/// Used by the Windows sniffer to pick the right raw-socket bind address —
/// no config plumbing, immune to DHCP rotations.
#[cfg(target_os = "windows")]
pub(crate) fn adapter_toward(target: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let probe = UdpSocket::bind("0.0.0.0:0")?;
    probe.connect(alias_addr(target, 9))?; // discard port; no packet sent
    match probe.local_addr()? {
        SocketAddr::V4(v4) => Ok(*v4.ip()),
        _ => Err(bad("tunnel_adapter_ip")),
    }
}

// FIX 7 helpers — old-draft STUN framing (16-byte txid at offset 4,
// response classes have bit 0x0100 set in the type word).
fn tunnel_stun_txid(buf: &[u8]) -> Option<[u8; 16]> {
    if buf.len() < 20 { return None; }
    let mut tx = [0u8; 16];
    tx.copy_from_slice(&buf[4..20]);
    Some(tx)
}

fn tunnel_stun_is_response(buf: &[u8]) -> bool {
    buf.len() >= 2 && (u16::from_be_bytes([buf[0], buf[1]]) & 0x0100) != 0
}

fn tunnel_remember_request(shared: &TunnelShared, payload: &[u8], console_src: SocketAddr, probed_port: u16) {
    if !tunnel_stun_is_response(payload) {
        if let Some(tx) = tunnel_stun_txid(payload) {
            let mut routes = shared.txid_routes.lock().unwrap();
            routes.insert(tx, (console_src, probed_port));
            if routes.len() > 4096 { routes.clear(); }
        }
    }
}

// ---------------------------------------------------------------------------
// REV 6.1 — dual-port frame construction.
// ---------------------------------------------------------------------------

/// Outbound framing mode, resolved once per process. P2_LEGACY_FRAMES=1
/// reverts outbound frames to the Rev 6 single-port form so a patched
/// build can interoperate with (or be A/B-tested against) an unpatched
/// peer. Inbound decoding ALWAYS accepts both forms.
fn dual_port_frames() -> bool {
    use std::sync::OnceLock;
    static MODE: OnceLock<bool> = OnceLock::new();
    *MODE.get_or_init(|| std::env::var_os("P2_LEGACY_FRAMES").is_none())
}

/// Build a data frame for the wire. Dual-port: [3][dst BE][src BE][payload].
/// Legacy: [0][dst BE][payload]. `dst` = arrival (alias) port on the
/// receiving side; `src` = the sending console's source port.
fn wire_data_frame(dst_port: u16, src_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(5 + payload.len());
    if dual_port_frames() {
        f.push(3u8);
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&src_port.to_be_bytes());
    } else {
        f.push(0u8);
        f.extend_from_slice(&dst_port.to_be_bytes());
    }
    f.extend_from_slice(payload);
    f
}

/// Per-socket console->tunnel worker. One per bound alias port; spawned by
/// the binder the moment its socket lands. Validates the console source,
/// learns the reply route, answers STUN locally, then forwards the original
/// through the tunnel (so the genuine remote answer also arrives).
///
/// WIRE HEADER (Rev 6 fix): the frame carries the ALIAS PORT this datagram
/// ARRIVED on (`port`) — the receiving console's destination/listening
/// port — NOT the console's source port. The far side delivers to
/// local_ps3:<header port>.
///
/// Lifecycle: exits on stop, fatal wire error, or socket error. Like the
/// rest of this codebase, threads blocked in recv_from terminate at process
/// teardown if never woken.
pub(crate) fn spawn_console_worker(
    shared: Arc<TunnelShared>,
    envelope: Envelope,
    local_ps3: Ipv4Addr,
    stun_enabled: bool,
    port: u16,
    socket: Arc<UdpSocket>,
) {
    thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            if shared.stop.load(Ordering::Relaxed) {
                return;
            }
            match socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    // Peer enforcement: only OUR console feeds the tunnel.
                    if from.ip() != std::net::IpAddr::V4(local_ps3) {
                        event("tunnel_flow_rejected", json!({
                            "from": from.to_string(),
                                                            "alias_port": port,
                        }));
                        continue;
                    }
                    if n > MAX_PAYLOAD {
                        continue;
                    }

                    // Reply fidelity: remember which alias port this console
                    // source port is talking to, so wire->console delivery
                    // (thread 3) sends from the same tuple.
                    shared.table.learn(from.port(), port);
                    // STUN sniff — GATED (Fix 8). Composition policy:
                    //   * Console->ALIAS checks: NEVER answered locally. The genuine peer
                    //     console (reached by the fall-through forwarding below) is the
                    //     only legitimate author of the reply. A local 0x0101 would teach
                    //     the console a fake reflexive address and credit a counterfeit
                    //     candidate (observed live: MAPPED 159.26.104.3:27050).
                    //   * Everything else: log only. Both public STUN servers were
                    //     black-holed throughout the successful local capture, so total
                    //     local silence is proven-harmless; forwarding still happens.
                    if stun_enabled {
                        match stun_classify(&buf[..n]) {
                            StunKind::BindingRequest => {
                                event("tunnel_check_forwarded_only", json!({
                                    "from": from.to_string(),
                                                                           "alias_port": port,
                                }));
                            }
                            StunKind::Other(msg_type) => {
                                event("tunnel_stun_other", json!({
                                    "type": format!("{:#06x}", msg_type),
                                                                 "len": n,
                                                                 "alias_port": port,
                                }));
                            }
                            StunKind::NotStun => {}
                        }
                    }

                    // FIX 7: remember which console socket sent this request, keyed by txid,
                    // so the peer's response finds its way back (thread 3).
                    tunnel_remember_request(&shared, &buf[..n], from, port);

                    // Forward (REV 6.1): [3][arrival (alias) port BE][console
                    // source port BE][payload] — or the Rev 6 single-port
                    // form under P2_LEGACY_FRAMES. Sealed to the CURRENT
                    // learned wire peer. Unconditional.
                    let frame = wire_data_frame(port, from.port(), &buf[..n]);
                    let sealed = envelope.encode(&frame);
                    let target = shared.wire_peer.lock().unwrap().addr;
                    if let Err(e) = shared.wire.send_to(&sealed, target) {
                        if !transient(&e) {
                            event("tunnel_wire_error", json!({
                                "kind": format!("{:?}", e.kind())
                            }));
                            return;
                        }
                    }
                    event("tunnel_out", json!({
                        "bytes": n,
                        "src_port": from.port(),
                                              "alias_port": port,
                    }));
                }
                Err(e) if transient(&e) => {}
                Err(_) => return,
            }
        }
    });
}

/// Acquire a dynamic alias port for relay traffic, mirroring
/// handle_dynamic's policy: find, else bind+insert+spawn worker.
fn acquire_relay_port(
    shared: &Arc<TunnelShared>,
    envelope: &Envelope,
) -> Option<u16> {
    use std::sync::atomic::Ordering;
    if shared.stop.load(Ordering::Relaxed) { return None; }

    let mut port: u16 = 63000;
    for _ in 0..2000 {
        if shared.table.get(port).is_some() { port = port.wrapping_add(1); continue; }
        shared.dyn_opened.fetch_add(1, Ordering::Relaxed);
        match bind_udp_reuse(SocketAddrV4::new(shared.remote_ps3, port)) {
            Ok(s) => {
                let s = Arc::new(s);
                shared.table.insert(port, s.clone());
                shared.dyn_opened.fetch_add(1, Ordering::Relaxed);
                event("tunnel_dynamic_bound", json!({ "port": port, "purpose": "relay" }));
                spawn_console_worker(
                    Arc::clone(shared), envelope.clone(),
                                     shared.local_ps3, true, port, s,
                );
                return Some(port);
            }
            Err(_) => { port = port.wrapping_add(1); }
        }
    }
    None
}

/// One diverted datagram from the catch-all (on Windows, nothing — the
/// sniffer drops the first datagram and retries flow through the standard
/// worker). Mirrors the Ok-arm of spawn_console_worker exactly: validate
/// source, acquire/bind the alias port, learn the reply route, answer STUN
/// locally, forward the ORIGINAL to the wire so the genuine remote answer
/// also arrives. After this call, the socket is in the AliasTable and the
/// mangle `-m socket` match steers subsequent packets to it — the standard
/// worker takes over from packet two onward.
#[cfg(target_os = "linux")]
fn handle_dynamic(
    stop: &Arc<AtomicBool>,
    table: &Arc<AliasTable>,
    wire: &Arc<UdpSocket>,
    wire_peer: &WirePeer,
    envelope: &Envelope,
    local_ps3: Ipv4Addr,
    remote_ps3: Ipv4Addr,
    stun_enabled: bool,
    shared: &Arc<TunnelShared>,
    orig: SocketAddrV4,
    src: SocketAddrV4,
    data: &[u8],
) {
    use std::sync::atomic::Ordering;

    if stop.load(Ordering::Relaxed) {
        return;
    }
    // Peer enforcement — same rule as the worker: only OUR console.
    if SocketAddrV4::new(local_ps3, src.port()) != src {
        event("tunnel_flow_rejected", json!({
            "from": src.to_string(),
                                            "alias_port": orig.port(),
                                            "path": "catchall",
        }));
        return;
    }
    if data.len() > MAX_PAYLOAD {
        event("tunnel_dynamic_dropped", json!({
            "port": orig.port(), "reason": "oversize", "len": data.len(),
        }));
        return;
    }

    let port = orig.port();

    // Acquire-or-find the alias socket for this candidate port.
    let sock = match table.get(port) {
        Some(s) => s,
        None => {
            if shared.dyn_opened.load(Ordering::Relaxed) >= MAX_DYNAMIC_SOCKETS {
                event("tunnel_dynamic_exhausted", json!({
                    "port": port, "budget": MAX_DYNAMIC_SOCKETS,
                }));
                return;
            }
            match bind_udp_reuse(SocketAddrV4::new(remote_ps3, port)) {
                Ok(s) => {
                    let s = Arc::new(s);
                    table.insert(port, s.clone());
                    shared.dyn_opened.fetch_add(1, Ordering::Relaxed);
                    event("tunnel_dynamic_bound", json!({ "port": port }));
                    spawn_console_worker(
                        shared.clone(), envelope.clone(),
                                         local_ps3, stun_enabled, port, s.clone(),
                    );
                    s
                }
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                    event("tunnel_port_busy", json!({ "port": port }));
                    return;
                }
                Err(e) => {
                    event("tunnel_dynamic_dropped", json!({
                        "port": port,
                        "reason": format!("{:?}", e.kind()),
                    }));
                    return;
                }
            }
        }
    };

    // Reply fidelity: same learning the worker performs.
    table.learn(src.port(), port);

    // Tuple breadcrumb: the alias socket's local address MUST be
    // (remote_ps3 : port) — the tuple the console dialed. Logged on the
    // forwarded-only event so dynamic-path deliveries carry their
    // reply-tuple identity into every log line.
    let local = sock.local_addr().map(|a| a.to_string()).unwrap_or_default();

    // STUN sniff — GATED (Fix 8). Composition policy:
    //   * Console->ALIAS checks: NEVER answered locally. The genuine peer
    //     console (reached by the fall-through forwarding below) is the
    //     only legitimate author of the reply. A local 0x0101 would teach
    //     the console a fake reflexive address and credit a counterfeit
    //     candidate (observed live: MAPPED 159.26.104.3:27050).
    //   * Everything else: log only. Both public STUN servers were
    //     black-holed throughout the successful local capture, so total
    //     local silence is proven-harmless; forwarding still happens.
    if stun_enabled {
        match stun_classify(data) {
            StunKind::BindingRequest => {
                event("tunnel_check_forwarded_only", json!({
                    "from": SocketAddr::V4(src).to_string(),
                                                           "alias_port": port,
                                                           "dynamic": true,
                                                           "local": local,
                }));
            }
            StunKind::Other(msg_type) => {
                event("tunnel_stun_other", json!({
                    "type": format!("{:#06x}", msg_type),
                                                 "len": data.len(),
                                                 "alias_port": port,
                }));
            }
            StunKind::NotStun => {}
        }
    }

    tunnel_remember_request(shared, data, SocketAddr::V4(src), port);

    // Forward the original (REV 6.1): dual-port wire frame, sealed to the
    // CURRENT learned peer. Unconditional: nothing above may skip it.
    let frame = wire_data_frame(port, src.port(), data);
    let target = wire_peer.lock().unwrap().addr;
    let sealed = envelope.encode(&frame);
    if let Err(e) = wire.send_to(&sealed, target) {
        if !transient(&e) {
            event("tunnel_wire_error", json!({
                "kind": format!("{:?}", e.kind())
            }));
            return;
        }
    }
    event("tunnel_out", json!({
        "bytes": data.len(),
                              "src_port": src.port(),
                              "alias_port": port,
                              "dynamic": true,
    }));
}

/// STUN error-code attribute (RFC 5389 §15.6) scanner. Returns
/// class<<8 | number (e.g. 430 = "Stale Credentials"), or None for
/// non-error datagrams / truncated data. Attributes start at offset 20
/// (type, len, magic cookie, txid) and are padded to 4 bytes.
fn stun_error_code(data: &[u8]) -> Option<u16> {
    if data.len() < 20 {
        return None;
    }
    let mut off = 20;
    while off + 4 <= data.len() {
        let at = u16::from_be_bytes([data[off], data[off + 1]]);
        let alen = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        if at == 0x0009 && off + 8 <= data.len() {
            // 2 reserved bytes, then class<<8 | number.
            return Some(u16::from_be_bytes([data[off + 6], data[off + 7]]));
        }
        off += 4 + ((alen + 3) & !3);
    }
    None
}

/// Detect + count a STUN binding error response. Logs (throttled) and
/// returns true when the caller must DROP the datagram instead of
/// relaying it. Call from every StunKind::Other arm.
pub(crate) fn note_stun_error(data: &[u8], alias_port: u16) -> bool {
    let Some(code) = stun_error_code(data) else {
        return false;
    };
    let n = STUN_REJECTS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n % 20 == 0 {
        event("tunnel_stun_rejected", json!({
            "code": code,
            "count": n,
            "alias_port": alias_port,
            "hint": if code == 430 {
                "peer session credential expired — restart the GAME on both consoles before retrying"
            } else { "" },
        }));
    }
    if code == 430 && STUN_DROP_REJECTS.load(Ordering::Relaxed) {
        event("tunnel_stun_reject_dropped", json!({ "code": code, "count": n }));
        return true;
    }
    false
}

/// Windows surfaces ICMP port-unreachable on unrelated later calls
/// (ConnectionReset/ConnectionAborted); treat as noise.
fn transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
             io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::WouldBlock
    )
}

// Keep bad() linked in even if future edits remove its other uses.
#[allow(dead_code)]
fn unused_marker() -> io::Error {
    bad("tunnel_internal")
}
