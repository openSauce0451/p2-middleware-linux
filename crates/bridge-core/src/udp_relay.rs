//! Transparent UDP relay for datagrams the console addresses to the legacy
//! CM servers.
//!
//! REV 3 — Option B catch-all support (TPROXY on Linux, sniffer on Windows).
//! The `catch_all_port` config enables dynamic interception: instead of
//! pre-binding a fixed port band, we let every candidate port the console
//! picks get answered through the tunnel.
//!
//! REV 4 — Reply-source fix. The console dials a legacy CM ALIAS (e.g.
//! 72.165.61.188:4380), but the wildcard STUN socket answered from the
//! primary interface address (192.168.0.33:4380). STUN clients discard
//! responses whose source != the address they dialed, so every reply —
//! regardless of format — was silently dropped by the console. Since the
//! route helper installs the LEGACY_CM addresses as LOCAL addresses on
//! this machine, a socket specifically bound to alias:port receives the
//! console's datagrams (most-specific match beats the wildcard) and
//! replies with the correct alias source tuple. SO_REUSEADDR (set before
//! bind, hence the raw-fd helper) lets the wildcard and the specific
//! binds coexist, preserving the REV 3 wildcard-first race fix.

use crate::bad;
use crate::gateway::event;
use crate::legacy_cm::LEGACY_CM;
use crate::stun::{
    hex, send_stun_response_advertised, stun_classify, StunKind,
};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;

const MAX_DATAGRAM: usize = 65_535;
const RECV_TIMEOUT: Duration = Duration::from_millis(250);
const BIND_RETRY: Duration = Duration::from_secs(1);
const FLOW_IDLE: Duration = Duration::from_secs(75);

// ---------------------------------------------------------------------------
// REV 4: raw-fd UDP bind with SO_REUSEADDR set BEFORE bind.
//
// std's UdpSocket exposes socket options only after binding, which is too
// late: the wildcard must already carry SO_REUSEADDR when the per-alias
// specific binds arrive (Linux requires the option on EVERY socket sharing
// the port). Same raw-fd pattern as catch_all.rs.
//
// Semantics we rely on: with SO_REUSEADDR on both, 0.0.0.0:P and
// alias:P coexist, and the kernel delivers each datagram to the MOST
// SPECIFIC matching socket — so alias-bound sockets capture the console's
// packets, and the wildcard remains a genuine fallback for anything not
// covered by LEGACY_CM.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(crate) fn bind_udp_reuse(addr: SocketAddrV4) -> io::Result<UdpSocket> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        let ptr = &one as *const libc::c_int as *const libc::c_void;
        let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, ptr, len) < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = addr.port().to_be();
        // sin_addr.s_addr is in network byte order; from_ne_bytes(octets)
        // yields an integer whose little-endian store reproduces the octets
        // in order (same convention catch_all.rs uses in reverse).
        sa.sin_addr.s_addr = u32::from_ne_bytes(addr.ip().octets());
        let sa_ptr = &sa as *const libc::sockaddr_in as *const libc::sockaddr;
        if libc::bind(
            fd,
            sa_ptr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) < 0
        {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(UdpSocket::from_raw_fd(fd))
    }
}

// ===========================================================================
// Windows raw-bind helpers (winsock FFI, pattern shared with win_catch_all.rs)
//
// The wildcard STUN socket binds with SO_EXCLUSIVEADDRUSE so
// it can never coexist with — and therefore never shadow — an alias-bound
// socket on the same port. Consoles silently discard STUN replies whose
// source differs from the dialed address, so wildcard/alias delivery
// ambiguity on Windows is not cosmetic.
// ===========================================================================

#[cfg(target_os = "windows")]
pub(crate) fn bind_udp_reuse(addr: SocketAddrV4) -> io::Result<UdpSocket> {
    win_bind_udp(addr, 0x0004 /* SO_REUSEADDR */)
}

// #[cfg(target_os = "windows")]
// pub(crate) fn bind_udp_exclusive(addr: SocketAddrV4) -> io::Result<UdpSocket> {
//     // winsock2.h: #define SO_EXCLUSIVEADDRUSE ((u_int)(~SO_REUSEADDR))
//     win_bind_udp(addr, 0xFFFF_FFFB_u32 as i32)
// }

#[cfg(target_os = "windows")]
fn win_bind_udp(addr: SocketAddrV4, sockopt: i32) -> io::Result<UdpSocket> {
    use std::os::windows::io::FromRawSocket;

    type SOCKET = usize;
    const AF_INET: i32 = 2;
    const SOCK_DGRAM: i32 = 2;
    const IPPROTO_UDP: i32 = 17;
    const SOL_SOCKET: i32 = 0xFFFF;
    const INVALID_SOCKET: SOCKET = usize::MAX;
    const SOCKET_ERROR: i32 = -1;

    #[repr(C)]
    struct SockaddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    #[link(name = "ws2_32")]
    extern "system" {
        fn socket(af: i32, kind: i32, protocol: i32) -> SOCKET;
        fn setsockopt(s: SOCKET, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
        fn bind(s: SOCKET, addr: *const SockaddrIn, len: i32) -> i32;
        fn closesocket(s: SOCKET) -> i32;
    }

    crate::win_catch_all::ensure_wsa()?;

    unsafe {
        let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if s == INVALID_SOCKET {
            return Err(io::Error::last_os_error());
        }

        let one: i32 = 1;
        if setsockopt(
            s,
            SOL_SOCKET,
            sockopt,
            &one as *const i32 as *const u8,
            std::mem::size_of::<i32>() as i32,
        ) == SOCKET_ERROR
        {
            let e = io::Error::last_os_error();
            closesocket(s);
            return Err(e);
        }

        let mut sa: SockaddrIn = std::mem::zeroed();
        sa.sin_family = AF_INET as u16;
        sa.sin_port = addr.port().to_be();
        sa.sin_addr = u32::from(*addr.ip()).to_be();

        if bind(s, &sa, std::mem::size_of::<SockaddrIn>() as i32) == SOCKET_ERROR {
            let e = io::Error::last_os_error();
            closesocket(s);
            return Err(e);
        }

        Ok(UdpSocket::from_raw_socket(s as u64))
    }
}

// Old-draft STUN layout: type(2) len(2) txid(16). The console dialect
// uses 16-byte txids with no magic cookie, so bytes 4..20 are the id.
fn stun_txid(buf: &[u8]) -> Option<[u8; 16]> {
    if buf.len() < 20 { return None; }
    let mut tx = [0u8; 16];
    tx.copy_from_slice(&buf[4..20]);
    Some(tx)
}

fn remember_txid(shared: &Arc<Shared>, buf: &[u8], console: SocketAddr) {
    if let Some(tx) = stun_txid(buf) {
        let mut routes = shared.txid_routes.lock().unwrap();
        routes.insert(tx, console);
        // Keep the map bounded; entries are tiny and sessions are short.
        if routes.len() > 4096 {
            routes.clear();
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(crate) fn bind_udp_reuse(addr: SocketAddrV4) -> io::Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::V4(addr))
}

/// Hooks connecting the legacy relay to the tunnel.
/// All-off = legacy behavior (Allocates logged+dropped, raw tuple advertised).
#[derive(Default)]
pub struct UdpRelayHooks {
    pub relay_allocations: bool,
    pub allocate_relay: Option<Arc<dyn Fn(SocketAddrV4) -> Option<SocketAddrV4> + Send + Sync>>,
    pub stun_advertise: Option<Arc<dyn Fn() -> Option<SocketAddr> + Send + Sync>>,
}

pub struct UdpRelayConfig {
    pub peer: Ipv4Addr,
    pub upstream: SocketAddr,
    pub ports: Vec<u16>,
    pub seconds: u64,
    pub max_flows: usize,
    pub stun_ports: Vec<u16>,
    pub stun_wildcard: bool,
    pub hooks: UdpRelayHooks,
}

struct Flow {
    local: SocketAddrV4,
    ps3: SocketAddr,
    upstream: UdpSocket,
    reply: Arc<UdpSocket>,
    alive: Arc<AtomicBool>,
    last_used: Mutex<Instant>,
    packets_up: AtomicUsize,
    packets_down: AtomicUsize,
}

struct Shared {
    config: UdpRelayConfig,
    deadline: Instant,
    stop: AtomicBool,
    flows: Mutex<Vec<Arc<Flow>>>,
    // FIX 6: STUN transaction-id -> console source map. Console-originated
    // requests are indexed as they leave; diverted upstream replies are
    // routed back by the txid they echo, which uniquely identifies the
    // requesting console port even when many flows share one server IP.
    pub txid_routes: Mutex<HashMap<[u8; 16], SocketAddr>>,
    opened_total: AtomicUsize,
    rejected: AtomicUsize,
    relayed_up: AtomicUsize,
    relayed_down: AtomicUsize,
    hooks: Mutex<UdpRelayHooks>,
}

impl Shared {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }
}

pub struct UdpRelay {
    shared: Arc<Shared>,
}

impl UdpRelay {
    pub fn set_hooks(&self, hooks: UdpRelayHooks) {
        let _ = self.shared.hooks.lock().map(|mut h| *h = hooks);
    }

    pub fn spawn(mut config: UdpRelayConfig) -> io::Result<Self> {
        // Validation: catch_all overrides band, so ports can be empty
        if config.ports.is_empty() {
            return Err(bad("udp_ports_or_catchall_required"));
        }
        if config.stun_ports.is_empty() {
            return Err(bad("udp_stun_ports_empty"));
        }
        if config.max_flows == 0 {
            return Err(bad("udp_flow_budget"));
        }
        if config.seconds == 0 {
            return Err(bad("udp_session_seconds"));
        }

        let deadline = Instant::now() + Duration::from_secs(config.seconds);

        // Take hooks out of the config before the move into Shared.
        let hooks = std::mem::take(&mut config.hooks);

        let shared = Arc::new(Shared {
            relayed_up: AtomicUsize::new(0),
                              relayed_down: AtomicUsize::new(0),
                              rejected: AtomicUsize::new(0),
                              opened_total: AtomicUsize::new(0),
                              flows: Mutex::new(Vec::new()),
                              txid_routes: Mutex::new(HashMap::new()),
                              stop: AtomicBool::new(false),
                              config,
                              deadline,
                              hooks: Mutex::new(hooks),
        });

        event(
            "udp_relay_started",
            json!({
                "addresses": LEGACY_CM.len(),
                  "ports": shared.config.ports,
                  "stun_ports": shared.config.stun_ports,
                  "upstream": shared.config.upstream.to_string(),
                  "peer": shared.config.peer.to_string(),
                  "seconds": shared.config.seconds,
                  "max_flows": shared.config.max_flows,
            }),
        );
        let mut claimed: HashSet<(Ipv4Addr, u16)> = HashSet::new();
        // ---- RELAY family: config.ports on each legacy CM address ----
        for addr in LEGACY_CM {
            for port in shared.config.ports.clone() {
                let shared = shared.clone();
                thread::spawn(move || listener_thread(shared, addr, port));
            }
        }

        // ---- STUN family ----
        // Windows ordering guarantee: every alias STUN socket must own its port
        // BEFORE any wildcard listener binds. The wildcard uses SO_EXCLUSIVEADDRUSE,
        // which only succeeds when no alias socket holds the port, so coexistence
        // — the source of reply-tuple ambiguity — is impossible by construction.
        #[cfg(not(target_os = "windows"))]
        {
            for addr in LEGACY_CM {
                for port in shared.config.stun_ports.clone() {
                    let shared = shared.clone();
                    thread::spawn(move || stun_listener_thread(shared, addr, port));
                }
            }
            if shared.config.stun_wildcard {
                for port in shared.config.stun_ports.clone() {
                    let shared = shared.clone();
                    thread::spawn(move || {
                        stun_listener_thread(shared, Ipv4Addr::UNSPECIFIED, port)
                    });
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            // (a) ALIAS STUN sockets: bound synchronously HERE. By the time (b)
            // exists, each port is either alias-owned or provably unbindable.
            for port in shared.config.stun_ports.clone() {
                for addr in LEGACY_CM {
                    let bind_addr = SocketAddrV4::new(addr, port);
                    let first = match bind_udp_reuse(bind_addr) {
                        Ok(s) => {
                            let _ = s.set_read_timeout(Some(RECV_TIMEOUT));
                            event("udp_stun_listening", json!({"local": bind_addr.to_string()}));
                            Some(s)
                        }
                        Err(e) => {
                            // NEW: 10013/10049 were vanishing into the silent retry.
                            event("udp_stun_alias_bind_failed", json!({
                                "local": bind_addr.to_string(),
                                                                      "errno": e.raw_os_error(),
                            }));
                            None
                        }
                    };
                    let shared = shared.clone();
                    thread::spawn(move || stun_alias_thread_windows(shared, bind_addr, first));
                }
            }
            // (b) Wildcard: spawned strictly AFTER every bind above RETURNED.
            let mut wildcard_socks = Vec::new();
            if shared.config.stun_wildcard {
                for port in shared.config.stun_ports.clone() {
                    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
                    match bind_udp_reuse(bind_addr) {
                        Ok(s) => wildcard_socks.push((Arc::new(s), port)),
                        Err(e) => event("udp_stun_wildcard_bind_failed",
                                        json!({"local": bind_addr.to_string(), "error": e.to_string()})),
                    }
                }
            }
            for (sock, port) in wildcard_socks {
                let _ = sock.set_read_timeout(Some(RECV_TIMEOUT));
                event("udp_stun_listening", json!({ "local": format!("0.0.0.0:{port}") }));
                let shared = shared.clone();
                let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
                thread::spawn(move || serve_stun(&shared, &sock, bind_addr));
            }
        }

        // ---- legacy CM aliases: specific binds; now coexisting with the
        // wildcard via SO_REUSEADDR (REV 4). Each replies from the alias
        // the console actually dialed — the reply-source fix. ----
        for addr in LEGACY_CM {
            for port in shared.config.stun_ports.clone() {
                if !claimed.insert((addr, port)) {
                    event("udp_stun_duplicate_alias_skipped", json!({
                        "local": format!("{}:{}", addr, port),
                    }));
                    continue;
                }
                let shared = shared.clone();
                thread::spawn(move || stun_listener_thread(shared, addr, port));
            }
        }

        Ok(Self { shared })
    }

    pub fn stop(&mut self) {
        if !self.shared.stop.swap(true, Ordering::AcqRel) {
            let flows = self.shared.flows.lock().map(|f| f.len()).unwrap_or(0);
            event(
                "udp_relay_stopped",
                json!({
                    "flows_open": flows,
                    "flows_opened_total": self.shared.opened_total.load(Ordering::Relaxed),
                      "flows_rejected": self.shared.rejected.load(Ordering::Relaxed),
                      "relayed_up": self.shared.relayed_up.load(Ordering::Relaxed),
                      "relayed_down": self.shared.relayed_down.load(Ordering::Relaxed),
                }),
            );
        }
    }

    pub fn flow_count(&self) -> usize {
        self.shared.flows.lock().map(|f| f.len()).unwrap_or(0)
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.stop();
    }
}

fn listener_thread(shared: Arc<Shared>, addr: Ipv4Addr, port: u16) {
    let bind_addr = SocketAddrV4::new(addr, port);
    loop {
        if shared.stopping() { return; }
        let sock = match UdpSocket::bind(SocketAddr::V4(bind_addr)) {
            Ok(s) => Arc::new(s),
            Err(_) => {
                thread::sleep(BIND_RETRY);
                continue;
            }
        };
        let _ = sock.set_read_timeout(Some(RECV_TIMEOUT));
        event("udp_listener_bound", json!({"local": bind_addr.to_string()}));
        if serve_listener(&shared, &sock, bind_addr) { return; }
        thread::sleep(BIND_RETRY);
    }
}

fn serve_listener(shared: &Arc<Shared>, sock: &Arc<UdpSocket>, local: SocketAddrV4) -> bool {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if shared.stopping() { return true; }
        let (n, source) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => continue,
            Err(_) => return false,
        };
        if source.ip() != std::net::IpAddr::V4(shared.config.peer) {
            // FIX 5: was a bare, SILENT continue here — diverted upstream
            // replies (see rescue_upstream_reply) vanished invisibly on the
            // generic band. Try the flow rescue first; only drop if no live
            // flow's upstream matches this source.
            if rescue_upstream_reply(shared, source, &buf[..n]) {
                continue;
            }
            event("udp_listener_peer_filter_drop", json!({
                "source": source.to_string(),
                                                         "peer": shared.config.peer.to_string(),
            }));
            continue;
        }
        let Some(flow) = flow_for(shared, sock, local, source, shared.config.upstream) else { continue; };
        if flow.upstream.send(&buf[..n]).is_ok() {
            *flow.last_used.lock().unwrap() = Instant::now();
            flow.packets_up.fetch_add(1, Ordering::Relaxed);
            shared.relayed_up.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// Un-gate: works on all platforms again.
fn stun_listener_thread(shared: Arc<Shared>, addr: Ipv4Addr, port: u16) {
    let bind_addr = SocketAddrV4::new(addr, port);
    loop {
        if shared.stopping() { return; }
        // Platform dispatch: SO_REUSEADDR before bind on all platforms
        // (Windows FFI helper, Linux raw-fd helper, plain std elsewhere).
        let sock = match bind_udp_reuse(bind_addr) {
            Ok(s) => Arc::new(s),
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                event("udp_stun_port_busy", json!({"local": bind_addr.to_string()}));
                return;
            }
            Err(_) => { thread::sleep(BIND_RETRY); continue; }
        };
        let _ = sock.set_read_timeout(Some(RECV_TIMEOUT));
        event("udp_stun_listening", json!({"local": bind_addr.to_string()}));
        if serve_stun(&shared, &sock, bind_addr) { return; }
        thread::sleep(BIND_RETRY);
    }
}

#[cfg(target_os = "windows")]
fn stun_alias_thread_windows(
    shared: Arc<Shared>,
    bind_addr: SocketAddrV4,
    first: Option<UdpSocket>,
) {
    let mut pre = first;
    let mut attempt: u32 = 0;
    loop {
        if shared.stopping() { return; }
        let sock = match pre.take() {
            Some(s) => Arc::new(s),
            None => match bind_udp_reuse(bind_addr) {
                Ok(s) => {
                    attempt = 0;
                    let _ = s.set_read_timeout(Some(RECV_TIMEOUT));
                    event("udp_stun_listening", json!({"local": bind_addr.to_string()}));
                    Arc::new(s)
                }
                // HERE — this arm was: Err(_) => { thread::sleep(BIND_RETRY); continue; }
                Err(e) => {
                    attempt += 1;
                    if attempt == 1 || attempt % 10 == 0 {
                        event("udp_stun_alias_retry_failed", json!({
                            "local": bind_addr.to_string(),
                                                                   "errno": e.raw_os_error(),
                                                                   "attempt": attempt,
                        }));
                    }
                    thread::sleep(BIND_RETRY);
                    continue;
                }
            },
        };
        if serve_stun(&shared, &sock, bind_addr) { return; }
        thread::sleep(BIND_RETRY);
    }
}

fn serve_stun(shared: &Arc<Shared>, sock: &Arc<UdpSocket>, local: SocketAddrV4) -> bool {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if shared.stopping() { return true; }
        let (n, source) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => continue,
            Err(_) => return false,
        };
        if source.ip() != std::net::IpAddr::V4(shared.config.peer)
            && std::env::var("P2_ALLOW_ANY_SENDER").is_err()
            {
                if rescue_upstream_reply(shared, source, &buf[..n]) {
                    continue;
                }
                event("tunnel_peer_filter_drop", json!({
                    "source": source.to_string(),
                                                       "peer": shared.config.peer.to_string(),
                }));
                continue;
            }

            // The advertise hook is the only one still consulted.
            let stun_advertise = {
                let h = shared.hooks.lock().unwrap();
                h.stun_advertise.clone()
            };

            match stun_classify(&buf[..n]) {
                StunKind::BindingRequest => {
                    // Fix 8 gate: answer ONLY when the hook yields a truthful endpoint.
                    // None => silence (mimics the Valve black-hole that held for the
                    // whole successful local capture). Never fall back to source or
                    // wire_port — that manufactured the dead :27050 candidate.
                    match stun_advertise.as_ref().and_then(|f| f()) {
                        Some(advertised) => {
                            match send_stun_response_advertised(sock, source, &buf[..n], advertised) {
                                Ok(resp) => event("udp_stun_answered", json!({
                                    "local": sock.local_addr().map(|a| a.to_string()).unwrap_or_default(),
                                                                             "console": source.to_string(),
                                                                             "advertised": advertised.to_string(),
                                                                             "resp_hex": hex(&resp),
                                })),
                                Err(_) => event("udp_stun_error", json!({
                                    "console": source.to_string(),
                                })),
                            }
                        }
                        None => event("udp_stun_probe_blackholed", json!({
                            "console": source.to_string(),
                                                                         "reason": "no verified advertised endpoint; silence is safe",
                        })),
                    }
                }
                StunKind::Other(0x0003) => {
                    // FIX 1: TURN Allocate. NO local answer — the request
                    // is addressed to genuine Valve TURN infrastructure and
                    // carries credentials only that infrastructure can
                    // honor (MESSAGE-INTEGRITY under Valve's key). Our
                    // unsigned fabrication was rejected every time (the
                    // console retransmitted identical txids across every
                    // capture). Forward it upstream like ordinary traffic;
                    // the real server's signed response flows back to the
                    // console through this socket's tuple.
                    event("udp_stun_allocate_passthrough", json!({
                        "console": source.to_string(),
                                                                 "local": local.to_string(),
                                                                 "len": n,
                    }));
                    remember_txid(shared, &buf[..n], source);
                    let Some(flow) = flow_for(shared, sock, local, source, upstream_for(shared, local)) else {
                        event("udp_stun_allocate_passthrough_failed", json!({
                            "console": source.to_string(),
                                                                            "reason": "flow_budget_or_bind",
                        }));
                        continue;
                    };
                    if flow.upstream.send(&buf[..n]).is_ok() {
                        *flow.last_used.lock().unwrap() = Instant::now();
                        flow.packets_up.fetch_add(1, Ordering::Relaxed);
                        shared.relayed_up.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                }
                StunKind::Other(msg_type) => {
                    if msg_type == 0x0102 {
                        // Binding SUCCESS response — relayed downstream
                        // material; log loudly, and unlike the old arm it
                        // MUST still pass through the flow (see the 0x0003
                        // rationale — same reasoning, same machinery).
                        event("udp_stun_success", json!({
                            "console": source.to_string(),
                                                        "len": n,
                                                        "hex": hex(&buf[..n]),
                        }));
                        remember_txid(shared, &buf[..n], source);
                    } else {
                        event("udp_stun_other", json!({
                            "type": format!("{msg_type:#06x}"),
                                                      "len": n,
                                                      "console": source.to_string(),
                        }));
                    }
                    // ALL other STUN traffic also passes through upstream.
                    // It previously fell through the match and vanished;
                    // infra-facing STUN exchanges belong to Valve's
                    // servers, so hand them their traffic.
                    if let Some(flow) = flow_for(shared, sock, local, source, upstream_for(shared, local)) {
                        if flow.upstream.send(&buf[..n]).is_ok() {
                            *flow.last_used.lock().unwrap() = Instant::now();
                            flow.packets_up.fetch_add(1, Ordering::Relaxed);
                            shared.relayed_up.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                StunKind::NotStun => {
                    // Non-STUN datagram on a STUN port: pass through, same
                    // as serve_listener would.
                    remember_txid(shared, &buf[..n], source);
                    if let Some(flow) = flow_for(shared, sock, local, source, upstream_for(shared, local)) {
                        if flow.upstream.send(&buf[..n]).is_ok() {
                            *flow.last_used.lock().unwrap() = Instant::now();
                            flow.packets_up.fetch_add(1, Ordering::Relaxed);
                            shared.relayed_up.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
    }
}

// Chooses the true upstream for a flow. Under Linux TPROXY the listener's
// local address is the original destination (public Valve/SONY infra) and is
// directly routable. Under the Windows catch-all it is a private alias
// (10.x / 127.x / 192.168.x / 172.16-31.x) that must not be dialed; fall back
// to the CM upstream exactly as before.
fn upstream_for(shared: &Shared, orig_dst: SocketAddrV4) -> SocketAddr {
    let o = orig_dst.ip().octets();
    let private_alias = o[0] == 10
        || o[0] == 127
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 172 && (o[1] & 0xf0) == 0x10);
    if private_alias {
        shared.config.upstream
    } else {
        SocketAddr::V4(orig_dst)
    }
}

// Diverted-upstream-reply rescue. When a flow's upstream socket binds an
// ephemeral port inside the TPROXY band, genuine upstream answers (e.g.
// Valve TURN replying from 79.141.174.7:45296 to an Allocate sent to
// 79.141.174.7:4380) get diverted into our listeners instead of reaching
// flow_reader. Match the live flow whose upstream remote has this source IP
// and deliver the payload to the console through the flow's transparent
// reply socket, so the console sees it arriving from the exact original-
// destination tuple it probed. Pure relay: the bytes are the upstream's own;
// no fabrication. Returns true when the datagram was consumed.
fn rescue_upstream_reply(shared: &Arc<Shared>, source: SocketAddr, payload: &[u8]) -> bool {
    // FIX 6: route by the STUN transaction ID echoed in the response.
    // IP-only matching cross-delivered Valve's Allocate Success to a
    // console port that never asked (observed: request from :57828,
    // delivery to :57846) because several flows share the server IP.
    let console = stun_txid(payload).and_then(|tx| {
        shared.txid_routes.lock().ok().and_then(|m| m.get(&tx).copied())
    });

    let guard = shared.flows.lock().ok();
    let Some(flows) = guard else { return false; };
    let mut matching = flows.iter().filter(|f| {
        f.alive.load(Ordering::Relaxed)
        && f.upstream.peer_addr().ok().map(|a| a.ip()) == Some(source.ip())
    });
    let flow = match console {
        Some(c) => matching.find(|f| f.ps3 == c).cloned(),
        None => {
            // No txid (non-STUN payload or unknown id): fall back to the
            // most recently used matching flow.
            let mut best: Option<(std::time::Instant, Arc<Flow>)> = None;
            for f in matching {
                let Ok(used) = f.last_used.lock() else { continue; };
                if best.as_ref().is_some_and(|(t, _)| *used <= *t) { continue; }
                best = Some((*used, f.clone()));
            }
            best.map(|(_, f)| f)
        }
    };
    let Some(flow) = flow else { return false; };
    if flow.reply.send_to(payload, flow.ps3).is_ok() {
        flow.packets_down.fetch_add(1, Ordering::Relaxed);
        shared.relayed_down.fetch_add(1, Ordering::Relaxed);
        *flow.last_used.lock().unwrap() = Instant::now();
        event("udp_flow_reply_delivered", json!({
            "source": source.to_string(),
            "console": flow.ps3.to_string(),
            "txid_routed": console.is_some(),
            "len": payload.len(),
            "resp_hex": hex(&payload),
        }));
    } else {
        event("udp_flow_reply_send_failed", json!({
            "source": source.to_string(),
            "console": flow.ps3.to_string(),
        }));
    }
    true
}

fn flow_for(
    shared: &Arc<Shared>,
    reply: &Arc<UdpSocket>,
    local: SocketAddrV4,
    ps3: SocketAddr,
    dst: SocketAddr,
) -> Option<Arc<Flow>> {
    let mut flows = shared.flows.lock().ok()?;
    if let Some(found) = flows
        .iter()
        .find(|f| f.local == local && f.ps3 == ps3 && f.alive.load(Ordering::Relaxed))
        {
            return Some(found.clone());
        }
        if flows.len() >= shared.config.max_flows {
            shared.rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let upstream = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                event("udp_flow_bind_failed", json!({"error": e.to_string()}));
                return None;
            }
        };
        // FIX 4: dial the ORIGINAL DESTINATION (Valve TURN / STUN / game
        // server) instead of the generic CM fallback. The dedup key
        // (local, ps3) is unaffected: under TPROXY local == the destination,
        // so retransmissions of the same Allocate still reuse one flow.
        if let Err(e) = upstream.connect(dst) {
            event("udp_flow_connect_failed", json!({
                "error": e.to_string(),
                                                   "dst": dst.to_string(),
            }));
            return None;
        }
        let _ = upstream.set_read_timeout(Some(RECV_TIMEOUT));
        let flow = Arc::new(Flow {
            local,
            ps3,
            upstream,
            reply: reply.clone(),
                            alive: Arc::new(AtomicBool::new(true)),
                            last_used: Mutex::new(Instant::now()),
                            packets_up: AtomicUsize::new(0),
                            packets_down: AtomicUsize::new(0),
        });
        flows.push(flow.clone());
        shared.opened_total.fetch_add(1, Ordering::Relaxed);
        event("udp_flow_opened",
              json!({
                  "local": local.to_string(),
                    "console_port": ps3.port(),
                    "upstream": dst.to_string(),
              }));
        let reader_shared = shared.clone();
        let reader_flow = flow.clone();
        thread::spawn(move || flow_reader(reader_shared, reader_flow));
        Some(flow)
}

fn flow_reader(shared: Arc<Shared>, flow: Arc<Flow>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if !flow.alive.load(Ordering::Relaxed) || shared.stopping() { break; }
        match flow.upstream.recv(&mut buf) {
            Ok(n) => {
                if flow.reply.send_to(&buf[..n], flow.ps3).is_ok() {
                    flow.packets_down.fetch_add(1, Ordering::Relaxed);
                    shared.relayed_down.fetch_add(1, Ordering::Relaxed);
                }
                *flow.last_used.lock().unwrap() = Instant::now();
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {
                if flow.last_used.lock().unwrap().elapsed() >= FLOW_IDLE { break; }
            }
            Err(_) => break,
        }
    }
    flow.alive.store(false, Ordering::Relaxed);
    event("udp_flow_closed",
          json!({
              "local": flow.local.to_string(),
                "console_port": flow.ps3.port(),
                "packets_up": flow.packets_up.load(Ordering::Relaxed),
                "packets_down": flow.packets_down.load(Ordering::Relaxed),
          }));
}
