// =============================================================================
// ps3_tunnel.rs — bridge-core: user-space VPN-style tunnel between two
// middleware instances. Pure std threads, no new dependencies, crypto
// reuses channel::Envelope (AES-256-CBC + HMAC-SHA1).
//
// REV 3 — PORT-BAND ALIAS LISTENER
//
// Motivation (live capture, 00:34–00:35): with a single alias socket on the
// configured remote_port, the console swept DOWNWARD through candidate
// ports 61795 -> 61783 -> 61770 -> 61760 -> 61751 in ~40 seconds, each
// probe answered by a kernel ICMP port-unreachable (nothing bound), after
// which the session died. The remote console advertises a SET of candidate
// ports (its ephemeral bindings), and the local console tries them until
// one answers — classic ICE-style candidate checking.
//
// Fix: instead of one socket, bind a BAND of sockets across the candidate
// range on the alias IP (configurable via TunnelConfig::port_band). Each
// bound port gets a lightweight recv worker. Reply fidelity is preserved:
// each worker records console_src_port -> alias_port, and wire->console
// delivery uses the learned socket, so replies carry the exact source
// tuple (remote_ps3 : dialed_port) the console expects.
//
// MODEL (validated topology):
//
//   Console L 192.168.0.242 ─ gw: Linux PC ══tunnel══ Windows PC :gw ─ Console W 10.0.0.182
//
//   Console L sends: src 192.168.0.242:541xx -> dst 10.0.0.182:<candidate>
//   Console W sends: src 10.0.0.182:<candidate>  -> dst 192.168.0.242:541xx
//
// Each middleware holds a /32 alias for the REMOTE console's IP and binds
// sockets on (remote_ip : remote_port) plus every port in the optional
// band. Consequences:
//
//   * Outbound console traffic lands on some bound socket by normal
//     routing (the PC is the console's gateway; the destination is a
//     local alias). Whichever candidate port answers first is expected
//     to lock the session (first-responsive-candidate-wins).
//   * Replies sent from that same socket carry source
//     (remote_ip : candidate_port) — the exact tuple the console dialed.
//   * No NAT state, no port rewriting, symmetric both sides.
//
// STARTUP ORDERING (unchanged): the app waits for serve()'s "listening"
// event before applying network settings, and the privileged helper
// creates the /32 alias only during that apply. The bind loops therefore
// RETRY in a background thread until the alias appears. spawn() never
// blocks.
//
// WIRE FORMAT (inside Envelope encryption, 16-byte block padded):
//   [u8 flag][u16 src_port BE][payload]
//   flag 0 = data, 1 = keepalive (src_port ignored)
//   NOTE: src_port is the CONSOLE's source port, not the alias port.
//   Alias-port routing is local knowledge per side and never crosses
//   the wire — the two sides learn their own maps symmetrically.
//
// EVENTS:
//   tunnel_wire_listening — wire socket bound, awaiting the peer and alias
//   tunnel_started        — PRIMARY alias socket (remote_port) bound
//   tunnel_band_ready     — every requested port is bound (or skipped-busy)
//   tunnel_band_partial   — deadline hit; some band ports never bound
//                           (primary bound, session still usable)
//   tunnel_alias_absent   — deadline hit and the primary never bound
//   tunnel_port_busy      — another process owns one band port (skipped)
//   tunnel_wire_rejected  — datagram from an unexpected wire peer
//   tunnel_flow_rejected  — console traffic from an address other than ours
//   tunnel_decrypt_rejected — garbage or forgery on the wire
//   tunnel_in_dropped     — inbound payload with no alias socket to send
//                           from (before band/binder completes)
//   tunnel_stun_answered  — STUN Binding Request intercepted and answered
//   tunnel_stun_other     — STUN message type not handled (e.g. 0x0003 = Allocate)
//   tunnel_stun_listening — probe responder bound on a dedicated port
//   tunnel_stun_error     — send failure on a STUN response (transient-filtered)
//   tunnel_out / tunnel_in — per-datagram counters (debug stream only)
// =============================================================================

use crate::{bad, channel::Envelope, gateway::event};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const MAX_PAYLOAD: usize = 1400; // stay under wire MTU after envelope padding
const KEEPALIVE: Duration = Duration::from_secs(8);
const POLL: Duration = Duration::from_millis(200);
/// Hard cap on band sockets so a fat-fingered range can't fork 65k threads.
const MAX_BAND_SOCKETS: usize = 512;

const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x4A];

/// STUN configuration — minimal, no external dependencies.
#[derive(Clone)]
pub struct StunCfg {
    /// Whether to enable STUN responder handling.
    pub enabled: bool,
    /// Dedicated answer-only probe ports (default: 3478, the standard STUN
    /// port). Kept separate from the gameplay band; they never forward.
    pub probe_ports: Vec<u16>,
}

impl Default for StunCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            probe_ports: vec![3478],
        }
    }
}

#[derive(Clone)]
pub struct TunnelConfig {
    /// This side's console (the only accepted source on the alias sockets).
    pub local_ps3: Ipv4Addr,
    /// The remote console's private IP — the address OUR console dials.
    /// This PC must hold a /32 alias for it (privileged helper's job).
    pub remote_ps3: Ipv4Addr,
    /// The remote console's PRIMARY advertised port. Always bound first
    /// and doubles as the fallback delivery socket.
    pub remote_port: u16,
    /// Own wire listener, e.g. 0.0.0.0:27050.
    pub wire_bind: SocketAddr,
    /// The other middleware's public endpoint.
    pub wire_peer: SocketAddr,
    /// Pre-shared session key (paired setup).
    pub key: [u8; 32],
    /// Startup grace period for the alias to appear, in seconds.
    pub seconds: u64,
    /// STUN responder configuration.
    pub stun: StunCfg,
    /// OPTIONAL inclusive band of extra alias ports to bind, (first, last).
    /// The live capture showed the peer console advertising a downward
    /// sweep of ephemeral candidates (61795 -> 61751 over 40s), so a band
    /// like Some((61700, 61800)) catches the whole sweep. None = legacy
    /// single-port behaviour (remote_port only).
    ///
    /// Each side should derive its band from ITS OWN capture (the tuple
    /// their console observes for us): tcpdump "udp and dst host <remote>"
    /// on this machine shows the candidate ports OUR console dials.
    pub port_band: Option<(u16, u16)>,
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
struct AliasTable {
    sockets: Mutex<HashMap<u16, Arc<UdpSocket>>>,
    routes: Mutex<HashMap<u16, u16>>,
}

impl AliasTable {
    fn insert(&self, port: u16, socket: Arc<UdpSocket>) {
        self.sockets.lock().unwrap().insert(port, socket);
    }

    fn get(&self, port: u16) -> Option<Arc<UdpSocket>> {
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
}

fn alias_addr(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(std::net::IpAddr::V4(ip), port)
}

pub struct Ps3Tunnel {
    stop: Arc<AtomicBool>,
}

impl Ps3Tunnel {
    /// Non-blocking: returns as soon as the wire socket is bound. Alias
    /// sockets are bound later by the retrying binder thread (see module
    /// header for why this must never block). `stop()` terminates workers.
    pub fn spawn(config: TunnelConfig) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(config.seconds.max(1));

        // PC<->PC wire socket: no alias involved, bind immediately.
        let wire = Arc::new(UdpSocket::bind(config.wire_bind)?);
        let wire_peer = config.wire_peer;

        let table = Arc::new(AliasTable::default());
        let ports = config.listen_set();

        event("tunnel_wire_listening", json!({
            "wire": config.wire_bind.to_string(),
                                             "peer": config.wire_peer.to_string(),
                                             "remote_ps3": config.remote_ps3.to_string(),
                                             "remote_port": config.remote_port,
                                             "alias_ports": ports.len(),
        }));

        // ---- thread 1: band binder (retry until the helper creates the alias) ----
        //
        // Iterates the port set every POLL, binding anything not yet bound.
        // AddrNotAvailable => alias not up yet, retry. AddrInUse => another
        // process owns that port, skip permanently (the console will just
        // keep sweeping past it). Emits tunnel_started when the PRIMARY
        // socket lands (same semantics as the previous revision).
        {
            let stop = stop.clone();
            let table = table.clone();
            let wire = wire.clone();
            let wire_peer = wire_peer;
            let remote_ps3 = config.remote_ps3;
            let local_ps3 = config.local_ps3;
            let key = config.key;
            let stun_enabled = config.stun.enabled;
            let primary = config.remote_port;
            let ports = ports.clone();
            let deadline = deadline;
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
                        match UdpSocket::bind(alias_addr(remote_ps3, p)) {
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
                                    stop.clone(),
                                                     table.clone(),
                                                     wire.clone(),
                                                     wire_peer,
                                                     Envelope::modern(key),
                                                     local_ps3,
                                                     stun_enabled,
                                                     p,
                                                     s,
                                );
                            }
                            // Alias does not exist yet — the helper hasn't
                            // finished. Expected during startup; keep polling.
                            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                                pending += 1;
                            }
                            // Someone else owns this port (e.g. the console
                            // itself reached us directly, or a stale bind).
                            // Skip it; the sweep will pass it by.
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

        // ---- thread 3: tunnel -> console (reads the wire socket) ----
        {
            let stop = stop.clone();
            let table = table.clone();
            let local_ps3 = config.local_ps3;
            let primary = config.remote_port;
            let envelope = Envelope::modern(config.key);
            let wire = wire.clone();
            let wire_peer = wire_peer;
            thread::spawn(move || {
                // Wait for the primary socket, honouring stop. (Binder emits
                // tunnel_alias_absent on deadline; we just keep polling until
                // then because stop/process teardown ends us regardless.)
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    if table.get(primary).is_some() {
                        break;
                    }
                    thread::sleep(POLL);
                }
                let mut buf = [0u8; 65536];
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    match wire.recv_from(&mut buf) {
                        Ok((n, from)) => {
                            if from != wire_peer {
                                event("tunnel_wire_rejected", json!({"from": from.to_string()}));
                                continue;
                            }
                            let plain = match envelope.decode(&buf[..n]) {
                                Ok(p) => p,
                          Err(_) => {
                              event("tunnel_decrypt_rejected", json!({}));
                              continue;
                          }
                            };
                            if plain.len() < 3 {
                                continue;
                            }
                            let (flag, port) =
                            (plain[0], u16::from_be_bytes([plain[1], plain[2]]));
                            if flag != 0 {
                                continue; // keepalive (1) and anything unknown
                            }
                            // Deliver from the LEARNED alias socket: the console
                            // sees the exact remote tuple it dialed as source.
                            let target = SocketAddr::new(
                                std::net::IpAddr::V4(local_ps3), port);
                            match table.route_socket(port, primary) {
                                Some(socket) => {
                                    if let Err(e) = socket.send_to(&plain[3..], target) {
                                        if !transient(&e) {
                                            return;
                                        }
                                    }
                                    event("tunnel_in", json!({
                                        "bytes": plain.len() - 3,
                                                             "dst_port": port,
                                    }));
                                }
                                None => {
                                    // Primary not bound yet (or busy-skipped):
                                    // dropping beats answering from the wrong port.
                                    event("tunnel_in_dropped", json!({"dst_port": port}));
                                }
                            }
                        }
                        Err(e) if transient(&e) => {}
                        Err(_) => return,
                    }
                }
            });
        }

        // ---- thread 4: keepalive — holds the NAT mapping and proves liveness ----
        {
            let stop = stop.clone();
            let envelope = Envelope::modern(config.key);
            let wire = wire.clone();
            let wire_peer = wire_peer;
            thread::spawn(move || {
                let frame = vec![1u8, 0, 0];
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let sealed = envelope.encode(&frame);
                    let _ = wire.send_to(&sealed, wire_peer);
                    thread::sleep(KEEPALIVE);
                }
            });
        }

        // ---- thread 5+: STUN probe responders (dedicated ports, answer-only) ----
        //
        // Separate from the gameplay band: these bind the alias IP at the
        // standard probe ports (3478 default), answer Binding Requests, and
        // forward nothing. Answer-only, so they never feed the gameplay path.
        if config.stun.enabled {
            for port in &config.stun.probe_ports {
                let stop = stop.clone();
                let remote_ps3 = config.remote_ps3;
                let probe_port = *port;
                let deadline = deadline;
                thread::spawn(move || {
                    let target = alias_addr(remote_ps3, probe_port);
                    // Bind with the same retry semantics: the alias may not
                    // exist yet when spawn() runs.
                    let socket = loop {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        match UdpSocket::bind(target) {
                            Ok(s) => break s,
                              Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                                  if Instant::now() >= deadline {
                                      return; // alias never appeared; nothing to serve
                                  }
                                  thread::sleep(POLL);
                              }
                              Err(_) => return,
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
                                match stun_classify(&buf[..n]) {
                                    StunKind::BindingRequest => {
                                        if let Err(e) =
                                            send_stun_response(&socket, from, &buf[..n])
                                            {
                                                if !transient(&e) {
                                                    event("tunnel_stun_error", json!({
                                                        "kind": format!("{:?}", e.kind()),
                                                                                     "probe_port": probe_port,
                                                    }));
                                                }
                                            } else {
                                                event("tunnel_stun_answered", json!({
                                                    "probe_port": probe_port,
                                                    "from": from.to_string(),
                                                }));
                                            }
                                    }
                                    StunKind::Other(msg_type) => {
                                        event("tunnel_stun_other", json!({
                                            "probe_port": probe_port,
                                            "type": format!("{:#06x}", msg_type),
                                                                         "len": n,
                                        }));
                                    }
                                    StunKind::NotStun => {}
                                }
                            }
                            Err(e) if transient(&e) => {}
                            Err(_) => return,
                        }
                    }
                });
            }
        }

        Ok(Self { stop })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

impl Drop for Ps3Tunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Per-socket console->tunnel worker. One per bound alias port; spawned by
/// the binder the moment its socket lands. Validates the console source,
/// learns the reply route, answers STUN locally, then forwards the original
/// through the tunnel (so the genuine remote answer also arrives).
///
/// Lifecycle: exits on stop, fatal wire error, or socket error. Like the
/// rest of this codebase, threads blocked in recv_from terminate at process
/// teardown if never woken.
fn spawn_console_worker(
    stop: Arc<AtomicBool>,
    table: Arc<AliasTable>,
    wire: Arc<UdpSocket>,
    wire_peer: SocketAddr,
    envelope: Envelope,
    local_ps3: Ipv4Addr,
    stun_enabled: bool,
    port: u16,
    socket: Arc<UdpSocket>,
) {
    thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            if stop.load(Ordering::Relaxed) {
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
                    table.learn(from.port(), port);

                    // STUN sniff: answer locally, then fall through to
                    // forwarding so the genuine remote reply also arrives.
                    if stun_enabled {
                        match stun_classify(&buf[..n]) {
                            StunKind::BindingRequest => {
                                if let Err(e) = send_stun_response(&socket, from, &buf[..n]) {
                                    if !transient(&e) {
                                        event("tunnel_stun_error", json!({
                                            "kind": format!("{:?}", e.kind()),
                                                                         "alias_port": port,
                                        }));
                                    }
                                } else {
                                    event("tunnel_stun_answered", json!({
                                        "from": from.to_string(),
                                                                        "alias_port": port,
                                    }));
                                }
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

                    let mut frame = Vec::with_capacity(3 + n);
                    frame.push(0u8);
                    frame.extend_from_slice(&from.port().to_be_bytes());
                    frame.extend_from_slice(&buf[..n]);
                    let sealed = envelope.encode(&frame);
                    if let Err(e) = wire.send_to(&sealed, wire_peer) {
                        if !transient(&e) {
                            event("tunnel_wire_error", json!({
                                "kind": format!("{:?}", e.kind()),
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

/// Windows surfaces ICMP port-unreachable on unrelated later calls
/// (ConnectionReset/ConnectionAborted); treat as noise. Same helper as the
/// UDP relay module — hoist to a shared util when convenient.
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

// =============================================================================
// STUN responder — RFC 5389 + legacy RFC 3489 Binding Requests
// =============================================================================
//
// STRICT FRAMING (deliberate): a datagram qualifies only if
//   * length >= 20, and the declared header length matches exactly
//     (20 + msg_len == datagram len) — game traffic can't false-positive;
//   * top two bits of the message type are zero;
//   * the type is a Binding Request (0x0001).
//
// MAGIC COOKIE: required for RFC 5389 requests. If absent, we treat the
// message as legacy RFC 3489 and answer with a plain MAPPED-ADDRESS
// attribute instead of XOR-MAPPED-ADDRESS.
//
// RESPONSE SOURCE: sent from the socket the request arrived on (an alias
// band socket or a probe socket), so the console sees source
// (remote_ps3 : dialed_port) — exactly the tuple it dialed. THAT is the
// candidate-verification signal.
//
// NO MESSAGE-INTEGRITY: credentials live in the consoles' signaling; a
// strict stack may reject our response. The forwarded original lets the
// genuine remote console answer too.

enum StunKind {
    BindingRequest,
    /// A well-formed STUN message of some other type (e.g. 0x0003 Allocate).
    Other(u16),
    NotStun,
}

/// Classify a datagram: BindingRequest / Other(type) / NotStun.
fn stun_classify(buf: &[u8]) -> StunKind {
    if buf.len() < 20 {
        return StunKind::NotStun;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;

    // Top two bits must be zero (method/class encoding space).
    if msg_type & 0xC000 != 0 {
        return StunKind::NotStun;
    }
    // Declared length must match the datagram exactly.
    if 20 + msg_len != buf.len() {
        return StunKind::NotStun;
    }
    if msg_type == 0x0001 {
        StunKind::BindingRequest
    } else {
        // Valid STUN framing, different type (Allocate, Send Indication, ...)
        StunKind::Other(msg_type)
    }
}

/// Build and send a Binding Success Response for `req` to `from`, on `socket`.
///
/// RFC 5389 request (magic cookie present):
///   0x0101 | len | cookie | txid | XOR-MAPPED-ADDRESS
/// Legacy RFC 3489 request (no cookie):
///   0x0101 | len | txid          | MAPPED-ADDRESS (plain)
fn send_stun_response(socket: &UdpSocket, from: SocketAddr, req: &[u8]) -> io::Result<()> {
    let rfc5389 = req[4..8] == STUN_MAGIC_COOKIE;
    let mut resp: Vec<u8> = Vec::with_capacity(44);

    // Header: type 0x0101, length placeholder, cookie (5389 only), txid.
    resp.extend_from_slice(&0x0101u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes()); // patched after attrs
    if rfc5389 {
        resp.extend_from_slice(&STUN_MAGIC_COOKIE);
    }
    resp.extend_from_slice(&req[8..20]); // transaction ID, echoed verbatim

    // One address attribute describing the REQUESTER's observed tuple.
    let (attr_type, xor): (u16, bool) = if rfc5389 {
        (0x0020, true) // XOR-MAPPED-ADDRESS
    } else {
        (0x0001, false) // MAPPED-ADDRESS
    };
    resp.extend_from_slice(&attr_type.to_be_bytes());
    resp.extend_from_slice(&8u16.to_be_bytes()); // attribute length
    resp.push(0); // reserved byte
    resp.push(0x01); // family: IPv4

    let port = from.port();
    let mapped_port = if xor { port ^ 0x2112 } else { port };
    resp.extend_from_slice(&mapped_port.to_be_bytes());

    if let std::net::IpAddr::V4(v4) = from.ip() {
        let o = v4.octets();
        if xor {
            resp.push(o[0] ^ STUN_MAGIC_COOKIE[0]);
            resp.push(o[1] ^ STUN_MAGIC_COOKIE[1]);
            resp.push(o[2] ^ STUN_MAGIC_COOKIE[2]);
            resp.push(o[3] ^ STUN_MAGIC_COOKIE[3]);
        } else {
            resp.extend_from_slice(&o);
        }
    } else {
        // IPv4-only tunnel topology; anything else is a caller error.
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "stun_v6_unsupported"));
    }

    // Patch the header message length now that attributes are known.
    let attr_bytes = resp.len() - 20;
    resp[2] = (attr_bytes >> 8) as u8;
    resp[3] = attr_bytes as u8;

    socket.send_to(&resp, from)?;
    Ok(())
}

// =============================================================================
// INTEGRATION NOTES
//
// CONFIG RIPPLE (breaking — every TunnelConfig construction must add the
// new field; E0363 otherwise):
//
//     port_band: None,                       // legacy single-port behaviour
//     // or, per the live capture:
//     port_band: Some((61700, 61800)),       // catch the candidate sweep
//
//   rg "TunnelConfig \{" for every constructor (serve() in bridge-core's
//   main.rs, plus any test fixtures).
//
//   BOTH sides should enable a band. Each side's band must cover the ports
//   ITS console dials, i.e. the candidates the REMOTE console advertises —
//   read them from a local capture:
//     sudo tcpdump -i any -nn "udp and dst host <remote_ps3>"
//   Capture through one gameplay transition and take the union of the
//   destination ports observed (the sweep was 61795..61751 in the rev-3
//   capture; a comfortable margin is 61700..61800, 101 sockets).
//
// EVENT SURFACING: optional friendly_event arms for tunnel_band_ready /
// tunnel_band_partial / tunnel_port_busy / tunnel_in_dropped.
//
// RESOURCE SHAPE: one OS thread + one 64 KB receive buffer per bound port.
// A 101-port band is ~101 mostly-idle threads (~6.5 MB of buffers) — well
// within budget on Linux and Windows. MAX_BAND_SOCKETS (512) is the hard
// ceiling; trim the band if you ever see fd/thread pressure (ulimit -n,
// p2-middleware's RLIMIT_NOFILE at ~1024 is the first wall).
//
// WHY THE WIRE FORMAT DID NOT CHANGE: [flag][src_port][payload] carries
// the CONSOLE's source port only. Alias-port knowledge (which of our
// sockets a given console flow talked to) is per-side and learned
// symmetrically on both ends, so no extra wire field is needed.
//
// FIRST-RESPONSIVE-CANDIDATE-WINS ASSUMPTION: the revision bets that the
// console commits to whichever candidate port answers (ICE-like behaviour,
// consistent with the observed orderly downward sweep). If it turns out
// the console requires the PEER's payload (a real tunneled reply from the
// remote console, not our locally generated STUN answer) before locking,
// the band still helps: the genuine reply flows through the learned route
// and arrives from the correct tuple — that path needs BOTH middlewares
// live, so test with both sides running.
//
// ALIAS CREATION (unchanged) — the privileged helper must create the /32:
//   Linux:   ip addr add <remote_ps3>/32 dev <lan-iface>
//            (or tunnel_setup::ensure_alias via the headless confirm splice)
//   Windows: New-NetIPAddress -IPAddress <remote_ps3> -PrefixLength 32 `
//              -InterfaceAlias "<lan>" -SkipAsSource $false
//   Manual mid-session works: all bind loops retry until the deadline.
//
// THREAD EXIT SEMANTICS: stop() flips a flag checked between blocking
// calls; threads blocked inside recv_from wake on their next datagram or
// die with the process at session teardown. Same model as the whole
// codebase; not a general-purpose cancellation primitive.
//
// LIMITATIONS: no congestion/loss handling (a dumb datagram pipe, which
// is what a game wants); payloads over 1400 bytes are dropped rather than
// fragmented; static PSK without forward secrecy; no MESSAGE-INTEGRITY
// forgery (genuine remote answers via forwarding are the strict-stack
// backstop); datagrams larger than the worker buffer (64 KB) truncate —
// unreachable in practice given the MAX_PAYLOAD drop at 1400.
// =============================================================================
