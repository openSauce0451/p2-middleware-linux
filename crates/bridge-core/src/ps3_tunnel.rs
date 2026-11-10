// ps3_tunnel.rs — bridge-core: user-space VPN-style tunnel between two
// middleware instances. Pure std threads, no new dependencies, crypto
// reuses channel::Envelope (AES-256-CBC + HMAC-SHA1).
//
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
    build_allocate_success, send_stun_response_advertised, stun_classify, StunKind,
};
use crate::udp_relay::bind_udp_reuse;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
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
    sync::atomic::AtomicUsize,
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

#[derive(Debug, Clone)]
pub struct WirePeerState {
    /// Current effective peer address (starts as the configured value,
    /// updated by learning when a PSK-valid datagram arrives from elsewhere).
    pub addr: SocketAddr,
    /// Value read from settings.toml, kept for diagnostics.
    pub configured: SocketAddr,
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

/// Query the local NAT gateway (Proton VPN supports NAT-PMP on many exits)
/// for a UDP mapping on our wire port. Returns the external port if granted.
#[cfg(target_os = "linux")]
fn nat_pmp_request(internal_port: u16) -> Option<u16> {
    let gw: Ipv4Addr = "10.2.255.254".parse().ok()?; // typical Proton gateway
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let req = [
        0u8, 0,        // version 0
        1,             // opcode 1: MAP-UDP
        0, 0,          // reserved
        (internal_port >> 8) as u8, internal_port as u8,  // internal port
        0, 0, 0, 0,    // suggested external port = 0 (let gateway choose)
        0, 0, 0, 0,    // lifetime seconds = 0 (use gateway default)
    ];
    sock.send_to(&req, SocketAddr::new(gw.into(), 5351)).ok()?;
    let mut resp = [0u8; 16];
    let (n, _) = sock.recv_from(&mut resp).ok()?;
    if n < 12 || resp[1] != 129 || resp[3] == 0 {
        return None; // unsupported / denied
    }
    Some(u16::from_be_bytes([resp[10], resp[11]]))
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

        // REV 7: the port we tell the peer to dial. Proton's forwarding
        // assigns an arbitrary exit-side port; a direct-ISP peer leaves
        // this None and announces wire_port as before.
        let announced_port: Arc<Mutex<u16>> = Arc::new(Mutex::new(
            config.advertised_port.unwrap_or_else(|| config.wire_bind.port()),
        ));
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
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let mut seen_lens: std::collections::HashSet<usize> = std::collections::HashSet::new();
                loop {
                    let (n, from) = match wire.recv_from(&mut buf) {
                        Ok(v) => v,
                          Err(_) => continue,
                    };

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

                    // Deliver through the learned route. NOTE: `port` here
                    // is the port the ORIGINAL datagram ARRIVED on at the
                    // forwarding side (Rev 6 wire-header fix) — i.e. the
                    // receiving console's own port — so route_socket's
                    // console-src key (populated by OUR console's outbound
                    // traffic to that same port) matches exactly.
                    let target_sock = match table.route_socket(port, primary) {
                        Some(s) => s,
                          None => {
                              event("tunnel_in_dropped", json!({
                                  "port": port,
                                  "len": plain.len()
                              }));
                              continue;
                          }
                    };
                    if let Err(e) = target_sock.send_to(&plain[3..], alias_addr(local_ps3, port)) {
                        if !transient(&e) {
                            event("tunnel_wire_error", json!({
                                "kind": format!("{:?}", e.kind())
                            }));
                        }
                    }
                    if seen_lens.insert(plain.len()) {
                        event("tunnel_in_first", json!({
                            "port": port,
                            "len": plain.len() - 3,
                                                       "payload_hex": crate::stun::hex(&plain[3..]),
                        }));
                    }
                    event("tunnel_in", json!({ "port": port, "len": plain.len() }));
                }
            });
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

            #[cfg(target_os = "linux")]
            let pinned = config.advertised_port.is_some();
            #[cfg(target_os = "linux")]
            let internal_port = config.wire_bind.port();

            // pinned_stun moved to constructor scope; captured here:
            let pinned_stun = config.stun_advertise;

            // Side thread: detect the public IP immediately, then re-check
            // every PUBLIC_RECHECK so a rotating VPN exit is picked up.
            // On Linux it also renews the NAT-PMP mapping each cycle —
            // mappings carry a lifetime and must be refreshed. Skipped
            // entirely when the operator pinned advertised_port.
            {
                let stop = stop.clone();
                let public_ip = public_ip.clone();
                #[cfg(target_os = "linux")]
                let announced_port = announced_port.clone();
                thread::spawn(move || {
                    let mut first = true;
                    let mut had_any = false;
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        #[cfg(target_os = "linux")]
                        if !pinned {
                            if let Some(ext) = nat_pmp_request(internal_port) {
                                let changed = {
                                    let mut slot = announced_port.lock().unwrap();
                                    let ch = *slot != ext;
                                    *slot = ext;
                                    ch
                                };
                                if changed {
                                    event("tunnel_nat_pmp_mapped", json!({
                                        "internal": internal_port,
                                        "external": ext,
                                    }));
                                }
                            }
                        }

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
                                // REV 7: announce "ip:port". The port comes
                                // from the slot: configured/advertised, or
                                // NAT-PMP-discovered (updated by the side
                                // thread). Skip only if the FULL endpoint is
                                // unchanged since the last announce.
                                let port = *announced_port.lock().unwrap();
                                let endpoint = format!("{ip}:{port}");
                                let already = {
                                    let p = published.lock().unwrap();
                                    *p == endpoint
                                };
                                // REV 7 announce arm: store for STUN advertising,
                                // unless the operator pinned stun_advertise.
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
            for port in &config.stun.probe_ports {
                let stop = stop.clone();
                let remote_ps3 = config.remote_ps3;
                let probe_port = *port;
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
                                match stun_classify(&buf[..n]) {
                                    StunKind::BindingRequest => {
                                        let advertised = announced_endpoint
                                        .lock().unwrap().unwrap_or(from);
                                        match send_stun_response_advertised(
                                            &socket, from, &buf[..n], advertised,
                                        ) {
                                            Ok(()) => {
                                                event("tunnel_stun_answered", json!({
                                                    "probe_port": probe_port,
                                                    "from": from.to_string(),
                                                                                    "advertised": advertised.to_string(),
                                                }));
                                            }
                                            Err(e) if !transient(&e) => {
                                                event("tunnel_stun_error", json!({
                                                    "kind": format!("{:?}", e.kind()),
                                                                                 "probe_port": probe_port,
                                                }));
                                            }
                                            Err(_) => {}
                                        }
                                    }
                                    StunKind::Other(0x0003) if shared_acq.relay_allocations => {
                                            let port = match acquire_relay_port(&shared_acq, &envelope_acq) {
                                            Some(p) => p,
                              None => {
                                  event("tunnel_relay_exhausted", json!({
                                      "from": from.to_string(),
                                  }));
                                  continue;
                              }
                                        };
                                        let relayed = SocketAddrV4::new(remote_ps3, port);
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
                                    }
                                    StunKind::Other(msg_type) => {
                                        event("tunnel_stun_other", json!({
                                            "probe_port": probe_port,
                                            "len": n,
                                            "type": format!("{:#06x}", msg_type),
                                                                         "payload_hex": crate::stun::hex(&buf[..n]),
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
                    if stun_enabled {
                        match stun_classify(&buf[..n]) {
                            StunKind::BindingRequest => {
                                let advertised = shared
                                .announced_endpoint
                                .lock()
                                .unwrap()
                                .unwrap_or(from);
                                match send_stun_response_advertised(
                                    &socket, from, &buf[..n], advertised,
                                ) {
                                    Ok(()) => event("tunnel_stun_answered", json!({
                                        "alias_port": port,
                                        "from": from.to_string(),
                                                                                  "advertised": advertised.to_string(),
                                    })),
                                    Err(e) if !transient(&e) => event("tunnel_stun_error", json!({
                                        "kind": format!("{:?}", e.kind()),
                                                                                                 "alias_port": port,
                                    })),
                                    Err(_) => {}
                                }
                            }
                            // Allocate on an already-bound alias socket:
                            // this socket IS the relay — self tuple, no
                            // fresh allocation, no budget cost.
                            StunKind::Other(0x0003) if shared.relay_allocations => {
                                let relayed = SocketAddrV4::new(shared.remote_ps3, port);
                                let requester = match from { SocketAddr::V4(v4) => v4, SocketAddr::V6(_) => continue };
                                match build_allocate_success(&buf[..n], requester , relayed) {
                                    Some(resp) => match socket.send_to(&resp, from) {
                                        Ok(_) => event("tunnel_relay_allocated", json!({
                                            "from": from.to_string(),
                                                                                       "alias_port": port,
                                                                                       "relayed": relayed.to_string(),
                                        })),
                                        Err(e) if !transient(&e) => event("tunnel_relay_error", json!({
                                            "kind": format!("{:?}", e.kind()),
                                                                                                      "alias_port": port,
                                        })),
                                        Err(_) => {}
                                    },
                                    None => event("tunnel_relay_error", json!({
                                        "kind": "request_shorter_than_header",
                                        "alias_port": port,
                                    })),
                                }
                            }
                            StunKind::Other(msg_type) => {
                                event("tunnel_stun_other", json!({
                                    "port": port,
                                    "type": format!("{:#06x}", msg_type),
                                                                 "len": n,
                                                                 "payload_hex": crate::stun::hex(&buf[..n]),
                                }));
                            }
                            StunKind::NotStun => {}
                        }
                    }

                    // Forward: [0][arrival (alias) port BE][payload], sealed
                    // to the CURRENT learned wire peer (Rev 6).
                    let mut frame = Vec::with_capacity(3 + n);
                    frame.push(0u8);
                    frame.extend_from_slice(&port.to_be_bytes());
                    frame.extend_from_slice(&buf[..n]);
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
        Some(s) => s, // race: another thread bound it first — fine
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
                // Something else owns the tuple — same policy as the band
                // binder: skip.
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                    event("tunnel_port_busy", json!({ "port": port }));
                    return;
                }
                // AddrNotAvailable: alias not up yet. TPROXY already
                // consumed the datagram, so NO ICMP leaks to the console.
                // Retry comes with the console's next sweep.
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

    // STUN sniff — identical to the worker, answering from the
    // newly-bound socket so the source tuple is (remote_ps3 : port).
    if stun_enabled {
        match stun_classify(data) {
            StunKind::BindingRequest => {
                let advertised = shared
                .announced_endpoint
                .lock()
                .unwrap()
                .unwrap_or(SocketAddr::V4(src));
                match send_stun_response_advertised(
                    &sock, SocketAddr::V4(src), data, advertised,
                ) {
                    Ok(()) => event("tunnel_stun_answered", json!({
                        "from": SocketAddr::V4(src).to_string(),
                                                                  "alias_port": port,
                                                                  "dynamic": true,
                                                                  "advertised": advertised.to_string(),
                    })),
                    Err(e) if !transient(&e) => event("tunnel_stun_error", json!({
                        "kind": format!("{:?}", e.kind()),
                                                                                 "alias_port": port,
                    })),
                    Err(_) => {}
                }
            }
            StunKind::Other(0x0003) if shared.relay_allocations => {
                // The console Allocated on this exact tuple; this socket
                // IS the relay — hand the tuple back, no fresh allocation.
                let relayed = SocketAddrV4::new(shared.remote_ps3, port);
                match build_allocate_success(data, src, relayed) {
                    Some(resp) => match sock.send_to(&resp, SocketAddr::V4(src)) {
                        Ok(_) => event("tunnel_relay_allocated", json!({
                            "from": SocketAddr::V4(src).to_string(),
                                                                       "alias_port": port,
                                                                       "relayed": relayed.to_string(),
                                                                       "dynamic": true,
                        })),
                        Err(e) if !transient(&e) => event("tunnel_relay_error", json!({
                            "kind": format!("{:?}", e.kind()),
                                                                                      "alias_port": port,
                        })),
                        Err(_) => {}
                    },
                    None => event("tunnel_relay_error", json!({
                        "kind": "request_shorter_than_header",
                        "alias_port": port,
                        "dynamic": true,
                    })),
                }
            }
            StunKind::Other(msg_type) => {
                event("tunnel_stun_other", json!({
                    "type": format!("{:#06x}", msg_type),
                                                 "len": data.len(),
                                                 "alias_port": port,
                                                 "payload_hex": crate::stun::hex(data),
                }));
            }
            StunKind::NotStun => {}
        }
    }

    // Forward the original — same wire frame as the worker:
    // [0][arrival (alias) port BE][payload], sealed to the CURRENT learned
    // peer. (Rev 6: was src.port(); see spawn_console_worker note.)
    let mut frame = Vec::with_capacity(3 + data.len());
    frame.push(0u8);
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(data);
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
