//! Transparent UDP relay for datagrams the console addresses to the legacy
//! CM servers.
//!
//! REV 3 — Option B catch-all support (TPROXY on Linux, sniffer on Windows).
//! The `catch_all_port` config enables dynamic interception: instead of
//! pre-binding a fixed port band, we let every candidate port the console
//! picks get answered through the tunnel.

use crate::bad;
use crate::gateway::event;
use crate::legacy_cm::LEGACY_CM;
use crate::stun::{send_allocate_response, send_stun_response_advertised, stun_classify, StunKind};
use serde_json::json;
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_DATAGRAM: usize = 65_535;
const RECV_TIMEOUT: Duration = Duration::from_millis(250);
const BIND_RETRY: Duration = Duration::from_secs(1);
const FLOW_IDLE: Duration = Duration::from_secs(75);

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
    opened_total: AtomicUsize,
    rejected: AtomicUsize,
    relayed_up: AtomicUsize,
    relayed_down: AtomicUsize,
    relay_cache: Mutex<HashMap<SocketAddrV4, SocketAddrV4>>,
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
                              stop: AtomicBool::new(false),
                              config,
                              deadline,
                              hooks: Mutex::new(hooks),
                              relay_cache: Mutex::new(HashMap::new()),
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

        // ---- RELAY family: config.ports on each legacy CM address ----
        for addr in LEGACY_CM {
            for port in shared.config.ports.clone() {
                let shared = shared.clone();
                thread::spawn(move || listener_thread(shared, addr, port));
            }
        }

        // ---- STUN family ----
        for addr in LEGACY_CM {
            for port in shared.config.stun_ports.clone() {
                let shared = shared.clone();
                thread::spawn(move || stun_listener_thread(shared, addr, port, false));
            }
        }
        if shared.config.stun_wildcard {
            for port in shared.config.stun_ports.clone() {
                let shared = shared.clone();
                thread::spawn(move || {
                    stun_listener_thread(shared, Ipv4Addr::UNSPECIFIED, port, true)
                });
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
        if source.ip() != std::net::IpAddr::V4(shared.config.peer) { continue; }
        let Some(flow) = flow_for(shared, sock, local, source) else { continue; };
        if flow.upstream.send(&buf[..n]).is_ok() {
            *flow.last_used.lock().unwrap() = Instant::now();
            flow.packets_up.fetch_add(1, Ordering::Relaxed);
            shared.relayed_up.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn stun_listener_thread(shared: Arc<Shared>, addr: Ipv4Addr, port: u16, wildcard: bool) {
    let bind_addr = SocketAddrV4::new(addr, port);
    loop {
        if shared.stopping() { return; }
        let sock = match UdpSocket::bind(SocketAddr::V4(bind_addr)) {
            Ok(s) => Arc::new(s),
            Err(e) if wildcard && e.kind() == ErrorKind::AddrInUse => {
                event("udp_stun_port_busy", json!({"local": bind_addr.to_string()}));
                return;
            }
            Err(_) => {
                thread::sleep(BIND_RETRY);
                continue;
            }
        };
        let _ = sock.set_read_timeout(Some(RECV_TIMEOUT));
        event("udp_stun_listening", json!({"local": bind_addr.to_string()}));
        if serve_stun(&shared, &sock) { return; }
        thread::sleep(BIND_RETRY);
    }
}

fn serve_stun(shared: &Arc<Shared>, sock: &Arc<UdpSocket>) -> bool {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if shared.stopping() { return true; }
        let (n, source) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => continue,
            Err(_) => return false,
        };
        if source.ip() != std::net::IpAddr::V4(shared.config.peer) { continue; }
        let (do_relay, allocate_relay, stun_advertise) = {
            let h = shared.hooks.lock().unwrap();
            (h.relay_allocations, h.allocate_relay.clone(), h.stun_advertise.clone())
        };
        match stun_classify(&buf[..n]) {
            StunKind::BindingRequest => {
                let advertised = stun_advertise.as_ref().and_then(|f| f())
                .unwrap_or(source);
                match send_stun_response_advertised(sock, source, &buf[..n], advertised) {
                    Ok(()) => {
                        event("udp_stun_answered",
                              json!({
                                  "local": sock.local_addr().map(|a| a.to_string()).unwrap_or_default(),
                                    "console": source.to_string(),
                                    "advertised": advertised.to_string(),
                              }));
                    }
                    Err(_) => {
                        event("udp_stun_error", json!({"console": source.to_string()}));
                    }
                }
            }
            StunKind::Other(0x0003) if do_relay => {
                let requester = match source {
                    SocketAddr::V4(v4) => v4,
                    SocketAddr::V6(_) => continue,
                };
                let relayed = {
                    let mut cache = shared.relay_cache.lock().unwrap();
                    if let Some(hit) = cache.get(&requester) {
                        Some(*hit)
                    } else {
                        let fresh =
                        allocate_relay.as_ref().and_then(|f| f(requester));
                        if let Some(r) = fresh {
                            cache.insert(requester, r);
                        }
                        fresh
                    }
                };
                match relayed {
                    Some(relayed) => match send_allocate_response(sock, source, &buf[..n], relayed) {
                        Ok(()) => event("udp_relay_allocated", json!({
                            "console": source.to_string(),
                                                                     "relayed": relayed.to_string(),
                                                                     "local": sock.local_addr().map(|a| a.to_string()).unwrap_or_default(),
                        })),
                        Err(_) => event("udp_relay_allocate_error", json!({"console": source.to_string()})),
                    },
                    None => event("udp_relay_allocate_unavailable", json!({
                        "console": source.to_string(),
                                                                          "reason": "no allocator hook or budget exhausted",
                    })),
                }
            }
            StunKind::Other(msg_type) => {
                event("udp_stun_other",
                      json!({
                          "type": format!("{msg_type:#06x}"),
                            "len": n,
                            "console": source.to_string(),
                      }));
            }
            StunKind::NotStun => {}
        }
    }
}

fn flow_for(
    shared: &Arc<Shared>,
    reply: &Arc<UdpSocket>,
    local: SocketAddrV4,
    ps3: SocketAddr,
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
        if let Err(e) = upstream.connect(shared.config.upstream) {
            event("udp_flow_connect_failed", json!({"error": e.to_string()}));
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
                    "upstream": shared.config.upstream.to_string(),
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
