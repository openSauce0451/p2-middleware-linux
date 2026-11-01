//! Transparent UDP relay for datagrams the console addresses to the legacy
//! CM servers.
//!
//! While the native gateway is active the 26 legacy CM /32 addresses exist
//! on a local interface, so every datagram the PS3 sends to those addresses
//! is delivered to this host instead of being routed onward. Before this
//! module nothing listened on UDP there: the kernel answered with ICMP
//! port-unreachable and the console session broke during the transition
//! into gameplay.
//!
//! The relay terminates those datagrams locally and relays them to a single
//! configurable upstream. Reply datagrams are emitted from the exact legacy
//! address and port the console contacted, so the PS3 sees an endpoint that
//! answers from where it wrote to. Policy mirrors the TCP bridge: only
//! datagrams from the configured PS3 peer are accepted, flows are bounded
//! and expire when idle, everything stops with the session, and no payload
//! byte is ever logged.

use crate::bad;
use crate::gateway::event;
use crate::legacy_cm::LEGACY_CM;
use serde_json::json;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_DATAGRAM: usize = 65_535;
const RECV_TIMEOUT: Duration = Duration::from_millis(250);
const BIND_RETRY: Duration = Duration::from_secs(1);
/// Idle expiry for a flow: past Steam's own heartbeat cadence.
const FLOW_IDLE: Duration = Duration::from_secs(75);
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

pub struct UdpRelayConfig {
    /// Only datagrams from this console are relayed.
    pub peer: Ipv4Addr,
    /// Every accepted datagram is relayed to this single endpoint.
    pub upstream: SocketAddr,
    /// UDP ports to claim on each legacy CM address. Default: [27017].
    pub ports: Vec<u16>,
    /// Session lifetime, mirroring the TCP bridge's --seconds.
    pub seconds: u64,
    /// Upper bound on concurrent relayed flows, mirroring --sessions.
    pub max_flows: usize,
}

struct Flow {
    /// Legacy (address, port) the console wrote to; also the reply source.
    local: SocketAddrV4,
    /// Console endpoint (peer ip : ephemeral port) to answer.
    ps3: SocketAddr,
    /// Connected to the upstream; filters foreign datagrams.
    upstream: UdpSocket,
    /// Listener socket bound to `local`; replies are sent from it so the
    /// console sees the address it originally contacted.
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
    pub fn spawn(config: UdpRelayConfig) -> io::Result<Self> {
        if config.ports.is_empty() {
            return Err(bad("udp_ports_empty"));
        }
        if config.max_flows == 0 {
            return Err(bad("udp_flow_budget"));
        }
        if config.seconds == 0 {
            return Err(bad("udp_session_seconds"));
        }
        let deadline = Instant::now() + Duration::from_secs(config.seconds);
        let shared = Arc::new(Shared {
            relayed_up: AtomicUsize::new(0),
                              relayed_down: AtomicUsize::new(0),
                              rejected: AtomicUsize::new(0),
                              opened_total: AtomicUsize::new(0),
                              flows: Mutex::new(Vec::new()),
                              stop: AtomicBool::new(false),
                              config,
                              deadline,
        });
        event(
            "udp_relay_started",
            json!({
                "addresses": LEGACY_CM.len(),
                  "ports": shared.config.ports,
                  "upstream": shared.config.upstream.to_string(),
                  "peer": shared.config.peer.to_string(),
                  "seconds": shared.config.seconds,
                  "max_flows": shared.config.max_flows,
            }),
        );
        for addr in LEGACY_CM {
            for port in shared.config.ports.clone() {
                let shared = shared.clone();
                thread::spawn(move || listener_thread(shared, addr, port));
            }
        }
        {
            let shared = shared.clone();
            thread::spawn(move || sweep_thread(shared));
        }
        Ok(Self { shared })
    }

    /// Idempotent; also runs from Drop. Detached threads observe the flag
    /// within one receive timeout and exit on their own.
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

/// Owns one (legacy address, port) listener for the whole session.
///
/// The bridge starts before the network helper activates the gateway, so the
/// legacy aliases may not exist yet; a failed bind is retried rather than
/// treated as fatal, mirroring why the TCP listener binds the wildcard.
fn listener_thread(shared: Arc<Shared>, addr: Ipv4Addr, port: u16) {
    let bind_addr = SocketAddrV4::new(addr, port);
    loop {
        if shared.stopping() {
            return;
        }
        let sock = match UdpSocket::bind(SocketAddr::V4(bind_addr)) {
            Ok(s) => Arc::new(s),
            Err(_) => {
                thread::sleep(BIND_RETRY);
                continue;
            }
        };
        let _ = sock.set_read_timeout(Some(RECV_TIMEOUT));
        event("udp_listener_bound", json!({"local": bind_addr.to_string()}));
        if serve_listener(&shared, &sock, bind_addr) {
            return; // session stopped or expired
        }
        thread::sleep(BIND_RETRY);
    }
}

/// Returns true when the relay is shutting down, false when the socket died.
fn serve_listener(shared: &Arc<Shared>, sock: &Arc<UdpSocket>, local: SocketAddrV4) -> bool {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if shared.stopping() {
            return true;
        }
        let (n, source) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
            if matches!(
                e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
            ) =>
            {
                continue
            }
            Err(_) => return false,
        };
        // Same admission policy as legacy_cm::accepts on the TCP path.
        if source.ip() != std::net::IpAddr::V4(shared.config.peer) {
            continue;
        }
        let Some(flow) = flow_for(shared, sock, local, source) else {
            continue;
        };
        if flow.upstream.send(&buf[..n]).is_ok() {
            *flow.last_used.lock().unwrap() = Instant::now();
            flow.packets_up.fetch_add(1, Ordering::Relaxed);
            shared.relayed_up.fetch_add(1, Ordering::Relaxed);
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
        event(
            "udp_flow_opened",
            json!({
                "local": local.to_string(),
                  "console_port": ps3.port(),
                  "upstream": shared.config.upstream.to_string(),
            }),
        );
        let reader_shared = shared.clone();
        let reader_flow = flow.clone();
        thread::spawn(move || flow_reader(reader_shared, reader_flow));
        Some(flow)
}

fn flow_reader(shared: Arc<Shared>, flow: Arc<Flow>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if !flow.alive.load(Ordering::Relaxed) || shared.stopping() {
            break;
        }
        match flow.upstream.recv(&mut buf) {
            Ok(n) => {
                if flow.reply.send_to(&buf[..n], flow.ps3).is_ok() {
                    flow.packets_down.fetch_add(1, Ordering::Relaxed);
                    shared.relayed_down.fetch_add(1, Ordering::Relaxed);
                }
                *flow.last_used.lock().unwrap() = Instant::now();
            }
            Err(e)
            if matches!(
                e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
            ) =>
            {
                if flow.last_used.lock().unwrap().elapsed() >= FLOW_IDLE {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    flow.alive.store(false, Ordering::Relaxed);
    event(
        "udp_flow_closed",
        json!({
            "local": flow.local.to_string(),
              "console_port": flow.ps3.port(),
              "packets_up": flow.packets_up.load(Ordering::Relaxed),
              "packets_down": flow.packets_down.load(Ordering::Relaxed),
        }),
    );
}

fn sweep_thread(shared: Arc<Shared>) {
    loop {
        if shared.stopping() {
            return;
        }
        thread::sleep(SWEEP_INTERVAL);
        if let Ok(mut flows) = shared.flows.lock() {
            flows.retain(|f| f.alive.load(Ordering::Relaxed));
        }
    }
}
