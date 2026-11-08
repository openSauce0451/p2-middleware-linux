// =============================================================================
// crates/app/src/win_catch_all.rs  (or bridge-core if shared)
// Windows-side Option B: ICMP dest-unreachability shield + raw-socket sniffer
// with eager bind. The Linux counterpart is the TPROXY catch-all (catch_all.rs).
//
// Theory of operation (why this works):
//   The remote console re-rolls its P2P candidate ports every session. Instead
//   of pre-binding a guessed band, we WATCH every datagram addressed to the
//   alias. The first probe on a fresh port is sacrificial — it reaches no
//   socket. Normally Windows answers with ICMP type 3 code 3, which the PS3
//   interprets as "path refused" and aborts the session. Two countermeasures:
//     (a) the ICMP shield silences that answer (blocked = retry, not refuse),
//     (b) the sniffer has already bound that port by the time the console's
//         ~20 Hz retransmit arrives (< 50 ms later). From then on the port is
//         a live relay socket.
//
// Requires: process elevated (raw sockets + firewall). The middleware's
// network helper already runs elevated — spawn this from there.
//
// [INTEGRATE #1] event emission: search for `emit(` — replace with the
// crate's event emitter used for tunnel_*/udp_stun_* events.
// [INTEGRATE #2] flow registration: `on_new_flow` in SnifferConfig — plug in
// the same per-socket flow factory the Windows band sockets use today.
// =============================================================================

#![cfg(target_os = "windows")]

use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use crate::ps3_tunnel::alias_addr;
use crate::gateway::event;


// ---------------------------------------------------------------------------
// Minimal winsock FFI (avoids adding a windows-sys dependency; declare only
// what we use. ws2_32.dll is linked implicitly by any socket code already.)
// ---------------------------------------------------------------------------

type SOCKET = usize;
pub type OnNewFlow = Box<dyn Fn(u16) + Send + Sync>;

const AF_INET: i32 = 2;
const SOCK_RAW: i32 = 3;
const IPPROTO_IP: i32 = 0;
const IPPROTO_UDP: i32 = 17;
const INVALID_SOCKET: SOCKET = usize::MAX;
const SOCKET_ERROR: i32 = -1;

/// SIO_RCVALL = _WSAIOW(IOC_VENDOR, 1) = 0x98000001
const SIO_RCVALL: u32 = 0x9800_0001;
/// Receive at IP level (includes the IP header; skips lower-layer noise).
const RCVALL_IPLEVEL: u32 = 3;

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
#[allow(dead_code)]
struct WsaData {
    w_version: u16,
    w_high_version: u16,
    sz_description: [u8; 257],
    sz_system_status: [u8; 129],
    i_max_sockets: u16,
    i_max_udp_dg: u16,
    lp_vendor_info: usize,
    padding: [u8; 64], // WsaData is 400+ bytes; generous slack avoids overflow
}

extern "system" {
    fn WSAStartup(w_version_requested: u16, wsa_data: *mut WsaData) -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(af: i32, kind: i32, protocol: i32) -> SOCKET;
    fn bind(s: SOCKET, addr: *const SockaddrIn, len: i32) -> i32;
    fn ioctlsocket(s: SOCKET, cmd: u32, argp: *mut u32) -> i32;
    fn recv(s: SOCKET, buf: *mut u8, len: i32, flags: i32) -> i32;
    fn closesocket(s: SOCKET) -> i32;
}

/// WSA error code of the most recent winsock call on this thread.
#[inline]
fn wsa_last_error() -> i32 {
    unsafe { WSAGetLastError() }
}

fn wsa_err(err: i32) -> io::Error {
    io::Error::from_raw_os_error(err)
}

/// Winsock is reference-counted; WSAStartup is safe to call again even if the
/// app already initialized it. Defensive: raw sockets fail with 10093
/// (WSANOTINITIALISED) if nobody ever started it.
fn ensure_wsa() -> io::Result<()> {
    unsafe {
        let mut data: WsaData = std::mem::zeroed();
        let rc = WSAStartup(0x0202, &mut data); // MAKEWORD(2,2)
        if rc != 0 {
            return Err(wsa_err(rc));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// (5a) ICMP shield — firewall rule, managed via netsh (no WMI dependency).
// Scope note: this silences OUR OWN "destination unreachable" answers for the
// duration of a session only. Install on gateway startup, remove on teardown.
// Leaving it resident would hide real port-unreachable diagnostics — the
// lifecycle pair below must be wired symmetrically (see INTEGRATION NOTES).
// ---------------------------------------------------------------------------

// CHANGED: no spaces — immune to any argv-quoting nuance.
const SHIELD_RULE_NAME: &str = "P2_Suppress_ICMPv4_3_3";

fn shield_name_arg() -> String {
    // No embedded quotes: Rust's Command handles argv quoting; netsh
    // parses `name=<token>` as one token because there are no spaces.
    format!("name={SHIELD_RULE_NAME}")
}

/// Runs `netsh advfirewall ...` capturing output. Elevation is required —
/// from a non-elevated context netsh fails with "The requested operation
/// requires elevation", which surfaces here as an Err.
fn run_netsh(args: &[&str]) -> io::Result<String> {
    let out = std::process::Command::new("netsh")
    .args(args)
    .output()
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("spawn netsh: {e}")))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("netsh {} failed: {}", args.join(" "), msg.trim()),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn icmp_shield_installed() -> bool {
    run_netsh(&[
        "advfirewall",
        "firewall",
        "show",
        "rule",
        &shield_name_arg(),
    ])
    .map(|o| !o.contains("No rules match"))
    .unwrap_or(false)
}

pub fn install_icmp_shield() -> io::Result<()> {
    if icmp_shield_installed() {
        emit("icmp_shield_present", "");
        return Ok(());
    }
    run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &shield_name_arg(),
              "dir=out",
              "action=block",
              "protocol=icmpv4:3,3",
    ])?;
    emit("icmp_shield_installed", SHIELD_RULE_NAME);
    Ok(())
}

pub fn remove_icmp_shield() -> io::Result<()> {
    if !icmp_shield_installed() {
        return Ok(());
    }
    run_netsh(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        &shield_name_arg(),
    ])?;
    emit("icmp_shield_removed", SHIELD_RULE_NAME);
    Ok(())
}

// ---------------------------------------------------------------------------
// (5b) Sniffer with eager bind
// ---------------------------------------------------------------------------

pub struct SnifferConfig {
    /// Address of the LAN adapter to sniff on (raw socket bind target).
    pub adapter_ip: Ipv4Addr,
    /// The remote-console alias (created via New-NetIPAddress). All UDP to
    /// this address is a candidate for interception.
    pub alias: Ipv4Addr,
    /// Ports we must never grab: already owned by other listeners — STUN
    /// (3478, 4380), the relay (27017), the wire (27050), and the legacy band
    /// range if the fallback path is active. A blind bind on these yields
    /// WSAEADDRINUSE anyway, but excluding them keeps the log clean and the
    /// intent explicit.
    pub protected_ports: Vec<u16>,
    /// Band bounds (inclusive) when legacy sockets are active, so the sniffer
    /// skips them. `None` when pure catch-all mode.
    pub band: Option<(u16, u16)>,
}

impl SnifferConfig {
    /// Ports excluded from eager binding: dedicated STUN probe responders
    /// (3478, 4380) and anything else already owned at construction time.
    fn is_protected(&self, port: u16) -> bool {
        self.protected_ports.iter().any(|&p| p == port)
    }
}

/// Build the dynamic-port acquisition callback for the sniffer. All state
/// is threaded in as arguments, so this is a plain item and can be
/// constructed from the tunnel-activation site, where these values live.
///
/// INTEGRATE: requires in ps3_tunnel.rs —
///   * struct AliasTable:      pub(crate)
///   * fn spawn_console_worker: pub(crate)
///   * const MAX_DYNAMIC_SOCKETS: pub(crate)
pub(crate) fn make_on_new_flow(
    shared: Arc<crate::ps3_tunnel::TunnelShared>,
    envelope: crate::channel::Envelope,
    local_ps3: Ipv4Addr,
    stun_enabled: bool,
) -> OnNewFlow {
    Box::new(move |port: u16| {
        use std::sync::atomic::Ordering;

        if shared.table.get(port).is_some() {
            return; // band port, probe port, or prior acquisition
        }
        if shared.dyn_opened.load(Ordering::Relaxed)
            >= crate::ps3_tunnel::MAX_DYNAMIC_SOCKETS
            {
                event("tunnel_dynamic_exhausted", serde_json::json!({ "port": port }));
                return;
            }
            let sock = match UdpSocket::bind(alias_addr(shared.remote_ps3, port)) {
                Ok(s) => Arc::new(s),
             Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                 event("tunnel_port_busy", serde_json::json!({ "port": port }));
                 return;
             }
             Err(e) => {
                 event("tunnel_dynamic_dropped", serde_json::json!({
                     "port": port,
                     "reason": format!("{:?}", e.kind()),
                 }));
                 return;
             }
            };
            shared.table.insert(port, sock.clone());
            shared.dyn_opened.fetch_add(1, Ordering::Relaxed);
            event("tunnel_dynamic_bound", serde_json::json!({ "port": port }));
            crate::ps3_tunnel::spawn_console_worker(
                shared.clone(), envelope.clone(), local_ps3, stun_enabled, port, sock,
            );
    })
}

pub struct SnifferHandle {
    stop: Arc<AtomicBool>,
}

impl SnifferHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

pub fn spawn_sniffer(
    cfg: SnifferConfig,
    on_new_flow: OnNewFlow,
) -> io::Result<SnifferHandle> {
    ensure_wsa()?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    std::thread::Builder::new()
    .name("p2_win_sniffer".into())
    .spawn(move || run(cfg, stop_t, on_new_flow))
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(SnifferHandle { stop })
}

fn run(cfg: SnifferConfig, stop: Arc<AtomicBool>, on_new_flow: OnNewFlow) {
    // --- raw socket with SIO_RCVALL --------------------------------------
    let s = unsafe {
        let s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if s == INVALID_SOCKET {
            let e = wsa_last_error();
            emit("sniffer_raw_socket_failed", &e.to_string());
            return;
        }

        let mut sa: SockaddrIn = std::mem::zeroed();
        sa.sin_family = AF_INET as u16;
        sa.sin_port = 0;
        sa.sin_addr = u32::from(cfg.adapter_ip).to_be();
        if bind(s, &sa, std::mem::size_of::<SockaddrIn>() as i32) == SOCKET_ERROR {
            let e = wsa_last_error();
            emit("sniffer_bind_failed", &e.to_string());
            closesocket(s);
            return;
        }

        let mut mode = RCVALL_IPLEVEL;
        if ioctlsocket(s, SIO_RCVALL, &mut mode) == SOCKET_ERROR {
            let e = wsa_last_error();
            emit("sniffer_rcvall_failed",
                 "SIO_RCVALL requires elevation (admin)");
            emit("sniffer_rcvall_failed", &e.to_string());
            closesocket(s);
            return;
        }
        s
    };

    emit("sniffer_started",
         &format!("adapter={} alias={}", cfg.adapter_ip, cfg.alias));

    // Bound flow sockets, kept alive for the session lifetime.
    let mut seen: HashSet<u16> = HashSet::new();
    let mut buf = vec![0u8; 65535];

    while !stop.load(Ordering::Relaxed) {
        let n = unsafe { recv(s, buf.as_mut_ptr(), buf.len() as i32, 0) };
        if n == SOCKET_ERROR {
            // Transient winsock hiccups: sleep and retry; do not die on one.
            let e = wsa_last_error();
            if e == 10004 /* WSAEINTR */ || e == 10054 /* WSAECONNRESET */ {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            emit("sniffer_recv_error", &e.to_string());
            break;
        }
        if n < 28 {
            continue; // too short for IPv4(20) + UDP(8)
        }

        // --- IPv4 header --------------------------------------------------
        if buf[0] >> 4 != 4 {
            continue;
        }
        if buf[9] != IPPROTO_UDP as u8 {
            continue;
        }
        let ihl = ((buf[0] & 0x0f) as usize) * 4;
        if ihl < 20 || (n as usize) < ihl + 8 {
            continue;
        }

        let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        if dst_ip != cfg.alias {
            continue; // strictly scoped: only the remote-console alias
        }

        // --- UDP header ----------------------------------------------------
        let p = ihl;
        let dst_port = u16::from_be_bytes([buf[p + 2], buf[p + 3]]);
        let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let src_port = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let first_src = SocketAddrV4::new(src_ip, src_port);

        // --- eager bind -----------------------------------------------------
        // The datagram that triggered this bind is lost — no socket received
        // it. The ICMP shield (5a) ensures the console sees silence rather
        // than refusal, so its ~20 Hz retransmit lands here < 50 ms later.
        if seen.contains(&dst_port) || cfg.is_protected(dst_port) {
            continue; // already acquired, or owned by a dedicated listener
        }
        // ALL binding happens in on_new_flow — exactly once per port.
        // On failure (busy/unavailable) it emits its own event; marking
        // the port seen prevents retry loops either way.
        seen.insert(dst_port);
        event("udp_catchall_flow", serde_json::json!({ "src": first_src.to_string(), "dst_port": dst_port }));
        on_new_flow(dst_port);
    }

    unsafe { closesocket(s) };
    emit("sniffer_stopped", &seen.len().to_string());

    // `flows` drops here: all eagerly-bound sockets close. Callers must stop
    // the sniffer only at session teardown, after the console has gone idle.
}

// ---------------------------------------------------------------------------
// [INTEGRATE #1] Event emission — replace these with the crate's emitter,
// mirroring the Linux events so both sides share a log grammar:
//   sniffer_started / sniffer_stopped / sniffer_raw_socket_failed (+errno)
//   sniffer_bind_failed / sniffer_rcvall_failed / sniffer_alias_missing
//   udp_catchall_flow { port, first_src }
//   icmp_shield_installed / icmp_shield_removed / icmp_shield_present
// ---------------------------------------------------------------------------
fn emit(name: &str, detail: &str) {
    crate::gateway::event(name, serde_json::json!({ "detail": detail }));
}

// =============================================================================
// INTEGRATION NOTES (where to call what)
//
// 1. Gateway startup (Windows network helper, elevated):
//        win_catch_all::install_icmp_shield()?;
//        let sniffer = win_catch_all::spawn_sniffer(
//            SnifferConfig {
//                adapter_ip: <LAN adapter address>,   // e.g. 192.168.1.10
//                alias:      <remote console alias>, // e.g. 10.0.0.242-ish
//                protected_ports: vec![3478, 4380, 27017, 27050],
//                band: None,   // Some((first,last)) if legacy band also active
//            },
//            Arc::new(|port, first_src, sock| {
//                // Feed the SAME factory the band-socket loop uses:
//                //   key = (first_src, alias:port)
//                //   socket = sock (Arc-share or try_clone into a recv thread)
//                //   wire the flow into tunnel_out, as a band socket would be.
//                register_flow_socket(port, first_src, sock.try_clone().unwrap());
//            }),
//        )?;
//
// 2. Teardown (mirrored, in the same cleanup path as the alias removal):
//        sniffer.stop();
//        win_catch_all::remove_icmp_shield()?;   // NEVER leave it resident —
//                                                // it masks genuine
//                                                "connection refused" diags.
//
// 3. Feature gating: spawn the sniffer only when catch-all mode is requested
//    (settings.toml catch_all_port set / --catch-all flag), otherwise keep the
//    legacy band path untouched for A/B comparison.
//
// 4. Verification (PowerShell, during the session):
//        Get-NetFirewallRule -DisplayName "P2 Suppress*"
//        netstat -ano -p UDP | findstr 10.0.0.        # alias ports appear
//        Get-Process -Id (Get-NetTCPConnection ... )  # owned by middleware pid
//    Success criterion mirrors Linux: the console's candidate sweep gets
//    bound + answered within one retransmit (~50 ms), the event log shows
//    one udp_catchall_flow per candidate port, and the peer session survives
//    the lobby->gameplay transition.
// =============================================================================
