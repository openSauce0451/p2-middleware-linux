// =============================================================================
// REV 2 — after integrating with the REAL app config (config.rs REV 2) and
// main.rs. Changes from REV 1:
//
//   * SETTINGS WRITING REMOVED from this module. `Settings` lives in the
//     app crate (p2-middleware), which depends on bridge-core — layering
//     forbids bridge-core from knowing it. This module now ends at a
//     `PairingOutcome`; the app crate's pairing_cli.rs (FILE 2) merges it
//     into Settings and writes the TOML through the REAL serde structs
//     (never hand-rendered — deny_unknown_fields would eat any mistake).
//   * PairingPayload gains `advertised_wire_port`: BUG FIX. REV 1 composed
//     the host's wire_peer from the accepted TCP socket, which carries the
//     EPHEMERAL pairing port, not the joiner's wire port — the host would
//     keepalive a dead port and tunnel_plan()'s public check passes anyway,
//     so nothing would catch it. wire_peer is now always
//     observed_source_ip + peer_advertised_wire_port.
//   * Alias selection is SUBNET-AWARE: tunnel_plan() rejects a remote_ps3
//     on the player's own LAN, so candidates are masked against (pc_ip,
//     prefix_len) supplied by the caller.
//   * PayloadChannel trait removed: the real channel::Envelope is used
//     directly (its API was read and wired in conversation).
//
// Remaining new dependency for bridge-core: spake2 (everything else —
// aes/hmac/sha2/base64/serde — already present via channel.rs et al).
// =============================================================================

use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};

pub const PAIR_PORT: u16 = 27052;
pub const PAIRING_WINDOW_SECS: u64 = 120;
// Role namespaced, so a pairing session can never entangle with any other
// protocol run that happens to reuse the same code. CRITICAL: both sides
// must pass the SAME ordered pair — (host identity, joiner identity) —
// regardless of which side they are. start_a plays the first slot,
// start_b the second; the pairing roles are pinned by these constants.
const HOST_ID: &[u8] = b"p2-pair-host";
const JOINER_ID: &[u8] = b"p2-pair-join";

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub enum PairingError {
    Io(io::Error),
    BadPassword,
    Protocol(&'static str),
    PeerUnreachable,
    NotOnLan, // new: host_addr resolved to an address in the caller's subnet
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairingError::Io(e) => write!(f, "io: {e}"),
            PairingError::BadPassword => write!(f, "wrong pairing code"),
            PairingError::Protocol(s) => write!(f, "protocol violation: {s}"),
            PairingError::PeerUnreachable => write!(f, "peer unreachable (window expired?)"),
            PairingError::NotOnLan => write!(f, "peer address is on this LAN; use the public address"),
        }
    }
}

impl From<io::Error> for PairingError {
    fn from(e: io::Error) -> Self {
        PairingError::Io(e)
    }
}

pub type PairResult<T> = Result<T, PairingError>;

// -----------------------------------------------------------------------------
// Discovery helpers (unchanged from REV 1 — already platform-split)
// -----------------------------------------------------------------------------

pub fn local_ipv4() -> io::Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect("203.0.113.1:9")?; // UDP connect consults the routing table only
    match probe.local_addr()? {
        SocketAddr::V4(v4) => Ok(*v4.ip()),
        SocketAddr::V6(_) => Err(io::Error::other("ipv6_only")),
    }
}

#[cfg(target_os = "linux")]
pub fn default_gateway() -> io::Result<Ipv4Addr> {
    let text = std::fs::read_to_string("/proc/net/route")?;
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in text.lines().skip(1) {
        let col: Vec<&str> = line.split_whitespace().collect();
        if col.len() < 8 || col[1] != "00000000" || col[2] == "00000000" {
            continue;
        }
        let (Ok(raw), Ok(metric)) = (u32::from_str_radix(col[2], 16), col[7].parse::<u32>()) else {
            continue;
        };
        let gw = Ipv4Addr::from(raw.swap_bytes());
        if best.map(|(m, _)| metric < m).unwrap_or(true) {
            best = Some((metric, gw));
        }
    }
    best.map(|(_, gw)| gw).ok_or_else(|| io::Error::other("no_default_gateway"))
}

#[cfg(target_os = "windows")]
pub fn default_gateway() -> io::Result<Ipv4Addr> {
    let out = std::process::Command::new("route").args(["PRINT", "-4", "0.0.0.0"]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let col: Vec<&str> = line.trim().split_whitespace().collect();
        if col.len() >= 5 && col[0] == "0.0.0.0" {
            for c in &col[1..5] {
                if let Ok(ip) = c.parse::<Ipv4Addr>() {
                    if ip != Ipv4Addr::UNSPECIFIED && !ip.is_broadcast() {
                        return Ok(ip);
                    }
                }
            }
        }
    }
    Err(io::Error::other("no_default_gateway"))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn default_gateway() -> io::Result<Ipv4Addr> {
    Err(io::Error::other("unsupported_platform"))
}

// -----------------------------------------------------------------------------
// Code + fingerprint (unchanged; see REV 1 notes re: entropy ceiling)
// -----------------------------------------------------------------------------

fn weak_entropy() -> u64 {
    use std::hash::{Hash, Hasher};
    let nanos = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_nanos() as u64)
    .unwrap_or(0);
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (nanos, std::process::id()).hash(&mut h);
    h.finish()
}

pub fn generate_code() -> String {
    format!("{:06}", weak_entropy() % 1_000_000)
}

pub fn pairing_code_tag(key: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    format!("{:012x}", h.finish())
}

// -----------------------------------------------------------------------------
// TCP framing: [u32 BE length][payload]
// -----------------------------------------------------------------------------

fn send_frame(stream: &mut TcpStream, bytes: &[u8]) -> PairResult<()> {
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn recv_frame(stream: &mut TcpStream, cap: usize) -> PairResult<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > cap {
        return Err(PairingError::Protocol("frame_too_large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// -----------------------------------------------------------------------------
// SPAKE2 + key derivation — now producing ONE 32-byte key (the real
// channel::Envelope uses a single key for both AES-256 and HMAC-SHA1,
// digesting with key[..16]; REV 1's (aes, hmac) split was wrong).
// -----------------------------------------------------------------------------

fn run_pake(stream: &mut TcpStream, is_host: bool, code: &str) -> PairResult<[u8; 32]> {
    let pw = Password::new(code.as_bytes());
    let id_host = Identity::new(HOST_ID);
    let id_joiner = Identity::new(JOINER_ID);
    let (spake, outbound) = if is_host {
        Spake2::<Ed25519Group>::start_a(&pw, &id_host, &id_joiner)
    } else {
        Spake2::<Ed25519Group>::start_b(&pw, &id_host, &id_joiner)
    };
    send_frame(stream, &outbound)?;
    let inbound = recv_frame(stream, 128)?;
    match spake.finish(&inbound) {
        Ok(secret) => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&secret);
            Ok(key)
        }
        Err(_) => Err(PairingError::Protocol("pake_failed")),
    }
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut prk = HmacSha256::new_from_slice(salt).expect("hmac any key len");
    prk.update(ikm);
    let prk = prk.finalize().into_bytes();
    let mut okm = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < out_len {
        let mut mac = HmacSha256::new_from_slice(&prk).expect("hmac any key len");
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t);
        counter += 1;
    }
    okm.truncate(out_len);
    okm
}

/// Domain-separated 32-byte channel key, fed straight into
/// channel::Envelope::modern — the exact cipher/HMAC path the production
/// tunnel wire already uses. No new crypto surface.
fn derive_channel_key(pake_secret: &[u8; 32]) -> [u8; 32] {
    let okm = hkdf_sha256(pake_secret, b"p2-pair-v1", b"channel-envelope", 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

// -----------------------------------------------------------------------------
// Authenticated payload exchange (real Envelope, no placeholder trait)
// -----------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct PairingPayload {
    /// THIS side's alias for the remote console (each side picks its own).
    pub tunnel_alias: Ipv4Addr,
    /// Tunnel band anchor port. Host decides; joiner adopts (0 = "you decide").
    pub remote_port: u16,
    /// NEW: the port the OTHER side should dial for THIS side's wire.
    /// None = wire_port (27050) is already public/reachable. This is what
    /// fixes REV 1's ephemeral-port bug in wire_peer composition.
    pub advertised_wire_port: Option<u16>,
    pub app_revision: u32,
}

fn exchange_payload(
    stream: &mut TcpStream,
    env: &crate::channel::Envelope,
    ours: &PairingPayload,
) -> PairResult<PairingPayload> {
    let plain = serde_json::to_vec(ours).map_err(|_| PairingError::Protocol("serde_out"))?;
    send_frame(stream, &env.encode(&plain))?;
    let sealed = recv_frame(stream, 4096)?;
    let theirs = env
    .decode(&sealed)
    .map_err(PairingError::Io)?;
    serde_json::from_slice(&theirs).map_err(|_| PairingError::Protocol("serde_in"))
}

// -----------------------------------------------------------------------------
// Subnet-aware alias selection
//
// tunnel_plan() REJECTS a remote_ps3 inside the player's own LAN, so a
// hardcoded 10.0.0.182 would brick pairing on any 10.x LAN. Candidates are
// masked against the caller-supplied (pc_ip, prefix_len) and skipped on
// collision.
// -----------------------------------------------------------------------------

pub fn choose_alias(pc_ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let bits = prefix_len.min(31) as u32;
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    let own_net = u32::from(pc_ip) & mask;
    let mut candidates = Vec::new();
    for third in 0..=255u32 {
        candidates.push(Ipv4Addr::new(10, third as u8, 0, 182));
    }
    for second in [172, 192] {
        // extra pools if every 10.x band somehow collides
        candidates.push(Ipv4Addr::new(second as u8, 16, 0, 182));
    }
    candidates
    .into_iter()
    .find(|c| u32::from(*c) & mask != own_net)
    .unwrap_or(Ipv4Addr::new(10, 254, 0, 182))
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix_len: u8) -> bool {
    let bits = prefix_len.min(31) as u32;
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    u32::from(a) & mask == u32::from(b) & mask
}

// -----------------------------------------------------------------------------
// Outcome — everything the app crate needs to merge into Settings
// -----------------------------------------------------------------------------

pub struct PairingOutcome {
    /// Composed CORRECTLY: observed_source_ip : peer_advertised_wire_port.
    pub wire_peer: String,
    /// This side's alias for the remote console -> Settings.tunnel.remote_ps3.
    pub tunnel_alias: Ipv4Addr,
    /// Band anchor port (host-chosen).
    pub remote_port: u16,
    /// This side's public wire port -> Settings.tunnel.advertised_port.
    pub advertised_port: Option<u16>,
    /// Derived AES key, base64 -> Settings.tunnel.key (raw 32-byte key
    /// fed to Envelope::modern; base64 is the Settings serialization).
    pub key_b64: String,
    /// Voice-compare tag for the paranoid.
    pub pairing_tag: String,
}

fn key_to_b64(key: &[u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Shared epilogue: finish PAKE, exchange payloads, compose the outcome.
/// `peer_source_ip` = the address the peer's TCP packets actually came from.
fn handshake_epilogue(
    stream: &mut TcpStream,
    is_host: bool,
    code: &str,
    pc_ip: Ipv4Addr,
    prefix_len: u8,
    peer_source_ip: Ipv4Addr,
) -> PairResult<PairingOutcome> {
    let pake_secret = run_pake(stream, is_host, code)?;
    let key = derive_channel_key(&pake_secret);

    // Key confirmation: proves both sides derived the SAME key from the SAME
    // code. SPAKE2 itself cannot detect a wrong password — this exchange is
    // what makes a mistyped code fail as BadPassword instead of dying later
    // with an opaque upstream_hmac_mismatch inside payload exchange.
    let confirm = hkdf_sha256(&pake_secret, b"p2-pair-v1", b"key-confirm", 16);
    send_frame(stream, &confirm)?;
    let theirs_confirm = recv_frame(stream, 64)?;
    if theirs_confirm != confirm {
        return Err(PairingError::BadPassword);
    }
    let env = crate::channel::Envelope::modern(key);

    let ours = PairingPayload {
        tunnel_alias: choose_alias(pc_ip, prefix_len),
        remote_port: if is_host { 61795 } else { 0 },
        advertised_wire_port: None, // caller-level default: wire_port is public
        app_revision: 2,
    };
    let theirs = exchange_payload(stream, &env, &ours)?;
    if theirs.app_revision != ours.app_revision {
        eprintln!(
            "warning: peer revision {} != ours {}; settings schema may drift",
            theirs.app_revision, ours.app_revision
        );
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);

    let peer_wire_port = theirs.advertised_wire_port.unwrap_or(27050);
    let wire_peer = SocketAddrV4::new(peer_source_ip, peer_wire_port).to_string();

    // Host chooses the band anchor; the joiner adopts it.
    let remote_port = if is_host { ours.remote_port } else { theirs.remote_port };

    // Sanity: the remote alias must not be inside OUR subnet either.
    if same_subnet(theirs.tunnel_alias, pc_ip, prefix_len) {
        return Err(PairingError::Protocol("peer_alias_in_local_subnet"));
    }

    Ok(PairingOutcome {
        wire_peer,
       tunnel_alias: ours.tunnel_alias,
       remote_port,
       advertised_port: ours.advertised_wire_port,
       key_b64: key_to_b64(&key),
       pairing_tag: pairing_code_tag(&key),
    })
}

// -----------------------------------------------------------------------------
// Entry points
// -----------------------------------------------------------------------------

/// HOST: display code, accept one joiner, negotiate. `pc_ip`/`prefix_len`
/// come from the caller (app crate has the richer detection); used only for
/// alias/subnet logic here.
pub fn pair_host(pc_ip: Ipv4Addr, prefix_len: u8) -> PairResult<PairingOutcome> {
    let code = generate_code();
    eprintln!("═══ Pairing (host) ═══");
    eprintln!("Give this code to the other player (valid {PAIRING_WINDOW_SECS}s):");
    eprintln!("        {code}");
    eprintln!("Waiting for incoming connection on port {PAIR_PORT} ...");

    let listener = TcpListener::bind(("0.0.0.0", PAIR_PORT))?;
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(PAIRING_WINDOW_SECS);
    let (mut stream, joiner_addr) = loop {
        match listener.accept() {
            Ok(v) => break v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(PairingError::PeerUnreachable);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => return Err(e.into()),
        }
    };
    listener.set_nonblocking(false)?;
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true).ok();

    let joiner_ip = match joiner_addr {
        SocketAddr::V4(v4) => *v4.ip(), // joiner's NAT-mapped public IP
        SocketAddr::V6(_) => return Err(PairingError::Protocol("ipv6_peer")),
    };

    handshake_epilogue(&mut stream, true, &code, pc_ip, prefix_len, joiner_ip)
}

/// JOINER: dial host, type code, adopt host's choices.
pub fn pair_join(
    host_addr: IpAddr,
    pc_ip: Ipv4Addr,
    prefix_len: u8,
    code_argv: Option<&str>,   // NEW: from argv; skips interactive stdin
) -> PairResult<PairingOutcome> {
    if let IpAddr::V4(host_v4) = host_addr {
        if same_subnet(host_v4, pc_ip, prefix_len) {
            // Dialing a LAN address in a pairing that exists to establish a
            // PUBLIC wire peer is almost certainly a mistake.
            return Err(PairingError::NotOnLan);
        }
    }
    eprintln!("═══ Pairing (join) ═══");
    eprintln!("Connecting to {host_addr}:{PAIR_PORT} ...");
    let mut stream = TcpStream::connect((host_addr, PAIR_PORT))?;
    stream.set_nodelay(true).ok();

    let code: String = match code_argv {
        Some(c) => {
            eprintln!("Using code from the command line.");
            c.to_string()
        }
        None => {
            eprint!("Enter the code the host read to you: ");
            std::io::stderr().flush().ok();
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            buf.trim().to_string()
        }
    };
    // validation applies to both sources identically:
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(PairingError::BadPassword);
    }

    let host_ip = match stream.peer_addr()? {
        SocketAddr::V4(v4) => *v4.ip(), // the address we dialed = host's wire IP
        SocketAddr::V6(_) => return Err(PairingError::Protocol("ipv6_peer")),
    };

    handshake_epilogue(&mut stream, false, &code, pc_ip, prefix_len, host_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_avoids_own_subnet() {
        // 10.0.0.24 LAN must not yield a 10.0.0.x alias.
        let pc: Ipv4Addr = "10.0.0.24".parse().unwrap();
        let alias = choose_alias(pc, 24);
        assert!(!same_subnet(alias, pc, 24));
        // A 192.168.x LAN may keep the conventional 10.0.0.182.
        let pc2: Ipv4Addr = "192.168.0.33".parse().unwrap();
        assert_eq!(choose_alias(pc2, 24), "10.0.0.182".parse().unwrap());
    }

    #[test]
    fn hkdf_expands_deterministically() {
        let a = hkdf_sha256(&[7u8; 32], b"s", b"i", 32);
        let b = hkdf_sha256(&[7u8; 32], b"s", b"i", 32);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn code_is_six_digits() {
        for _ in 0..64 {
            let c = generate_code();
            assert_eq!(c.len(), 6);
            assert!(c.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
