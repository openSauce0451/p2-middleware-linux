//! Shared STUN responder: RFC 5389 + legacy RFC 3489 Binding Requests.
//!
//! Hoisted verbatim from ps3_tunnel.rs so both the gameplay tunnel's
//! probe responders and the legacy-CM UDP relay answer the console's
//! NAT-discovery probes locally. Reply fidelity rule (unchanged): the
//! response is always sent FROM the socket the request arrived on, so
//! the console sees an endpoint answering from the exact tuple it dialed.

use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::io;
/// Classification result for a datagram.
pub enum StunKind {
    BindingRequest,
    /// A well-formed STUN message of some other type (e.g. 0x0003 Allocate).
    Other(u16),
    NotStun,
}

/// Attribute types used in allocate responses.
pub const ATTR_MAPPED: u16 = 0x0001;
pub const ATTR_XOR_MAPPED: u16 = 0x0020;
pub const ATTR_RELAYED: u16 = 0x0016;
pub const ATTR_LIFETIME: u16 = 0x000D;

/// RFC 5389 magic cookie.
pub const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

fn push_attr(m: &mut Vec<u8>, ty: u16, val: &[u8]) {
    m.extend_from_slice(&ty.to_be_bytes());
    m.extend_from_slice(&(val.len() as u16).to_be_bytes());
    m.extend_from_slice(val);
    while m.len() % 4 != 0 { m.push(0); } // 32-bit alignment padding
}

/// Lowercase hex, no separators — compact for log events.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn plain_addr(addr: &SocketAddrV4) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[1] = 0x01;                                     // family: IPv4
    out[2..4].copy_from_slice(&addr.port().to_be_bytes()); // NO xor
    out[4..8].copy_from_slice(&addr.ip().octets());        // NO xor
    out
}

/// Scan a STUN request's attribute area for `want` and return its raw value.
/// Walks the 2+2 TLV headers; bails on a truncated attribute (malformed).
fn find_attr<'a>(req: &'a [u8], want: u16) -> Option<&'a [u8]> {
    let mut i = 20usize; // past type/len/txid header
    while i + 4 <= req.len() {
        let ty = u16::from_be_bytes([req[i], req[i + 1]]);
        let alen = u16::from_be_bytes([req[i + 2], req[i + 3]]) as usize;
        let v0 = i + 4;
        if alen > req.len().saturating_sub(v0) {
            return None; // truncated attribute — treat request as malformed
        }
        if ty == want {
            return Some(&req[v0..v0 + alen]);
        }
        i = v0 + alen; // RFC 3489: no 4-byte padding requirement; both
        // observed usernames (16/32 B) are aligned anyway
    }
    None
}

pub fn build_allocate_success(
    req: &[u8],
    mapped: SocketAddrV4,
    relayed: SocketAddrV4,
) -> Option<Vec<u8>> {
    if req.len() < 36 { return None; }
    let mut txid = [0u8; 16];
    txid.copy_from_slice(&req[4..20]);

    // Fix 1: echo the request's USERNAME (0x0006) — the credential-bearing
    // counterpart to the request that carried one. Binding responses (no
    // credential in the request) are accepted today; the Allocate (with one)
    // is rejected. This echoes exactly what the console sent, byte for byte.
    let username = find_attr(req, 0x0006);

    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(&0x0103u16.to_be_bytes());
    m.extend_from_slice(&[0, 0]);
    m.extend_from_slice(&txid);
    push_attr(&mut m, 0x0012, &plain_addr(&relayed));   // RELAYED-ADDRESS, plain
    push_attr(&mut m, 0x0001, &plain_addr(&mapped));    // MAPPED-ADDRESS, plain
    push_attr(&mut m, 0x000D, &3600u32.to_be_bytes());  // LIFETIME
    if let Some(user) = username {
        push_attr(&mut m, 0x0006, user);                // USERNAME echo
    }
    push_attr(&mut m, 0x000F, &[0x72, 0xc6, 0x4b, 0xc6]); // Steam marker

    let len = (m.len() - 20) as u16;
    m[2..4].copy_from_slice(&len.to_be_bytes());
    Some(m)
}

/// Classify a datagram: BindingRequest / Other(type) / NotStun.
///
/// STRICT FRAMING (deliberate): a datagram qualifies only if
///   * length >= 20, and the declared header length matches exactly
///     (20 + msg_len == datagram len) — game traffic can't false-positive;
///   * the top two bits of the message type are zero;
///   * the type is anything in the STUN method space (0x0001 Binding
///     Request is answered; other types are surfaced as Other for logging).
pub fn stun_classify(buf: &[u8]) -> StunKind {
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

/// Wrapper preserving the old call sites: advertises the requester's own
/// tuple (legacy behaviour). Prefer `send_stun_response_advertised`.
pub fn send_stun_response(socket: &UdpSocket, from: SocketAddr, req: &[u8]) -> io::Result<()> {
    send_stun_response_advertised(socket, from, req, from)
}

/// Binding Success Response advertising `advertise` (typically the
/// middleware's announced public endpoint) instead of the raw observed
/// tuple. `from` is still the reply destination.
pub fn send_stun_response_advertised(
    socket: &UdpSocket,
    from: SocketAddr,
    req: &[u8],
    advertise: SocketAddr,
) -> io::Result<()> {
    let rfc5389 = req[4..8] == STUN_MAGIC_COOKIE;
    let mut resp: Vec<u8> = Vec::with_capacity(44);

    resp.extend_from_slice(&0x0101u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    if rfc5389 {
        resp.extend_from_slice(&STUN_MAGIC_COOKIE);
    }
    resp.extend_from_slice(&req[8..20]);

    let (attr_type, xor): (u16, bool) = if rfc5389 {
        (ATTR_XOR_MAPPED, true)
    } else {
        (ATTR_MAPPED, false)
    };
    resp.extend_from_slice(&attr_type.to_be_bytes());
    resp.extend_from_slice(&8u16.to_be_bytes());
    resp.push(0);
    resp.push(0x01);

    // The ADVERTISED endpoint's port, not from.port().
    let port = advertise.port();
    let mapped_port = if xor { port ^ 0x2112 } else { port };
    resp.extend_from_slice(&mapped_port.to_be_bytes());

    match advertise.ip() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            if xor {
                for i in 0..4 {
                    resp.push(o[i] ^ STUN_MAGIC_COOKIE[i]);
                }
            } else {
                resp.extend_from_slice(&o);
            }
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "stun_v6_unsupported")),
    }

    let attr_bytes = resp.len() - 20;
    resp[2] = (attr_bytes >> 8) as u8;
    resp[3] = attr_bytes as u8;

    socket.send_to(&resp, from)?;
    Ok(())
}
