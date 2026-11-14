// Mechanics only: bind a transparent UDP socket, recvmsg with per-packet
// IP_ORIGDSTADDR recovery, hand (orig_dst, src, payload) to the caller.
// No policy, no STUN, no table — those live in ps3_tunnel.rs so the event
// vocabulary and reply routing stay in one place.

//! Linux TPROXY catch-all socket for the dynamic alias-port acquisition
//! (Option B). Receives datagrams that the mangle chain diverted because no
//! kernel socket was bound to their destination tuple, and reports the
//! ORIGINAL destination per packet via the IP_ORIGDSTADDR ancillary message
//! (the same technique Squid uses for transparent interception).

use crate::gateway::event;
use serde_json::json;
use std::io::{self, ErrorKind};
use std::net::SocketAddrV4;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// Stable uapi values; declared here so we don't fight libc version drift.
const SOL_IP: libc::c_int = 0;
const IP_TRANSPARENT: libc::c_int = 19;
const IP_RECVORIGDSTADDR: libc::c_int = 20;

/// One diverted datagram with its pre-divert destination recovered from
/// the IP_ORIGDSTADDR ancillary message.
pub struct Diverted {
    pub orig: SocketAddrV4,
    pub src: SocketAddrV4,
    pub len: usize,
}

pub struct TproxySocket {
    fd: RawFd,
}

impl TproxySocket {
    /// Bind a transparent wildcard socket on `port`. IP_TRANSPARENT is
    /// required for TPROXY delivery; the wildcard bind never conflicts
    /// with alias sockets, which bind specific addresses.
    pub fn bind(port: u16) -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        let ptr = &one as *const libc::c_int as *const libc::c_void;
        let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

        // Fail loudly if TPROXY support is missing (module/config varies).
        if unsafe { libc::setsockopt(fd, SOL_IP, IP_TRANSPARENT, ptr, len) } < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        // Ask the kernel to attach the pre-divert destination per packet.
        if unsafe { libc::setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, ptr, len) } < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        // 250 ms receive timeout so the serve loop can poll the stop flag
        // (same model as RECV_TIMEOUT in udp_relay.rs / POLL in ps3_tunnel.rs).
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000,
        };
        let tv_ptr = &tv as *const libc::timeval as *const libc::c_void;
        let tv_len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, tv_ptr, tv_len) } < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }

        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = libc::INADDR_ANY; // 0.0.0.0 — FIX: struct field
        let sa_ptr = &sa as *const libc::sockaddr_in as *const libc::sockaddr;
        if unsafe {
            libc::bind(fd, sa_ptr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        } < 0
        {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(Self { fd })
    }

    /// Receive one diverted datagram with per-packet original destination.
    ///
    /// FIX vs the earlier draft: msg_name points at a REAL sockaddr_in
    /// buffer. With msg_name = NULL the kernel discards the source address
    /// and the old code dereferenced NULL — crash on the first packet.
    /// Ok(None) = timed out (caller polls stop and retries) or a diverted
    /// packet without the ORIGDSTADDR cmsg (config/kernel mismatch; drop
    /// rather than guess — must never happen after bind() checks).
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<Diverted>> {
        let mut src_sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        // Fixed control buffer: plenty for one sockaddr_in cmsg
        // (CMSG_SPACE(sizeof(sockaddr_in)) is ~28 bytes on x86-64).
        let mut control = [0u8; 128];

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&mut src_sa as *mut libc::sockaddr_in) as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as libc::size_t;

        let n = unsafe { libc::recvmsg(self.fd, &mut msg, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => Ok(None),
                _ => Err(e),
            };
        }

        // Recover the original (pre-divert) destination from the cmsg.
        let mut orig: Option<SocketAddrV4> = None;
        let hdr_len = unsafe { libc::CMSG_LEN(0) } as usize;
        let sa_size = std::mem::size_of::<libc::sockaddr_in>();
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let cm = unsafe { &*cmsg };
            if cm.cmsg_level == SOL_IP && cm.cmsg_type as libc::c_int == IP_RECVORIGDSTADDR {
                if (cm.cmsg_len as usize) >= hdr_len + sa_size {
                    let o = unsafe { *(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in) };
                    orig = Some(sockaddr_to_v4(&o));
                }
                break;
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }

        let orig = match orig {
            Some(o) => o,
            None => return Ok(None),
        };
        Ok(Some(Diverted {
            orig,
            src: sockaddr_to_v4(&src_sa),
                len: n as usize,
        }))
    }
}

fn sockaddr_to_v4(sa: &libc::sockaddr_in) -> SocketAddrV4 {
    use std::net::Ipv4Addr;
    let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
    SocketAddrV4::new(ip, u16::from_be(sa.sin_port))
}

impl Drop for TproxySocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Policy loop: run until `stop`, calling `on_packet` for every diverted
/// datagram. Pure glue — all decisions (source validation, port
/// acquisition, STUN, forwarding) live in ps3_tunnel::handle_dynamic.
pub fn serve_until<F>(port: u16, stop: Arc<AtomicBool>, mut on_packet: F) -> io::Result<()>
where
F: FnMut(SocketAddrV4, SocketAddrV4, &[u8]),
{
    let mut sock = TproxySocket::bind(port)?;
    event("udp_catchall_bound", json!({ "port": port }));
    let mut buf = vec![0u8; 65_535];
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        match sock.recv(&mut buf) {
            Ok(Some(d)) => on_packet(d.orig, d.src, &buf[..d.len]),
            Ok(None) => continue,
            Err(e) => return Err(e),
        }
    }
}
