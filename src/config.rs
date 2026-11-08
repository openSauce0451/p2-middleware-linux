// config.rs — app crate (p2-middleware): settings load/validate/save.
//
// REV 2 — adds `port_band` to TunnelSettings (Rev 3 tunnel: band alias
// listener). This file uses `deny_unknown_fields`, so the moment a
// settings.toml contains `port_band = {...}` without this revision, load()
// fails with "Saved settings are invalid" — both sides need the rebuilt app
// before the new TOML key is written.
//
// WHAT CHANGED (everything else byte-equivalent in behaviour):
//   * `PortBand { first, last }` struct — inline-table TOML:
//       port_band = { first = 61700, last = 61800 }
//     (Option<(u16,u16)> round-trips badly through toml; a named struct
//     serializes predictably and reads better in the file.)
//   * TunnelSettings.port_band: Option<PortBand>, default None (= legacy
//     single-socket behaviour on remote_port only).
//   * tunnel_plan() validates the band when present: nonzero endpoints,
//     ordered, span <= 512 (matches MAX_BAND_SOCKETS in ps3_tunnel.rs),
//     each port within 1..=65535.
//   * TunnelPlan gains port_band: Option<(u16, u16)> for serve().
//
// STILL UNCHANGED (deliberately): validate() and the same-subnet /
// public-peer / 32-byte-key checks; wire_port clamping; the 8 KiB size
// cap on the settings file; the base64 recommendation in the trailer note.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{io, net::Ipv4Addr, path::PathBuf};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub ps3_ip: String,
    pub pc_ip: String,
    pub router_ip: String,
    pub prefix_len: u8,
    pub crossplay: bool,
    pub tunnel: Option<TunnelSettings>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            ps3_ip: String::new(),
            pc_ip: String::new(),
            router_ip: String::new(),
            prefix_len: 24,
            crossplay: true,
            tunnel: None,
        }
    }
}

/// Inclusive band of extra alias ports to bind on the remote console's
/// address, written as a TOML inline table:
///
///     port_band = { first = 61700, last = 61800 }
///
/// Rationale (live capture): the peer console advertises a SWEEP of
/// candidate ports (observed 61795 -> 61751 in ~40 s), and the local
/// console walks them until one answers. Binding the whole band means
/// the first probed candidate finds a live socket instead of a kernel
/// ICMP port-unreachable. Omit the field (or leave it out entirely) for
/// legacy single-port behaviour.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortBand {
    /// First port of the band, inclusive. Must be 1..=65535.
    pub first: u16,
    /// Last port of the band, inclusive. Must be >= first.
    pub last: u16,
}

/// Site-to-site tunnel to the other player's middleware. None = disabled.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TunnelSettings {
    /// The PEER console's private IPv4 — the address OUR console dials.
    pub remote_ps3: String,
    /// The peer console's advertised game port (54740 in the capture).
    pub remote_port: u16,
    /// This side's tunnel wire port (default 27050).
    pub wire_port: u16,
    /// The other middleware PC's public endpoint, "ip:port".
    pub wire_peer: String,
    /// 32-byte PSK, base64 (from the pairing flow between the two players).
    pub key: String,
    /// Optional band of extra alias ports (see PortBand). None = single port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_band: Option<PortBand>,
    #[serde(default)]
    pub catch_all_port: Option<u16>,
    /// Rev 7: public UDP port the peer should dial — the VPN provider's
    /// assigned forwarded port. None = wire_port is already public.
    #[serde(default)]
    pub advertised_port: Option<u16>,
    /// Pin for Binding-Response advertisement (Fix 2c). None = auto-detect.
    #[serde(default)]
    pub stun_advertise: Option<String>, // parse lazily to SocketAddr on load
}
impl Default for TunnelSettings {
    fn default() -> Self {
        Self {
            remote_ps3: String::new(),
            remote_port: 0,
            wire_port: 27050,
            wire_peer: String::new(),
            key: String::new(),
            port_band: None,
            catch_all_port: None,
            advertised_port: None,
            stun_advertise: None,
        }
    }
}

pub struct StunSettings {
    pub enabled: bool,
    pub probe_ports: Vec<u16>,
    /// Answer TURN Allocate requests with a relay allocation (Fix 1).
    pub relay_allocations: bool,
}

pub struct NetworkPlan {
    pub ps3: Ipv4Addr,
    pub pc: Ipv4Addr,
    pub router: Ipv4Addr,
}
/// Validated counterpart of TunnelSettings, consumed by Bridge::start (CLI
/// flags -> serve -> Ps3Tunnel) and by the helper (alias creation).
pub struct TunnelPlan {
    pub remote_ps3: Ipv4Addr,
    pub remote_port: u16,
    pub wire_port: u16,
    pub wire_peer: std::net::SocketAddr,
    pub key: [u8; 32],
    /// Validated inclusive band, or None for legacy single-port behaviour.
    pub port_band: Option<(u16, u16)>,
    pub catch_all_port: Option<u16>,
    pub advertised_port: Option<u16>,
}
impl Settings {
    pub fn validate(&self) -> Result<NetworkPlan, &'static str> {
        // UNCHANGED — do not touch this function. The tunnel fields are
        // validated separately so a half-filled tunnel config never blocks
        // saving the basic LAN settings.
        let parse = |s: &str| {
            s.trim()
                .parse::<Ipv4Addr>()
                .ok()
                .filter(|ip| ip.is_private())
        };
        let ps3 = parse(&self.ps3_ip).ok_or("Enter the PS3's private IPv4 address.")?;
        let pc = parse(&self.pc_ip).ok_or("Select this PC's private IPv4 address.")?;
        let router = parse(&self.router_ip).ok_or("Enter your router's private IPv4 address.")?;
        if ps3 == pc || ps3 == router || pc == router {
            return Err("PS3, PC and router must have different addresses.");
        }
        if !(8..=30).contains(&self.prefix_len) {
            return Err("Use a LAN prefix between 8 and 30.");
        }
        let mask = u32::MAX << (32 - self.prefix_len);
        let subnet = u32::from(pc) & mask;
        for ip in [ps3, pc, router] {
            let n = u32::from(ip);
            if n & mask != subnet {
                return Err("PS3, PC and router must be on the same subnet.");
            }
            if n & !mask == 0 || n & !mask == !mask {
                return Err("Use a device address, not the subnet or broadcast address.");
            }
        }
        Ok(NetworkPlan { ps3, pc, router })
    }

    /// Validate tunnel fields. Call only when `self.tunnel.is_some()`.
    /// All-or-nothing: a present-but-invalid tunnel config is an error,
    /// never silently ignored.
    pub fn tunnel_plan(&self) -> Result<TunnelPlan, &'static str> {
        let t = self.tunnel.as_ref().ok_or("No tunnel settings.")?;
        let remote_ps3 = t
            .remote_ps3
            .trim()
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|ip| ip.is_private())
            .ok_or("Enter the other PS3's private IPv4 address.")?;
        if !(1..=65535).contains(&t.remote_port) {
            return Err("Enter the other PS3's game port.");
        }
        let wire_port = if t.wire_port == 0 { 27050 } else { t.wire_port };
        if !(1024..=65535).contains(&wire_port) {
            return Err("Use a tunnel port between 1024 and 65535.");
        }
        // The wire peer must be a public endpoint; a private/loopback value
        // is a misconfiguration (leftover from copying the LAN addresses).
        let wire_peer = t
            .wire_peer
            .trim()
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "Enter the other PC's public address as ip:port.")?;
        match wire_peer.ip() {
            std::net::IpAddr::V4(ip)
                if !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified() => {}
            _ => return Err("The tunnel peer must be the other PC's public IPv4."),
        }
        if wire_peer.port() == 0 {
            return Err("The tunnel peer needs a port.");
        }
        // Same-subnet guard: the remote PS3 must NOT be on OUR LAN — if it
        // is, the player confused the two consoles' networks and the alias
        // would collide with local routing.
        let mask = u32::MAX << (32 - self.prefix_len.min(31));
        let own_net = self
            .pc_ip
            .trim()
            .parse::<Ipv4Addr>()
            .map(|ip| u32::from(ip) & mask)
            .unwrap_or(0);
        if u32::from(remote_ps3) & mask == own_net {
            return Err("The remote PS3 address is on this LAN; check which PS3 is which.");
        }
        let key = STANDARD
            .decode(t.key.trim())
            .map_err(|_| "The tunnel key must be base64.")?;
        if key.len() != 32 {
            return Err("The tunnel key must be 32 bytes of base64.");
        }
        let mut material = [0u8; 32];
        material.copy_from_slice(&key);

        // Port band: optional, but validated as strictly as everything
        // else. The bounds mirror ps3_tunnel.rs (MAX_BAND_SOCKETS = 512):
        // a fat-fingered range must fail at SAVE time, not at runtime
        // when the binder silently forks half a thousand threads.
        let port_band = match &t.port_band {
            None => None,
            Some(band) => {
                let (first, last) = (band.first, band.last);
                if first == 0 || last == 0 {
                    return Err("Port band endpoints must be between 1 and 65535.");
                }
                if first > last {
                    return Err("Port band: first must not exceed last.");
                }
                let span = u32::from(last) - u32::from(first) + 1;
                if span > 512 {
                    return Err("Port band may span at most 512 ports.");
                }
                // Ports below 1024 need privileges the runtime usually has
                // (the helper runs elevated), but a band there is almost
                // certainly a typo — the observed console candidates are
                // all ephemeral. Reject rather than warn.
                if first < 1024 {
                    return Err("Port band ports must be 1024 or higher.");
                }
                Some((first, last))
            }
        };
        let catch_all_port = t.catch_all_port.or(Some(27051));
        let advertised_port = t.advertised_port.filter(|p| (1..=65535).contains(p));

        Ok(TunnelPlan {
            remote_ps3,
            remote_port: t.remote_port,
            wire_port,
            wire_peer,
            key: material,
            port_band,
            catch_all_port,
            advertised_port,
        })
    }

    #[cfg(windows)]
    pub fn path() -> io::Result<PathBuf> {
        std::env::var_os("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("P2Middleware/settings.toml"))
            .ok_or_else(|| io::Error::other("Windows local application folder is unavailable"))
    }
    #[cfg(not(windows))]
    pub fn path() -> io::Result<PathBuf> {
        let home: PathBuf = {
            let sudo_home = || {
                if nix::unistd::Uid::effective().is_root() {
                    std::env::var_os("SUDO_USER").and_then(|u| {
                        // Root via plain sudo: reconstruct the calling user's
                        // XDG config dir — /home/<user>/.config — since HOME
                        // has been reset to /root.
                        let p = PathBuf::from("/home").join(&u).join(".config");
                        p.exists().then_some(p)
                    })
                } else {
                    None
                }
            };
            match std::env::var_os("XDG_CONFIG_HOME") {
                Some(x) => PathBuf::from(x),
                None => sudo_home()
                    .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
                    .ok_or_else(|| {
                        io::Error::other("Could not locate a configuration directory")
                    })?,
            }
        };
        Ok(home.join("p2-middleware/settings.toml"))
    }
    pub fn load() -> io::Result<Self> {
        let p = Self::path()?;
        match std::fs::read_to_string(p) {
            Ok(text) if text.len() <= 8192 => toml::from_str(&text).map_err(|_| {
                io::Error::other("Saved settings are invalid. Review and save new settings.")
            }),
            Ok(_) => Err(io::Error::other("Saved settings are too large.")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => Err(io::Error::other("Could not read saved settings.")),
        }
    }
    pub fn save(&self) -> io::Result<()> {
        self.validate().map_err(io::Error::other)?;
        // Also validate a present tunnel config so bad values cannot be
        // persisted. Disabled (None) tunnels stay legal.
        if self.tunnel.is_some() {
            self.tunnel_plan().map_err(io::Error::other)?;
        }
        let path = Self::path()?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        let text = toml::to_string_pretty(self)
            .map_err(|_| io::Error::other("Could not encode settings"))?;
        std::fs::write(path, text)
    }
}
