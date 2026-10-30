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
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            ps3_ip: String::new(),
            pc_ip: String::new(),
            router_ip: String::new(),
            prefix_len: 24,
            crossplay: true,
        }
    }
}
pub struct NetworkPlan {
    pub ps3: Ipv4Addr,
    pub pc: Ipv4Addr,
    pub router: Ipv4Addr,
}
impl Settings {
    pub fn validate(&self) -> Result<NetworkPlan, &'static str> {
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
    #[cfg(windows)]
    pub fn path() -> io::Result<PathBuf> {
        std::env::var_os("LOCALAPPDATA")
        .map(|p| PathBuf::from(p).join("P2Middleware/settings.toml"))
        .ok_or_else(|| io::Error::other("Windows local application folder is unavailable"))
    }
    #[cfg(not(windows))]
    pub fn path() -> io::Result<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or_else(|| io::Error::other("Could not locate a configuration directory"))?;
        Ok(base.join("p2-middleware/settings.toml"))
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
        let path = Self::path()?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        let text = toml::to_string_pretty(self)
            .map_err(|_| io::Error::other("Could not encode settings"))?;
        std::fs::write(path, text)
    }
}
