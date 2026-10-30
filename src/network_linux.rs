//! Linux native gateway.
//!
//! Deviations from the Windows implementation, and why:
//!
//! * `SkipAsSource` has no Linux equivalent, so the legacy CM addresses are placed on
//!   a dedicated dummy interface. They stay locally deliverable without becoming
//!   source-address candidates on the uplink.
//! * nftables cannot match an executable path, so the Windows rule's `-Program`
//!   clause has no direct analogue; matching is by interface, source and port.
//! * Lifetimes use `valid_lft`/`preferred_lft`, refreshed on the same 60s tick.

use crate::{
    journal_linux::{atomic_replace, JournalStore},
    request::Request,
    session::Network,
};
use p2_bridge_core::legacy_cm::LEGACY_CM;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io,
    net::Ipv4Addr,
    process::Command,
    time::{Duration, Instant},
};

const LIFETIME: u32 = 720;
const RENEW: Duration = Duration::from_secs(60);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u8,
    index: u32,
    iface: String,
    local: Ipv4Addr,
    peer: Ipv4Addr,
    previous_forwarding: bool,
    forwarding_intent: bool,
}

impl Record {
    fn validate(&self) -> io::Result<()> {
        if self.schema != 1
            || self.index == 0
            || !self.local.is_private()
            || !self.peer.is_private()
            || self.local == self.peer
            || self.iface.is_empty()
            || self.iface.contains('/')
            {
                return Err(io::Error::other("native_record_invalid"));
            }
            Ok(())
    }
}

fn interface_name(index: u32) -> io::Result<String> {
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let Ok(text) = fs::read_to_string(entry.path().join("ifindex")) else {
            continue;
        };
        if text.trim().parse::<u32>() == Ok(index) {
            return Ok(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Err(io::Error::other("interface_not_found"))
}

fn ip(args: &[&str]) -> io::Result<()> {
    let out = Command::new("ip").args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ))
    }
}

fn has_address(iface: &str, addr: Ipv4Addr) -> io::Result<bool> {
    let out = Command::new("ip").args(["-o", "addr", "show", "dev", iface]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let needle = format!("{addr}/32");
    Ok(text.split_whitespace().any(|f| f == needle))
}

fn address_present_anywhere(addr: Ipv4Addr) -> io::Result<bool> {
    let out = Command::new("ip").args(["-o", "addr", "show"]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let needle = format!("{addr}/32");
    Ok(text.split_whitespace().any(|f| f == needle))
}

fn add_address(iface: &str, addr: Ipv4Addr) -> io::Result<()> {
    let lifetime = LIFETIME.to_string();
    ip(&[
        "addr", "add", &format!("{addr}/32"), "dev", iface,
       "valid_lft", &lifetime, "preferred_lft", &lifetime, "nodad",
    ])
}

fn del_address(iface: &str, addr: Ipv4Addr) -> io::Result<()> {
    ip(&["addr", "del", &format!("{addr}/32"), "dev", iface])
}

fn forwarding(iface: &str) -> io::Result<bool> {
    let text = fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{iface}/forwarding"))?;
    Ok(text.trim() == "1")
}

fn set_forwarding(iface: &str, on: bool) -> io::Result<()> {
    fs::write(
        format!("/proc/sys/net/ipv4/conf/{iface}/forwarding"),
            if on { "1" } else { "0" },
    )?;
    if on {
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    }
    Ok(())
}

pub struct NativeHost {
    store: JournalStore,
    renewed: Option<Instant>,
    failed: bool,
}

impl NativeHost {
    pub fn new(store: JournalStore) -> Self {
        Self { store, renewed: None, failed: false }
    }

    fn read(&self) -> io::Result<Option<Record>> {
        let base = self.store.native_path();
        let pending = base.with_extension("next");
        let path = if pending.exists() { pending } else { base };
        match fs::read(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
            Ok(bytes) if bytes.len() > 16384 => Err(io::Error::other("native_record_size")),
            Ok(bytes) => {
                let r: Record = serde_json::from_slice(&bytes)?;
                r.validate()?;
                Ok(Some(r))
            }
        }
    }

    fn write(&self, r: &Record) -> io::Result<()> {
        r.validate()?;
        let path = self.store.native_path();
        let next = path.with_extension("next");
        fs::write(&next, serde_json::to_vec(r)?)?;
        atomic_replace(&next, &path)
    }

    fn clear(&self) -> io::Result<()> {
        let base = self.store.native_path();
        for path in [base.clone(), base.with_extension("next")] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn restore(&mut self) -> io::Result<()> {
        self.renewed = None;
        self.failed = false;
        let Some(r) = self.read()? else {
            return self.clear();
        };
        let mut failed = false;
        if r.forwarding_intent {
            failed |= set_forwarding(&r.iface, r.previous_forwarding).is_err();
        }
        for addr in LEGACY_CM {
            match has_address(&r.iface, addr) {
                Ok(true) => failed |= del_address(&r.iface, addr).is_err(),
                Ok(false) => {}
                Err(_) => failed = true,
            }
        }
        if failed {
            return Err(io::Error::other("native_cleanup_incomplete"));
        }
        self.clear()
    }

    fn activate(&mut self, request: Request) -> io::Result<()> {
        request.validate()?;
        if self.read()?.is_some() {
            return Err(io::Error::other("recovery_required"));
        }
        let plan = request.settings.validate().map_err(io::Error::other)?;
        let iface = interface_name(request.interface)?;
        for addr in LEGACY_CM {
            if address_present_anywhere(addr)? {
                return Err(io::Error::other("native_address_conflict"));
            }
        }
        let mut r = Record {
            schema: 1,
            index: request.interface,
            iface,
            local: plan.pc,
            peer: plan.ps3,
            previous_forwarding: forwarding(&interface_name(request.interface)?)?,
            forwarding_intent: false,
        };
        self.write(&r)?;
        if let Err(e) = self.configure(&mut r) {
            let _ = self.restore();
            return Err(e);
        }
        self.renewed = Some(Instant::now());
        Ok(())
    }

    fn configure(&self, r: &mut Record) -> io::Result<()> {
        for addr in LEGACY_CM {
            add_address(&r.iface, addr)?;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if LEGACY_CM.iter().all(|a| has_address(&r.iface, *a).unwrap_or(false)) {
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("address_timeout"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !r.previous_forwarding {
            r.forwarding_intent = true;
            self.write(r)?;
            set_forwarding(&r.iface, true)?;
        }
        // NOTE: no firewall rule. Traffic to the CM /32s is delivered locally, so none
        // is needed while the INPUT policy is ACCEPT. Under a restrictive policy, add:
        //   nft add rule inet filter input iifname "<iface>" ip saddr <ps3> \
        //       ip daddr { <cm addresses> } tcp dport 27017 accept
        Ok(())
    }

    fn renew(&mut self) -> io::Result<()> {
        let r = self
        .read()?
        .ok_or_else(|| io::Error::other("native_record_missing"))?;
        let lifetime = LIFETIME.to_string();
        for addr in LEGACY_CM {
            if !has_address(&r.iface, addr)? {
                return Err(io::Error::other("address_missing"));
            }
            ip(&[
                "addr", "change", &format!("{addr}/32"), "dev", &r.iface,
               "valid_lft", &lifetime, "preferred_lft", &lifetime,
            ])?;
        }
        Ok(())
    }

    fn tick(&mut self) {
        if self.renewed.is_some_and(|t| t.elapsed() >= RENEW) {
            self.renewed = Some(Instant::now());
            self.failed |= self.renew().is_err();
        }
    }
}

impl Network for NativeHost {
    fn cleanup(&mut self) -> io::Result<()> {
        self.restore()
    }
    fn start(&mut self, request: Request) -> io::Result<()> {
        self.activate(request)
    }
    fn maintain(&mut self) {
        self.tick()
    }
    fn failed(&self) -> bool {
        self.failed
    }
}
