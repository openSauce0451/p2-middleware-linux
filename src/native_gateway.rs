//! Native TCP delivery via fixed legacy CM /32 addresses. No packet driver.
use crate::{
    session::Network,
    windows_host::{self, JournalStore, Request},
};
use p2_bridge_core::legacy_cm::LEGACY_CM;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::ERROR_NOT_FOUND, NetworkManagement::IpHelper::*, Networking::WinSock::*,
};

// Short lifetimes bound a crashed helper; an active session renews them.
const LIFETIME: u32 = 720;
const RENEW: Duration = Duration::from_secs(60);
fn key(index: u32, ip: Ipv4Addr) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe {
        InitializeUnicastIpAddressEntry(&mut row);
    }
    row.InterfaceIndex = index;
    row.Address = SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    };
    row
}
fn lookup(mut row: MIB_UNICASTIPADDRESS_ROW) -> io::Result<Option<MIB_UNICASTIPADDRESS_ROW>> {
    match unsafe { GetUnicastIpAddressEntry(&mut row) } {
        0 => Ok(Some(row)),
        ERROR_NOT_FOUND => Ok(None),
        code => Err(io::Error::from_raw_os_error(code as i32)),
    }
}
/// Only an identity for matching a firewall rule, never a program to execute.
fn valid_bridge_path(value: &str) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        && path
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("p2-bridge.exe"))
        && !value.contains('\0')
        && value.len() < 8192
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Address {
    ip: Ipv4Addr,
    created: Option<i64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u8,
    index: u32,
    luid: u64,
    local: Ipv4Addr,
    peer: Ipv4Addr,
    name: String,
    program: String,
    previous_forwarding: bool,
    firewall_intent: bool,
    forwarding_intent: bool,
    addresses: Vec<Address>,
}
impl Record {
    fn validate(&self) -> io::Result<()> {
        let suffix = self.name.strip_prefix("p2-middleware-").unwrap_or("");
        if self.schema != 1
            || self.index == 0
            || self.luid == 0
            || !self.local.is_private()
            || !self.peer.is_private()
            || self.local == self.peer
            || !valid_bridge_path(&self.program)
            || suffix.len() != 16
            || !suffix.bytes().all(|b| b.is_ascii_hexdigit())
            || (self.previous_forwarding && self.forwarding_intent)
            || self.addresses.len() > LEGACY_CM.len()
            || self
                .addresses
                .iter()
                .zip(LEGACY_CM)
                .any(|(a, expected)| a.ip != expected)
        {
            return Err(io::Error::other("native_record_invalid"));
        }
        Ok(())
    }
    fn row(&self, ip: Ipv4Addr) -> MIB_UNICASTIPADDRESS_ROW {
        let mut r = key(self.index, ip);
        r.InterfaceLuid.Value = self.luid;
        r
    }
    fn owns(&self, a: &Address, r: &MIB_UNICASTIPADDRESS_ROW) -> bool {
        r.OnLinkPrefixLength == 32
            && r.SkipAsSource
            && r.PrefixOrigin == IpPrefixOriginManual
            && r.SuffixOrigin == IpSuffixOriginManual
            && r.ValidLifetime <= LIFETIME
            && a.created == Some(r.CreationTimeStamp)
            && unsafe { r.InterfaceLuid.Value == self.luid }
    }
}
pub struct NativeHost {
    store: JournalStore,
    renewed: Option<Instant>,
    failed: bool,
}
impl NativeHost {
    pub fn new(store: JournalStore) -> io::Result<Self> {
        Ok(Self {
            store,
            renewed: None,
            failed: false,
        })
    }
    fn renew(&mut self) -> io::Result<()> {
        let r = self
            .read()?
            .ok_or_else(|| io::Error::other("native_record_missing"))?;
        for a in &r.addresses {
            let mut row = lookup(r.row(a.ip))
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::other("address_missing"))?;
            if !r.owns(a, &row) {
                return Err(io::Error::other("address_changed"));
            }
            row.ValidLifetime = LIFETIME;
            row.PreferredLifetime = LIFETIME;
            let code = unsafe { SetUnicastIpAddressEntry(&row) };
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        Ok(())
    }
    // =============================================================================
    // FIX — src/native_gateway.rs, NativeHost::read()
    //
    // Replace the existing `let path = match fs::symlink_metadata(&pending) {...}`
    // block with the version below. Nothing else in the file changes.
    //
    // WHY THIS IS NEEDED
    //
    // A zero-length `native-gateway.next` is a torn write: the helper died between
    // create_new and the first flush. read() preferred that file, parsed zero
    // bytes, failed, and restore() surfaced recovery_incomplete -- while write()'s
    // create_new refused the existing path, so the store could neither be read nor
    // rewritten. Recovery was impossible by construction, on every launch, forever.
    //
    // WHY DROPPING AN EMPTY PENDING FILE LOSES NOTHING
    //
    // Every network side effect is performed only AFTER the record that authorises
    // it is durable in the base file:
    //
    //     r.firewall_intent = true;
    //     self.write(&r)?;                                  // durable first
    //     windows_host::command("native_rule_add", ..)?;    // side effect second
    //
    // The same holds for forwarding_intent, and for address creation (push+write
    // precedes CreateUnicastIpAddressEntry). So a torn pending file can never be
    // the sole record of committed intent -- the base is always at least as
    // informed, and an empty file is not a record at all.
    //
    // A NON-empty torn pending file still blocks recovery, exactly as before: it
    // may hold intent that the base lacks, and the original safety argument for
    // that case stands.
    // =============================================================================

    fn read(&self) -> io::Result<Option<Record>> {
        let base = self.store.native_path();
        let pending = base.with_extension("next");
        // A flushed pending update can contain newer mutation intent than the
        // base. An incomplete non-empty pending file blocks recovery rather
        // than losing that intent. An EMPTY one encodes no intent, so it is
        // discarded: it cannot authorise anything, and leaving it in place
        // would also wedge write(), whose create_new refuses an existing path.
        let path = match fs::symlink_metadata(&pending) {
            Ok(m) if m.is_file() && m.len() == 0 && m.file_attributes() & 0x400 == 0 => {
                fs::remove_file(&pending)?;
                base
            }
            Ok(_) => pending,
            Err(e) if e.kind() == io::ErrorKind::NotFound => base,
            Err(e) => return Err(e),
        };
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Ok(m) if m.is_file() && m.file_attributes() & 0x400 == 0 => (),
            _ => return Err(io::Error::other("native_record_file")),
        }
        let mut bytes = Vec::new();
        OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(path)?
        .take(16385)
        .read_to_end(&mut bytes)?;
        if bytes.len() > 16384 {
            return Err(io::Error::other("native_record_size"));
        }
        let r: Record = serde_json::from_slice(&bytes)?;
        r.validate()?;
        Ok(Some(r))
    }

    // =============================================================================
    // NOTES
    //
    // * The reparse-point guard (0x400) is kept on the removal path too: a junction
    //   named native-gateway.next must not be followed or deleted.
    //
    // * Removal failure propagates deliberately. If the file is held open by a
    //   live helper (write() opens it with share_mode(0)), that helper may be
    //   mid-write, so refusing to proceed is the honest outcome.
    //
    // * Optional, NOT required: write() could also unlink a stale pending file
    //   before create_new. read() now clears it on the recovery path, which is the
    //   one that matters, so I would leave write() alone.
    //
    // * This is a pre-existing fork bug, unrelated to the UDP relay work. Our patch
    //   set touches native_gateway.ps1 only; native_gateway.rs was unmodified.
    //
    // * Deployment note visible in the stranded record: it pinned
    //   program = C:\Users\Owner\Downloads\p2-middleware-v0.1.0-windows-x64\
    //   p2-bridge.exe. Both the record and the firewall rule pin that absolute
    //   path, so replacing binaries in a DIFFERENT folder while a record survives
    //   would fail the ownership check on the remove path. Keep all three exes in
    //   one folder and overwrite in place when upgrading.
    // =============================================================================
    fn write(&self, r: &Record) -> io::Result<()> {
        r.validate()?;
        let path = self.store.native_path();
        let next = path.with_extension("next");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(&next)?;
        file.write_all(&serde_json::to_vec(r)?)?;
        file.sync_all()?;
        drop(file);
        windows_host::atomic_replace(&next, &path)
    }
    fn clear(&self) -> io::Result<()> {
        for path in [
            self.store.native_path(),
            self.store.native_path().with_extension("next"),
        ] {
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_file() && m.file_attributes() & 0x400 == 0 => fs::remove_file(path)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                _ => return Err(io::Error::other("native_record_file")),
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
        if r.firewall_intent {
            failed |= windows_host::command(
                "native_rule_remove",
                json!({"record":r,"addresses":LEGACY_CM}),
            )
            .is_err();
        }
        if r.forwarding_intent {
            let same_interface = matches!(lookup(key(r.index,r.local)), Ok(Some(row)) if unsafe {row.InterfaceLuid.Value == r.luid});
            failed |= !same_interface;
            if same_interface {
                failed |= windows_host::command(
                    "forwarding",
                    json!({"index":r.index,"local":r.local,"enabled":false}),
                )
                .is_err();
            }
        }
        for a in &r.addresses {
            let result = (|| -> io::Result<()> {
                if let Some(row) = lookup(r.row(a.ip)).map_err(io::Error::other)? {
                    if !r.owns(a, &row) {
                        return Err(io::Error::other("native_address_conflict"));
                    }
                    let code = unsafe { DeleteUnicastIpAddressEntry(&row) };
                    if code != 0 && code != ERROR_NOT_FOUND {
                        return Err(io::Error::from_raw_os_error(code as i32));
                    }
                }
                if lookup(r.row(a.ip)).map_err(io::Error::other)?.is_some() {
                    return Err(io::Error::other("native_address_remains"));
                }
                Ok(())
            })();
            failed |= result.is_err();
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
        let state = windows_host::command(
            "interface",
            json!({"index":request.interface,"local":plan.pc}),
        )?;
        if state["address"] != plan.pc.to_string()
            || state["gateway"] != plan.router.to_string()
            || state["prefix"] != request.settings.prefix_len
        {
            return Err(io::Error::other("interface_changed"));
        }
        let before =
            windows_host::command("probe_network_snapshot", json!({"index":request.interface}))?;
        let primary = lookup(key(request.interface, plan.pc))
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("interface_changed"))?;
        // Refuse an existing address on ANY interface, rather than taking ownership.
        windows_host::command("native_addresses_free", json!({"addresses":LEGACY_CM}))?;
        let mut r = Record {
            schema: 1,
            index: request.interface,
            luid: unsafe { primary.InterfaceLuid.Value },
            local: plan.pc,
            peer: plan.ps3,
            name: format!("p2-middleware-{:016x}", rand::random::<u64>()),
            program: std::env::current_exe()?
                .with_file_name("p2-bridge.exe")
                .to_string_lossy()
                .into_owned(),
            previous_forwarding: state["forwarding"]
                .as_bool()
                .ok_or_else(|| io::Error::other("interface_state"))?,
            firewall_intent: false,
            forwarding_intent: false,
            addresses: vec![],
        };
        self.write(&r)?;
        let result = (|| -> io::Result<()> {
            for ip in LEGACY_CM {
                r.addresses.push(Address { ip, created: None });
                self.write(&r)?;
                let mut row = r.row(ip);
                row.OnLinkPrefixLength = 32;
                row.SkipAsSource = true;
                row.PrefixOrigin = IpPrefixOriginManual;
                row.SuffixOrigin = IpSuffixOriginManual;
                row.ValidLifetime = LIFETIME;
                row.PreferredLifetime = LIFETIME;
                let code = unsafe { CreateUnicastIpAddressEntry(&row) };
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
                r.addresses.last_mut().unwrap().created = Some(
                    lookup(row)
                        .map_err(io::Error::other)?
                        .ok_or_else(|| io::Error::other("address_missing"))?
                        .CreationTimeStamp,
                );
                self.write(&r)?;
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let mut ready = true;
                for a in &r.addresses {
                    let row = lookup(r.row(a.ip))
                        .map_err(io::Error::other)?
                        .ok_or_else(|| io::Error::other("address_missing"))?;
                    if !r.owns(a, &row) {
                        return Err(io::Error::other("address_changed"));
                    }
                    if row.DadState != IpDadStatePreferred {
                        if row.DadState != IpDadStateTentative {
                            return Err(io::Error::other("address_dad_failed"));
                        }
                        ready = false;
                    }
                }
                if ready {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other("address_dad_timeout"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let after = windows_host::command("probe_network_snapshot", json!({"index":r.index}))?;
            for field in ["dhcp", "defaults", "dns", "forwarding"] {
                if before[field] != after[field] {
                    return Err(io::Error::other("interface_changed"));
                }
            }
            r.firewall_intent = true;
            self.write(&r)?;
            windows_host::command("native_rule_add", json!({"record":r,"addresses":LEGACY_CM}))?;
            if !r.previous_forwarding {
                r.forwarding_intent = true;
                self.write(&r)?;
                windows_host::command(
                    "forwarding",
                    json!({"index":r.index,"local":r.local,"enabled":true}),
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.restore()?;
        }
        result?;
        self.renewed = Some(Instant::now());
        Ok(())
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
        if self.renewed.is_some_and(|t| t.elapsed() >= RENEW) {
            self.renewed = Some(Instant::now());
            self.failed |= self.renew().is_err();
        }
    }
    fn failed(&self) -> bool {
        self.failed
    }
}
