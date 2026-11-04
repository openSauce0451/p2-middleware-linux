use std::{
    fs,
    io::{self, Write},
    net::Ipv4Addr,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const STATE: &str = "/run/p2-middleware-tunnel.alias";

fn privileged() -> bool {
    fs::read_to_string("/proc/self/status")
    .ok()
    .and_then(|s| {
        s.lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|r| r.parse::<u32>().ok())
    })
    == Some(0)
}

fn ip(args: &[&str]) -> io::Result<()> {
    let out = Command::new("ip").args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "ip {}: {}",
            args.join(" "),
                                     String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Idempotent: `ip addr replace` succeeds whether or not the alias exists.
/// Journals the mutation AFTER the effect — the journal is advisory here
/// (the alias is harmless without a running tunnel), unlike the Windows
/// record whose ordering is a correctness requirement.
pub fn ensure_alias(remote: Ipv4Addr, iface: &str) -> Result<(), &'static str> {
    if !privileged() {
        return Err("tunnel_alias_requires_root");
    }
    let cidr = format!("{remote}/32");
    ip(&["addr", "replace", &cidr, "dev", iface]).map_err(|_| "tunnel_alias_create")?;
    let mut file = fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .open(STATE)
    .map_err(|_| "tunnel_alias_journal")?;
    writeln!(file, "{remote} {iface}").map_err(|_| "tunnel_alias_journal")?;
    Ok(())
}

/// Remove the journaled alias if one exists. Called on reset/teardown and
/// at startup as orphan recovery (the crashed-last-session case).
pub fn remove_journalled() {
    let Ok(line) = fs::read_to_string(STATE) else { return };
    let _ = fs::remove_file(STATE);
    let mut parts = line.split_whitespace();
    let (Some(remote), Some(iface)) = (parts.next(), parts.next()) else { return };
    let Ok(remote) = remote.parse::<Ipv4Addr>() else { return };
    // Only ever deletes OUR alias shape: a /32 we journalled. Absence is fine.
    let _ = ip(&["addr", "del", &format!("{remote}/32"), "dev", iface]);
}

/// Age of the journal file, for diagnostics (an alias left from days ago
/// means a crashed session, not a live one).
#[allow(dead_code)]
pub fn journalled_age() -> Option<u64> {
    let meta = fs::metadata(STATE).ok()?;
    let modified = meta.modified().ok()?;
    Some(modified.duration_since(UNIX_EPOCH).ok()?.as_secs())
}

#[allow(dead_code)]
pub fn debug_stamp() -> u64 {
    SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0)
}
