use std::{
    fs,
    io::{self, Write},
    net::Ipv4Addr,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub const STATE: &str = "/run/p2-middleware-tunnel.alias";

// REV 2 — Steam CM bypass route, journaled like the alias.
//
// The route is recorded in its own journal ONLY WHEN WE ADDED IT
// (ensure_steam_bypass returns Ok(true)). Teardown therefore removes only
// what this app created: a route placed manually or by a systemd unit is
// foreign, survives resets/crashes, and is never touched. Orphan recovery
// at startup uses the same journal, so a crashed session's route is
// cleaned exactly like its alias.
pub const STEAM_STATE: &str = "/run/p2-middleware-steambypass.route";

// ---------------------------------------------------------------------------
// Steam CM bypass route (session-scoped, mirrors the alias lifecycle).
//
// Several Proton exit servers swallow the CM greeting frame on established
// outbound TCP, killing every session at the ~15 s frame deadline. The ISP
// path is verified good (dd test). So Valve's CM range bypasses the VPN:
// a /19 route via the LAN router beats the tun0 default by specificity.
// More-specific prefixes always win, independent of metrics.
// ---------------------------------------------------------------------------

/// Valve's connection-manager range (162.254.192.0 – 162.254.223.255).
#[cfg(target_os = "linux")]
pub const STEAM_CM_PREFIX: &str = "162.254.192.0/19";

#[cfg(target_os = "linux")]
pub fn steam_bypass_active() -> bool {
    Command::new("ip")
        .args(["route", "show", "exact", STEAM_CM_PREFIX])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// Idempotent: Ok(true) = we added it (and journalled it), Ok(false) = it
/// was already present (foreign or ours from a live session — untouched).
/// Fails with a clean sentinel when unprivileged, mirroring ensure_alias.
#[cfg(target_os = "linux")]
pub fn ensure_steam_bypass(router: &str, iface: &str) -> Result<bool, &'static str> {
    if !privileged() {
        return Err("steam_bypass_requires_root");
    }
    if steam_bypass_active() {
        return Ok(false);
    }
    ip(&["route", "add", STEAM_CM_PREFIX, "via", router, "dev", iface])
        .map_err(|_| "steam_bypass_create")?;
    // Journal AFTER the effect, same ordering contract as the alias:
    // advisory — an unreferenced journal at worst triggers a harmless
    // no-op `ip route del` at recovery.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(STEAM_STATE)
        .map_err(|_| "steam_bypass_journal")?;
    writeln!(file, "{router} {iface}").map_err(|_| "steam_bypass_journal")?;
    Ok(true)
}

/// Remove the journaled Steam CM route if one exists. Never touches a
/// route we did not journal (manual / systemd-owned routes survive).
/// Called on reset/teardown and at startup as orphan recovery.
#[cfg(target_os = "linux")]
pub fn remove_steam_bypass() {
    let Ok(line) = fs::read_to_string(STEAM_STATE) else {
        return;
    };
    let _ = fs::remove_file(STEAM_STATE);
    let mut parts = line.split_whitespace();
    let (Some(router), Some(iface)) = (parts.next(), parts.next()) else {
        return;
    };
    // Delete the exact route we journalled (via/dev restrict the match), so
    // a foreign route for the same prefix is still left alone.
    let _ = ip(&["route", "del", STEAM_CM_PREFIX, "via", router, "dev", iface]);
}

fn privileged() -> bool {
    fs::read_to_string("/proc/self/status").ok().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|r| r.parse::<u32>().ok())
    }) == Some(0)
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
    let Ok(line) = fs::read_to_string(STATE) else {
        return;
    };
    let _ = fs::remove_file(STATE);
    let mut parts = line.split_whitespace();
    let (Some(remote), Some(iface)) = (parts.next(), parts.next()) else {
        return;
    };
    let Ok(remote) = remote.parse::<Ipv4Addr>() else {
        return;
    };
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
