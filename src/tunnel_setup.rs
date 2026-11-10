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

// REV 3 — TPROXY divert for the Linux catch-all (catch_all.rs).
//
// catch_all.rs binds a transparent socket on catch_all_port and waits for
// datagrams the kernel diverts to it. Without the mangle TPROXY rule (plus
// the fwmark policy route and local route table), NOTHING is ever diverted:
// probes to unbound alias ports fall through to the kernel's ICMP
// port-unreachable (observed live: console Binding Request to
// 10.0.0.182:57090 -> ICMP type 3 code 3), the peer console reads every
// candidate as refused, and the lobby->gameplay transition kicks both
// players. This revision installs the divert triplet with the same
// lifecycle discipline as the alias and the CM route: idempotent ensure,
// journal-after-effect, teardown + orphan recovery via the journal.
//
// Mark 0x1 verified clear of wg-quick/ProtonVPN's 0xea13b2c fwmark usage.
// Table 100 is the conventional TPROXY local table; it is created empty
// and harmless while the ip rule does not reference it.
#[cfg(target_os = "linux")]
pub const TPROXY_STATE: &str = "/run/p2-middleware-tproxy.divert";
#[cfg(target_os = "linux")]
const TPROXY_MARK: &str = "0x1";
#[cfg(target_os = "linux")]
const TPROXY_TABLE: &str = "100";

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

/// Like `ip`, but for iptables; same failure-reporting shape.
#[cfg(target_os = "linux")]
fn iptables(args: &[&str]) -> io::Result<()> {
    let out = Command::new("iptables").args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "iptables {}: {}",
            args.join(" "),
                                     String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// True when the mangle rule already exists (iptables -C exits 0/1/2; both
/// non-zero statuses read as "absent" here — a malformed rule string would
/// also read absent, but the caller then fails loudly on the -A).
#[cfg(target_os = "linux")]
fn tproxy_rule_exists(rule: &[&str]) -> bool {
    let mut args: Vec<&str> = vec!["-t", "mangle", "-C", "PREROUTING"];
    args.extend_from_slice(rule);
    Command::new("iptables")
    .args(&args)
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false)
}

/// True when the fwmark policy rule exists: `ip rule show` prints
/// "<priority>: from all fwmark 0x1 lookup 100".
#[cfg(target_os = "linux")]
fn tproxy_iprule_exists() -> bool {
    Command::new("ip")
    .args(["rule", "show"])
    .output()
    .map(|o| {
        String::from_utf8_lossy(&o.stdout)
        .lines()
        .any(|l| l.contains("fwmark") && l.contains(TPROXY_MARK) && l.contains("lookup")
        && l.contains(TPROXY_TABLE))
    })
    .unwrap_or(false)
}

/// True when table 100 already holds the catch-all local route. `ip`
/// normalizes 0.0.0.0/0 to "default" in its output, so accept both
/// spellings; matching either proves the route is installed.
#[cfg(target_os = "linux")]
fn tproxy_route_exists() -> bool {
    Command::new("ip")
    .args(["route", "show", "table", TPROXY_TABLE])
    .output()
    .map(|o| {
        let stdout = String::from_utf8_lossy(&o.stdout);
        stdout.contains("local default") || stdout.contains("local 0.0.0.0/0")
    })
    .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// REV 3 — TPROXY divert triplet (public API for the p2-route helper).
//
// Call `ensure_tproxy_divert` from the helper's activation flow, AFTER
// ensure_alias succeeds (a divert without the alias catches traffic that
// could never be answered). Port is the catch_all_port from the tunnel
// settings (config defaults it to 27051). Failure must roll back the alias
// and report activation_failed — the same all-or-nothing discipline as the
// rest of the helper. On failure the journal is NOT written, so recovery
// never tries to remove a half-installed divert.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn ensure_tproxy_divert(
    alias: Ipv4Addr,
    iface: &str,
    port: u16,
) -> Result<(), &'static str> {
    if !privileged() {
        return Err("tproxy_requires_root");
    }
    let dst = alias.to_string();
    let on_port = port.to_string();
    let rule: Vec<&str> = vec![
        "-i", iface, "-p", "udp", "-d", &dst,
        "-j", "TPROXY", "--on-port", &on_port, "--tproxy-mark", TPROXY_MARK,
    ];

    // 1. mangle divert rule (idempotent via -C).
    if !tproxy_rule_exists(&rule) {
        let mut args: Vec<&str> = vec!["-t", "mangle", "-A", "PREROUTING"];
        args.extend_from_slice(&rule);
        iptables(&args).map_err(|_| "tproxy_rule_create")?;
    }

    // 2. fwmark policy rule: diverted packets route via the local table.
    // EEXIST from a leftover/concurrent rule is only an error if the rule
    // really is absent afterwards; `ip` prints it either way.
    if !tproxy_iprule_exists() {
        if ip(&["rule", "add", "fwmark", TPROXY_MARK, "lookup", TPROXY_TABLE,
            "priority", "100"]).is_err()
            && !tproxy_iprule_exists()
            {
                return Err("tproxy_rule_route_create");
            }
    }

    // 3. local route in the policy table. `replace` is idempotent: it
    // succeeds whether the route already exists (an unjournaled orphan
    // from a crashed session) or not, and normalizes `local default` /
    // `local 0.0.0.0/0` spelling mismatches away. Failure here is a
    // genuine capability problem, not stale state.
    ip(&["route", "replace", "local", "0.0.0.0/0", "dev", "lo",
       "table", TPROXY_TABLE])
    .map_err(|_| "tproxy_local_route_create")?;

    // Post-write verification: prove the triplet is live, not assumed.
    if !tproxy_route_exists() {
        // The replace succeeded but the checker disagrees: the checker's
        // expected shape does not match what `ip` persists. Surface that
        // distinctly instead of looping on a phantom failure.
        eprintln!("[headless] tproxy: route replace ok but tproxy_route_exists() false; checker/glyph mismatch");
        return Err("tproxy_route_verify");
    }

    // Journal AFTER all effects succeeded. Advisory: worst case recovery
    // runs deletes on absent objects, which are tolerated no-ops below.
    let mut file = fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .open(TPROXY_STATE)
    .map_err(|_| "tproxy_journal")?;
    writeln!(file, "{alias} {iface} {port}").map_err(|_| "tproxy_journal")?;
    Ok(())
}

/// Remove the journaled TPROXY divert if one exists. Deletes exactly the
/// triplet shape this module installs; absent objects are fine (the -D and
// del variants exit non-zero on absence — ignored, matching the alias
/// recovery contract). Called on reset/teardown and at startup as orphan
/// recovery, next to remove_journalled().
#[cfg(target_os = "linux")]
pub fn remove_journalled_tproxy() {
    let Ok(line) = fs::read_to_string(TPROXY_STATE) else {
        return;
    };
    let _ = fs::remove_file(TPROXY_STATE);
    let mut parts = line.split_whitespace();
    let (Some(alias), Some(iface), Some(port)) =
    (parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    let Ok(alias_ip) = alias.parse::<Ipv4Addr>() else {
        return;
    };
    let _dst = alias_ip.to_string();
    let rule: Vec<String> = vec![
        "-i".into(), iface.into(), "-p".into(), "udp".into(),
        "-d".into(), alias.into(),
        "-j".into(), "TPROXY".into(),
        "--on-port".into(), port.into(),
        "--tproxy-mark".into(), TPROXY_MARK.into(),
    ];
    let mut args: Vec<String> = vec![
        "-t".into(), "mangle".into(), "-D".into(), "PREROUTING".into(),
    ];
    args.extend(rule);
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let _ = iptables(&refs);
    let _ = ip(&["rule", "del", "fwmark", TPROXY_MARK, "lookup", TPROXY_TABLE]);
    let _ = ip(&["route", "del", "local", "0.0.0.0/0", "dev", "lo",
               "table", TPROXY_TABLE]);
}

/// Diagnostics: is the divert triplet fully installed right now? Mirrors
/// steam_bypass_active(); the helper can log a state snapshot at startup.
#[cfg(target_os = "linux")]
pub fn tproxy_divert_active() -> bool {
    let args: Vec<&str> = vec!["-t", "mangle", "-S", "PREROUTING"];
    let listing = Command::new("iptables")
    .args(&args)
    .output()
    .ok()
    .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    .unwrap_or_default();
    listing.contains("TPROXY") && tproxy_iprule_exists() && tproxy_route_exists()
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
