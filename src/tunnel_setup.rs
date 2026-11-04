//! Gameplay-tunnel host setup on Linux: the /32 alias for the remote PS3,
//! journalled for crash recovery.
//!
//! Interim privilege model: the coop script and headless flow run under
//! sudo, so euid-0 `ip` invocations succeed. In the unprivileged GUI flow
//! this module reports `tunnel_alias_requires_root` and the operator falls
//! back to the script (until the helper-side migration lands — see notes
//! at the bottom of this file).

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        fs,
        io::{self, Write},
        net::Ipv4Addr,
        process::Command,
    };

    pub const STATE: &str = "/run/p2-middleware-tunnel.alias";

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

    /// Idempotent: `ip addr replace` succeeds whether or not the alias
    /// exists. Journals the mutation AFTER the effect — the journal is
    /// advisory here (the alias is harmless without a running tunnel),
    /// unlike the Windows record whose ordering is a correctness
    /// requirement.
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

    /// Remove the journaled alias if one exists. Called on reset/teardown
    /// and at startup as orphan recovery (the crashed-last-session case).
    pub fn remove_journalled() {
        let Ok(line) = fs::read_to_string(STATE) else { return };
        let _ = fs::remove_file(STATE);
        let mut parts = line.split_whitespace();
        let (Some(remote), Some(iface)) = (parts.next(), parts.next()) else { return };
        let Ok(remote) = remote.parse::<Ipv4Addr>() else { return };
        // Only ever deletes OUR alias shape: a /32 we journalled. Absence
        // is fine.
        let _ = ip(&["addr", "del", &format!("{remote}/32"), "dev", iface]);
    }
}

#[cfg(target_os = "linux")]
pub use imp::{ensure_alias, remove_journalled, STATE};

// ---------------------------------------------------------------------------
// Windows stubs: the app crate also builds for x86_64-pc-windows-gnu. There,
// alias creation is owned by native_gateway.rs (which journals and renews
// its own addresses during route.apply), so these are inert on that target.
// Keeping the signatures identical means src/main.rs needs no cfg blocks
// around call sites — it just gets Err(None-ish) / a no-op, which its
// Linux-gated #[cfg(target_os = "linux")] call sites never hit anyway.
// (The main.rs splices gate with cfg, so these stubs are belt-and-braces
// for any future un-gated callers.)
#[cfg(not(target_os = "linux"))]
mod imp {
    use std::net::Ipv4Addr;

    #[allow(unused_variables)]
    pub fn ensure_alias(remote: Ipv4Addr, iface: &str) -> Result<(), &'static str> {
        // Alias creation on Windows is handled by the native gateway helper
        // during route.apply. Report absence rather than guessing a
        // PowerShell invocation here (the helper already owns journaling).
        Err("tunnel_alias_not_supported_on_this_platform")
    }

    pub fn remove_journalled() {}
}

#[cfg(not(target_os = "linux"))]
pub use imp::{ensure_alias, remove_journalled};

// ---------------------------------------------------------------------------
// MIGRATION NOTE (the genuine long-term home): once network_linux.rs is
// available, ensure_alias/remove_journalled move into the privileged Linux
// helper's session flow (journal + renew + restore alongside its existing
// state, exec'd via pkexec), exactly the shape of native_gateway.rs on
// Windows — and the euid check disappears because the helper is the only
// privileged actor. This module is deliberately structured (ensure /
// journalled / recover) so that migration is a move, not a rewrite.
//
// SCRATCH-SPACE NOTE: the original sketch carried journalled_age() and
// debug_stamp() helpers for diagnostics. They are omitted here — nothing
// currently calls them, and dead code with #[allow] is worse than absence.
// Re-add journalled_age() (file mtime vs now) if/when the UI surfaces
// "alias left over from N minutes ago".
// ---------------------------------------------------------------------------
