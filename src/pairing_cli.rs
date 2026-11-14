// =============================================================================
// /src/pairing_cli.rs   (app crate = p2-middleware)
//
// App-level glue: console attachment, local-network discovery, and merging
// the bridge-core PairingOutcome into the REAL Settings struct — written
// through serde so deny_unknown_fields can never bite, and BYPASSING
// Settings::save() because ps3_ip is deliberately still blank at pairing
// time (it is filled by the existing confirm()/auto-discovery flow).
// =============================================================================

// -----------------------------------------------------------------------------
// Console attachment — REQUIRED on Windows because main.rs builds with
// `windows_subsystem = "windows"`: no console exists, so eprintln!/stdin
// would vanish. Attach to the parent's console when launched from a
// terminal; allocate one otherwise.
// -----------------------------------------------------------------------------

#[cfg(windows)]
pub fn attach_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process_id: usize) -> i32;
        fn AllocConsole() -> i32;
    }
    unsafe {
        const ATTACH_PARENT_PROCESS: usize = usize::MAX;
        // Prefer the terminal the user launched from; else open a new console.
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            let _ = AllocConsole();
        }
    }
}

#[cfg(not(windows))]
pub fn attach_console() {
    // POSIX: stdout/stderr already work in headless and GUI-less modes.
}

// -----------------------------------------------------------------------------
// Local network context for alias selection + Settings fill-in.
// prefix_len is taken from existing Settings when valid, else 24.
// -----------------------------------------------------------------------------

use p2_bridge_core::pairing::{self, PairingOutcome};
use p2_middleware::config::{PortBand, Settings, TunnelSettings};
use std::net::Ipv4Addr;

fn local_context(settings: &Settings) -> (Ipv4Addr, u8, Option<Ipv4Addr>) {
    let prefix = if (8..=30).contains(&settings.prefix_len) {
        settings.prefix_len
    } else {
        24
    };
    let known_pc: Option<Ipv4Addr> = settings.pc_ip.trim().parse().ok();
    let pc = match known_pc {
        Some(ip) => ip, // stored config wins: it survived validate() before
        None => pairing::local_ipv4()
        .expect("cannot determine local IPv4; set pc_ip manually"),
    };
    let router = pairing::default_gateway().ok();
    (pc, prefix, router)
}

/// `pair-host` subcommand handler. Returns a process exit code.
pub fn run_pair_host() -> i32 {
    attach_console();
    let settings = Settings::load().unwrap_or_default();
    let (pc, prefix, router) = local_context(&settings);
    match pairing::pair_host(pc, prefix) {
        Ok(outcome) => match merge_into_settings(outcome, pc, prefix, router) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("pairing succeeded but settings could not be written: {e}");
                2
            }
        },
        Err(e) => {
            eprintln!("pairing failed: {e}");
            1
        }
    }
}

/// `pair-join <host-ip> [<code>]` subcommand handler. The code may be passed
/// as argv (preferred for the no-console Windows path) or typed interactively.
pub fn run_pair_join(host: &str, code: Option<&str>) -> i32 {
    attach_console();
    let settings = Settings::load().unwrap_or_default();
    let (pc, prefix, router) = local_context(&settings);
    let host_ip: std::net::IpAddr = match host.parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("'{host}' is not an IP address");
            return 1;
        }
    };
    let outcome = match pairing::pair_join(host_ip, pc, prefix, code) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("pairing failed: {e}");
            return 1;
        }
    };
    match merge_into_settings(outcome, pc, prefix, router) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("pairing succeeded but settings could not be written: {e}");
            2
        }
    }
}

/// Merge the outcome into Settings and write the TOML directly.
/// Deliberately NOT Settings::save(): ps3_ip may still be blank (filled by
/// the existing confirm() auto-discovery), which validate() would reject.
fn merge_into_settings(
    outcome: PairingOutcome,
    pc: Ipv4Addr,
    prefix: u8,
    router: Option<Ipv4Addr>,
) -> Result<(), std::io::Error> {
    let mut settings = Settings::load().unwrap_or_default();

    // Local network fields: never clobber a user-entered PS3 address; the
    // gateway gets the discovered router only when none is stored.
    settings.pc_ip = pc.to_string();
    settings.prefix_len = prefix;
    if settings.router_ip.trim().parse::<Ipv4Addr>().is_err() {
        settings.router_ip = router
        .map(|r| r.to_string())
        .unwrap_or_default(); // validate() will prompt later
    }

    settings.tunnel = Some(TunnelSettings {
        remote_ps3: outcome.tunnel_alias.to_string(),
                           remote_port: outcome.remote_port,
                           wire_port: 27050,
                           wire_peer: outcome.wire_peer,
                           key: outcome.key_b64,
                           port_band: Some(PortBand {
                               first: 61700,
                               last: 61800,
                           }),
                           catch_all_port: Some(27051),
                           advertised_port: outcome.advertised_port,
                           stun_advertise: None, // Fix 2c pin stays auto-detect after pairing
    });

    let path = Settings::path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let bak = path.with_extension("toml.bak");
        let _ = std::fs::copy(&path, &bak);
    }
    let text = toml::to_string_pretty(&settings)
    .map_err(|_| std::io::Error::other("Could not encode settings"))?;
    std::fs::write(&path, text)?;

    eprintln!(
        "Paired! settings written to {} ; key tag {} (compare by voice for extra paranoia)",
              path.display(),
              outcome.pairing_tag
    );
    Ok(())
}
