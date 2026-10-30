//! Linux elevation: run directly when privileged, otherwise via pkexec.

use std::io;
use std::process::{Child, Command, Stdio};

pub fn elevate(binary: &str, socket: &str, parent: u32) -> io::Result<Child> {
    if elevated() {
        run(binary, socket, parent, None)
    } else {
        run(binary, socket, parent, Some("pkexec"))
    }
}

fn run(binary: &str, socket: &str, parent: u32, launcher: Option<&str>) -> io::Result<Child> {
    let mut cmd = match launcher {
        Some(l) => {
            let mut c = Command::new(l);
            c.arg(binary);
            c
        }
        None => Command::new(binary),
    };
    cmd.args(["--pipe", socket, "--parent", &parent.to_string()])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
}

/// Root, or holding CAP_NET_ADMIN (bit 12 of the effective set).
pub fn elevated() -> bool {
    (unsafe { libc::geteuid() } == 0) || has_cap_net_admin()
}

fn has_cap_net_admin() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(line) = status.lines().find(|l| l.starts_with("CapEff:")) else {
        return false;
    };
    let Ok(mask) = u64::from_str_radix(line.trim_start_matches("CapEff:").trim(), 16) else {
        return false;
    };
    mask & (1 << 12) != 0
}
