use crate::{config::Settings, network::hidden};
use p2_bridge_core::gateway::Authorization;
use std::{
    io::{self, BufRead, Write},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
};
use zeroize::Zeroizing;
use base64::{engine::general_purpose::STANDARD, Engine};

pub struct Bridge {
    child: Child,
    pub events: Receiver<String>,
    ready: Arc<AtomicBool>,
    #[cfg(windows)]
    _job: Job,
}
impl Bridge {
    pub fn start(settings: &Settings, auth: &Authorization) -> io::Result<Self> {
        let plan = settings.validate().map_err(io::Error::other)?;
        auth.validate()?;
        if matches!(auth.cm.ip(), std::net::IpAddr::V4(ip) if p2_bridge_core::legacy_cm::LEGACY_CM.contains(&ip))
        {
            return Err(io::Error::other("upstream_overlaps_native_addresses"));
        }

        // ---------------------------------------------------------------------------
        // Tunnel integration.
        //
        // `settings.tunnel` is Option<TunnelSettings>. Three cases:
        //   * None               -> no tunnel flags; serve() runs exactly as before.
        //   * Some(valid)        -> the five --tunnel-* flags are appended below.
        //   * Some(invalid)      -> hard error. A misconfigured tunnel that silently
        //                           disables itself would let the session proceed and
        //                           die at the gameplay transition - the exact crash
        //                           this whole feature exists to fix. Fail loudly
        //                           at start instead.
        //
        // The key is passed as the base64 STRING (stored in settings), not decoded
        // here: decoding is serve()'s job, where bridge-core already depends on
        // base64. This keeps the app crate free of the dependency. tunnel_plan()
        // has already verified the string decodes to 32 bytes, so serve() will
        // accept it.
        //
        // SECURITY TRADEOFF (flagged, deliberate): the key rides argv, which is
        // visible in process listings on this machine. The authorization token
        // deliberately uses the private stdin pipe instead. Mitigations: the key
        // is a rotatable session PSK scoped to gameplay traffic, not an account
        // credential, and both endpoints are the players' own PCs. Migrating it
        // into the stdin payload would require widening bridge-core's
        // Authorization struct - worth doing before any release, acceptable for
        // live-testing now.
        // ---------------------------------------------------------------------------
        let tunnel_args: Vec<String> = match &settings.tunnel {
            None => vec![],
            Some(_) => {
                let tunnel = settings.tunnel_plan()
                .map_err(|_| io::Error::other("tunnel_settings_invalid"))?;
                // Re-validate against the LAN plan we already computed: the
                // remote PS3 must not collide with our own network devices.
                if tunnel.remote_ps3 == plan.ps3 || tunnel.remote_ps3 == plan.pc {
                    return Err(io::Error::other("tunnel_remote_overlaps_local"));
                }
                let mut args = vec![
                    "--tunnel-ps3".to_string(),
                    tunnel.remote_ps3.to_string(),
                    "--tunnel-port".to_string(),
                    tunnel.remote_port.to_string(),
                    "--tunnel-wire".to_string(),
                    tunnel.wire_port.to_string(),
                    "--tunnel-peer".to_string(),
                    tunnel.wire_peer.to_string(),
                    "--tunnel-key".to_string(),
                    STANDARD.encode(tunnel.key),
                ];
                // Optional port band (Rev 3 tunnel). Absent = legacy single-port
                // behaviour; never part of the all-or-nothing flag set.
                if let Some((first, last)) = tunnel.port_band {
                    args.push("--tunnel-band".to_string());
                    args.push(format!("{first}-{last}"));
                }
                args
            }
        };

        // Platform-aware executable name
        #[cfg(windows)]
        let bridge_name = "p2-bridge.exe";
        #[cfg(not(windows))]
        let bridge_name = "p2-bridge";

        let executable = std::env::current_exe()?.with_file_name(bridge_name);

        let mut command = Command::new(executable);
        command.args([
            "serve",
            "--bind",
            "0.0.0.0:27017",
            "--native-cm",
            "true",
            "--peer",
            &plan.ps3.to_string(),
                     "--seconds",
                     "86400",
                     "--sessions",
                     "1000",
                     "--search-platform",
                     if settings.crossplay {
                         "any"
                     } else {
                         "preserve"
                     },
                     "--search-distance",
                     "worldwide",
                     "--advertise-platform",
                     if settings.crossplay {
                         "default"
                     } else {
                         "preserve"
                     },
        ]);
        if !tunnel_args.is_empty() {
            command.args(&tunnel_args);
        }
        command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        hidden(&mut command);
        #[cfg(windows)]
        let job = Job::new()?;
        let mut child = command.spawn()?;
        #[cfg(windows)]
        if let Err(e) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        let payload = Zeroizing::new(serde_json::to_vec(auth)?);
        let sent = (|| -> io::Result<()> {
            let mut input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("Missing private pipe"))?;
            input.write_all(&payload)?;
            input.write_all(b"\n")
        })();
        if let Err(e) = sent {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        let stderr = child.stderr.take().unwrap();
        let (tx, events) = mpsc::channel();
        let ready = Arc::new(AtomicBool::new(false));
        let worker_ready = ready.clone();
        thread::spawn(move || {
            let debug = std::env::var_os("P2_DEBUG_BRIDGE").is_some();
            for line in io::BufReader::new(stderr).lines().map_while(Result::ok) {
                if debug {
                    eprintln!("[bridge-raw] {line}");
                }
                if serde_json::from_str::<serde_json::Value>(&line)
                    .ok()
                    .is_some_and(|v| v["event"] == "listening")
                    {
                        worker_ready.store(true, Ordering::Release);
                    }
                    if let Some(message) = friendly_event(&line) {
                        if tx.send(message.into()).is_err() {
                            break;
                        }
                    }
            }
        });
        Ok(Self {
            child,
            events,
            ready,
            #[cfg(windows)]
            _job: job,
        })
    }
    pub fn finished(&mut self) -> io::Result<bool> {
        self.child.try_wait().map(|s| s.is_some())
    }
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = child_wait(&mut self.child);
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop();
    }
}

// Small helper so stop() reads like the original despite the linter preferring
// let _ = self.child.wait() with the field directly.
#[allow(dead_code)]
fn child_wait(child: &mut Child) -> std::process::ExitStatus {
    child.wait().unwrap_or_else(|_| {
        // A wait failure after kill is uninformative; fabricate a benign status.
        std::process::ExitStatus::default()
    })
}

// Platform-aware error messages
pub fn launch_error_message(error: &io::Error) -> &'static str {
    // Tunnel configuration errors have distinct, actionable meanings and no
    // OS error code; surface them by the app-level string we set.
    match error.raw_os_error() {
        None if error.to_string() == "tunnel_settings_invalid" => {
            return "The gameplay tunnel settings are incomplete or invalid. Review the remote PS3 address, port, peer endpoint and key.";
        }
        None if error.to_string() == "tunnel_remote_overlaps_local" => {
            return "The remote PS3 address collides with this network. Check which PS3 is which.";
        }
        _ => {}
    }
    let code = error.raw_os_error();

    #[cfg(windows)]
    {
        match code {
            Some(225 | 226) => "Windows security blocked the bridge file. Review the detection in Windows Security; the app did not change your protections.",
            Some(577) => "Windows could not verify the bridge image. Check the build and signature before retrying.",
            Some(5) => "Windows denied access to the bridge. This can be a permission or security restriction.",
            Some(2 | 3) => "The bridge executable is missing. Keep p2-bridge.exe beside the desktop app; check whether it was quarantined.",
            _ => "Could not start the bridge. Check the selected address, port and companion executable.",
        }
    }

    #[cfg(not(windows))]
    {
        match code {
            Some(2) => "The bridge executable is missing or has incorrect permissions. Check that p2-bridge exists next to the middleware binary.",
            Some(13) => "Permission denied. Ensure p2-bridge has execute permission: chmod +x p2-bridge",
            Some(8) => "Exec format error. Verify p2-bridge is built for your architecture.",
            _ => "Could not start the bridge. Check that p2-bridge exists and is executable.",
        }
    }
}

fn friendly_event(line: &str) -> Option<&'static str> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    match value.get("event")?.as_str()? {
        "listening" => Some("Bridge is listening."),
        "ps3_connected" => Some("The PS3 connected to the bridge."),
        "official_login_result" => Some(if value["data"]["eresult"] == 1 {
            "Steam accepted the game login."
        } else {
            "Steam declined the game login."
        }),
        "session_end" => Some("The console connection ended."),
        "fatal" => Some("The bridge could not continue. Check the selected address and port."),
        "stopped" => Some("The bridge session finished."),
        // Tunnel lifecycle surfacing. Deliberately kept minimal: the
        // per-datagram events (tunnel_in/tunnel_out, wire rejects) stay in the
        // P2_DEBUG_BRIDGE raw dump only, matching how the UDP relay's
        // per-flow events are treated.
        "tunnel_started" => Some("The gameplay tunnel is connected."),
        "tunnel_alias_absent" => Some("The tunnel could not bind the remote PS3 address. Create the alias, then retry."),
        _ => None,
    }
}

#[cfg(windows)]
struct Job(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl Job {
    fn new() -> io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::*;
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self(handle);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                                    std::mem::size_of_val(&limits) as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }
    fn assign(&self, child: &Child) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        let ok = unsafe {
            windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(
                self.0,
                child.as_raw_handle(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
