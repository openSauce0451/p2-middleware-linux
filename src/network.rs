use serde::Deserialize;
use std::{
    io,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Deserialize)]
pub struct Adapter {
    #[serde(default)]
    pub index: u32,
    pub name: String,
    pub address: String,
    pub prefix: u8,
    pub gateway: String,
}
/// Fixed read-only query; no user input is interpolated into PowerShell.
pub fn adapters() -> io::Result<Vec<Adapter>> {
    let script = r#"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); $rows=@(Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway } | ForEach-Object { $c=$_; foreach($a in $c.IPv4Address) { [pscustomobject]@{index=$c.InterfaceIndex;name=$c.InterfaceAlias;address=$a.IPAddress;prefix=$a.PrefixLength;gateway=([string]$c.IPv4DefaultGateway[0].NextHop)} } }); ConvertTo-Json -InputObject $rows -Compress"#;
    let mut command = Command::new(system_powershell()?);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    hidden(&mut command);
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Network discovery timed out.",
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return Err(io::Error::other("Network discovery failed."));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| io::Error::other("Network discovery returned an unexpected format."))
}
pub fn hidden(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    #[cfg(not(windows))]
    let _ = command;
}

/// Resolve the OS executable without trusting PATH, the package folder or environment overrides.
pub fn system_powershell() -> io::Result<std::path::PathBuf> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let mut buffer = vec![0u16; 32768];
        let length = unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        } as usize;
        if length == 0 || length >= buffer.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(
            std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length]))
                .join("WindowsPowerShell/v1.0/powershell.exe"),
        )
    }
    #[cfg(not(windows))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows required",
        ))
    }
}

/// Select only a unique LAN containing the console; never guess among VPNs/adapters.
pub fn for_console<'a>(adapters: &'a [Adapter], ps3: &str) -> Result<&'a Adapter, &'static str> {
    let candidates: Vec<_> = adapters
        .iter()
        .filter(|a| {
            a.index != 0
                && crate::config::Settings {
                    ps3_ip: ps3.into(),
                    pc_ip: a.address.clone(),
                    router_ip: a.gateway.clone(),
                    prefix_len: a.prefix,
                    crossplay: true,
                    tunnel: None,
                }
                .validate()
                .is_ok()
        })
        .collect();
    match candidates.as_slice() {
        [adapter] => Ok(adapter),
        [] => Err("Enter a PS3 address on the same home network as this PC."),
        _ => Err("More than one network matches. Select the home-network adapter below."),
    }
}
