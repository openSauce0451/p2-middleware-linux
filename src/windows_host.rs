//! Windows host operations. System changes are only reachable through the gated route helper.
use crate::{config::Settings, network::hidden};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

// Input is bounded JSON on stdin, not interpolated into executable PowerShell text.
const SCRIPT: &str = include_str!("windows_host.ps1");
pub fn command(operation: &str, args: Value) -> io::Result<Value> {
    let script = if matches!(
        operation,
        "native_addresses_free" | "native_rule_add" | "native_rule_remove"
    ) {
        include_str!("native_gateway.ps1")
    } else {
        SCRIPT
    };
    execute_script(operation, args, script)
}
fn execute_script(operation: &str, args: Value, script: &str) -> io::Result<Value> {
    let payload = serde_json::to_vec(&json!({"operation":operation,"args":args}))?;
    if payload.len() > 16384 {
        return Err(io::Error::other("host_input_limit"));
    }
    let encoded = STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let powershell = crate::network::system_powershell()?;
    let modules = powershell
        .parent()
        .ok_or_else(|| io::Error::other("system_shell_path"))?
        .join("Modules");
    let mut cmd = Command::new(&powershell);
    cmd.env("PSModulePath", modules);
    cmd.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        &encoded,
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    hidden(&mut cmd);
    let mut child = cmd.spawn()?;
    if let Err(e) = child.stdin.take().unwrap().write_all(&payload) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    let output = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        output.take(65537).read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(e);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "host_command_timeout",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    };
    let bytes = reader
        .join()
        .map_err(|_| io::Error::other("host_output_thread"))??;
    if !status.success() || bytes.len() > 65536 {
        return Err(io::Error::other("host_command_failed"));
    }
    serde_json::from_slice(&bytes).map_err(|_| io::Error::other("host_output_format"))
}

pub struct JournalStore {
    root: PathBuf,
    _owner: File,
}
impl JournalStore {
    pub fn open() -> io::Result<Self> {
        let value = command("secure_store", json!({}))?;
        let root = PathBuf::from(
            value
                .as_str()
                .ok_or_else(|| io::Error::other("store_path"))?,
        );
        Self::lock(root)
    }
    fn lock(root: PathBuf) -> io::Result<Self> {
        reject_reparse(&root)?;
        let lock = root.join("owner.lock");
        reject_reparse_if_exists(&lock)?;
        let owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(lock)?;
        Ok(Self {
            root,
            _owner: owner,
        })
    }
    pub(crate) fn native_path(&self) -> PathBuf {
        self.root.join("native-gateway.json")
    }
}
fn reject_reparse(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_attributes() & 0x400 != 0 {
        Err(io::Error::other("reparse_point_rejected"))
    } else {
        Ok(())
    }
}
fn reject_reparse_if_exists(path: &Path) -> io::Result<()> {
    match reject_reparse(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}
pub(crate) fn atomic_replace(from: &Path, to: &Path) -> io::Result<()> {
    let from: Vec<u16> = from.as_os_str().encode_wide().chain([0]).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain([0]).collect();
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8)
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub use crate::request::Request;

pub fn elevated() -> bool {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    unsafe {
        let mut raw = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) == 0 {
            return false;
        }
        let token = OwnedHandle::from_raw_handle(raw);
        let mut value: TOKEN_ELEVATION = std::mem::zeroed();
        let mut returned = 0;
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut value as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        ) != 0
            && value.TokenIsElevated != 0
    }
}
