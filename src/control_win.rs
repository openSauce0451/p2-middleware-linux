//! Windows transport: named pipes with DACL + peer verification.
//!
//! Mirrors control_linux.rs: same framing (`Lines`, `send`, `Command` via
//! control_common), same name grammar (`p2-<parent>-<32 hex>`), same rule
//! that a peer is trusted only when the kernel reports the exact process
//! identity we expect.
//!
//!   Linux                             Windows
//!   -------------------------------   --------------------------------------
//!   Unix socket in a 0700 per-user    \\.\pipe\p2-<pid>-<rand>, created
//!   directory                          first-instance-only (squatters fail)
//!                                     under a DACL admitting only SYSTEM,
//!                                     Administrators and the current user
//!   SO_PEERCRED uid == 0 (root        GetNamedPipeClientProcessId == the
//!   helper)                            exact PID UAC launched for us
//!   SO_PEERCRED pid == parent         GetNamedPipeServerProcessId == the
//!                                     pid passed to us via --parent
//!
//! Remote clients are rejected (tokio's PIPE_REJECT_REMOTE_CLIENTS default).

use rand::RngCore;
use std::{io, os::windows::io::AsRawHandle, ptr};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, HLOCAL, ERROR_PIPE_BUSY},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER, SECURITY_ATTRIBUTES,
    },
    System::{
        Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

pub use crate::control_common::{runtime, Lines, send};

fn bad_name() -> io::Error {
    io::Error::other("invalid_pipe_name")
}

/// Random, unguessable pipe name for `parent`.
pub fn pipe_name(parent: u32) -> String {
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!(r"\\.\pipe\p2-{parent}-{suffix}")
}

/// The grammar has no quotes, spaces or shell metacharacters, so the name is
/// safe to pass through ShellExecuteEx as `--pipe <name>`.
pub fn validate_name(name: &str, parent: u32) -> io::Result<()> {
    const ROOT: &str = r"\\.\pipe\";
    let file = name.strip_prefix(ROOT).ok_or_else(bad_name)?;
    let prefix = format!("p2-{parent}-");
    let valid = parent != 0
    && file.len() == prefix.len() + 32
    && file.starts_with(&prefix)
    && file[prefix.len()..].bytes().all(|b| b.is_ascii_hexdigit());
    if valid {
        Ok(())
    } else {
        Err(bad_name())
    }
}

/// SID string of the current token's user, for the pipe DACL.
fn user_sid() -> io::Result<String> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle::from_raw_handle(token);
        let mut length = 0;
        GetTokenInformation(token.as_raw_handle(), TokenUser, ptr::null_mut(), 0, &mut length);
        if length == 0 {
            return Err(io::Error::other("token_query_failed"));
        }
        let mut buffer = vec![0u8; length as usize];
        if GetTokenInformation(
            token.as_raw_handle(),
                               TokenUser,
                               buffer.as_mut_ptr().cast(),
                               length,
                               &mut length,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut wide: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut wide) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0;
        while *wide.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(wide, len));
        LocalFree(wide as HLOCAL);
        Ok(text)
    }
}

/// SECURITY_ATTRIBUTES admitting only SYSTEM, Administrators and the current
/// user. Freed on drop; the kernel copies the descriptor at create time.
struct PipeSecurity {
    attributes: SECURITY_ATTRIBUTES,
    descriptor: *mut core::ffi::c_void,
}

impl PipeSecurity {
    fn new() -> io::Result<Self> {
        let sid = user_sid()?;
        let mut sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})")
        .encode_utf16()
        .chain([0])
        .collect();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                                                                 SDDL_REVISION_1,
                                                                 &mut descriptor,
                                                                 ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            attributes: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
           lpSecurityDescriptor: descriptor,
           bInheritHandle: 0,
            },
            descriptor,
        })
    }
    fn raw(&mut self) -> *mut core::ffi::c_void {
        &mut self.attributes as *mut SECURITY_ATTRIBUTES as *mut core::ffi::c_void
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        unsafe { LocalFree(self.descriptor as HLOCAL) };
    }
}

/// First-instance-only listener. An existing pipe with this name fails
/// creation loudly instead of being silently shared. The returned server's
/// inherent `async fn connect(&mut self)` waits for the helper, after which
/// the caller runs `verify_client` before sending anything.
pub fn server(name: &str) -> io::Result<NamedPipeServer> {
    validate_name(name, std::process::id())?;
    let mut security = PipeSecurity::new()?;
    // SAFETY: `security` outlives this call, and the kernel copies the
    // security descriptor at pipe creation, so the freed-on-drop original
    // never outlives the descriptor the pipe actually uses.
    let pipe = unsafe {
        ServerOptions::new()
        .first_pipe_instance(true)
        // Default, stated for clarity: remote clients are refused.
        .reject_remote_clients(true)
        .create_with_security_attributes_raw(name, security.raw())
    }?;
    Ok(pipe)
}

/// Controller side: the connected client must be the exact process that UAC
/// launched for us, identified by the kernel — not a name we parsed.
pub fn verify_client(pipe: &NamedPipeServer, process: u32) -> io::Result<()> {
    let mut client = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut client) } == 0 {
        return Err(io::Error::last_os_error());
    }
    check(client, process)
}

/// Helper side: the pipe must be served by the process that launched us.
pub fn verify_server(pipe: &NamedPipeClient, parent: u32) -> io::Result<()> {
    let mut server = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server) } == 0 {
        return Err(io::Error::last_os_error());
    }
    check(server, parent)
}

fn check(found: u32, expected: u32) -> io::Result<()> {
    if found == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control_peer_mismatch",
        ))
    }
}

/// Helper side: connect to the controller's pipe and verify the far end is
/// the launching process (the pid from `--parent`).
pub fn client(name: &str, parent: u32) -> io::Result<NamedPipeClient> {
    validate_name(name, parent)?;
    // The instance is reserved for us; tolerate a busy instance briefly in
    // case the controller has not finished creating it yet.
    for _ in 0..100 {
        match ClientOptions::new().open(name) {
            Ok(pipe) => {
                verify_server(&pipe, parent)?;
                return Ok(pipe);
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("pipe_unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pipe_name_matches_validation() {
        let pid = std::process::id();
        let name = pipe_name(pid);
        assert!(validate_name(&name, pid).is_ok());
        assert!(validate_name(&name, pid + 1).is_err());
        assert!(validate_name(r"\\.\pipe\other", pid).is_err());
        assert!(validate_name("p2-x.sock", pid).is_err());
        assert!(validate_name("", pid).is_err());
    }

    #[test]
    fn framed_roundtrip() {
        let pid = std::process::id();
        let name = pipe_name(pid);
        let server_name = name.clone();
        let server_thread = std::thread::spawn(move || {
            let runtime = runtime().unwrap();
            runtime.block_on(async {
                let mut server = server(&server_name).unwrap();
                server.connect().await.unwrap();
                // The client is this very test process.
                verify_client(&server, pid).unwrap();
                let mut lines = Lines::default();
                let line = lines.next(&mut server).await.unwrap().unwrap();
                let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
                assert_eq!(value["event"], "hello");
            })
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        let runtime = runtime().unwrap();
        runtime.block_on(async {
            let mut pipe = client(&name, pid).unwrap();
            send(&mut pipe, &json!({"event": "hello"})).await.unwrap();
        });
        server_thread.join().unwrap();
    }
}
