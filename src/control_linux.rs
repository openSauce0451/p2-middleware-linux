//! Linux control transport: Unix domain sockets with `SO_PEERCRED` verification.
//!
//! Replaces the Windows named-pipe transport. The framing (`Lines`, `send`,
//! `Command`) is shared and unchanged; only the carrier and the peer checks differ.

use rand::RngCore;

use std::{
    io,
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

use tokio::net::{UnixListener, UnixStream};

pub use crate::control_common::{runtime, Lines, send};

/// `sun_path` is 108 bytes including the NUL terminator.
const MAX_PATH: usize = 100;

/// Per-user directory that only the invoking user (and root) can enter.
fn runtime_dir() -> io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(dir);
        if path.is_dir() {
            return Ok(path);
        }
    }
    // Fallback under /tmp. Ownership is verified so a squatted path is refused
    // rather than silently used.
    let uid = unsafe { libc::getuid() };
    let path = PathBuf::from(format!("/tmp/p2-middleware-{uid}"));
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            if !meta.is_dir() || meta.uid() != uid {
                return Err(io::Error::other("runtime_dir_untrusted"));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path)?;
        }
        Err(e) => return Err(e),
    }
    Ok(path)
}

/// Random, unguessable socket path for `parent`.
pub fn socket_path(parent: u32) -> io::Result<PathBuf> {
    let dir = runtime_dir()?;
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(format!("p2-{parent}-{suffix}.sock"));
    if path.as_os_str().len() > MAX_PATH {
        return Err(io::Error::other("socket_path_too_long"));
    }
    Ok(path)
}

pub fn validate_name(name: &str, parent: u32) -> io::Result<()> {
    let path = Path::new(name);
    let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
        return Err(io::Error::other("invalid_socket_path"));
    };
    let prefix = format!("p2-{parent}-");
    let valid = parent != 0
    && path.is_absolute()
    && file
    .strip_prefix(&prefix)
    .and_then(|s| s.strip_suffix(".sock"))
    .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    if valid {
        Ok(())
    } else {
        Err(io::Error::other("invalid_socket_path"))
    }
}

/// `(pid, uid, gid)` of the process at the far end of `stream`.
fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, u32, u32)> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
                         libc::SOL_SOCKET,
                         libc::SO_PEERCRED,
                         (&mut cred as *mut libc::ucred).cast(),
                         &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.pid as u32, cred.uid, cred.gid))
}

/// UID the helper must present, given our own privilege level.
fn expected_helper_uid() -> u32 {
    if crate::elevation_linux::elevated() {
        unsafe { libc::getuid() }
    } else {
        0
    }
}

fn verify_uid(stream: &UnixStream, expected: u32) -> io::Result<()> {
    let (_, uid, _) = peer_credentials(stream)?;
    if uid == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control_peer_mismatch",
        ))
    }
}

/// Helper side: the controller must be the process that launched us.
pub fn verify_server(stream: &UnixStream, parent: u32) -> io::Result<()> {
    let (pid, uid, _) = peer_credentials(stream)?;
    let expected_uid = std::env::var("PKEXEC_UID")
    .ok()
    .and_then(|v| v.parse::<u32>().ok());
    let uid_ok = expected_uid.is_none_or(|expected| expected == uid);
    if pid == parent && uid_ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control_peer_mismatch",
        ))
    }
}

/// Bound listener. Removes its socket file on drop.
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
}

impl Server {
    /// Wait for the elevated helper and verify its credentials.
    pub async fn connect(&self) -> io::Result<UnixStream> {
        let (stream, _) = self.listener.accept().await?;
        verify_uid(&stream, expected_helper_uid())?;
        Ok(stream)
    }

    /// Test hook: accept a peer with a chosen UID, so the happy path can be
    /// exercised without actually elevating.
    #[cfg(test)]
    async fn connect_as(&self, expected_uid: u32) -> io::Result<UnixStream> {
        let (stream, _) = self.listener.accept().await?;
        verify_uid(&stream, expected_uid)?;
        Ok(stream)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn server(name: &str) -> io::Result<Server> {
    validate_name(name, std::process::id())?;
    let path = PathBuf::from(name);
    // A stale socket from a crashed run is ours to replace; anything else is not.
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(&path)?,
        Ok(_) => return Err(io::Error::other("socket_path_occupied")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(Server { listener, path })
}

pub fn client(name: &str, parent: u32) -> io::Result<UnixStream> {
    validate_name(name, parent)?;
    let stream = std::os::unix::net::UnixStream::connect(name)?;
    stream.set_nonblocking(true)?;
    let stream = UnixStream::from_std(stream)?;
    verify_server(&stream, parent)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn socket_path_matches_validation() {
        let pid = std::process::id();
        let path = socket_path(pid).unwrap();
        let text = path.to_str().unwrap();
        assert!(validate_name(text, pid).is_ok());
        assert!(validate_name(text, pid + 1).is_err());
        assert!(validate_name("/etc/passwd", pid).is_err());
        assert!(validate_name("relative.sock", pid).is_err());
    }

    #[test]
    fn peer_credentials_report_self() {
        let runtime = runtime().unwrap();
        runtime.block_on(async {
            let (a, _b) = UnixStream::pair().unwrap();
            let (pid, uid, _) = peer_credentials(&a).unwrap();
            assert_eq!(pid, std::process::id());
            assert_eq!(uid, unsafe { libc::getuid() });
        });
    }

    #[test]
    fn framed_roundtrip() {
        let runtime = runtime().unwrap();
        runtime.block_on(async {
            let (mut a, mut b) = UnixStream::pair().unwrap();
            send(&mut a, &json!({"event": "hello"})).await.unwrap();
            let mut lines = Lines::default();
            let line = lines.next(&mut b).await.unwrap().unwrap();
            let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(value["event"], "hello");
        });
    }

    #[test]
    fn server_client_handshake() {
        let pid = std::process::id();
        let path = socket_path(pid).unwrap();
        let text = path.to_str().unwrap().to_owned();
        let uid = unsafe { libc::getuid() };

        let server_text = text.clone();
        let server_thread = std::thread::spawn(move || {
            let runtime = runtime().unwrap();
            runtime.block_on(async {
                let server = server(&server_text).unwrap();
                let mut stream = server.connect_as(uid).await.unwrap();
                let mut lines = Lines::default();
                let line = lines.next(&mut stream).await.unwrap().unwrap();
                let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
                assert_eq!(value["event"], "hello");
            })
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        let runtime = runtime().unwrap();
        runtime.block_on(async {
            let mut stream = client(&text, pid).unwrap();
            send(&mut stream, &json!({"event": "hello"})).await.unwrap();
        });

        server_thread.join().unwrap();
    }

    #[test]
    fn rejects_unelevated_helper() {
        // Meaningless when the test itself runs as root, since then the peer
        // legitimately is root.
        if unsafe { libc::getuid() } == 0 {
            return;
        }

        let pid = std::process::id();
        let path = socket_path(pid).unwrap();
        let text = path.to_str().unwrap().to_owned();

        let server_text = text.clone();
        let server_thread = std::thread::spawn(move || {
            let runtime = runtime().unwrap();
            runtime.block_on(async {
                let server = server(&server_text).unwrap();
                let result = server.connect().await;
                assert!(result.is_err(), "unprivileged peer must be rejected");
            })
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        let runtime = runtime().unwrap();
        runtime.block_on(async {
            // Connect and hold briefly so accept() returns, then let it drop.
            if let Ok(stream) = client(&text, pid) {
                drop(stream);
            }
        });

        server_thread.join().unwrap();
    }
}
