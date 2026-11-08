//! Linux journal store — root-owned, persistent, atomic updates.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub struct JournalStore {
    dir: PathBuf,
}

impl JournalStore {
    pub fn open() -> io::Result<Self> {
        let dir = PathBuf::from("/var/lib/p2-middleware");

        // Create with restrictive permissions
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }

        // Verify permissions
        let meta = fs::metadata(&dir)?;
        if meta.permissions().mode() & 0o777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Journal directory has incorrect permissions",
            ));
        }

        Ok(Self { dir })
    }

    /// Get the path for the native gateway record
    pub(crate) fn native_path(&self) -> PathBuf {
        self.dir.join("native-gateway.json")
    }

    /// Acquire the exclusive owner lock, non-blocking.
    ///
    /// Returns a guard that holds an OS-level lock for as long as it lives;
    /// dropping the guard releases it. Contention surfaces as
    /// `ErrorKind::WouldBlock` rather than blocking, because the caller is
    /// either the single privileged helper (no contention expected) or a
    /// stale instance that should stand down rather than queue behind a
    /// session that may never finish.
    pub(crate) fn lock(&self) -> io::Result<JournalLock> {
        let path = self.dir.join("owner.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;
        // `.mode()` is masked by umask and applies only at creation; this
        // also repairs a lock file left readable by an older build.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        // `File::try_lock` / `TryLockError` are stable since Rust 1.89 — no
        // external crate needed for OS-backed locking.
        match file.try_lock() {
            Ok(()) => Ok(JournalLock { file }),
            Err(TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another process holds the journal lock",
            )),
            Err(TryLockError::Error(err)) => Err(err),
        }
    }
}

/// RAII guard for [`JournalStore::lock`].
///
/// The lock lives exactly as long as this value does — which is the property
/// the previous `-> io::Result<Self>` signature could not express: there was
/// no value whose lifetime meant "locked".
pub(crate) struct JournalLock {
    file: File,
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        // Closing the descriptor releases the lock anyway; unlocking
        // explicitly keeps the release point visible at the call site.
        let _ = self.file.unlock();
    }
}

/// Atomic file replacement using rename(2) - POSIX guarantees atomicity for same-filesystem renames
///
/// Durability note: rename survives a process crash but not necessarily a
/// power loss. If the journal must survive the latter, fsync the temporary
/// file before this call and fsync the containing directory after it.
pub fn atomic_replace(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to atomically replace {}: {}", to.display(), e),
        )
    })
}
