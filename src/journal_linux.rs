//! Linux journal store - root-owned, persistent, atomic updates.

use std::{
    fs,
    io,
    os::unix::fs::PermissionsExt,
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

    /// Create a lock file (simple existence check, no blocking)
    pub(crate) fn lock(&self) -> io::Result<Self> {
        let lock = self.dir.join("owner.lock");
        if lock.exists() {
            fs::File::open(&lock)?;
        } else {
            fs::File::create(&lock)?;
            fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { dir: self.dir.clone() })
    }
}

/// Atomic file replacement using rename(2) - POSIX guarantees atomicity for same-filesystem renames
pub fn atomic_replace(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to).map_err(|e| {
        io::Error::new(
            e.kind(),
                       format!("Failed to atomically replace {}: {}", to.display(), e),
        )
    })
}
