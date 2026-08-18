//! The hardened *authority-file* reader — the ONE way any Cermet component loads a file whose
//! contents confer authority, including the daemon sentence record.
//!
//! Shared down the dependency graph so custody readers use one implementation.

use std::fs::OpenOptions;
use std::io::{self, ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// The max bytes read from an authority file. A generous 1 MiB cap bounds a hostile or corrupt file
/// while never truncating a legitimate one. An OVER-cap file is REFUSED (not silently truncated) so
/// a consumer never parses a half file.
pub const MAX_AUTHORITY_FILE: u64 = 1024 * 1024;

/// Read an *authority file* — one whose CONTENTS confer authority — fail-closed:
/// `O_NOFOLLOW | O_NONBLOCK` (no symlink-follow, no FIFO block), the fd must `fstat` as a regular
/// file owned by our effective uid, no group/other WRITE bit, and the read is bounded (an over-cap
/// file is refused rather than truncated).
///
/// A plain `read_to_string` would follow a symlink and trust any owner — an attacker who can plant a
/// file (or link) at the path would then load attacker-controlled authority. The caller must fail
/// closed on every error; `NotFound` is surfaced distinctly so absence can become deny-all.
pub fn read_authority_file(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    let me = nix::unistd::geteuid().as_raw();
    if !meta.file_type().is_file() || meta.uid() != me {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "not a regular file owned by us — refusing",
        ));
    }
    // Owner + regular is NOT enough for an authority file: under the separate-uid boundary an
    // `_cermet`-owned but `0666` file is WRITABLE by the agent uid, who could rewrite it into an
    // ALLOW policy — the owner check alone would still accept it. Reject any group/other WRITE bit
    // (`fstat` on the open fd → no TOCTOU). Read bits are not a threat (policy is not a secret), so
    // a world-READABLE-but-not-writable file is fine. This reader must not mutate the file, so it
    // fails closed instead of tightening. Write access granted purely through a POSIX ACL is not
    // visible in the mode bits and is a known gap in this check.
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "authority file is group/other-writable — refusing (another uid could rewrite it)",
        ));
    }
    let mut buf = Vec::new();
    // Read one past the cap so an exactly-cap file is accepted but anything larger is detectable.
    file.take(MAX_AUTHORITY_FILE + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_AUTHORITY_FILE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "authority file exceeds the maximum size — refusing (fail closed)",
        ));
    }
    Ok(buf)
}
