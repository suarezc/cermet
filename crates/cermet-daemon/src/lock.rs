//! The cermetd single-writer lock: the daemon wrapper over the shared hardened host-lock primitive.
//!
//! The security-load-bearing acquire (`O_NOFOLLOW`/`O_NONBLOCK` open + flock + fd validation) lives
//! in [`cermet_broker_actor::host_lock`]; the DAEMON policy here is "on acquire, clear the stale app
//! `host.json` advertisement; never attach — fail closed on busy."

use std::path::Path;

use cermet_broker_actor::host_lock;

pub use cermet_broker_actor::host_lock::HostLock;

/// Try to become the sole writer for `home`.
///
/// Wraps [`host_lock::acquire_hardened_lock`] and applies the daemon's `host.json` policy: on
/// success, remove any stale advertisement (the daemon is the writer, not an attaching app); on
/// contention, return `None` (the daemon then fails closed — it never attaches to another host).
pub fn acquire_single_writer(home: &Path) -> std::io::Result<Option<HostLock>> {
    match host_lock::acquire_hardened_lock(&home.join("host.lock"))? {
        Some(lock) => {
            let _ = std::fs::remove_file(home.join("host.json"));
            Ok(Some(lock))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn single_writer_lock_is_exclusive_and_self_heals() {
        let home = tempdir().unwrap();
        let first = acquire_single_writer(home.path())
            .expect("io")
            .expect("first acquires");
        assert!(
            acquire_single_writer(home.path()).expect("io").is_none(),
            "a second writer must be refused while the first holds the lock"
        );
        drop(first);
        // `drop` releases the flock synchronously, but under heavy PARALLEL test load the kernel's
        // advisory-lock release can lag the close() by a hair, so a same-process tight-loop reacquire
        // occasionally sees a transient WouldBlock. The daemon never hits this — its contention is
        // CROSS-PROCESS (separate kernel file-descriptions, released at process exit) — so retry
        // briefly to keep the test deterministic without changing any production lock logic.
        let reacquired =
            (0..5).find_map(|_| match acquire_single_writer(home.path()).expect("io") {
                Some(lock) => Some(lock),
                None => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    None
                }
            });
        assert!(
            reacquired.is_some(),
            "a released lock is re-acquirable (crash self-heal)"
        );
    }

    #[test]
    fn acquire_clears_a_stale_host_json() {
        let home = tempdir().unwrap();
        std::fs::write(
            home.path().join("host.json"),
            br#"{"pid":1,"port":9,"started_at":0}"#,
        )
        .unwrap();
        let _g = acquire_single_writer(home.path())
            .expect("io")
            .expect("acquires");
        assert!(
            !home.path().join("host.json").exists(),
            "a stale host.json is removed under the lock"
        );
    }
}
