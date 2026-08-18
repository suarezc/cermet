//! The daemon-owned `0700` runtime directory holding the sockets.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("neither CERMET_HOME nor HOME is set")]
    NoHome,
    #[error("runtime dir io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Resolve `CERMET_HOME` (env, else `~/.cermet`).
pub fn resolve_home() -> Result<PathBuf, RuntimeError> {
    std::env::var_os("CERMET_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cermet")))
        .ok_or(RuntimeError::NoHome)
}

/// Create (or tighten) the owner-only `0700` runtime dir under `home` and return its path.
///
/// Delegates to [`cermet_broker_actor::host_lock::harden_dir`], which adds the OWNER check the
/// previous mode-only `set_permissions` lacked: a foreign-owned, non-directory, or symlinked `run/`
/// is refused (fail closed) rather than chmod'd. `home` is expected to already be a hardened
/// owner-only directory (the daemon runs `harden_dir(&home)` before this).
pub fn runtime_dir(home: &Path) -> Result<PathBuf, RuntimeError> {
    let dir = home.join("run");
    cermet_broker_actor::host_lock::harden_dir(&dir)?;
    Ok(dir)
}

/// Pick the runtime-dir PATH (no fs side effects): `CERMET_RUNTIME` when set, else `home/run`.
///
/// Under systemd the unit sets `RuntimeDirectory=cermetd` + `Environment=CERMET_RUNTIME=/run/cermetd`,
/// so the sockets live OUTSIDE the `0700` `CERMET_HOME` state tree (where a cross-uid approver could
/// never traverse to `ctl.sock`). Same-uid / no-systemd falls back to the in-home `run/` dir.
pub fn resolve_runtime_path(env_runtime: Option<OsString>, home: &Path) -> PathBuf {
    env_runtime
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("run"))
}

/// Resolve + harden the runtime dir the daemon serves from, sourcing `CERMET_RUNTIME` from the env.
/// The path is hardened to owner-only `0700` (refusing a foreign-owned/symlinked dir) exactly like
/// [`runtime_dir`]; only the LOCATION changes when `CERMET_RUNTIME` is set.
pub fn resolve_runtime_dir(home: &Path) -> Result<PathBuf, RuntimeError> {
    let dir = resolve_runtime_path(std::env::var_os("CERMET_RUNTIME"), home);
    cermet_broker_actor::host_lock::harden_dir(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn runtime_dir_is_0700() {
        let home = tempfile::tempdir().unwrap();
        let dir = runtime_dir(home.path()).expect("create runtime dir");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "runtime dir must be owner-only 0700, got {mode:o}"
        );
    }

    #[test]
    fn existing_loose_dir_is_retightened() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("run");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let out = runtime_dir(home.path()).expect("retighten");
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "a loosened runtime dir must be retightened to 0700"
        );
    }

    #[test]
    fn runtime_dir_refuses_a_symlinked_run() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), home.path().join("run")).unwrap();
        assert!(
            runtime_dir(home.path()).is_err(),
            "a symlinked run/ must be refused (the harden_dir owner/symlink check)"
        );
    }

    #[test]
    fn resolve_runtime_path_prefers_cermet_runtime_env() {
        // The flip moves sockets OUT of the 0700 CERMET_HOME state tree to /run/cermetd, sourced
        // from CERMET_RUNTIME. When it is set, it wins over home/run.
        let runtime = std::path::Path::new("/run/cermetd");
        let home = std::path::Path::new("/var/lib/cermetd");
        let got = resolve_runtime_path(Some(runtime.as_os_str().to_os_string()), home);
        assert_eq!(got, runtime, "CERMET_RUNTIME, when set, is the runtime dir");
    }

    #[test]
    fn resolve_runtime_path_falls_back_to_home_run() {
        // Same-uid / no systemd RuntimeDirectory: fall back to the in-home run/ dir.
        let home = std::path::Path::new("/home/me/.cermet");
        let got = resolve_runtime_path(None, home);
        assert_eq!(
            got,
            home.join("run"),
            "with no CERMET_RUNTIME, the runtime dir is home/run"
        );
    }
}
