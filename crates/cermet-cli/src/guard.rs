use std::path::PathBuf;

/// Resolve the Cermet home exactly as the daemon does.
pub fn cermet_home() -> PathBuf {
    match std::env::var_os("CERMET_HOME") {
        Some(home) if !home.is_empty() => PathBuf::from(home),
        _ => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(".cermet"),
    }
}
