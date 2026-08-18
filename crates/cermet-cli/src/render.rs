//! Rendering broker view JSON into terminal `CliOutput` text — the pure presentation layer. Every
//! view is deserialized into its TYPED owner so a missing/mistyped required field fails closed.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;

use serde_json::Value;

use super::{CliError, CliOutput};

/// A relay receipt hands back an invocation the CALLER runs with a NATIVE CLI — the broker
/// brings the credential, not the tool. When that tool is not installed, the copy-paste line dies on
/// the shell's own "command not found", which reads as Cermet having failed. Return the one-line
/// warning to print ABOVE the invocation, or `None` when the receipt carries no relay invocation or
/// the tool resolves.
///
/// Client-preflight ONLY (one validation per boundary): the check belongs in the process that PRINTS
/// the line, because that process's `PATH` is the one the caller will run the invocation in — the
/// daemon's `PATH` is a different environment and answers a different question. It never blocks,
/// never touches minting, and a miss is advisory.
///
/// `path` is the rendering process's `PATH` (`std::env::var_os("PATH")`), passed in so the lookup is
/// testable without mutating process-wide state. An absent `PATH` resolves nothing, so it warns.
pub fn relay_tool_warning(result: &Value, path: Option<&OsStr>) -> Option<String> {
    let invocation = result.get("relay")?.get("invocation")?.as_str()?;
    let tool = invocation.split_whitespace().next()?;
    if which(path, tool).is_some() {
        return None;
    }
    Some(format!(
        "warning: '{tool}' not found on PATH — the invocation below will fail as written; \
         install it or invoke it by full path."
    ))
}

/// Where `tool` resolves on `path`, if it resolves at all — the one PATH lookup in this crate.
/// Second consumer: `cermet check` asks the same question of the same PATH, and reporting
/// WHERE a tool was found is most of what makes that answer useful.
pub(crate) fn which(path: Option<&OsStr>, tool: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(path.unwrap_or_else(|| OsStr::new(""))).find_map(|dir| {
        let candidate = dir.join(tool);
        std::fs::metadata(&candidate)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .then_some(candidate)
    })
}

/// Render an artifact span: metadata header + content, with the truncation / frame-truncation
/// notes. Read-only; no secret.
///
/// The view is deserialized into the TYPED wire [`cermet_ipc::wire::ArtifactSpan`] — required
/// fields (handle/digest/size/stored_size/truncated/unit/start/end/content) that are missing or
/// mistyped are a MALFORMED response and fail closed, never rendered as empty/zero defaults. Only
/// the explicitly-optional `frame_truncated` (`#[serde(default)]` on the wire type) may default.
/// `handle` is the human's requested handle, used only in the error message.
///
/// The client does NOT re-verify that the daemon echoed back the `path` pointer it was sent: the
/// daemon's own path resolution is the one enforcement point.
pub fn render_artifact(handle: &str, addressed: bool, span: &Value) -> Result<CliOutput, CliError> {
    let a: cermet_ipc::wire::ArtifactSpan = serde_json::from_value(span.clone())
        .map_err(|e| CliError::Malformed(format!("artifact {handle}: malformed span view: {e}")))?;

    let trunc = if a.truncated {
        " · truncated (head+tail kept)"
    } else {
        ""
    };
    let mut text = format!(
        "artifact: {}\ndigest:   {}\nsize:     {} bytes ({} stored{trunc})\n",
        a.handle, a.digest, a.size, a.stored_size
    );
    if addressed {
        match a.path.as_deref() {
            Some(p) => text.push_str(&format!("path:     {p}\n")),
            None => text.push_str(&format!("span:     {} {}..{}\n", a.unit, a.start, a.end)),
        }
    }
    if a.frame_truncated {
        text.push_str(&format!(
            "note:     output too large to show in full — showing the first {} bytes; \
             read more with --range bytes:<start>-<end>\n",
            a.content.len()
        ));
    }
    text.push_str("---\n");
    text.push_str(&a.content);
    Ok(CliOutput { text, ok: true })
}
