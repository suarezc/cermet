//! The update-hook callback: `githook.sock`, plus the `cermetd git-update-hook` client git runs.
//!
//! Git's `update` hook is a program, not a library call, so the decision has to cross a process
//! boundary. It crosses ONE way — the hook asks, the daemon answers — and the credential never
//! moves: the daemon performs the credentialed hop itself and tells the hook whether it landed.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cermet_core::broker::RefUpdate;
use serde::{Deserialize, Serialize};

use super::HookRegistry;
use cermet_ipc::peer;

use crate::serve::{accept_loop, ServeConfig};

/// One question from a spawned `receive-pack`'s update hook.
#[derive(Debug, Serialize, Deserialize)]
pub struct HookQuestion {
    /// The PER-STREAM token the daemon put in this `receive-pack`'s environment. It is what proves
    /// which attested stream is asking; the hook is never trusted to name the repo or the
    /// principal itself. One push of several refs presents it once per ref.
    pub token: String,
    pub refname: String,
    pub old: String,
    pub new: String,
}

/// The daemon's answer. `message` is what git prints as `remote: …` in the agent's push output.
#[derive(Debug, Serialize, Deserialize)]
pub struct HookAnswer {
    pub allow: bool,
    pub message: String,
}

/// Bind `githook.sock` in the daemon's OWN runtime dir at 0600: the only legitimate client is a
/// process the daemon itself spawned, running as the daemon uid.
pub fn bind_hook_socket(
    runtime_dir: &Path,
) -> Result<(std::os::unix::net::UnixListener, PathBuf), crate::serve::ServeError> {
    crate::serve::bind_socket(runtime_dir, "githook.sock", 0o600)
}

/// Serve hook questions forever. `daemon_uid` is the only uid admitted (T3: a peer uid must not be
/// able to ask for a decision, and the socket mode alone is never the boundary).
pub fn serve_hook_socket(
    listener: std::os::unix::net::UnixListener,
    broker: cermet_broker_actor::BrokerHandle,
    registry: HookRegistry,
    daemon_uid: u32,
    config: ServeConfig,
) {
    let rt = tokio::runtime::Handle::current();
    let handle: crate::serve::ConnHandler = Arc::new(move |stream| {
        answer(stream, &broker, &registry, daemon_uid, &rt);
    });
    accept_loop(listener, config.max_conns, handle);
}

fn answer(
    mut stream: StdUnixStream,
    broker: &cermet_broker_actor::BrokerHandle,
    registry: &HookRegistry,
    daemon_uid: u32,
    rt: &tokio::runtime::Handle,
) {
    let Ok(peer) = peer::peer_cred(stream.as_raw_fd()) else {
        return;
    };
    if peer.uid != daemon_uid {
        crate::log::emit(format!(
            "cermetd: refused githook.sock connection from uid {} (admits only the daemon uid \
             {daemon_uid})",
            peer.uid
        ));
        return;
    }

    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let Ok(question) = serde_json::from_str::<HookQuestion>(&line) else {
        return reply(
            &mut stream,
            &HookAnswer {
                allow: false,
                message: "cermet: malformed hook question; failing closed".into(),
            },
        );
    };

    // The token is the whole of the hook's authority to be asked about a stream. An unknown one —
    // a stale hook, a stream that already closed — is a fail-closed refusal. It is not consumed
    // here: git asks once per ref in the same push.
    let context = registry
        .lock()
        .ok()
        .and_then(|map| map.get(&question.token).cloned());
    let Some(context) = context else {
        return reply(
            &mut stream,
            &HookAnswer {
                allow: false,
                message: "cermet: this push has no live attested stream; failing closed".into(),
            },
        );
    };

    let update = RefUpdate {
        repo: context.repo,
        refname: question.refname,
        old: question.old,
        new: question.new,
        principal: context.principal,
        session_id: context.session_id,
        peer_uid: context.peer_uid,
    };
    let verdict = rt.block_on(async { broker.authorize_ref_update(update).await });
    let answer = match verdict {
        Ok(verdict) => HookAnswer {
            allow: verdict.allow,
            message: verdict.message,
        },
        Err(error) => HookAnswer {
            allow: false,
            message: format!("cermet: {error}"),
        },
    };
    reply(&mut stream, &answer);
}

fn reply(stream: &mut StdUnixStream, answer: &HookAnswer) {
    if let Ok(mut json) = serde_json::to_vec(answer) {
        json.push(b'\n');
        let _ = stream.write_all(&json);
        let _ = stream.flush();
    }
}

// ---------------------------------------------------------------------------
// The client side: `cermetd git-update-hook <ref> <old> <new>`
// ---------------------------------------------------------------------------

/// Run the update hook. Git invokes this (through the two-line stub the daemon installed in the
/// mirror) with `(refname, old, new)` and reads its exit status: zero lets the ref land, non-zero
/// refuses it and renders our stderr into the agent's own `git push` output.
///
/// Every failure arm here is a DENY. A hook that cannot reach the daemon must never let a ref land.
pub fn run_update_hook(args: &[String]) -> std::process::ExitCode {
    let [refname, old, new] = args else {
        eprintln!("cermet: update hook expects <ref> <old> <new>");
        return std::process::ExitCode::FAILURE;
    };
    let (Ok(socket), Ok(token)) = (
        std::env::var("CERMET_HOOK_SOCKET"),
        std::env::var("CERMET_HOOK_TOKEN"),
    ) else {
        eprintln!("cermet: this mirror was pushed to outside an attested stream; refusing");
        return std::process::ExitCode::FAILURE;
    };

    let question = HookQuestion {
        token,
        refname: refname.clone(),
        old: old.clone(),
        new: new.clone(),
    };
    match ask(&socket, &question) {
        Ok(answer) => {
            for line in answer.message.lines() {
                eprintln!("{line}");
            }
            if answer.allow {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("cermet: could not reach the broker for a decision ({error}); refusing");
            std::process::ExitCode::FAILURE
        }
    }
}

fn ask(socket: &str, question: &HookQuestion) -> std::io::Result<HookAnswer> {
    let mut stream = StdUnixStream::connect(socket)?;
    let mut json = serde_json::to_vec(question)?;
    json.push(b'\n');
    stream.write_all(&json)?;
    stream.flush()?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    serde_json::from_str(&line).map_err(std::io::Error::other)
}
