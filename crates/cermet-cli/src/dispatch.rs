//! Driving one parsed `CliCommand` over the real `ctl.sock` to a rendered `CliOutput`.
//!
//! `run` is the only command here that makes two calls, and the reason is the whole point of the
//! fused form: an operator whose sentence corpus ALLOWS a thing does not then need a second command
//! to do it. The decision, the freeze, and every execute-path check are the daemon's and are
//! untouched — this layer only stopped making the human ask twice.

use cermet_ctl_client::broker_client::CtlBrokerClient;
use cermet_ipc::wire::AgentRequestOutcome;
use serde_json::{json, Value};

use super::render::{relay_tool_warning, render_artifact};
use super::{CliCommand, CliError, CliOutput};

/// Drive one command to a rendered [`CliOutput`] over the real `ctl.sock`.
///
/// Takes NO presence adapter, deliberately: nothing reachable here mutates authority —
/// every command is decide-or-read — so a gate would have nothing to gate. The presence-gated
/// paths are the sentence ceremony and `doc apply`, which take their adapter from
/// `sentence_presence()` in the binary.
pub async fn dispatch(client: &CtlBrokerClient, cmd: &CliCommand) -> Result<CliOutput, CliError> {
    match cmd {
        CliCommand::Run {
            provider,
            action,
            resource,
            environment,
            justification,
            ask_only,
            retry_effect,
        } => {
            let req_json =
                build_request_json(provider, action, resource, environment, justification);
            // The reference handle rides BESIDE the request, never inside it: it is metadata about
            // which effect this attempt continues, not a field of the effect. Unexamined here.
            let view = client
                .request(mint_session(), req_json, retry_effect.clone())
                .await
                .map_err(CliError::Server)?;
            // `--ask-only` asked a QUESTION, so the answer is the decision receipt verbatim — the
            // same JSON for allow and for deny, and NOTHING else glued to it, because a caller
            // parses it (a trailing human hint line would make the one machine-readable form
            // unparseable). The EXIT CODE is not part of that payload and follows the documented
            // contract instead — 0 allow, 1 denied: the shape a wrapper reaches for first is
            // `if cermet run … --ask-only; then`, and answering a refusal with 0 made that
            // wrapper fail open. Branching on `decision` still works and is still the richer read.
            if *ask_only {
                return decision_receipt(&view);
            }

            let outcome: Value = serde_json::from_str(&view)
                .map_err(|e| CliError::Malformed(format!("request view is not JSON: {e}")))?;

            // Fail closed: access requires a definite "allow". Anything else — a deny, a decision
            // field that is absent or unrecognized — stops here without executing. Here the caller
            // asked for the EFFECT and did not get it, so this one renders in words and exits 1.
            if outcome.get("decision").and_then(Value::as_str) != Some("allow") {
                return render_denial(provider, action, &outcome);
            }
            let request_id = outcome
                .get("request_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::Malformed("an allowed request carried no request_id".to_string())
                })?
                .to_string();
            execute(client, &request_id).await
        }
        CliCommand::Resume { request_id } => execute(client, request_id).await,
        CliCommand::Artifact {
            handle,
            range,
            path,
        } => {
            // range/path ride raw (parse.rs already rejected both-set/bad grammar client-side; the
            // daemon boundary re-validates).
            let view = client
                .read_artifact(handle.clone(), range.clone(), path.clone())
                .await
                .map_err(CliError::Server)?;
            let span: Value = serde_json::from_str(&view)
                .map_err(|e| CliError::Malformed(format!("artifact span is not JSON: {e}")))?;
            render_artifact(handle, range.is_some() || path.is_some(), &span)
        }
        CliCommand::AuditVerify => {
            let view = client.verify_audit().await.map_err(CliError::Server)?;
            json_output(&view)
        }
        CliCommand::Evidence { request_id } => {
            let view = client
                .evidence(request_id.clone())
                .await
                .map_err(CliError::Server)?;
            json_output(&view)
        }
        // `cermet catalog` is a THIN client of the daemon's OWN catalog join. The
        // sentence×verb decision, the admitting/denying sentence text, and the discoverability bit
        // are all the daemon's (`catalog_listing()` — the same call `agent.sock` serves); this only
        // re-tags the ctl view as the catalog frame and hands it to the ONE renderer both surfaces
        // share. A transport failure PROPAGATES: an unreachable daemon must never render as an
        // empty catalog, which reads exactly like "you may do nothing".
        CliCommand::Catalog { all } => {
            let view = client.catalog().await.map_err(CliError::Server)?;
            let mut frame: Value = serde_json::from_str(&view)
                .map_err(|e| CliError::Malformed(format!("catalog view is not JSON: {e}")))?;
            let Some(map) = frame.as_object_mut() else {
                return Err(CliError::Malformed("catalog view is not an object".into()));
            };
            map.insert("kind".to_string(), json!("catalog"));
            let zoom = if *all {
                crate::mcp_bridge::CatalogZoom::All
            } else {
                crate::mcp_bridge::CatalogZoom::Allowed
            };
            let out = crate::mcp_bridge::render_catalog_zoom(
                &frame,
                zoom,
                crate::mcp_bridge::CatalogSurface::Cli,
            )
            .map_err(|e| CliError::Malformed(e.to_string()))?;
            Ok(CliOutput {
                text: out.text,
                ok: out.ok,
            })
        }

        // Commands with a local seam (terminal / token source / repository / process env) are driven
        // by the binary front-end (see `main.rs`); they never reach the ctl dispatch.
        CliCommand::Connect(_)
        | CliCommand::Check { .. }
        | CliCommand::Init
        | CliCommand::DocCheck { .. }
        | CliCommand::Diff
        | CliCommand::Status { .. }
        | CliCommand::Export { .. }
        | CliCommand::Apply { .. }
        | CliCommand::Preset(_)
        | CliCommand::OwnerStatus
        | CliCommand::OwnerLockdown
        | CliCommand::OwnerLockdownClear
        | CliCommand::Allow { .. }
        | CliCommand::Rules
        | CliCommand::Revoke { .. }
        | CliCommand::Refresh { .. }
        | CliCommand::Log { .. }
        | CliCommand::Setup(_)
        | CliCommand::Update { .. }
        | CliCommand::UpdateDailyCheck
        | CliCommand::UpdateDaily { .. }
        | CliCommand::UpdateApply { .. }
        | CliCommand::UpdateApplyDeb { .. }
        | CliCommand::Journal { .. }
        | CliCommand::McpInstall(_) => Err(CliError::Usage(
            "the document, preset, rules, connect, owner, log, check, setup, update, journal, and \
             mcp commands are driven by the CLI front-end"
                .to_string(),
        )),
    }
}

/// The execute half of `run` (and all of `run --resume`): the operator execute keyed by the one
/// public id. A failure names the id, because the decision still stands and the run is resumable.
async fn execute(client: &CtlBrokerClient, request_id: &str) -> Result<CliOutput, CliError> {
    match client.execute_operator(request_id.to_string()).await {
        Ok(view) => json_output(&view),
        Err(error) => Err(CliError::Refused(execute_failure_text(&error, request_id))),
    }
}

/// What an execute failure tells the operator to do next.
///
/// An ALREADY-USED grant is the one refusal for which "finish it with `--resume`" is the
/// advice that just failed. Its single effect has run — for a relay verb that effect is minting the
/// session, so the effect's whole result is a handle and an invocation that were in a reply this
/// client may never have received (the live case: a 30s ctl timeout on a mint the daemon had already
/// completed). A single-use grant cannot run it again, and repeating the resume sends the operator
/// in a circle.
///
/// So this says the true thing instead: the effect ran, its result is on its own receipt — where a
/// relay session's handle and ready-to-run invocation are readable until the session's TTL lapses —
/// and a fresh effect needs a fresh request. Every other failure leaves the decision standing with
/// nothing run, so it keeps the resume advice unchanged.
pub(crate) fn execute_failure_text(error: &cermet_lang::error::Error, request_id: &str) -> String {
    use cermet_lang::error::{Error, ExecuteRefusal};
    if matches!(error, Error::ExecuteRefused(ExecuteRefusal::AlreadyUsed)) {
        return format!(
            "{error}\nthis grant's one effect has already run — resuming cannot run it again.\n\
             what it produced is on its own receipt, including a relay verb's session handle and \
             invocation, which stay usable until that session's TTL lapses:\n  \
             cermet log {request_id}\n\
             for a fresh effect, make a fresh request: cermet run <provider>.<action>"
        );
    }
    format!("{error}\nthe decision stands — finish it with: cermet run --resume {request_id}")
}

/// The decision receipt `--ask-only` prints, projected through the wire type that CANNOT carry a
/// grant id.
///
/// `request_id` is the ONE public id and the daemon's ctl `request` reply is the core
/// `RequestOutcome`, which still carries the operator-internal `grant_id` — that is record data for
/// the audit rows and the `log <request_id>` evidence JSON, not receipt data. Deserializing into
/// [`AgentRequestOutcome`] (defined as "`RequestOutcome` MINUS `grant_id`") drops it, along with any
/// future id the daemon adds: an unknown key has no field to land in. Reusing that type rather than
/// deleting a key by hand is the point — the leak becomes unrepresentable, not merely unwritten.
fn decision_receipt(view: &str) -> Result<CliOutput, CliError> {
    let receipt: AgentRequestOutcome = serde_json::from_str(view)
        .map_err(|e| CliError::Malformed(format!("decision receipt is not a decision: {e}")))?;
    // Fail closed on the exit code too: only a definite "allow" is a zero exit.
    let allowed = receipt.decision == cermet_lang::types::Decision::Allow;
    let text = serde_json::to_string_pretty(&receipt)
        .map_err(|e| CliError::Malformed(format!("cannot render the decision receipt: {e}")))?;
    Ok(CliOutput { text, ok: allowed })
}

/// Render a refused request: what was refused, why, and the human-only command that would widen
/// authority. A denial is an OUTCOME, not a transport error, so it is printed and exits non-zero.
fn render_denial(provider: &str, action: &str, outcome: &Value) -> Result<CliOutput, CliError> {
    let reason = outcome
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Malformed("a refusal carried no reason".to_string()))?;
    let mut text = format!("denied — {provider}.{action}\n  {reason}");
    if let Some(hint) = outcome.get("hint").and_then(Value::as_str) {
        text.push_str(&format!("\n  {hint}"));
    }
    if let Some(request_id) = outcome.get("request_id").and_then(Value::as_str) {
        text.push_str(&format!("\n  request: {request_id}"));
    }
    Ok(CliOutput { text, ok: false })
}

/// Build the ctl `request` body the daemon expects (a null resource normalizes to `{}`).
fn build_request_json(
    provider: &str,
    action: &str,
    resource: &Value,
    environment: &Option<String>,
    justification: &Option<String>,
) -> String {
    let resource = if resource.is_null() {
        json!({})
    } else {
        resource.clone()
    };
    json!({
        "provider": provider,
        "action": action,
        "environment": environment,
        "resource": resource,
        "justification": justification,
    })
    .to_string()
}

/// A fresh server-minted throwaway session id (`sess_<16 hex>`) for a CLI request — the CLI never
/// supplies a session, so a same-uid CLI cannot forge a victim session (mirrors
/// `operator.rs:mint_session`).
fn mint_session() -> String {
    let b: [u8; 8] = rand::random();
    let mut s = String::from("sess_");
    for byte in b {
        s.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Pretty-print a broker view JSON string. A view that is not JSON is a malformed response — fail
/// closed.
///
/// A relay receipt's `invocation` is run by the CALLER with a native CLI, so when that CLI
/// is not on THIS process's PATH the render leads with [`relay_tool_warning`] — the receipt itself is
/// unchanged and still rendered below it.
pub(crate) fn json_output(view: &str) -> Result<CliOutput, CliError> {
    let v: Value = serde_json::from_str(view)
        .map_err(|e| CliError::Malformed(format!("view is not JSON: {e}")))?;
    let body = serde_json::to_string_pretty(&v).unwrap_or_else(|_| view.to_string());
    let text = match v
        .get("result")
        .and_then(|r| relay_tool_warning(r, std::env::var_os("PATH").as_deref()))
    {
        Some(warning) => format!("{warning}\n{body}"),
        None => body,
    };
    Ok(CliOutput { text, ok: true })
}
