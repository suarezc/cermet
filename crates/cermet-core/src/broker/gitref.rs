//! The update-hook → sentence bridge, and the credentialed hop it confirms.
//!
//! This is the whole of Cermet's participation in a push: authorization and receipt, nothing
//! else. Git moved the objects; git's `update` hook is the sanctioned per-ref policy seam; the
//! daemon answers it with a sentence decision and, on allow, the one credentialed step. There is
//! no carrier, no staging area, and no held pending push.

use std::path::PathBuf;

use serde_json::json;

use crate::error::Result;
use crate::git::{ChangedPaths, RepoId, NULL_OID};
use crate::types::{CapabilityRequest, Decision};

/// One proposed ref update, exactly as git's `update` hook presents it. Every field is git's, not
/// the agent's self-description: `receive-pack` computed `old`/`new` from the ref transaction it is
/// about to perform.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RefUpdate {
    /// The repo the attested stream opened, already validated by [`RepoId::parse`].
    pub repo: RepoId,
    /// The fully-qualified ref, e.g. `refs/heads/main`.
    pub refname: String,
    /// The MIRROR's tip for this ref; [`NULL_OID`] when the mirror had no such ref. NOT the
    /// upstream's tip — with no fetch refresh the mirror can lag it.
    pub old: String,
    /// The proposed tip; [`NULL_OID`] for a DELETION.
    pub new: String,
    /// The attested principal of the stream that carried this push.
    pub principal: String,
    /// The session the stream plane minted for this connection.
    pub session_id: String,
    /// The attested peer uid of the stream.
    pub peer_uid: Option<i64>,
}

/// One proposed mirror refresh, as the read stream presents it at stream-open.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FetchAttempt {
    pub repo: RepoId,
    pub principal: String,
    pub session_id: String,
    pub peer_uid: Option<i64>,
    /// The program git's `update` hook execs, needed because a refresh may CREATE the mirror (a
    /// clone of a repo this host has never seen) and every mirror gets its hook installed.
    pub hook_program: PathBuf,
}

/// What the hook does with the answer: exit 0 and let the ref land, or exit non-zero and let git
/// render `message` into the agent's own `git push` output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefVerdict {
    pub allow: bool,
    /// The text git will print as `remote: <message>`. Legible on purpose — it IS the product's
    /// refusal surface for a push.
    pub message: String,
    pub request_id: Option<String>,
}

impl RefVerdict {
    fn deny(message: impl Into<String>, request_id: Option<String>) -> Self {
        RefVerdict {
            allow: false,
            message: message.into(),
            request_id,
        }
    }
}

impl super::Broker {
    /// Decide one proposed mirror refresh and, on allow, perform it.
    ///
    /// The invariant in one function: **the only path to served refs is a refresh that just
    /// succeeded.** No matching sentence refuses; a refresh that fails refuses and carries git's own
    /// error; and neither arm falls back to serving what the mirror already had. A mirror that is
    /// absent is created and seeded here, which is what makes cloning a repo this host has never
    /// received work at all.
    pub fn authorize_fetch(&self, attempt: &FetchAttempt) -> RefVerdict {
        let request = CapabilityRequest {
            provider: attempt.repo.provider.clone(),
            action: "fetch".into(),
            resource: json!({ "owner": attempt.repo.owner, "name": attempt.repo.name }),
            environment: None,
            justification: None,
            // The git plane is not an agent runtime and reports nothing about a model.
            model: None,
        };
        let outcome = match self.request_capability_from_git_plane(
            &attempt.session_id,
            &attempt.principal,
            request,
            attempt.peer_uid,
        ) {
            Ok(outcome) => outcome,
            Err(error) => return RefVerdict::deny(format!("cermet: {error}"), None),
        };
        if outcome.decision != Decision::Allow {
            let mut message = format!(
                "cermet: no standing authority to read {} ({}); add a rule like `allow \
                 {}.fetch where owner = \"{}\" and name = \"{}\"` and try again",
                attempt.repo.slug(),
                outcome.reason,
                attempt.repo.provider,
                attempt.repo.owner,
                attempt.repo.name
            );
            if let Some(hint) = &outcome.hint {
                message.push_str(&format!("\ncermet:   {hint}"));
            }
            return RefVerdict::deny(message, Some(outcome.request_id));
        }
        let Some(grant_id) = outcome.grant_id.clone() else {
            return RefVerdict::deny(
                "cermet: authority allowed the read but minted no grant; failing closed"
                    .to_string(),
                Some(outcome.request_id),
            );
        };

        // The mirror must exist for git to fetch INTO — created only now, after the allow, so an
        // unruled repo never materializes a directory.
        let mirror =
            match crate::git::ensure_mirror(&self.git, &attempt.repo, &attempt.hook_program) {
                Ok(path) => path,
                Err(error) => {
                    return RefVerdict::deny(format!("cermet: {error}"), Some(outcome.request_id))
                }
            };

        let result = {
            let _guard = MirrorSlot::set(self, mirror);
            self.execute_capability(&grant_id)
        };
        match result {
            Ok(execution) if execution.ok => RefVerdict {
                allow: true,
                message: format!(
                    "cermet: refreshed {} from upstream (request {})",
                    attempt.repo.slug(),
                    outcome.request_id
                ),
                request_id: Some(outcome.request_id),
            },
            Ok(_) => RefVerdict::deny(
                format!(
                    "cermet: the upstream refresh did not complete for {}; refusing to serve a \
                     stale mirror (request {})",
                    attempt.repo.slug(),
                    outcome.request_id
                ),
                Some(outcome.request_id),
            ),
            Err(error) => RefVerdict::deny(
                format!(
                    "cermet: {error}\ncermet: refusing to serve a stale mirror for {} (request {})",
                    attempt.repo.slug(),
                    outcome.request_id
                ),
                Some(outcome.request_id),
            ),
        }
    }

    /// Decide one proposed ref update and, on allow, carry it to the upstream.
    ///
    /// The order is the invariant: sentence decision → credentialed hop → confirm. The hook returns
    /// success ONLY if the upstream accepted, so the mirror's ref advances iff the upstream's did
    /// and `mirror ≡ upstream` holds through every failure arm.
    ///
    /// Vocabulary the sentences do not yet have — force/non-fast-forward and deletion — refuses
    /// here as a hook refusal, not a code gap: that vocabulary is a deliberate gap.
    pub fn authorize_ref_update(&self, update: &RefUpdate) -> RefVerdict {
        let Some(branch) = update.refname.strip_prefix("refs/heads/") else {
            return RefVerdict::deny(
                format!(
                    "cermet: {} is not a branch. Only branch updates have vocabulary today; tags \
                     and other ref namespaces have none yet.",
                    update.refname
                ),
                None,
            );
        };
        if update.new == NULL_OID {
            return RefVerdict::deny(
                format!(
                    "cermet: refusing to DELETE {}. Deletion is deliberately absent vocabulary — \
                     it is destructive and would need its own word.",
                    update.refname
                ),
                None,
            );
        }

        let mut resource = json!({
            "owner": update.repo.owner,
            "name": update.repo.name,
            "branch": branch,
            "new_oid": update.new,
        });
        if update.old != NULL_OID {
            // The MIRROR's tip, labelled as such. The receipt's `upstream_old_oid` is
            // the separate, upstream-reported fact.
            resource["mirror_old_oid"] = json!(update.old);
        }
        let request = CapabilityRequest {
            provider: update.repo.provider.clone(),
            action: "push".into(),
            resource,
            environment: None,
            justification: None,
            // The git plane is not an agent runtime and reports nothing about a model.
            model: None,
        };

        let outcome = match self.request_ref_update_capability(update, request) {
            Ok(outcome) => outcome,
            Err(error) => {
                return RefVerdict::deny(format!("cermet: {error}"), None);
            }
        };
        if outcome.decision != Decision::Allow {
            return RefVerdict::deny(
                self.render_refusal(update, branch, &outcome.reason, outcome.hint.as_deref()),
                Some(outcome.request_id),
            );
        }
        let Some(grant_id) = outcome.grant_id.clone() else {
            return RefVerdict::deny(
                "cermet: authority allowed the push but minted no grant; failing closed"
                    .to_string(),
                Some(outcome.request_id),
            );
        };

        // The credentialed hop, inside the decision. The mirror slot is set for exactly this
        // execute and cleared by the guard however we leave.
        let mirror = crate::git::mirror_path(&self.git, &update.repo);
        let result = {
            let _guard = MirrorSlot::set(self, mirror);
            self.execute_capability(&grant_id)
        };
        match result {
            Ok(execution) if execution.ok => RefVerdict {
                allow: true,
                message: format!(
                    "cermet: carried {}@{} to {} (request {})",
                    branch,
                    short(&update.new),
                    update.repo.slug(),
                    outcome.request_id
                ),
                request_id: Some(outcome.request_id),
            },
            Ok(_) => RefVerdict::deny(
                format!(
                    "cermet: the upstream did not accept {branch}; the mirror is unchanged \
                     (request {})",
                    outcome.request_id
                ),
                Some(outcome.request_id),
            ),
            Err(error) => RefVerdict::deny(
                format!(
                    "cermet: {error}\ncermet: the mirror is unchanged (request {})",
                    outcome.request_id
                ),
                Some(outcome.request_id),
            ),
        }
    }

    /// Run the ref update through the ordinary sentence machinery. It is the SAME path an agent
    /// request takes — the same corpus, audit, grant kernel and receipt — entered from the git
    /// plane instead of the agent plane.
    fn request_ref_update_capability(
        &self,
        update: &RefUpdate,
        request: CapabilityRequest,
    ) -> Result<crate::types::RequestOutcome> {
        self.request_capability_from_git_plane(
            &update.session_id,
            &update.principal,
            request,
            update.peer_uid,
        )
    }

    /// The refusal a human reads. It names the exact sentence-shaped facts and, when a consumer of
    /// content facts is worth serving, the bounded changed-path list derived from git's own objects
    /// — never the agent's description of them.
    fn render_refusal(
        &self,
        update: &RefUpdate,
        branch: &str,
        reason: &str,
        hint: Option<&str>,
    ) -> String {
        let mut out = format!(
            "cermet: no standing authority for {} on {} ({reason})",
            branch,
            update.repo.slug()
        );
        // address the party that can actually act. The pusher is usually an AGENT, and
        // authority is human-only and presence-gated — telling it to "add the rule and re-push"
        // named an act it cannot perform, so the refusal read as advice and was really a dead end.
        // What the agent CAN do is carry the sentence to its operator, so that is what it is told.
        match hint {
            Some(hint) => {
                out.push_str("\ncermet: authority is human-only — ask your operator to apply:");
                out.push_str(&format!("\ncermet:   {hint}"));
            }
            None => out.push_str(
                "\ncermet: authority is human-only — ask your operator to widen it with \
                 `cermet rules allow`",
            ),
        }
        if let Some(paths) = self.derive_changed_paths(update) {
            out.push_str(&format!(
                "\ncermet: this push touches {} path(s)",
                paths.total
            ));
            for row in paths.rows.iter().take(10) {
                out.push_str(&format!("\ncermet:   {} {}", row.status, row.path));
            }
            if paths.rows.len() > 10 || paths.truncated {
                out.push_str("\ncermet:   …");
            }
        }
        out
    }

    /// DEMAND-DRIVEN derivation, in the one moment it is consumed: a human is about to decide what
    /// sentence to write. Runs git's own `diff-tree` against the objects `receive-pack` already
    /// migrated into the mirror.
    ///
    /// FAIL-SOFT because it is a RENDERING, not an authorization input — the decision above already
    /// denied. A future path-predicate sentence is a different consumer and fails CLOSED on its own
    /// behalf: an unmatched restriction is never an allow.
    fn derive_changed_paths(&self, update: &RefUpdate) -> Option<ChangedPaths> {
        let mirror = crate::git::mirror_path(&self.git, &update.repo);
        crate::git::changed_paths(&self.git, &mirror, &update.old, &update.new).ok()
    }
}

fn short(oid: &str) -> &str {
    &oid[..oid.len().min(12)]
}

/// Sets the broker's in-flight mirror slot and clears it on drop, so an early return or a panicking
/// execute can never leave a stale mirror visible to the next verb.
struct MirrorSlot<'a> {
    broker: &'a super::Broker,
}

impl<'a> MirrorSlot<'a> {
    fn set(broker: &'a super::Broker, mirror: PathBuf) -> Self {
        *broker.git_mirror.borrow_mut() = Some(mirror);
        MirrorSlot { broker }
    }
}

impl Drop for MirrorSlot<'_> {
    fn drop(&mut self) {
        *self.broker.git_mirror.borrow_mut() = None;
    }
}
