use super::helpers::*;
use super::*;
use crate::types::EffectFailureClass;

/// The OBSERVATION a hop's `Err` carries when that hop TRACKS an effect: the executor got no usable
/// provider response, and the seam that raised the error is the only place the fact is typed.
///
/// Only the seam's own definitive evidence that nothing was written to the wire — a connection never
/// established, a name never resolved, our own egress refusing before a byte went out — earns a class
/// saying the effect cannot have happened. Everything else is [`EffectFailureClass::TransportNoResponse`]:
/// a request that may have been written may have landed, and an adapter's optimistic account of
/// itself is not evidence that it did not. The reader draws the conclusion; this function only
/// records what was seen — the taxonomy stores observations, never conclusions.
fn observed_failure_class(error: &Error) -> EffectFailureClass {
    match error.effect_failure_class() {
        Some(
            class @ (EffectFailureClass::TransportPreSend
            | EffectFailureClass::LocalExecutionFailure),
        ) => class,
        _ => EffectFailureClass::TransportNoResponse,
    }
}

/// What the executor tells the AGENT about that hop — THE single rendering, shared with the durable
/// record's `error` field, so the two can never say different things. It is built from the CLASS and
/// the effect handle alone: no adapter prose reaches the agent or the record through here.
///
/// **The "never hint retryability" invariant is REPEALED.** It made this path answer every failure
/// with one fixed reconcile instruction, which is what discarded the class the seam had already
/// typed on the way to the record: the path stamped the residual while a prose transport string
/// sat beside it in the same event. The error now states what the executor OBSERVED and claims no
/// more certainty than that — "nothing left this machine" and "it went out and nothing came back"
/// are different facts and get different sentences. The residual arm is the honest one: absent
/// definitive pre-send evidence, never say the effect did not happen.
///
/// The undetermined arm names the EXISTING referenced-retry channel concretely, by the
/// `effect_id` the agent already holds, instead of gesturing at "the safe effect handle". Stating
/// that derivation in a message is fine; storing it is not, and nothing here is persisted. (T2 — a
/// sloppy cooperative model that retries by making a FRESH request would mint a new key and could
/// double the effect; this is the sentence that stops it.)
pub(super) fn effect_failure_message(class: EffectFailureClass, effect_id: &str) -> String {
    match class {
        EffectFailureClass::TransportPreSend | EffectFailureClass::LocalExecutionFailure => {
            "the request never left this machine and the effect did not occur; \
             a new request is the retry path"
                .to_string()
        }
        _ => format!(
            "the request was sent and no response arrived, so whether the effect landed is \
             not yet determined; retry this exact effect with retry_effect={effect_id}, which \
             reuses its idempotency key, rather than making a fresh request"
        ),
    }
}

/// The proof observation an execution returned, mapped to the DERIVED disposition the durable record
/// has always carried for its crash-recovery consumers. The derivation lives here, in one place, and
/// nothing upstream of it states a verdict.
fn derived_effect_outcome(proof: crate::EffectProof) -> EffectOutcome {
    match proof {
        crate::EffectProof::Proved => EffectOutcome::Succeeded,
        // The key was attached and the provider answered with a clean typed refusal its compiled
        // rejection contract recognizes, so it never processed the request.
        crate::EffectProof::Refused => EffectOutcome::DefinitelyFailed,
        // Invocation happened and nothing observed establishes what came of it.
        crate::EffectProof::Unproved => EffectOutcome::Ambiguous,
    }
}

pub(super) struct VerifiedTerminalExecution {
    definitely_pre_effect: bool,
}

/// How long past the ratified max_runtime a lease stays reportable before the
/// overdue sweep terminalizes it — headroom for the report upload (chunks + finalize + one
/// session-expiry resend).
pub(super) const LEASE_REPORT_GRACE_SECS: i64 = 120;

impl Broker {
    fn verify_grant_evidence(
        &self,
        grant: &GrantRow,
        resource: &CanonicalResource,
    ) -> Result<EvidenceEnvelope> {
        let envelope = EvidenceEnvelope::from_canonical_json(&grant.evidence_json)
            .map_err(Error::Integrity)?;
        match &envelope {
            EvidenceEnvelope::None { .. } => {
                let current = self
                    .templates
                    .loaded(&grant.provider, &grant.action)
                    .and_then(|loaded| loaded.template.request_evidence_id());
                if current.is_some() {
                    return Err(Error::Integrity(
                        "grant has no evidence for an evidence-backed action".into(),
                    ));
                }
            }
            EvidenceEnvelope::ProviderResolved(payload) => {
                let ProviderResolvedEnvelope {
                    credential_generation,
                    fields,
                    mint_deadline_epoch,
                    oldest_observed_at_epoch,
                    profile: profile_id,
                    profile_fingerprint,
                    resolution_digest,
                    sources,
                    ..
                } = payload.as_ref();
                if self.now_epoch() > *mint_deadline_epoch {
                    return Err(Error::Integrity("grant evidence is stale".into()));
                }
                let profile = crate::evidence::profile(profile_id).ok_or_else(|| {
                    Error::Integrity("grant names an unknown evidence profile".into())
                })?;
                let live_profile_fingerprint = profile.semantics_fingerprint();
                if profile.provider != grant.provider || profile.action != grant.action {
                    return Err(Error::Integrity(
                        "grant evidence profile is registered for another action".into(),
                    ));
                }
                let current = self
                    .templates
                    .loaded(&grant.provider, &grant.action)
                    .and_then(|loaded| loaded.template.request_evidence_id());
                if current != Some(profile.id) {
                    return Err(Error::Integrity(
                        "grant evidence profile no longer matches the action".into(),
                    ));
                }
                if *profile_fingerprint != live_profile_fingerprint {
                    return Err(Error::Integrity(
                        "grant evidence profile semantics changed".into(),
                    ));
                }
                if fields.len() != profile.outputs.len() || sources.len() != profile.sources.len() {
                    return Err(Error::Integrity(
                        "grant evidence has the wrong field/source set".into(),
                    ));
                }
                for output in profile.outputs {
                    let field = fields.get(output.field).ok_or_else(|| {
                        Error::Integrity("grant evidence is missing a declared output".into())
                    })?;
                    let value = resource.scalar(output.field).ok_or_else(|| {
                        Error::Integrity("grant resource is missing an evidence field".into())
                    })?;
                    if value.kind() != output.ty
                        || field.source != output.source
                        || field.value != value.to_json()
                    {
                        return Err(Error::Integrity(
                            "grant evidence does not equal its complete resource".into(),
                        ));
                    }
                }
                for (decl, source) in profile.sources.iter().zip(sources) {
                    if source.kind != decl.kind
                        || resource.req_str(decl.id_field).ok() != Some(source.id.as_str())
                    {
                        return Err(Error::Integrity(
                            "grant evidence source does not match its requested object".into(),
                        ));
                    }
                }
                let template_hash = grant.template_hash.as_deref().ok_or_else(|| {
                    Error::Integrity("evidence-backed grant has no template hash".into())
                })?;
                let expected_digest = crate::evidence::resolution_digest(
                    &grant.request_id,
                    &grant.provider,
                    &grant.action,
                    profile.id,
                    &live_profile_fingerprint,
                    template_hash,
                    &grant.descriptor_hash,
                    credential_generation,
                    *oldest_observed_at_epoch,
                    *mint_deadline_epoch,
                    fields,
                    sources,
                );
                if expected_digest != *resolution_digest {
                    return Err(Error::Integrity(
                        "grant evidence resolution digest is invalid".into(),
                    ));
                }
                if !self.vault.matches_generation(
                    &credential_ref(&grant.provider),
                    &grant.provider,
                    credential_generation,
                )? {
                    return Err(Error::Integrity(
                        "evidence credential generation changed".into(),
                    ));
                }
            }
        }
        Ok(envelope)
    }

    /// Resolve an agent-issued request handle without accepting an operator-internal grant id.
    pub(super) fn resolve_grant_id_by_request_id(&self, request_id: &str) -> Result<String> {
        self.state
            .query_row(
                "SELECT id FROM grants WHERE request_id=?1",
                rusqlite::params![request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| Error::Invalid(format!("no grant for request_id {request_id}")))
    }
    /// Fail-closed pre-invocation terminalizer: route a claimed (`executing`) grant
    /// that failed DEFINITIVELY before any provider invocation or plan handoff to a terminal state whose
    /// debit self-heals. It CAN itself fail (`?`-propagating steps) — safety comes from the fact-FIRST
    /// ordering, not from infallibility: (1) durably record the authenticated
    /// `mutation_invoked:false` fact FIRST (so budget recovery can idempotently release even if a crash
    /// or an error interrupts the rest — an early fault before the fact merely RETAINS the debit), (2) flip
    /// `executing→executed`, (3) release the grant's own debit (`pre_invocation_terminal_failure`).
    /// `secrets` is the pre-fetched redaction set — NO fallible vault read runs between the claim and
    /// this record. No-op release for a non-budget grant.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn terminalize_pre_invocation_failure(
        &self,
        grant_id: &str,
        g: &GrantRow,
        lease_opened_at: i64,
        lease_deadline: i64,
        secrets: &[String],
        outcome: &str,
        detail: &str,
        executing_session: &str,
    ) -> Result<()> {
        let money = crate::money::MoneyMetadata::from_canonical_json(&g.money_json)
            .map_err(Error::Integrity)?;
        let mut data = json!({
            "grant_id": grant_id,
            "request_id": g.request_id,
            "provider": g.provider,
            "action": g.action,
            "outcome": outcome,
            "mutation_invoked": false,
            "request_session": g.session_id,
            "executing_session": executing_session,
        });
        // Emitted for any grant that froze a tracked effect.
        if let Some(effect_id) = money.effect_id() {
            data["effect_id"] = json!(effect_id);
            data["effect_outcome"] = json!("definitely_pre_effect");
        }
        self.audit.record(NewEvent {
            session_id: Some(&g.session_id),
            event_type: "provider_action_failed",
            severity: "high",
            summary: detail,
            data,
            secrets,
        })?;
        let executed_digest =
            self.redigest_leased(grant_id, g, "executed", lease_opened_at, lease_deadline);
        self.state.execute(
            "UPDATE grants SET status='executed', grant_digest=?2 WHERE id=?1 AND status='executing'",
            rusqlite::params![grant_id, executed_digest],
        )?;
        self.release_budget_for_grant(
            grant_id,
            super::budget::BudgetReleaseCause::PreInvocationTerminalFailure,
        )?;
        Ok(())
    }

    pub(super) fn effect_start_resource_binding(
        &self,
        grant_id: &str,
        grant: &GrantRow,
        recorded_resource: &Value,
    ) -> Result<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let recorded = crate::evidence::canonical_json(recorded_resource);
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.grant_key).expect("HMAC accepts a 32-byte key");
        mac.update(b"cermet-effect-start-resource-v1\0");
        for field in [grant_id, grant.resource_json.as_str(), recorded.as_str()] {
            mac.update(&(field.len() as u64).to_le_bytes());
            mac.update(field.as_bytes());
        }
        Ok(format!(
            "hmac-sha256:{}",
            crate::util::hex(&mac.finalize().into_bytes())
        ))
    }

    /// Verify and, when necessary, finish the state half of an audit-first terminal write.
    pub(super) fn reconcile_terminal_execution(
        &self,
        grant_id: &str,
        grant: &GrantRow,
    ) -> Result<Option<VerifiedTerminalExecution>> {
        let Some(evidence) = self.verified_in_process_terminal_execution(grant_id, grant)? else {
            return Ok(None);
        };
        if grant.status == GrantStatus::Executing {
            let executed_digest = self.redigest(grant_id, grant, "executed");
            self.state.execute(
                "UPDATE grants SET status='executed', grant_digest=?2 \
                 WHERE id=?1 AND status='executing'",
                rusqlite::params![grant_id, executed_digest],
            )?;
        }
        if evidence.definitely_pre_effect {
            self.release_budget_for_grant(
                grant_id,
                super::budget::BudgetReleaseCause::PreInvocationTerminalFailure,
            )?;
        }
        Ok(Some(evidence))
    }

    /// Whether an in-process terminal execution event exists for this grant, and whether it landed
    /// DEFINITIVELY before the provider adapter was invoked (`mutation_invoked: false` — the durable
    /// fact that earns a budget release). Money grants derive the same answer from their effect chain.
    ///
    /// The grant digest (`assert_grant_integrity`) is the one authoritative check on this side of the
    /// boundary; the audit chain stays tamper-evident for the operator-facing `audit-verify` surface.
    pub(super) fn verified_in_process_terminal_execution(
        &self,
        grant_id: &str,
        grant: &GrantRow,
    ) -> Result<Option<VerifiedTerminalExecution>> {
        let money = crate::money::MoneyMetadata::from_canonical_json(&grant.money_json)
            .map_err(Error::Integrity)?;
        if money.effect_id().is_some() {
            return self
                .verified_money_terminal_effect_outcome(grant_id, grant, &money)
                .map(|outcome| {
                    outcome.map(|effect_outcome| VerifiedTerminalExecution {
                        definitely_pre_effect: effect_outcome == EffectOutcome::PreEffect,
                    })
                });
        }
        let events = self
            .audit
            .verified_execution_events(grant_id, &grant.request_id)?;
        let Some(terminal) = events.iter().rev().find(|event| {
            matches!(
                event.event_type.as_str(),
                "provider_action_succeeded" | "provider_action_failed"
            )
        }) else {
            return Ok(None);
        };
        let mutation_invoked = terminal
            .data
            .get("mutation_invoked")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                Error::Integrity(format!(
                    "grant {grant_id} terminal evidence has invalid invocation state"
                ))
            })?;
        Ok(Some(VerifiedTerminalExecution {
            definitely_pre_effect: !mutation_invoked,
        }))
    }

    /// The artifact-store root for this broker (`dir/artifacts/`).
    fn artifacts_dir(&self) -> PathBuf {
        self.dir.join("artifacts")
    }

    /// Store command/tool output as a content-addressed artifact and chain its digest into the audit
    /// log. Recording the digest via `AuditLog::record` is what makes post-hoc blob tampering
    /// detectable (the read path re-verifies the digest against this chained value).
    ///
    /// The audit event carries only metadata (handle/request/digest/size/truncated) — never the blob
    /// bytes, so no output content rides the HMAC chain or any read surface here. (Redacting secrets
    /// out of the blob CONTENT itself is the caller's job at ingestion; this API stores bytes as given.)
    pub fn store_artifact(
        &self,
        request_id: &str,
        bytes: &[u8],
    ) -> Result<crate::artifacts::StoredArtifact> {
        self.store_artifact_capped(request_id, bytes, self.artifacts.max_bytes, None)
    }

    /// As [`Broker::store_artifact`] but with an explicit byte cap.
    ///
    /// `session_id` binds the `artifact_stored` event to the grant's session so
    /// `events_for_session` — which filters by session — surfaces the digest in `session show`. `None`
    /// leaves it unbound (a caller with no session context).
    pub fn store_artifact_capped(
        &self,
        request_id: &str,
        bytes: &[u8],
        max_bytes: usize,
        session_id: Option<&str>,
    ) -> Result<crate::artifacts::StoredArtifact> {
        // Chain the digest event BEFORE the index row, so no `artifacts` row can exist
        // outside the HMAC chain. audit.db and state.db are separate files (no shared transaction), so
        // this is ordered writes: stage the content-addressed blob, record the digest event, THEN
        // commit the row. If the record fails the row is never inserted (fail closed); a staged blob
        // whose row never commits is harmless content-addressed orphan garbage (unreferenced,
        // dedup-safe). The "every stored artifact row is chained" property holds under partial failure.
        let staged = crate::artifacts::stage(&self.artifacts_dir(), bytes, max_bytes)?;
        let secrets = self.vault.all_secrets()?;
        self.audit.record(NewEvent {
            session_id,
            event_type: "artifact_stored",
            severity: "info",
            summary: &format!(
                "stored artifact {} for {} ({} bytes{})",
                staged.handle,
                request_id,
                staged.size,
                if staged.truncated { ", truncated" } else { "" }
            ),
            data: json!({
                "handle": staged.handle,
                "request_id": request_id,
                "digest": staged.digest,
                "size": staged.size,
                "truncated": staged.truncated,
            }),
            secrets: &secrets,
        })?;
        let stored = crate::artifacts::commit_row(&self.state, request_id, &staged)?;
        Ok(stored)
    }

    /// Retrieve a span of a stored artifact by its `handle`. Read-only, no authority, no secret. Fail
    /// closed: an unknown handle, a missing blob, or a digest mismatch is an error (never empty-success).
    ///
    /// A SUCCESSFUL read is audited (`artifact_read`, free-but-audited): the handle, digest, resolved
    /// span, and `surface` (agent|ctl) chain into the log so every retrieval of a full response body is
    /// attributable. A FAILED lookup is deliberately NOT audited — auditing it would turn the chain
    /// into a handle-existence oracle (the read surface itself already collapses failures to one opaque
    /// `ARTIFACT_UNAVAILABLE`).
    pub fn read_artifact(
        &self,
        handle: &str,
        addr: Option<crate::artifacts::ArtifactAddress>,
        surface: crate::artifacts::ArtifactReadSurface,
    ) -> Result<crate::artifacts::ArtifactSpan> {
        let span = crate::artifacts::read_span(&self.state, &self.artifacts_dir(), handle, addr)?;
        let secrets = self.vault.all_secrets()?;
        self.audit.record(NewEvent {
            session_id: None,
            event_type: "artifact_read",
            severity: "info",
            summary: &format!("artifact {} read via {}", span.handle, surface.tag()),
            data: json!({
                "handle": span.handle,
                "digest": span.digest,
                "unit": span.unit,
                "start": span.start,
                "end": span.end,
                "path": span.path,
                "surface": surface.tag(),
            }),
            secrets: &secrets,
        })?;
        Ok(span)
    }

    fn record_capability_execution_refused(
        &self,
        grant_id: &str,
        grant: &GrantRow,
        reason: &str,
        detail: &str,
    ) -> Result<()> {
        self.audit.record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "capability_execution_refused",
            severity: "high",
            summary: detail,
            data: json!({
                "grant_id": grant_id,
                "provider": grant.provider,
                "action": grant.action,
                "reason": reason,
                "mutation_invoked": false,
            }),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }

    pub fn execute_capability(&self, grant_id: &str) -> Result<ExecutionResult> {
        self.execute_capability_attributed(grant_id, &ExecAttribution::default())
    }

    /// THE operator execute path — addressed by `request_id`, the one public id. The
    /// operator-internal `grant_id` is resolved HERE through the kernel's 1:1 request→grant mapping,
    /// so no surface asks a human (or an agent) to hold two ids for one thing. Unlike the agent path
    /// this is not principal-bound: the ctl socket's operator peer check is that boundary.
    ///
    /// A DENIED request never minted a grant, so it resolves to nothing and refuses cleanly here —
    /// the same answer an unknown id gets, which is the truth in both cases.
    pub fn execute_capability_by_request_id(&self, request_id: &str) -> Result<ExecutionResult> {
        let grant_id = self.resolve_grant_id_by_request_id(request_id)?;
        self.execute_capability_attributed(&grant_id, &ExecAttribution::default())
    }

    /// Execute a grant on the OPERATOR path (grant_id-addressed), attributing the audit event to the
    /// connection that ran it.
    ///
    /// `claim_and_run` is the single enforcement point for `assert_grant_integrity` and the
    /// product-disabled refusal — this path does not repeat either check.
    fn execute_capability_attributed(
        &self,
        grant_id: &str,
        exec: &ExecAttribution,
    ) -> Result<ExecutionResult> {
        match self.claim_and_run(grant_id, exec)? {
            ExecOutcome::Executed(r) => Ok(r),
        }
    }

    /// Claim the single-use grant (`approved`→`executing`, atomic) and run the HTTP verb in-core to
    /// completion. `exec` is audit-only.
    fn claim_and_run(&self, grant_id: &str, exec: &ExecAttribution) -> Result<ExecOutcome> {
        self.enforce_not_locked_down("new execution claims")?;
        // MCP-repoint quiesce barrier: every approved→executing claim funnels through here,
        // so refuse a NEW claim (fail closed, single-use grant NOT consumed) while a repoint holds the
        // barrier. A lapsed-TTL barrier is released here first.
        self.enforce_quiesce_barrier()?;
        let g = self.load_grant(grant_id)?;
        // THE authoritative store-integrity check for every execute path:
        // the entry points above do not repeat it, so this one guards the claim CAS alone.
        self.assert_grant_integrity(grant_id, &g)?;
        if self.provider_is_product_disabled(&g.provider, &g.action) {
            self.record_capability_execution_refused(
                grant_id,
                &g,
                "provider_disabled",
                "provider_disabled",
            )?;
            return Err(Error::ProviderDisabled);
        }
        let parsed_envelope =
            EvidenceEnvelope::from_canonical_json(&g.evidence_json).map_err(Error::Integrity)?;
        let evidence_backed = parsed_envelope.profile_id().is_some();
        let money = crate::money::MoneyMetadata::from_canonical_json(&g.money_json)
            .map_err(Error::Integrity)?;
        // A grant that EXISTS and is owned but is off the approved path refuses with a TYPED
        // class the daemon surfaces to the handle's owner — never a bare opaque failure. Map each grant
        // state to its class (a fresh `Approved` grant falls through to run).
        if g.status != GrantStatus::Approved {
            return Err(match g.status {
                GrantStatus::Requested => Error::ExecuteRefused(ExecuteRefusal::NotReady),
                GrantStatus::Executing | GrantStatus::Executed => {
                    Error::ExecuteRefused(ExecuteRefusal::AlreadyUsed)
                }
                GrantStatus::Expired => Error::ExecuteRefused(ExecuteRefusal::Expired),
                // A denied grant is a terminal decision, not one of the surfaced re-request classes;
                // keep it opaque (the owner already saw the denial on the request path).
                GrantStatus::Denied => Error::Denied(format!("grant {grant_id} was denied")),
                GrantStatus::Approved => unreachable!("handled by the outer guard"),
            });
        }
        if let Some(exp) = g.expiry_epoch {
            if self.now_epoch() > exp {
                self.expire_grant(grant_id, &g)?;
                return Err(Error::ExecuteRefused(ExecuteRefusal::Expired));
            }
        }
        if money
            .retry_deadline_epoch()
            .is_some_and(|deadline| self.now_epoch() > deadline)
        {
            self.expire_grant(grant_id, &g)?;
            return Err(Error::ExecuteRefused(ExecuteRefusal::Expired));
        }
        if g.approved_by_kind.as_deref() != Some("sentence") {
            let detail = format!(
                "grant {grant_id} lacks sentence provenance required by universal authority; re-request it"
            );
            self.record_capability_execution_refused(
                grant_id,
                &g,
                "sentence_provenance_required",
                &detail,
            )?;
            return Err(Error::Denied(detail));
        }
        // Bracket the claim with an authenticated sentence-authority read: an authority change
        // between approval and claim refuses before egress.
        match self.current_sentence_authority() {
            Ok((_, current)) if current == g.policy_fingerprint => {}
            result => {
                let (reason, detail) = match result {
                        Ok(_) => (
                            "sentence_authority_changed",
                            format!("grant {grant_id} sentence authority changed; re-request it"),
                        ),
                        Err(error) => (
                            "sentence_authority_unavailable",
                            format!(
                                "grant {grant_id} sentence authority is unavailable; re-request it: {error}"
                            ),
                        ),
                    };
                self.record_capability_execution_refused(grant_id, &g, reason, &detail)?;
                return Err(Error::Denied(detail));
            }
        }
        // The ratified action template IS the HTTP recipe (authority). Deny unless the
        // template frozen on the grant equals the one this broker resolves NOW. `frozen != live`
        // (both `Option<&str>`) covers all four combos: template changed (Some != other Some),
        // vanished (Some != None), appeared over a built-in name (None != Some), and built-in
        // steady-state (None == None ⇒ proceed). Placed BEFORE the contract lookup so a vanished
        // template denies cleanly here instead of as a downstream "no contract" error.
        let frozen_template = g.template_hash.as_deref();
        let live_template = self.templates.content_hash(&g.provider, &g.action);
        if frozen_template != live_template.as_deref() {
            if evidence_backed {
                self.record_capability_execution_refused(
                    grant_id,
                    &g,
                    "evidence_stale",
                    "evidence-backed grant template drifted",
                )?;
                return Err(Error::Denied(
                    crate::evidence::EVIDENCE_DENIAL_REASON.into(),
                ));
            }
            return Err(Error::ExecuteRefused(ExecuteRefusal::TemplateDrifted));
        }
        // The loaded provider descriptor IS authority (auth mode, origin, egress). Deny
        // unless the descriptor hash frozen on the grant equals the one this broker loaded NOW —
        // BEFORE the atomic claim and any credential use, so a descriptor replacement invalidates
        // every unspent dependent grant without consuming it and never reinterprets it under new
        // semantics. A vanished descriptor (`None`) also fails closed.
        if self.descriptor_hash(&g.provider) != Some(g.descriptor_hash.as_str()) {
            if evidence_backed {
                self.record_capability_execution_refused(
                    grant_id,
                    &g,
                    "evidence_stale",
                    "evidence-backed grant descriptor drifted",
                )?;
                return Err(Error::Denied(
                    crate::evidence::EVIDENCE_DENIAL_REASON.into(),
                ));
            }
            return Err(Error::ExecuteRefused(ExecuteRefusal::TemplateDrifted));
        }
        let provider = self
            .providers
            .get(&g.provider)
            .ok_or_else(|| Error::Provider(format!("provider {} not registered", g.provider)))?;

        // THE execution discipline of this hop, derived HERE — before the claim CAS, so a
        // disagreement refuses while the single-use grant is still unspent — from the RATIFIED
        // action template this grant froze. The two checks above already refused unless the frozen
        // template hash and descriptor hash still equal the live ones, so this reads the same bytes
        // the approval was decided against. It is never the adapter's opinion of itself, and never a
        // class of verb: two independent properties cross the seam as data.
        //
        // The key is the one MINTED WITH THE GRANT (`money_json`, persisted before the first attempt
        // and reused verbatim by a referenced retry). A template declaring the key discipline whose
        // grant carries none is a fail-closed integrity stop, not a silent plain hop.
        let declared = self.templates.loaded(&g.provider, &g.action);
        let mints_key = declared.is_some_and(|loaded| loaded.template.mints_idempotency_key());
        if mints_key != money.idempotency_key().is_some() {
            return Err(Error::Integrity(
                "the grant's persisted execution discipline disagrees with its ratified template"
                    .into(),
            ));
        }
        let discipline = crate::provider::ExecutionDiscipline {
            idempotency_key: money.idempotency_key(),
            prove_effect: declared.is_some_and(|loaded| loaded.template.proves_effect()),
        };
        let declares_preconditions =
            declared.is_some_and(|loaded| !loaded.template.precondition_names().is_empty());

        let contract = provider.action_contract(&g.action).ok_or_else(|| {
            Error::Denied(format!(
                "action {}.{} has no contract; cannot execute",
                g.provider, g.action
            ))
        })?;
        let stored = CanonicalResource::from_stored(&g.resource_json, contract)?;
        let stored_value: Value = serde_json::from_str(&stored.to_canonical_json())?;
        // Re-enter the same provider canonicalization used before mint. Template-only admission
        // constraints (formats and character budgets) are not duplicated into ActionContract, so
        // persisted frozen bytes must pass their live hash-bound template constraints again.
        let resource = provider.canonicalize(&g.action, &stored_value)?;
        let evidence = match self.verify_grant_evidence(&g, &resource) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.record_capability_execution_refused(
                    grant_id,
                    &g,
                    "evidence_integrity",
                    &error.to_string(),
                )?;
                return Err(Error::Denied(
                    crate::evidence::EVIDENCE_DENIAL_REASON.into(),
                ));
            }
        };

        // Fetch the redaction material (the vault-wide secret set) BEFORE the claim CAS. A
        // vault-wide SQL/read fault then fails HERE while the grant is still `approved` (no stuck
        // `executing` grant, no bypassed release) rather than between the claim and the terminal record.
        // Every post-claim terminal record reuses this pre-fetched set — no fallible vault read sits
        // between the claim and a terminal fact. The private replay key joins this in-memory redaction
        // set so a provider-controlled body or error cannot echo it into any result, audit, or artifact.
        let mut secrets = self.vault.all_secrets()?;
        if let Some(key) = money.idempotency_key() {
            secrets.push(key.to_string());
        }

        // Stamp the HMAC-covered claim-time lease at the CAS. HTTP claims normally finalize in the
        // same call; the lease covers a mid-call daemon crash.
        let lease_max_rt = crate::templates::DEFAULT_MAX_RUNTIME_SECS;
        let lease_opened_at = self.now_epoch();
        if matches!(
            &evidence,
            EvidenceEnvelope::ProviderResolved(payload)
                if lease_opened_at > payload.mint_deadline_epoch
        ) {
            self.record_capability_execution_refused(
                grant_id,
                &g,
                "evidence_stale",
                "evidence-backed grant crossed its deadline before claim",
            )?;
            return Err(Error::Denied(
                crate::evidence::EVIDENCE_DENIAL_REASON.into(),
            ));
        }
        let lease_deadline = lease_opened_at + lease_max_rt as i64 + LEASE_REPORT_GRACE_SECS;
        let claiming_digest =
            self.redigest_leased(grant_id, &g, "executing", lease_opened_at, lease_deadline);
        let claimed = self.state.execute(
            "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, \
             lease_deadline=?4 WHERE id=?1 AND status='approved'",
            rusqlite::params![grant_id, claiming_digest, lease_opened_at, lease_deadline],
        )?;
        if claimed != 1 {
            // Lost the atomic claim race — someone already consumed the single-use grant.
            return Err(Error::ExecuteRefused(ExecuteRefusal::AlreadyUsed));
        }

        if let Err(error) = self.enforce_not_locked_down("post-claim egress") {
            let executing_session = exec
                .session_id
                .as_deref()
                .unwrap_or(&g.session_id)
                .to_string();
            self.terminalize_pre_invocation_failure(
                grant_id,
                &g,
                lease_opened_at,
                lease_deadline,
                &secrets,
                "lockdown_engaged",
                &error.to_string(),
                &executing_session,
            )?;
            return Err(error);
        }

        // Bracket the atomic claim with authenticated source reads. If a custody commit overlaps the
        // claim, the post-claim snapshot is unavailable or different and no provider call/plan handoff
        // occurs. If it changes after this read, the claim linearized before that later revocation.
        {
            let (outcome, detail) = match self.current_sentence_authority() {
                Ok((_, current)) if current == g.policy_fingerprint => (None, None),
                Ok(_) => (
                    Some("authority_changed"),
                    Some(format!(
                        "grant {grant_id} sentence authority changed during claim; refusing before egress"
                    )),
                ),
                Err(error) => (
                    Some("authority_unavailable"),
                    Some(format!(
                        "grant {grant_id} sentence authority became unavailable during claim; refusing before egress: {error}"
                    )),
                ),
            };
            if let (Some(outcome), Some(detail)) = (outcome, detail) {
                let executing_session = exec
                    .session_id
                    .as_deref()
                    .unwrap_or(&g.session_id)
                    .to_string();
                // A DEFINITIVE terminal failure BEFORE any adapter invocation (the post-claim/pre-egress
                // authority re-read refused before egress) — route it through the fail-closed
                // pre-invocation terminalizer (fact-FIRST ordering: it records the authenticated `mutation_invoked:false` fact,
                // flips executed, releases the debit) using the pre-fetched redaction set.
                self.terminalize_pre_invocation_failure(
                    grant_id,
                    &g,
                    lease_opened_at,
                    lease_deadline,
                    &secrets,
                    outcome,
                    &detail,
                    &executing_session,
                )?;
                return Err(Error::Denied(detail));
            }
        }

        // Run the verb's COMPILED PRECONDITIONS when it declares any — a property of the verb read
        // off the same ratified template the discipline came from, not a class test.
        // Only the seven proving verbs declare preconditions today, so this is byte-identical.
        if declares_preconditions {
            let loaded = self
                .templates
                .loaded(&g.provider, &g.action)
                .ok_or_else(|| Error::Integrity("action template vanished".into()))?;
            let preconditions = crate::preconditions::resolve_exact(
                &g.provider,
                &g.action,
                loaded.template.precondition_names(),
            )
            .ok_or_else(|| Error::Integrity("precondition profile is unavailable".into()))?;
            let generation = evidence.credential_generation().ok_or_else(|| {
                Error::Integrity(
                    "a precondition-bearing grant has no authenticated credential generation"
                        .into(),
                )
            })?;
            let secret = match self.vault.open_secret_for_generation(
                &credential_ref(&g.provider),
                &g.provider,
                generation,
            ) {
                Ok(secret) => secret,
                Err(error) => {
                    let executing_session = exec
                        .session_id
                        .as_deref()
                        .unwrap_or(&g.session_id)
                        .to_string();
                    self.terminalize_pre_invocation_failure(
                        grant_id,
                        &g,
                        lease_opened_at,
                        lease_deadline,
                        &secrets,
                        "precondition_credential_unavailable",
                        "money precondition credential unavailable",
                        &executing_session,
                    )?;
                    return Err(error);
                }
            };
            let checked =
                provider.check_preconditions(&preconditions, secret.expose_secret(), &resource);
            drop(secret);
            if let Err(failure) = checked {
                let executing_session = exec
                    .session_id
                    .as_deref()
                    .unwrap_or(&g.session_id)
                    .to_string();
                self.audit.record(NewEvent {
                    session_id: Some(&g.session_id),
                    event_type: "money_precondition_denied",
                    severity: "high",
                    summary: "money precondition denied before mutation",
                    data: json!({
                        "grant_id": grant_id,
                        "effect_id": money.effect_id(),
                        "precondition": failure.name,
                        "failure_class": failure.class.as_str(),
                    }),
                    secrets: &secrets,
                })?;
                self.terminalize_pre_invocation_failure(
                    grant_id,
                    &g,
                    lease_opened_at,
                    lease_deadline,
                    &secrets,
                    "precondition_denied",
                    "money precondition denied before mutation",
                    &executing_session,
                )?;
                return Err(Error::Denied("money precondition unavailable".into()));
            }
        }

        // Before any provider call, chain the complete frozen
        // non-secret resource. FreePayload fields remain verbatim; Secret fields are replaced by the
        // fixed marker before persistence, and vault-wide redaction remains defense in depth.
        let frozen_value: Value = serde_json::from_str(&g.resource_json).map_err(|error| {
            Error::Invalid(format!("frozen resource is not valid JSON: {error}"))
        })?;
        let safe_resource = crate::audit::redacted_for_record(
            redact_secret_fields(contract, frozen_value),
            &secrets,
        );
        let provider_fields: BTreeSet<String> = match &evidence {
            EvidenceEnvelope::None { .. } => BTreeSet::new(),
            EvidenceEnvelope::ProviderResolved(payload) => payload.fields.keys().cloned().collect(),
        };
        let agent_fields: Vec<String> = safe_resource
            .as_object()
            .map(|fields| {
                fields
                    .keys()
                    .filter(|field| !provider_fields.contains(*field))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut effect_data = json!({
            "grant_id": grant_id,
            "request_id": g.request_id,
            "provider": g.provider,
            "action": g.action,
            "authority_digest": g.policy_fingerprint,
            "resource": safe_resource,
            "agent_request_fields": agent_fields,
            "provider_resolved_fields": provider_fields.into_iter().collect::<Vec<_>>(),
            "request_session": g.session_id,
            "executing_session": exec.session_id.as_deref().unwrap_or(&g.session_id),
        });
        effect_data["resource_binding"] =
            json!(self.effect_start_resource_binding(grant_id, &g, &effect_data["resource"],)?);
        if let EvidenceEnvelope::ProviderResolved(payload) = &evidence {
            effect_data["evidence_receipt_id"] = json!(payload.receipt_id);
            effect_data["evidence_resolution_digest"] = json!(payload.resolution_digest);
        }
        if let Some(effect_id) = money.effect_id() {
            effect_data["effect_id"] = json!(effect_id);
        }
        self.audit.record(NewEvent {
            session_id: Some(&g.session_id),
            event_type: "capability_effect_starting",
            severity: "high",
            summary: &format!("{}.{} effect starting", g.provider, g.action),
            data: effect_data,
            // `safe_resource` already passed through the complete scrubber. Do not apply the live
            // secret set after computing `resource_binding`, or a coincidental secret substring in
            // the HMAC text could mutate the authenticated projection.
            secrets: &[],
        })?;

        // Track whether the provider adapter was actually INVOKED. A vault-open failure is
        // definitively PRE-invocation (no provider-side effect possible ⇒ its debit must release); any
        // error AT or AFTER `provider.execute` keeps the debit (money may have moved).
        // This trusted classification is the ONLY thing that earns a release — never an HTTP status, a
        // generic `Err`, or an agent assertion.
        let mut mutation_invoked = false;
        // A relay verb's execution is not a provider call — it OPENS the
        // predicate-bounded relay session the native client will then drive, and returns the receipt
        // naming it. No credential is opened here (each hop opens the vault for itself). The grant is
        // consumed by this claim exactly like any other verb; the session is the TTL-bounded
        // continuation of that one effect, and its own receipt lands when it closes.
        let relay_predicate = self.relay_predicate_for(&g.provider, &g.action);
        // The moment the executor entered the provider call. Paired with the terminal event's own
        // `recorded_at`, this brackets the attempt when no response arrived at all.
        let attempted_at = crate::util::now_rfc3339();
        // the mirror this hop carries from, set by `authorize_push` for the duration of
        // exactly this execute. `None` for every other verb.
        let git_mirror = self.git_mirror.borrow().clone();
        // ONE call shape, whatever the verb. The discipline (computed before the claim, off the
        // ratified template) rides on the call as data; there is no second method to pick and
        // therefore no class of verb that reaches a different door.
        let exec_result = if let Some(predicate) = relay_predicate {
            // Handing out live relay authority IS the invocation boundary: from here the effect can
            // happen, so the trusted classification says so.
            mutation_invoked = true;
            self.open_relay_session(&g, grant_id, &resource, predicate)
        } else if provider.requires_credential() {
            let opened = match evidence.credential_generation() {
                Some(generation) => self.vault.open_secret_for_generation(
                    &credential_ref(&g.provider),
                    &g.provider,
                    generation,
                ),
                None => self.vault.open_secret(&credential_ref(&g.provider)),
            };
            match opened {
                Ok(secret) => {
                    let r = match self.enforce_not_locked_down("provider egress") {
                        Ok(()) => {
                            mutation_invoked = true;
                            provider.execute(ProviderCall {
                                git_mirror: git_mirror.as_deref(),
                                request_id: &g.request_id,
                                action: &g.action,
                                token: secret.expose_secret(),
                                resource: &resource,
                                discipline,
                            })
                        }
                        Err(error) => Err(error),
                    };
                    drop(secret);
                    r
                }
                // Vault-open failed BEFORE any mutation call — `mutation_invoked` stays false.
                Err(e) => Err(e),
            }
        } else {
            // A credential-free provider (the daemon `files` provider) holds no secret; there is
            // nothing to decrypt. It runs with an empty token — no credential ever exists to leak.
            match self.enforce_not_locked_down("provider egress") {
                Ok(()) => {
                    mutation_invoked = true;
                    provider.execute(ProviderCall {
                        git_mirror: git_mirror.as_deref(),
                        request_id: &g.request_id,
                        action: &g.action,
                        token: "",
                        resource: &resource,
                        discipline,
                    })
                }
                Err(error) => Err(error),
            }
        };

        // The flip to `executed` runs strictly AFTER the terminal audit event lands (both
        // outcome branches) — mirroring the shell finalizer's audit-first ordering. A crash / audit
        // failure in the window can then only leave an EXECUTING grant with no terminal event
        // (honest torn state: the lease-deadline sweep terminalizes it as abandoned/unreported),
        // never an `executed` grant whose async projection reads as a benign clean finish with the
        // outcome of an irreversible provider action concealed.
        // The operation auto-close runs strictly AFTER the provider terminal audit event
        // below (both outcome branches) — bookkeeping must never sit between the consumed grant and
        // its terminal record.

        // Attribute the connection that ACTUALLY executed (audit-only). When unset (operator/in-proc
        // execute), the executor IS the request session, so we fall back to it — never null. Kept
        // distinct from the request session (`g.session_id`) so both are recoverable. `secrets`
        // was pre-fetched before the claim — no fallible vault read between claim and record.
        let executing_session = exec
            .session_id
            .as_deref()
            .unwrap_or(&g.session_id)
            .to_string();

        // The grant is already consumed (`executed`) — single-use is correct — so the
        // consumed attempt MUST be audited on BOTH outcomes. The Err path (vault open failure, or a
        // provider `execute` returning Err vs a provider `ok:false`) previously returned via `?`
        // BEFORE the audit below, leaving the spent grant dark in the chain. Record the failure
        // outcome here (the error string is scrubbed of any vault secret by `audit.record`), then
        // propagate the error unchanged.
        let resp = match exec_result {
            Ok(resp) => resp,
            Err(e) => {
                // Name the verb (provider/action) AND carry the executor's error string so
                // the terminal event reconstructs into a DURABLE receipt that says WHY the run failed
                // (owner-bound legibility, parity with a shell non-zero exit). Without provider/action
                // `reconstruct_terminal_receipt` bailed, leaving the owner an opaque "receipt no longer
                // reconstructable". The error string is scrubbed of vault secrets by `audit.record`.
                // WHY it failed, as a CLASS, recorded in the shape `provider_evidence_failed`
                // already uses and spelled by the enum itself.
                //
                // This branch got no usable provider response, so no status exists for a reader to
                // classify from later: the seam that raised the error is the only place the fact is
                // typed. An error no seam typed falls back on the ONE other typed fact in hand —
                // `mutation_invoked`, the trusted pre/post-invocation classification. Never invoked
                // means nothing left the box (a vault fault, a lockdown), which is a local failure;
                // past invocation, nothing here is evidence of anything finer than the residual.
                //
                // A hop that TRACKS an effect is the exception, and deliberately more conservative:
                // there, only the seam's DEFINITIVE evidence that nothing was written earns a
                // class saying the effect cannot have happened, so an untyped error records
                // `transport_no_response` rather than the residual.
                let tracked_effect = money.effect_id().filter(|_| mutation_invoked);
                let class = match tracked_effect {
                    Some(_) => observed_failure_class(&e),
                    None => e.effect_failure_class().unwrap_or_else(|| {
                        crate::types::EffectFailureClass::of(if mutation_invoked {
                            crate::types::FailureSignal::Unclassifiable
                        } else {
                            crate::types::FailureSignal::LocalFault
                        })
                    }),
                };
                // ONE rendering for the record and the caller, from the class and the effect
                // handle alone — no adapter prose reaches either.
                let recorded_error = match tracked_effect {
                    Some(effect_id) => {
                        format!(
                            "provider error: {}",
                            effect_failure_message(class, effect_id)
                        )
                    }
                    None => e.to_string(),
                };
                let mut event_data = json!({
                    "grant_id": grant_id,
                    "request_id": g.request_id,
                    "provider": g.provider,
                    "action": g.action,
                    "outcome": "error",
                    // Record the trusted invocation classification on the terminal event so
                    // the release decision (and crash recovery) reads it from durable evidence.
                    "mutation_invoked": mutation_invoked,
                    "error": recorded_error,
                    "failure_class": class.as_str(),
                    "request_session": g.session_id,
                    "executing_session": executing_session,
                });
                // Emitted for any verb whose execution TRACKS an effect (the grant froze one at
                // mint), never for a class called money.
                if let Some(effect_id) = money.effect_id() {
                    event_data["effect_id"] = json!(effect_id);
                    event_data["effect_outcome"] = json!(if mutation_invoked {
                        "ambiguous"
                    } else {
                        "definitely_pre_effect"
                    });
                    // Bracket the attempt when no provider response arrived. `recorded_at` on the
                    // event itself is the terminal stamp; `attempted_at` is when the executor
                    // entered the call. The prose `transport_error` that used to sit here is gone:
                    // the same fact rides `failure_class` as a typed observation, and one fact in
                    // two vocabularies is one vocabulary too many.
                    event_data["attempted_at"] = json!(attempted_at);
                }
                if let Some(pid) = exec.pid {
                    event_data["executing_pid"] = json!(pid);
                }
                self.audit.record(NewEvent {
                    session_id: Some(&g.session_id),
                    event_type: "provider_action_failed",
                    severity: "high",
                    summary: &format!("{}.{} failed", g.provider, g.action),
                    data: event_data,
                    secrets: &secrets,
                })?;
                // Consume the grant only now that its terminal record is durable. `g`
                // predates the claim CAS, so the redigest carries the lease stamps the row holds.
                let executed_digest =
                    self.redigest_leased(grant_id, &g, "executed", lease_opened_at, lease_deadline);
                self.state.execute(
                    "UPDATE grants SET status='executed', grant_digest=?2 WHERE id=?1 \
                     AND status='executing'",
                    rusqlite::params![grant_id, executed_digest],
                )?;
                // A DEFINITIVE pre-invocation terminal failure (e.g. vault-open before
                // `provider.execute`) moved no money — void the grant's own debit. RELEASE-second
                // (terminal-state-first: the flip to `executed` above already landed). An at/after
                // invocation failure keeps the debit (money may have moved). No-op for a non-budget
                // grant. A crash between the flip and this release is recovered by the sweep,
                // reading the durable `mutation_invoked:false` fact on the terminal event above.
                if !mutation_invoked {
                    self.release_budget_for_grant(
                        grant_id,
                        super::budget::BudgetReleaseCause::PreInvocationTerminalFailure,
                    )?;
                }
                // A pipeline step's command FAILURE does not sweep the run — it PAUSES it. The
                // terminal `provider_action_failed` above is what the ordering gate reads; the model may
                // then retry this step or abandon the run (the run TTL / abandon is the backstop). The
                // grant is now `executed` (single-use); nothing here revives or expires a later step.
                //
                // Past the invocation boundary on a hop that TRACKS an effect, the agent gets the
                // rendered sentence — the same class the record above stamped, and the same words —
                // whatever raised the error. Every other verb propagates the executor's own error
                // unchanged. `ProviderFailed` renders and wires exactly as `Provider` does.
                return Err(match tracked_effect {
                    Some(effect_id) => {
                        Error::ProviderFailed(class, effect_failure_message(class, effect_id))
                    }
                    None => e,
                });
            }
        };

        if provider.requires_credential() {
            let _ = self.vault.touch(&credential_ref(&g.provider));
        }

        let crate::provider::ProviderResponse {
            ok,
            result: raw_result,
            retained,
            envelope,
            failure_class,
            proof,
        } = resp;
        // The seam returned an OBSERVATION; the broker derives the disposition its durable record
        // and its crash-recovery consumers read.
        let effect_outcome = proof.map(derived_effect_outcome);
        let result = redacted(raw_result, &secrets);
        // The verb's envelope metadata is broker-authored, but a capture can carry a value
        // the agent submitted, so it gets the same redaction pass the result does.
        let broker_metadata = match redacted(Value::Object(envelope), &secrets) {
            Value::Object(map) => map,
            // Redaction preserves shape; a non-object here would be an envelope we cannot trust, and
            // dropping it is the fail-closed direction.
            _ => Default::default(),
        };
        // THE seam. Every verb's response passes through here, so identity is stamped once,
        // where the request id is in hand — a verb-local constructor has no way to omit it.
        let envelope = ReceiptEnvelope::stamp(&g.request_id, broker_metadata);
        // kept = the bytes the agent actually received (the narrowed, redacted result).
        let kept_bytes = serde_json::to_vec(&result)
            .map(|v| v.len() as u64)
            .unwrap_or(0);

        // Retain the FULL provider body as a content-addressed artifact + a kept-vs-total counter.
        // The ordered writes mirror the shell path (store_artifact_capped: stage → chain
        // `artifact_stored` → commit row) and land BEFORE the terminal event, which then
        // carries the handle+digest+wire_stats. A test double leaves `retained` None ⇒ no artifact,
        // no wire_stats (the terminal event keeps its pre-feature shape).
        let session = (!g.session_id.is_empty()).then_some(g.session_id.as_str());
        let mut retention_error: Option<String> = None;
        let (artifact, wire_stats) = match retained {
            Some(rb) => {
                let ws = Some(crate::WireStats {
                    total_bytes: rb.total_bytes,
                    kept_bytes,
                });
                // The retained bytes get the SAME vault-secret byte-level redaction the
                // narrowed result gets, BEFORE storing — a provider echoing the Authorization header
                // into a body must never persist the raw credential into an agent-readable artifact.
                let bytes = crate::redaction::redact_body_bytes(&rb.bytes, &secrets);
                match self.store_artifact_capped(
                    &g.request_id,
                    &bytes,
                    self.artifacts.max_bytes,
                    session,
                ) {
                    Ok(stored) => (Some(stored), ws),
                    Err(e) => {
                        // The grant is already consumed — a retention-store failure must
                        // never eat the terminal event below (a consumed-but-dark grant). Record the
                        // failure on the terminal event instead and carry on without a handle.
                        retention_error = Some(e.to_string());
                        (None, ws)
                    }
                }
            }
            None => (None, None),
        };

        let mut event_data = json!({
            "grant_id": grant_id,
            "request_id": g.request_id,
            // Structured verb identity: the report aggregate keys on these fields, never
            // on display summary text.
            "provider": g.provider,
            "action": g.action,
            "outcome": if ok { "ok" } else { "provider_error" },
            "mutation_invoked": mutation_invoked,
            "result": result,
            "request_session": g.session_id,
            "executing_session": executing_session,
        });
        // A response ARRIVED and it is a failure: the seam that read it typed why. The class is
        // broker-authored metadata about the response, never part of it — `result` stays the
        // verbatim body the response contract promises, byte-identical to the artifact.
        if !ok {
            event_data["failure_class"] = json!(failure_class
                .unwrap_or(crate::types::EffectFailureClass::Failed)
                .as_str());
        }
        if let Some(effect_id) = money.effect_id() {
            let observed = proof.ok_or_else(|| {
                Error::Integrity("a proving verb returned no effect observation".into())
            })?;
            event_data["effect_id"] = json!(effect_id);
            // THE OBSERVATION: what the compiled success contract could read in the body the
            // provider sent. It is the authoritative fact.
            event_data["effect_proof"] = json!(observed.as_str());
            // The DERIVED disposition, kept because crash recovery and the retry lineage gate read
            // it. It is computed from the observation above, in one place, and nothing upstream of
            // that derivation states a verdict.
            event_data["effect_outcome"] = json!(effect_outcome
                .ok_or_else(|| Error::Integrity(
                    "a proving verb returned no effect observation".into()
                ))?
                .as_str());
        }
        if let Some(st) = &artifact {
            event_data["artifact"] = json!(st.handle);
            event_data["digest"] = json!(st.digest);
        }
        if let Some(ws) = &wire_stats {
            event_data["wire_stats"] =
                json!({ "total_bytes": ws.total_bytes, "kept_bytes": ws.kept_bytes });
        }
        // The terminal record carries the envelope so a reconstructed receipt is the
        // same receipt. Always present — the envelope carries a mandatory identity.
        event_data["envelope"] = json!(envelope);
        if let Some(err) = &retention_error {
            event_data["retention_error"] = json!(err);
        }
        if let Some(pid) = exec.pid {
            event_data["executing_pid"] = json!(pid);
        }
        self.audit.record(NewEvent {
            session_id: Some(&g.session_id),
            event_type: if ok {
                "provider_action_succeeded"
            } else {
                "provider_action_failed"
            },
            severity: if ok { "info" } else { "high" },
            summary: &format!("{}.{} executed", g.provider, g.action),
            data: event_data,
            secrets: &secrets,
        })?;
        // Consume the grant only now that its terminal record is durable (audit-first,
        // like the shell finalizer). `g` predates the claim CAS, so the redigest carries the lease
        // stamps the row holds.
        let executed_digest =
            self.redigest_leased(grant_id, &g, "executed", lease_opened_at, lease_deadline);
        self.state.execute(
            "UPDATE grants SET status='executed', grant_digest=?2 WHERE id=?1 AND status='executing'",
            rusqlite::params![grant_id, executed_digest],
        )?;
        // A provider-level `ok=false` is the SOFT failure shape — the grant is `executed` but
        // the chained terminal event is a FAILURE. For a pipeline step this PAUSES the run (it does
        // not sweep): the gate reads this failure, and the model retries the step or abandons.

        Ok(ExecOutcome::Executed(ExecutionResult {
            ok,
            provider: g.provider,
            action: g.action,
            effect_id: money.effect_id().map(str::to_string),
            effect_outcome,
            result,
            artifact: artifact.map(|s| s.handle),
            wire_stats,
            envelope,
        }))
    }

    /// Execute a grant on behalf of an agent bound to `session`; the grant must belong to that session.
    pub fn execute_capability_in_session(
        &self,
        grant_id: &str,
        session: &str,
    ) -> Result<ExecutionResult> {
        // The ownership check below is this function's job; the grant digest check
        // is `claim_and_run`'s — it is not repeated here.
        let g = self.load_grant(grant_id)?;
        if g.session_id.as_str() != session {
            return Err(Error::Denied(format!(
                "grant {grant_id} is not in session '{session}'; an agent may only execute its \
                 own session's grants"
            )));
        }
        self.execute_capability(grant_id)
    }

    /// Execute a grant on behalf of an enrolled `principal`; the grant must be owned by that principal.
    pub fn execute_capability_for_principal(
        &self,
        grant_id: &str,
        principal: &str,
    ) -> Result<ExecutionResult> {
        // The ownership check below is this function's job; the grant digest check
        // is `claim_and_run`'s — it is not repeated here.
        let g = self.load_grant(grant_id)?;
        if g.principal_id.as_deref() != Some(principal) {
            return Err(Error::Denied(format!(
                "grant {grant_id}: principal '{principal}' does not own this grant"
            )));
        }
        self.execute_capability(grant_id)
    }

    /// Execute a grant that must be both in `session` and owned by `principal`.
    pub fn execute_capability_for_principal_in_session(
        &self,
        grant_id: &str,
        session: &str,
        principal: &str,
    ) -> Result<ExecutionResult> {
        // The ownership check below is this function's job; the grant digest check
        // is `claim_and_run`'s — it is not repeated here.
        let g = self.load_grant(grant_id)?;
        if g.session_id.as_str() != session {
            return Err(Error::Denied(format!(
                "grant {grant_id} is not in session '{session}'; an agent may only execute its \
                 own session's grants"
            )));
        }
        if g.principal_id.as_deref() != Some(principal) {
            return Err(Error::Denied(format!(
                "grant {grant_id}: principal '{principal}' does not own this grant"
            )));
        }
        self.execute_capability(grant_id)
    }

    /// Execute by the agent's stable handle — the agent-issued `request_id` ONLY. The agent never
    /// receives a `grant_id` on Ask (`request_capability` returns it only on Allow), so the
    /// operator-internal `grant_id` is NOT an acceptable handle here: a grant is addressed solely
    /// from the agent-held vocabulary, authorized by PRINCIPAL (uid), not session. The resolver
    /// matches `request_id` and `request_id` ONLY — a `grant_id` is structurally
    /// un-routable on this path because the query never inspects the `id` column — so a grant_id
    /// leaked through any operator surface cannot be replayed as an agent execute handle. The agent
    /// drives via short-lived CLI invocations, so session is audit-only and a distinct agent uid is
    /// the real ownership boundary. The daemon collapses every failure here to one opaque reason,
    /// so unknown / foreign-principal / unapproved / grant_id handles are
    /// indistinguishable to the agent.
    pub fn execute_request_for_principal(
        &self,
        request_id: &str,
        principal: &str,
    ) -> Result<ExecutionResult> {
        match self.execute_request_for_principal_attributed(
            request_id,
            principal,
            &ExecAttribution::default(),
        )? {
            ExecOutcome::Executed(r) => Ok(r),
        }
    }

    /// As [`Broker::execute_request_for_principal`], but returns the full [`ExecOutcome`] and
    /// attributes the audit event to the executing connection (`exec`, audit-only — never
    /// authorization). THE agent-socket execute path.
    pub fn execute_request_for_principal_attributed(
        &self,
        request_id: &str,
        principal: &str,
        exec: &ExecAttribution,
    ) -> Result<ExecOutcome> {
        // A caller-supplied session must still be OPEN, checked atomically here (before any
        // grant resolution or lease claim) so a concurrent sweep cannot close it in the daemon's
        // preflight gap. Fail closed — a closed/unknown supplied session never opens a lease.
        self.require_supplied_session_open(exec)?;
        // request_id-ONLY resolution: the agent path NEVER routes on the operator `id` column.
        let grant_id = self.resolve_grant_id_by_request_id(request_id)?;
        // The ownership check below is this function's job; the grant digest check
        // is `claim_and_run`'s — it is not repeated here.
        let g = self.load_grant(&grant_id)?;
        if g.principal_id.as_deref() != Some(principal) {
            return Err(Error::Denied(format!(
                "grant {grant_id}: principal '{principal}' does not own this grant"
            )));
        }
        self.claim_and_run(&grant_id, exec)
    }
}
