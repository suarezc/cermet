use super::helpers::*;
use super::*;

/// What a caller SELF-REPORTED about who is driving the session. Nothing here is attested, and
/// **no authority reads any of it** — it exists so this box's own receipts can say which runtime and
/// model produced a decision, and for nothing else.
///
/// Borrowed rather than owned: the caller already holds these strings off the wire, and a session
/// open is on the hot path of every agent conversation.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionActor<'a> {
    /// The MCP `initialize` handshake's `clientInfo.name`.
    pub client_name: Option<&'a str>,
    pub client_version: Option<&'a str>,
    /// The human's own `CERMET_AGENT_MODEL` declaration.
    pub model: Option<&'a str>,
}

/// Strip control characters and cap the length of a CLIENT-SUPPLIED label.
///
/// Every string this touches is written by a party we did not build and lands in a database an
/// operator reads, so no terminal escape may survive ingestion into a human review surface. One
/// function, so a new self-report cannot arrive without the same treatment.
fn defang_label(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(AGENT_LABEL_MAX)
        .collect()
}

impl Broker {
    pub(super) fn now_epoch(&self) -> i64 {
        match self.clock_override.get() {
            Some(t) => {
                // Test-only within-handler drift: advance the override so a later read in the
                // same handler observes a strictly later clock.
                #[cfg(test)]
                {
                    let step = self.clock_tick.get();
                    if step != 0 {
                        self.clock_override.set(Some(t + step));
                    }
                }
                t
            }
            None => crate::util::now_epoch(),
        }
    }

    #[cfg(test)]
    pub(super) fn set_now(&self, epoch: i64) {
        self.clock_override.set(Some(epoch));
    }

    #[cfg(feature = "test-double")]
    pub fn set_now_for_test(&self, epoch: i64) {
        self.clock_override.set(Some(epoch));
    }

    /// Test-only: make every `now_epoch()` read advance the frozen clock by `step` (0 = frozen), so a
    /// test can reproduce the real within-handler clock drift the budget gate must be immune to.
    #[cfg(test)]
    pub(super) fn set_clock_tick(&self, step: i64) {
        self.clock_tick.set(step);
    }

    pub(super) fn current_sentence_authority(&self) -> Result<(crate::sentence::RuleSet, String)> {
        let source = self.sentence_authority.as_ref().ok_or_else(|| {
            Error::Denied("sentence authority source is not configured".to_string())
        })?;
        let authority = source.current_authority().map_err(|error| {
            Error::Denied(format!("sentence authority source is unavailable: {error}"))
        })?;
        Ok((authority.rules, authority.digest))
    }

    pub(super) fn lockdown_engaged(&self) -> bool {
        self.lockdown_source
            .as_ref()
            .is_some_and(|source| source.is_engaged())
    }

    pub(super) fn enforce_not_locked_down(&self, operation: &str) -> Result<()> {
        if self.lockdown_engaged() {
            return Err(Error::Denied(format!(
                "owner lockdown is engaged; {operation} is disabled"
            )));
        }
        Ok(())
    }

    /// Persist ONE `requests` row. Every request lands here — allow, ask, and every deny class — so
    /// a denial is never structurally invisible (it mints no grant, hence no console row). The
    /// submitted resource is REDACTED before it is stored: a secret-classed field is known from the
    /// resolved contract at request time, so its value never persists at rest in
    /// `requests.resource_json` (a deny never executes, so unlike a grant it need not retain the
    /// value). Only the redaction marker is stored. Every OTHER value is retained as submitted — a
    /// denial row's job is to say what was asked for. `matched_rule` is the canonical printed text
    /// of the admitting sentence rule on an allow — the rule's identity is its text, not its file
    /// position — and NULL on every deny (nothing admitted it).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_request(
        &self,
        request_id: &str,
        req: &CapabilityRequest,
        decision: &str,
        reason: &str,
        principal: &str,
        session: &str,
        authority_fingerprint: Option<&str>,
        matched_rule: Option<&str>,
        deny_reason: Option<&crate::sentence::DenyReason>,
    ) -> Result<()> {
        let stored_resource = match self.suggestion_contract(&req.provider, &req.action) {
            Some(contract) => redact_secret_fields(contract, req.resource.clone()),
            // With no contract resolved (misspelled/unsupported/unregistered action) there are no
            // field classes to redact against — and this row is the ONLY record that someone wanted
            // a verb we do not gate, so its values are retained, size-capped. Accepted residual: a
            // capped self-labelled secret can land here.
            None => cap_field_values(req.resource.clone()),
        };
        let resource_json =
            serde_json::to_string(&stored_resource).unwrap_or_else(|_| "null".into());
        let authority_fingerprint = authority_fingerprint.unwrap_or("unavailable");
        // The evaluator's OWN typed refusal, stored whole beside the prose it was rendered into.
        // It is the `DenyReason` the sentence evaluator produced, serialized by its own serde — no
        // second vocabulary, and nothing here parses the sentence above it.
        let deny_reason_json = deny_reason.and_then(|reason| serde_json::to_string(reason).ok());
        // The agent's own per-request model claim, de-fanged at the SAME seam as every
        // other client-supplied label: control characters stripped, length capped. It is stored, and
        // nothing reads it to decide anything.
        let agent_model = req.model.as_deref().map(defang_label);
        self.state.execute(
            "INSERT INTO requests (id, provider, action, resource_json, justification, decision, reason, policy_fingerprint, matched_rule, deny_reason_json, principal, session_id, pid, created_at, agent_model)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![
                request_id,
                req.provider,
                req.action,
                resource_json,
                req.justification,
                decision,
                reason,
                authority_fingerprint,
                matched_rule,
                deny_reason_json,
                principal,
                session,
                Option::<i64>::None,
                now_rfc3339(),
                agent_model
            ],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn deny(
        &self,
        session: &str,
        request_id: &str,
        req: &CapabilityRequest,
        reason: &str,
        deny_class: &str,
        scope: Option<&Value>,
        hint: Option<&str>,
        secrets: &[String],
        principal: &str,
        authority_kind: AuthorityKind,
        authority_fingerprint: &str,
        deny_reason: Option<&crate::sentence::DenyReason>,
    ) -> Result<RequestOutcome> {
        let mut event_data = json!({
            "provider": req.provider,
            "action": req.action,
            "deny_class": deny_class,
            "authority_kind": authority_kind,
            "authority_fingerprint": authority_fingerprint,
        });
        if deny_class == "policy" {
            if let Some(resource) = scope {
                if let Ok(Some(shape)) = widening_shape(
                    self.suggestion_contract(&req.provider, &req.action),
                    &req.provider,
                    &req.action,
                    resource,
                ) {
                    event_data["denied_base_key"] = json!(shape.key);
                    event_data["denied_names"] =
                        json!(shape.names.iter().cloned().collect::<Vec<_>>());
                }
            }
        }
        if authority_kind == AuthorityKind::Sentence {
            if let Some(resource) = scope {
                let safe_resource = self
                    .suggestion_contract(&req.provider, &req.action)
                    .map(|contract| redact_secret_fields(contract, resource.clone()))
                    .unwrap_or_else(|| cap_field_values(resource.clone()));
                event_data["canonical_request"] = json!({
                    "provider": req.provider,
                    "action": req.action,
                    "resource": safe_resource,
                });
            }
            if let Some(hint) = hint {
                event_data["hint"] = json!(hint);
            }
        }
        self.audit.record(NewEvent {
            session_id: Some(session),
            event_type: "capability_denied",
            severity: "high",
            summary: reason,
            data: event_data,
            secrets,
        })?;
        // Record the request row BEFORE returning — the whole point of the requests table is that a
        // deny is no longer silent. `unregistered`/`unsupported` keep their own decision; every other
        // class (policy, invalid canonicalization) records the generic `deny`.
        let request_decision = match deny_class {
            "unregistered" => "unregistered",
            "unsupported" => "unsupported",
            _ => "deny",
        };
        self.record_request(
            request_id,
            req,
            request_decision,
            reason,
            principal,
            session,
            Some(authority_fingerprint),
            None,
            deny_reason,
        )?;
        Ok(RequestOutcome {
            request_id: request_id.into(),
            decision: Decision::Deny,
            reason: reason.into(),
            budget_exceeded: None,
            hint: hint.map(str::to_string),
            grant_id: None,
            effect_id: None,
            authority_kind: (deny_class == "policy").then_some(authority_kind),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn insert_grant(
        &self,
        id: &str,
        request_id: &str,
        session: &str,
        req: &CapabilityRequest,
        resource: &CanonicalResource,
        evidence_json: &str,
        money_json: &str,
        status: GrantStatus,
        decision: Decision,
        principal: Option<&str>,
        // Canonical source-authenticated sentence authority digest.
        authority_fingerprint: &str,
        // For a budget/rate grant, the mint ticket's SINGLE captured expiry
        // (`decision_at_epoch + TTL`) — the grant's `expiry_epoch` MUST equal the `budget_mint`'s
        // `expires_at_epoch` so the mint-driven sweep never frees capacity while the grant is still
        // executable. `None` for a non-budget grant (samples `now_epoch() + TTL`).
        expiry_epoch_override: Option<i64>,
    ) -> Result<()> {
        let resource_json = resource.to_canonical_json();
        let frozen_value = serde_json::from_str::<Value>(&resource_json).map_err(|error| {
            Error::Invalid(format!("frozen resource is not valid JSON: {error}"))
        })?;
        let contract = self
            .providers
            .get(&req.provider)
            .and_then(|provider| provider.action_contract(&req.action));
        let environment = projected_environment(contract, &frozen_value);
        let expiry_epoch =
            expiry_epoch_override.unwrap_or_else(|| self.now_epoch() + GRANT_TTL_SECS);
        // Freeze the ratified template's content hash onto the grant (None for a built-in action).
        // The HTTP recipe is authority; binding it here makes a post-authorization template edit
        // fail the execute-time freshness check below.
        let template_hash = self.templates.content_hash(&req.provider, &req.action);
        // Freeze the loaded provider-descriptor hash onto the grant. A registered provider always
        // has a descriptor (the registry is built from descriptors); fail closed if it is somehow
        // absent — a grant must never mint without the descriptor binding.
        let descriptor_hash = self.descriptor_hash(&req.provider).ok_or_else(|| {
            Error::Invalid(format!(
                "provider {} has no loaded descriptor; refusing to mint a grant without its \
                 descriptor binding",
                req.provider
            ))
        })?;
        if authority_fingerprint.is_empty() {
            return Err(Error::Invalid(
                "sentence grant missing its canonical authority digest".into(),
            ));
        }
        let (approved_by_kind, approved_at): (Option<&str>, Option<String>) = match decision {
            Decision::Allow => (Some("sentence"), Some(now_rfc3339())),
            _ => (None, None),
        };
        let approver: Option<&str> = None;
        let digest = grant_digest(
            &self.grant_key,
            id,
            request_id,
            &req.provider,
            &req.action,
            &resource_json,
            evidence_json,
            money_json,
            decision_str(decision),
            authority_fingerprint,
            status_str(status),
            session,
            descriptor_hash,
            Some(expiry_epoch),
            principal,
            template_hash.as_deref(),
            approved_by_kind,
            approver,
            approved_at.as_deref(),
            None,
            None,
        );
        self.state.execute(
              "INSERT INTO grants (id, request_id, session_id, provider, action, resource_json, evidence_json, money_json, environment, status, decision, created_at, policy_fingerprint, grant_digest, expiry_epoch, principal_id, template_hash, descriptor_hash, approved_by_kind, approver, approved_at)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
              rusqlite::params![
                  id, request_id, session, req.provider, req.action, resource_json,
                  evidence_json, money_json, environment, status_str(status), decision_str(decision), now_rfc3339(), authority_fingerprint, digest, expiry_epoch, principal, template_hash, descriptor_hash,
                  approved_by_kind, approver, approved_at
              ],
          )?;
        Ok(())
    }

    pub(super) fn load_grant(&self, id: &str) -> Result<GrantRow> {
        self.state
            .query_row(
                  "SELECT session_id, provider, action, resource_json, evidence_json, money_json, status, policy_fingerprint, decision, grant_digest, expiry_epoch, principal_id, template_hash, descriptor_hash, approved_by_kind, approver, approved_at, request_id, lease_opened_at, lease_deadline FROM grants WHERE id=?1",
                  rusqlite::params![id],
                  |r| {
                      let persisted_status = r.get::<_, String>(6)?;
                      let status = parse_status(&persisted_status).map_err(|error| {
                          rusqlite::Error::FromSqlConversionFailure(
                              6,
                              rusqlite::types::Type::Text,
                              Box::new(error),
                          )
                      })?;
                      Ok(GrantRow {
                          session_id: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                          provider: r.get(1)?,
                          action: r.get(2)?,
                           resource_json: r.get::<_, String>(3)?,
                           evidence_json: r.get::<_, String>(4)?,
                           money_json: r.get::<_, String>(5)?,
                           status,
                           policy_fingerprint: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                           decision: r.get::<_, String>(8)?,
                           grant_digest: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
                           expiry_epoch: r.get(10)?,
                           principal_id: r.get::<_, Option<String>>(11)?,
                           template_hash: r.get::<_, Option<String>>(12)?,
                           descriptor_hash: r.get::<_, String>(13)?,
                           approved_by_kind: r.get::<_, Option<String>>(14)?,
                           approver: r.get::<_, Option<String>>(15)?,
                           approved_at: r.get::<_, Option<String>>(16)?,
                           request_id: r.get::<_, String>(17)?,
                           lease_opened_at: r.get::<_, Option<i64>>(18)?,
                           lease_deadline: r.get::<_, Option<i64>>(19)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("grant {id}")))
    }

    pub(super) fn redigest(&self, id: &str, g: &GrantRow, status: &str) -> String {
        grant_digest(
            &self.grant_key,
            id,
            &g.request_id,
            &g.provider,
            &g.action,
            &g.resource_json,
            &g.evidence_json,
            &g.money_json,
            &g.decision,
            &g.policy_fingerprint,
            status,
            &g.session_id,
            &g.descriptor_hash,
            g.expiry_epoch,
            g.principal_id.as_deref(),
            g.template_hash.as_deref(),
            g.approved_by_kind.as_deref(),
            g.approver.as_deref(),
            g.approved_at.as_deref(),
            g.lease_opened_at,
            g.lease_deadline,
        )
    }

    /// As [`redigest`], but with the lease stamps OVERRIDDEN — the claim CAS computes the new
    /// digest BEFORE the row carries the stamps.
    pub(super) fn redigest_leased(
        &self,
        id: &str,
        g: &GrantRow,
        status: &str,
        lease_opened_at: i64,
        lease_deadline: i64,
    ) -> String {
        grant_digest(
            &self.grant_key,
            id,
            &g.request_id,
            &g.provider,
            &g.action,
            &g.resource_json,
            &g.evidence_json,
            &g.money_json,
            &g.decision,
            &g.policy_fingerprint,
            status,
            &g.session_id,
            &g.descriptor_hash,
            g.expiry_epoch,
            g.principal_id.as_deref(),
            g.template_hash.as_deref(),
            g.approved_by_kind.as_deref(),
            g.approver.as_deref(),
            g.approved_at.as_deref(),
            Some(lease_opened_at),
            Some(lease_deadline),
        )
    }

    pub(super) fn assert_grant_integrity(&self, grant_id: &str, g: &GrantRow) -> Result<()> {
        let expected = self.redigest(grant_id, g, status_str(g.status));
        if !constant_time_eq(g.grant_digest.as_bytes(), expected.as_bytes()) {
            return Err(Error::Denied(format!(
                "grant {grant_id} failed its integrity check (tampered store)"
            )));
        }
        let money = crate::money::MoneyMetadata::from_canonical_json(&g.money_json)
            .map_err(Error::Integrity)?;
        let loaded = self.templates.loaded(&g.provider, &g.action);
        let action_is_money = loaded.is_some_and(|loaded| loaded.template.is_money());
        if action_is_money != money.is_money() {
            return Err(Error::Integrity(format!(
                "grant {grant_id} money metadata does not match its signed action template"
            )));
        }
        if let Some(loaded) = loaded.filter(|loaded| loaded.template.is_money()) {
            let live_fingerprint = loaded.template.precondition_fingerprint().ok_or_else(|| {
                Error::Integrity("money precondition implementation is unavailable".into())
            })?;
            if money.precondition_fingerprint() != Some(live_fingerprint.as_str()) {
                return Err(Error::Integrity(format!(
                    "grant {grant_id} money precondition semantics changed"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn expire_grant(&self, id: &str, g: &GrantRow) -> Result<()> {
        let digest = self.redigest(id, g, "expired");
        self.state.execute(
            "UPDATE grants SET status='expired', grant_digest=?2 WHERE id=?1",
            rusqlite::params![id, digest],
        )?;
        self.audit.record(NewEvent {
            session_id: Some(&g.session_id),
            event_type: "grant_expired",
            severity: "medium",
            summary: &format!("grant {id} expired before use"),
            data: json!({ "grant_id": id }),
            secrets: &self.vault.all_secrets()?,
        })?;
        // Budget release, RELEASE-second (the status is already `expired` above): a
        // Requested/Approved grant that TTL-lapsed was never invoked, so void its own `budget_mint`.
        // An Executing lease (abandoned/swept) may have crossed the `provider.execute` effect boundary
        // — KEEP its debit. No-op for a non-budget grant.
        if matches!(g.status, GrantStatus::Requested | GrantStatus::Approved) {
            self.release_budget_for_grant(id, super::budget::BudgetReleaseCause::ExpiredUnclaimed)?;
        }
        Ok(())
    }

    /// Boot-time convergence: flip any `requested` grant whose TTL has already lapsed to
    /// `expired`. Expiry is otherwise lazy, so a never-touched pre-cutover requested row would
    /// linger forever. Goes through `expire_grant` (redigest + audit) rather than a raw UPDATE so
    /// integrity/audit stay correct. Fail-safe like the artifact purge on boot: a query fault or
    /// one bad row must not brick boot for the rest, so the enumeration fault is swallowed and
    /// each flip is best-effort (`let _`). Also the DURABLE custody backstop — terminalize every
    /// `executing` lease whose HMAC-covered claim-time deadline has lapsed with no report. It is
    /// error-aware and idempotent: the honest `lease_abandoned` record lands FIRST (re-checked,
    /// never duplicated), so a flip is never durable without its record; any failed half leaves
    /// the row `executing` (or the run only partially swept) and the NEXT sweep — or the
    /// typed-proof path's healing — completes it. Revoke-only: a swept lease is never reminted or
    /// re-executed. Returns the count of leases fully terminalized this pass.
    pub fn sweep_overdue_leases(&self) -> usize {
        let now = self.now_epoch();
        let ids: Vec<String> = match self
            .state
            .prepare(
                "SELECT id FROM grants \
                 WHERE status = 'executing' AND lease_deadline IS NOT NULL AND lease_deadline < ?1",
            )
            .and_then(|mut stmt| {
                stmt.query_map(rusqlite::params![now], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            }) {
            Ok(ids) => ids,
            Err(_) => return 0,
        };
        let mut swept = 0;
        for id in ids {
            let Ok(g) = self.load_grant(&id) else {
                continue;
            };
            // A tampered row is never silently redigested by a sweep — the integrity surfaces
            // (views/verify) own reporting it; the sweep skips it. The digest covers the lease
            // stamps, and this row was selected BY its deadline, so the stamps are present.
            if self.assert_grant_integrity(&id, &g).is_err() {
                continue;
            }
            // A terminal report may have chained before the state flip and then crossed its deadline
            // while the daemon was down. Exact verified terminal evidence wins before abandonment.
            match self.reconcile_terminal_execution(&id, &g) {
                Ok(Some(_)) => {
                    swept += 1;
                    continue;
                }
                Ok(None) => {}
                Err(_) => continue,
            }
            // Any failed half leaves the row re-selectable (still `executing`) or heals at the
            // next pass / the typed-proof path — never a typed proof over a half-terminalized run.
            if self.terminalize_abandoned_lease(&id, &g).is_err() {
                continue;
            }
            swept += 1;
        }
        swept
    }

    /// Boot-time audit-first convergence for every executing grant, including leases whose deadline
    /// has not elapsed. Malformed evidence stays executing and fail-closed; the overdue sweep will
    /// likewise refuse to overwrite it with abandonment.
    pub(super) fn reconcile_terminal_executions_on_boot(&self) {
        let ids: Vec<String> = match self
            .state
            .prepare("SELECT id FROM grants WHERE status = 'executing'")
            .and_then(|mut stmt| {
                stmt.query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            }) {
            Ok(ids) => ids,
            Err(_) => return,
        };
        for id in ids {
            let Ok(grant) = self.load_grant(&id) else {
                continue;
            };
            if self.assert_grant_integrity(&id, &grant).is_ok() {
                let _ = self.reconcile_terminal_execution(&id, &grant);
            }
        }
    }

    /// The ordered, idempotent halves of abandoning an overdue lease, shared by the sweep and the
    /// finalize-side overdue gate: (1) the honest `lease_abandoned` audit record —
    /// FIRST, and re-checked so a retry never duplicates it; a flipped row therefore always has
    /// its record. (2) the terminal flip: the lease is reclaimed to `expired`. Any error propagates
    /// with the row still re-selectable — the caller retries; no typed proof is emitted on this path.
    pub(super) fn terminalize_abandoned_lease(&self, grant_id: &str, g: &GrantRow) -> Result<()> {
        if !self.audit.lease_abandoned_event_exists(
            grant_id,
            &g.request_id,
            &g.grant_digest,
            g.lease_opened_at,
            g.lease_deadline,
        )? {
            self.audit.record(NewEvent {
                session_id: (!g.session_id.is_empty()).then_some(g.session_id.as_str()),
                event_type: "lease_abandoned",
                severity: "high",
                summary: &format!(
                    "execution lease for {}.{} abandoned — deadline passed with no report",
                    g.provider, g.action
                ),
                data: json!({
                    "grant_id": grant_id,
                    "request_id": g.request_id,
                    "grant_digest": g.grant_digest,
                    "lease_opened_at": g.lease_opened_at,
                    "lease_deadline": g.lease_deadline,
                    // HONEST: the sweep cannot know the child's result — only that none arrived.
                    "outcome": "unreported",
                }),
                secrets: &self.vault.all_secrets()?,
            })?;
        }
        self.expire_grant(grant_id, g)?;
        Ok(())
    }

    pub(super) fn sweep_expired_requested_grants(&self) {
        let now = self.now_epoch();
        let ids: Vec<String> = match self
            .state
            .prepare(
                "SELECT id FROM grants \
                 WHERE status = 'requested' AND expiry_epoch IS NOT NULL AND expiry_epoch < ?1",
            )
            .and_then(|mut stmt| {
                stmt.query_map(rusqlite::params![now], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            }) {
            Ok(ids) => ids,
            Err(_) => return,
        };
        for id in ids {
            if let Ok(g) = self.load_grant(&id) {
                if self.assert_grant_integrity(&id, &g).is_ok() {
                    let _ = self.expire_grant(&id, &g);
                }
            }
        }
    }

    /// Authority cutover: authenticate and terminalize every unclaimed grant that was minted by a
    /// pre-sentence authority path. Running before either socket serves prevents persisted profile,
    /// human-approval, or test-window rows from surviving the removal of those writers. Executing
    /// leases are deliberately untouched: their effect may already have happened, so only their
    /// evidence-only report/sweep path may settle them.
    pub(super) fn terminalize_pre_sentence_grants_on_boot(&self) -> Result<usize> {
        let ids: Vec<String> = {
            let mut statement = self.state.prepare(
                "SELECT id FROM grants WHERE status IN ('requested', 'approved') \
                 AND COALESCE(approved_by_kind, '') != 'sentence' ORDER BY id",
            )?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let prior_events = self
            .audit
            .events_of_type("authority_cutover_terminalized")?;
        let secrets = self.vault.all_secrets()?;
        let mut terminalized = 0;
        for id in ids {
            let grant = self.load_grant(&id)?;
            self.assert_grant_integrity(&id, &grant)?;
            if !prior_events
                .iter()
                .any(|event| event.data.get("grant_id").and_then(Value::as_str) == Some(&id))
            {
                self.audit.record(NewEvent {
                    session_id: (!grant.session_id.is_empty()).then_some(grant.session_id.as_str()),
                    event_type: "authority_cutover_terminalized",
                    severity: "high",
                    summary: "pre-sentence unclaimed grant terminalized at authority cutover",
                    data: json!({
                        "grant_id": id,
                        "request_id": grant.request_id,
                        "provider": grant.provider,
                        "action": grant.action,
                        "prior_status": status_str(grant.status),
                        "prior_authority_kind": grant.approved_by_kind,
                        "mutation_invoked": false,
                    }),
                    secrets: &secrets,
                })?;
            }
            let digest = self.redigest(&id, &grant, "expired");
            let changed = self.state.execute(
                "UPDATE grants SET status='expired', grant_digest=?2 WHERE id=?1 \
                 AND status IN ('requested', 'approved')",
                rusqlite::params![id, digest],
            )?;
            if changed == 1 {
                self.release_budget_for_grant(
                    &id,
                    super::budget::BudgetReleaseCause::AuthorityCutoverUnclaimed,
                )?;
                terminalized += 1;
            }
        }
        Ok(terminalized)
    }

    /// Atomic gate: if `exec` names a CALLER-SUPPLIED session (`require_session_open`), refuse
    /// unless that session is still OPEN. Runs inside the same core call as the gated execute/finalize,
    /// so a concurrent sweep/close cannot slip between this check and the action. Fail closed.
    pub(super) fn require_supplied_session_open(&self, exec: &ExecAttribution) -> Result<()> {
        if exec.require_session_open {
            if let Some(sid) = exec.session_id.as_deref() {
                if !self.session_open_for_peer(sid, exec.peer_uid)? {
                    return Err(Error::SessionExpired);
                }
            }
        }
        Ok(())
    }

    /// The combined still-OPEN + owned-by-the-attested-peer gate for a CALLER-SUPPLIED session id,
    /// fetched in ONE query so it is atomic within this actor turn. A closed/unknown id is false.
    /// When the caller ATTESTS a peer uid (the daemon always does), the session's recorded
    /// `owner_uid` must be present AND equal — a NULL-owned row refuses too, otherwise a leaked
    /// ownerless `sess_*` would pass for any peer. Only a peerless caller (the local same-uid
    /// convenience path and tests — no peercred to attest) skips the ownership check. Fail closed:
    /// the caller turns `false` into `SessionExpired`.
    pub(super) fn session_open_for_peer(
        &self,
        session_id: &str,
        peer_uid: Option<i64>,
    ) -> Result<bool> {
        let owner: Option<Option<i64>> = self
            .state
            .query_row(
                "SELECT owner_uid FROM sessions WHERE id = ?1 AND status = 'open'",
                rusqlite::params![session_id.trim()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match owner {
            None => false,
            Some(stored) => match peer_uid {
                Some(attested) => stored == Some(attested),
                None => true,
            },
        })
    }

    /// Lazily create the session row on first use. The caller's attested peer uid (when it has one
    /// — every daemon path does) is recorded as the owner so no daemon-created row is ownerless;
    /// the conflict no-op keeps an existing row's owner immutable.
    pub(super) fn ensure_session(&self, session: &str, owner_uid: Option<i64>) -> Result<()> {
        let authority_digest = self
            .current_sentence_authority()
            .map(|(_, digest)| digest)
            .unwrap_or_else(|_| "unavailable".to_string());
        self.ensure_session_with_fingerprint(session, owner_uid, &authority_digest)
    }

    pub(super) fn ensure_session_with_fingerprint(
        &self,
        session: &str,
        owner_uid: Option<i64>,
        authority_fingerprint: &str,
    ) -> Result<()> {
        self.state.execute(
            "INSERT INTO sessions (id, created_at, status, policy_fingerprint, owner_uid)
             VALUES (?1, ?2, 'open', ?3, ?4)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![session, now_rfc3339(), authority_fingerprint, owner_uid],
        )?;
        Ok(())
    }

    /// Open a session up front, stamping provenance (the agent command and child pid).
    ///
    /// `actor` is the SELF-REPORTED story of who is driving, captured for the local receipt only.
    ///
    /// The agent label is CLIENT-supplied (`CERMET_AGENT_NAME` via `Hello`), so it is de-fanged
    /// here at ingestion — control characters stripped (no terminal escapes into the human review
    /// surfaces) and length capped — covering every present and future render path.
    pub fn open_session(
        &self,
        session_id: &str,
        agent_cmd: &str,
        pid: Option<i64>,
        owner_uid: Option<i64>,
        actor: SessionActor<'_>,
    ) -> Result<()> {
        let session = session_id.trim();
        if session.is_empty() {
            return Err(Error::Denied("cannot open a blank session".into()));
        }
        let agent_cmd = defang_label(agent_cmd);
        let authority_digest = self
            .current_sentence_authority()
            .map(|(_, digest)| digest)
            .unwrap_or_else(|_| "unavailable".to_string());
        // Bind the session to the peer that minted it. A later CALLER-SUPPLIED use of this id
        // must come from the same attested uid (checked in `require_supplied_session_open`). The
        // conflict update never rewrites `owner_uid` — a session's minting peer is immutable.
        // The self-reports get the SAME de-fanging as the agent label, for the same reason: every
        // one of them is written by a party we did not build, and they land in a database an
        // operator reads. Control characters stripped, length capped.
        let client_name = actor.client_name.map(defang_label);
        let client_version = actor.client_version.map(defang_label);
        let model = actor.model.map(defang_label);
        self.state.execute(
            "INSERT INTO sessions (id, created_at, status, policy_fingerprint, agent, pid, owner_uid,
                                   client_name, client_version, agent_model)
             VALUES (?1, ?2, 'open', ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET agent = excluded.agent, pid = excluded.pid,
                                           client_name = excluded.client_name,
                                           client_version = excluded.client_version,
                                           agent_model = excluded.agent_model",
            rusqlite::params![
                session,
                now_rfc3339(),
                authority_digest,
                agent_cmd,
                pid,
                owner_uid,
                client_name,
                client_version,
                model
            ],
        )?;
        Ok(())
    }

    /// Close a session when the agent exits (or the idle sweep reclaims it), stamping `ended_at` and
    /// flipping `status` to `closed`. The grants minted under it are untouched.
    pub fn close_session(&self, session_id: &str) -> Result<()> {
        self.state.execute(
            "UPDATE sessions SET ended_at = ?2, status = 'closed' WHERE id = ?1",
            rusqlite::params![session_id, now_rfc3339()],
        )?;
        Ok(())
    }

    /// True iff `session_id` names an existing OPEN session row. The daemon's handshake path uses this
    /// to REFUSE a caller-supplied session id that does not reference a live session (fail closed —
    /// never silently mint a session to satisfy an unknown/expired id).
    pub fn session_open(&self, session_id: &str) -> Result<bool> {
        let n: i64 = self.state.query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = ?1 AND status = 'open'",
            rusqlite::params![session_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Opportunistic idle-session sweep (run at the handshake): close every OPEN session whose last
    /// activity is older than `idle_secs`, EXCEPT `keep` (the just-minted handshake session). "Last
    /// activity" is the newest of the session's own `created_at` and the `created_at` of any grant it
    /// owns — the cheapest correct signal wholly inside `state.db` (no audit-log scan). Returns the
    /// number of sessions swept closed. Best-effort reclamation, not a security boundary.
    pub fn sweep_idle_sessions(&self, keep: &str, idle_secs: i64) -> Result<u64> {
        let cutoff = rfc3339_of_epoch(self.now_epoch() - idle_secs);
        // Sweep through `close_session` (not a bulk UPDATE) so the operation cascade runs for a
        // swept session exactly as for any other session end. Small-N local daemon; per-session
        // cost is fine.
        let idle: Vec<String> = {
            let mut stmt = self.state.prepare(
                "SELECT id FROM sessions
                  WHERE status = 'open'
                    AND id != ?1
                    AND COALESCE(
                          (SELECT MAX(created_at) FROM grants WHERE grants.session_id = sessions.id),
                          sessions.created_at
                        ) < ?2",
            )?;
            let rows =
                stmt.query_map(rusqlite::params![keep, cutoff], |r| r.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut closed = 0u64;
        for sid in idle {
            match self.close_session(&sid) {
                Ok(()) => closed += 1,
                // Best-effort per session — one faulting close must not block the rest of the
                // sweep, and the still-open session stays eligible for the next sweep's retry.
                Err(e) => eprintln!(
                    "cermet: idle sweep could not close session {sid}: {e} (will retry next sweep)"
                ),
            }
        }
        Ok(closed)
    }
}
