use super::helpers::*;
use super::*;
use crate::types::EffectState;

struct AllGrantsSnapshot {
    grants: Vec<GrantView>,
    lifecycle: Vec<GrantLifecycle>,
}

struct GrantLifecycle {
    id: String,
    status: String,
    lease_opened_at: Option<i64>,
    lease_deadline: Option<i64>,
}

/// One session's row in the actor lookup: what it SELF-REPORTED, plus the one thing it did not
/// report — whether it came in over the agent socket at all.
///
/// Local-view only. Every string is held in full here, because this is the operator's own view; the
/// operator's own receipt view renders them; nothing leaves the box.
struct SessionActorRow {
    client_name: Option<String>,
    client_version: Option<String>,
    model: Option<String>,
    agent_session: bool,
}

impl Broker {
    /// Contract resolution for a grant READ view. A receipt renders its frozen resource AS
    /// RECORDED: the durable record is the evidence, and a later vocabulary edit cannot change what
    /// was approved. When the live template still matches the grant's frozen `template_hash` we
    /// render THROUGH its contract, so a Secret-class field (structurally absent from today's
    /// request vocabulary, but the guard stays enforceable) is never shown raw. When the template
    /// has drifted, or no contract resolves, there is nothing to redact against and the resource is
    /// rendered verbatim — never suppressed.
    pub(super) fn frozen_contract(
        &self,
        provider: &str,
        action: &str,
        frozen: Option<&str>,
    ) -> FrozenContract {
        // A NULL frozen hash is a built-in action (template actions always freeze `Some(hash)`) and
        // has no template bytes to drift from; a `Some(hash)` matches only while the live template's
        // bytes still hash equal.
        let matches = match frozen {
            None => true,
            Some(h) => self.templates.content_hash(provider, action).as_deref() == Some(h),
        };
        match matches
            .then(|| self.templates.resolve(provider, action))
            .flatten()
        {
            Some(c) => FrozenContract::Live(c),
            None => FrozenContract::Raw,
        }
    }

    /// Render a grant's stored `resource_json` for a view: redact Secret fields when the template is
    /// live, render the record verbatim when the frozen template has drifted or resolves to no
    /// contract. Every view path routes through here so none can drift from the rule.
    pub(super) fn render_grant_resource(
        &self,
        provider: &str,
        action: &str,
        frozen: Option<&str>,
        resource_json: &str,
    ) -> Value {
        let resource = serde_json::from_str(resource_json).unwrap_or(Value::Null);
        match self.frozen_contract(provider, action, frozen) {
            FrozenContract::Live(contract) => {
                summarize_large_payloads(contract, redact_secret_fields(contract, resource))
            }
            FrozenContract::Raw => resource,
        }
    }

    /// Build one redacted [`GrantView`] from a full grant row (the columns of [`GRANT_VIEW_COLUMNS`],
    /// in order). Recomputes the per-grant HMAC over every signed column, including durable authority
    /// provenance, so a raw store-tamper of any of them surfaces as `integrity_ok = false`. Every
    /// grant read path funnels through here so none can drift from the digest or the fail-closed
    /// resource-redaction rule.
    fn grant_view_from_row(&self, r: &rusqlite::Row) -> rusqlite::Result<GrantView> {
        let id: String = r.get(0)?;
        let session_id: Option<String> = r.get(1)?;
        let provider: String = r.get(2)?;
        let action: String = r.get(3)?;
        let resource_json: String = r.get(4)?;
        let _stored_environment: Option<String> = r.get(5)?;
        let status: String = r.get(6)?;
        parse_status(&status).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
        let decision: String = r.get(7)?;
        let created_at: String = r.get(8)?;
        let policy_fingerprint: String = r.get::<_, Option<String>>(9)?.unwrap_or_default();
        let stored_digest: String = r.get::<_, Option<String>>(10)?.unwrap_or_default();
        let expiry_epoch: Option<i64> = r.get(11)?;
        let principal_id: Option<String> = r.get(12)?;
        let template_hash: Option<String> = r.get(13)?;
        // Index 14 is the REQUIRED provider-descriptor hash, folded into the digest so a store edit
        // (or a descriptor swap) flags `integrity_ok=false`.
        let descriptor_hash: String = r.get(14)?;
        let approved_by_kind: Option<String> = r.get(15)?;
        let approver: Option<String> = r.get(16)?;
        let approved_at: Option<String> = r.get(17)?;
        // Index 18: `request_id` is a SIGNED field folded into the digest (a store edit
        // of the cross-reference handle flags `integrity_ok=false`). It is NOT NULL on every grant.
        let request_id: Option<String> = r.get(18)?;
        // Indices 19/20: the claim-time lease stamps, folded into the recomputed
        // digest so a raw edit of the deadline the overdue sweep enforces flags integrity_ok=false.
        let lease_opened_at: Option<i64> = r.get(19)?;
        let lease_deadline: Option<i64> = r.get(20)?;
        let evidence_json: String = r.get(21)?;
        let money_json: String = r.get(22)?;
        let session_for_digest = session_id.clone().unwrap_or_default();
        let expected = grant_digest(
            &self.grant_key,
            &id,
            request_id.as_deref().unwrap_or_default(),
            &provider,
            &action,
            &resource_json,
            &evidence_json,
            &money_json,
            &decision,
            &policy_fingerprint,
            &status,
            &session_for_digest,
            &descriptor_hash,
            expiry_epoch,
            principal_id.as_deref(),
            template_hash.as_deref(),
            approved_by_kind.as_deref(),
            approver.as_deref(),
            approved_at.as_deref(),
            lease_opened_at,
            lease_deadline,
        );
        let integrity_ok = constant_time_eq(stored_digest.as_bytes(), expected.as_bytes());
        let effect_id = integrity_ok
            .then(|| crate::money::MoneyMetadata::from_canonical_json(&money_json).ok())
            .flatten()
            .and_then(|metadata| metadata.effect_id().map(str::to_string));
        // `environment` is a redundant compatibility column outside the digest. Views derive it from
        // the HMAC-covered frozen resource so a store edit cannot forge evidence while integrity stays
        // green; a marker-bearing runtime hole naturally projects to no value until fill lands.
        let frozen_value = serde_json::from_str::<Value>(&resource_json).unwrap_or(Value::Null);
        let environment = match self.frozen_contract(&provider, &action, template_hash.as_deref()) {
            FrozenContract::Live(contract) => projected_environment(Some(contract), &frozen_value),
            FrozenContract::Raw => projected_environment(None, &frozen_value),
        };
        let resource = self.render_grant_resource(
            &provider,
            &action,
            template_hash.as_deref(),
            &resource_json,
        );
        Ok(GrantView {
            // Absent here by construction: the session's self-report is stamped by `history()`, the
            // one operator-view read that joins it. Every agent-facing projection leaves it absent.
            client_name: None,
            client_version: None,
            agent_model: None,
            agent_session: false,
            grant_id: id,
            session_id,
            provider,
            action,
            effect_id,
            effect_outcome: None,
            failure_class: None,
            // Stamped by `history()` alone (`project_grant_effect_states`): what became of the
            // effect is derived from the audit log and a clock read, and is never a stored column.
            effect_state: None,
            burn_reason: None,
            environment,
            resource,
            status,
            decision,
            created_at,
            // Stamped by `history()` alone (`project_request_authority`): the claim lives on the
            // request row, not the grant.
            request_model: None,
            // Stamped by `history()` alone (`project_grant_terminal_times`): an effect's end lives
            // in the audit log, not on the grant row.
            terminal_at: None,
            request_id,
            approved_by_kind,
            approver,
            approved_at,
            reason: None,
            deny_reason: None,
            authority_fingerprint: None,
            matched_rule: None,
            justification: None,
            integrity_ok,
            principal_label: principal_id.as_deref().and_then(resolve_principal_label),
            principal_id,
        })
    }

    /// The frozen grant rows for one session, oldest first.
    pub fn list_grants(&self, session_id: &str) -> Result<Vec<GrantView>> {
        #[cfg(test)]
        self.list_grants_calls.set(self.list_grants_calls.get() + 1);
        let sql = format!(
            "SELECT {GRANT_VIEW_COLUMNS} FROM grants WHERE session_id = ?1 ORDER BY created_at, id"
        );
        let mut stmt = self.state.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![session_id], |r| {
            self.grant_view_from_row(r)
        })?;
        let mut grants = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Error::from)?;
        self.project_grant_effect_outcomes(&mut grants);
        Ok(grants)
    }

    pub(super) fn list_all_grants(&self) -> Result<Vec<GrantView>> {
        Ok(self.load_all_grants_snapshot()?.grants)
    }

    /// The minimal per-grant projection the MCP-repoint quiesce classifier consumes: the HMAC
    /// verdict (`integrity_ok`, recomputed in `grant_view_from_row`), the lifecycle status, and the
    /// signed lease stamps. Every grant is read through the same fail-closed HMAC path as every other
    /// view, so a store-tampered lease/status surfaces as an integrity fault, never as "safe".
    pub(super) fn load_quiesce_rows(&self) -> Result<Vec<super::quiesce::QuiesceGrantRow>> {
        let snap = self.load_all_grants_snapshot()?;
        Ok(snap
            .grants
            .iter()
            .zip(snap.lifecycle.iter())
            .map(|(g, lc)| super::quiesce::QuiesceGrantRow {
                id: lc.id.clone(),
                integrity_ok: g.integrity_ok,
                status: lc.status.clone(),
                lease_opened_at: lc.lease_opened_at,
                lease_deadline: lc.lease_deadline,
            })
            .collect())
    }

    fn load_all_grants_snapshot(&self) -> Result<AllGrantsSnapshot> {
        let sql = format!("SELECT {GRANT_VIEW_COLUMNS} FROM grants ORDER BY created_at, id");
        let mut stmt = self.state.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((
                self.grant_view_from_row(r)?,
                GrantLifecycle {
                    id: r.get(0)?,
                    status: r.get(6)?,
                    lease_opened_at: r.get(19)?,
                    lease_deadline: r.get(20)?,
                },
            ))
        })?;
        let mut grants = Vec::new();
        let mut lifecycle = Vec::new();
        for row in rows {
            let (grant, state) = row?;
            grants.push(grant);
            lifecycle.push(state);
        }
        Ok(AllGrantsSnapshot { grants, lifecycle })
    }

    /// The flat request log for the History view (**requests-backed**), **newest first**
    /// (`created_at` descending, id as a stable tiebreak). Grant rows (allow/ask lifecycle) carry
    /// their redacted resource + integrity; requests the broker refused WITHOUT minting a grant
    /// (`deny | unsupported | unregistered`) now appear too — with their `reason` — so a denial is no
    /// longer structurally invisible. No secret: grant rows redact
    /// through the frozen contract; denial rows carry no frozen resource and are suppressed here.
    pub fn history(&self) -> Result<Vec<GrantView>> {
        let mut all = self.list_all_grants()?;
        self.project_grant_effect_outcomes(&mut all);
        self.project_grant_failure_classes(&mut all)?;
        self.project_grant_effect_states(&mut all)?;
        self.project_grant_terminal_times(&mut all)?;
        self.project_request_authority(&mut all)?;
        all.extend(self.denial_history_views()?);
        self.project_session_actors(&mut all)?;
        all.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.grant_id.cmp(&a.grant_id))
        });
        Ok(all)
    }

    /// Stamp each row with what its SESSION self-reported about who was driving.
    ///
    /// One query for the whole session table rather than a join per row: the sessions are few, the
    /// rows are many, and every other view in this file reads the denormalized `session_id` column
    /// straight off `grants`. Rows whose session predates the columns, or which never handshook,
    /// read `None` — the truth about them.
    ///
    /// `agent_session` is the part nobody reported: it is TRUE exactly when the session row carries
    /// an agent display label, which only the agent-socket handshake and the git plane set. That is
    /// what lets an operator's own `cermet run` be told from an agent's request downstream without
    /// trusting anything either of them said.
    fn project_session_actors(&self, rows: &mut [GrantView]) -> Result<()> {
        let mut stmt = self
            .state
            .prepare("SELECT id, client_name, client_version, agent_model, agent FROM sessions")?;
        let mut actors: std::collections::HashMap<String, SessionActorRow> =
            std::collections::HashMap::new();
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        for row in mapped {
            let (id, client_name, client_version, model, agent) = row?;
            actors.insert(
                id,
                SessionActorRow {
                    client_name,
                    client_version,
                    model,
                    agent_session: agent.is_some_and(|label| !label.trim().is_empty()),
                },
            );
        }
        for view in rows.iter_mut() {
            let Some(actor) = view
                .session_id
                .as_ref()
                .and_then(|session| actors.get(session))
            else {
                continue;
            };
            view.client_name = actor.client_name.clone();
            view.client_version = actor.client_version.clone();
            view.agent_model = actor.model.clone();
            view.agent_session = actor.agent_session;
        }
        Ok(())
    }

    /// What `cermet log <request_id>` answers: ONE public id, three fates. A request the broker
    /// REFUSED is answered by its own record — the same lossless deny row `cermet log --denied`
    /// lists; an executed one by its verified execution evidence; an ALLOWED-but-unexecuted one —
    /// what `run --ask-only` leaves behind — by its decision. The denial is checked FIRST because
    /// a refusal never minted a grant, so the evidence join finds nothing and the id would
    /// otherwise read as unknown. An id the broker never saw keeps the plain not-found.
    pub fn request_log(&self, request_id: &str) -> Result<crate::types::RequestLogView> {
        if let Some(denied) = self.denial_views(Some(request_id))?.pop() {
            return Ok(crate::types::RequestLogView::Denied(Box::new(denied)));
        }
        match self.evidence(request_id) {
            Ok(evidence) => Ok(crate::types::RequestLogView::Executed(Box::new(evidence))),
            // "No execution evidence" has two causes: an id with no grant at all (unknown — the
            // plain not-found stands) and an id whose grant is decided but not yet run. Only the
            // second has a record to render.
            Err(Error::NotFound(not_found)) => match self.decided_view(request_id)? {
                Some(decided) => Ok(crate::types::RequestLogView::Decided(Box::new(decided))),
                None => Err(Error::NotFound(not_found)),
            },
            Err(error) => Err(error),
        }
    }

    /// The DECIDED record for a request that has a grant but no terminal execution;
    /// `None` when the id has no grant at all.
    ///
    /// Reads the same grant row every other view reads — so the frozen resource is redacted through
    /// the same fail-closed contract rule — and joins the request row's stored authority (the
    /// admitting sentence, the corpus digest, the justification) exactly as [`Broker::history`] does.
    fn decided_view(&self, request_id: &str) -> Result<Option<crate::types::DecidedRequestView>> {
        let sql = format!("SELECT {GRANT_VIEW_COLUMNS} FROM grants WHERE request_id = ?1");
        let mut stmt = self.state.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![request_id], |row| {
            self.grant_view_from_row(row)
        })?;
        let mut grants = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Error::from)?;
        if grants.len() != 1 {
            return Ok(None);
        }
        self.project_request_authority(&mut grants)?;
        let grant = grants.pop().expect("exactly one grant");
        Ok(Some(crate::types::DecidedRequestView {
            request_id: request_id.to_string(),
            provider: grant.provider,
            action: grant.action,
            resource: grant.resource,
            decision: grant.decision,
            status: grant.status,
            matched_rule: grant.matched_rule,
            authority_fingerprint: grant.authority_fingerprint,
            justification: grant.justification,
            created_at: grant.created_at,
            principal_id: grant.principal_id,
            principal_label: grant.principal_label,
            integrity_ok: grant.integrity_ok,
            next: format!("cermet run --resume {request_id}"),
        }))
    }

    /// Return one request's execution evidence only after the signed grant and the complete audit
    /// chain agree on its identity and terminal event schema. This is deliberately operator-facing
    /// plumbing; the agent protocol has no corresponding request.
    pub fn evidence(&self, request_id: &str) -> Result<crate::types::RequestEvidenceView> {
        let sql = format!("SELECT {GRANT_VIEW_COLUMNS} FROM grants WHERE request_id = ?1");
        let mut stmt = self.state.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![request_id], |row| {
            self.grant_view_from_row(row)
        })?;
        let mut grants = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Error::from)?;
        if grants.len() != 1 {
            // No grant means no EXECUTION evidence. A refused request still has a record; it is
            // rendered by [`Broker::request_log`], which resolves the denial before reaching here.
            return Err(Error::NotFound(format!(
                "no execution evidence for {request_id}"
            )));
        }
        let mut view = grants.pop().expect("exactly one grant");
        if !view.integrity_ok || view.request_id.as_deref() != Some(request_id) {
            return Err(Error::Integrity(format!(
                "request {request_id} grant integrity failed"
            )));
        }
        let grant = self.load_grant(&view.grant_id)?;
        if self
            .verified_in_process_terminal_execution(&view.grant_id, &grant)?
            .is_none()
        {
            return Err(Error::NotFound(format!(
                "no terminal execution evidence for {request_id}"
            )));
        }
        let events = self
            .audit
            .verified_execution_events(&view.grant_id, request_id)?
            .into_iter()
            .map(|event| crate::types::ExecutionEvidenceView {
                resource_binding: event
                    .data
                    .get("resource_binding")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                authority_digest: event
                    .data
                    .get("authority_digest")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                outcome: event
                    .data
                    .get("outcome")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                mutation_invoked: event.data.get("mutation_invoked").and_then(Value::as_bool),
                effect_outcome: event
                    .data
                    .get("effect_outcome")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                result: event.data.get("result").cloned().unwrap_or(Value::Null),
                event_type: event.event_type,
            })
            .collect();
        // The relay hops this grant authorized, rendered under the request that opened
        // the session. The session's own close receipt is lifted out of the list — it is the
        // session's terminal record, not a hop.
        let mut relay_hops = Vec::new();
        let mut relay_session = None;
        for event in self.audit.verified_relay_events(Some(&view.grant_id))? {
            match event.event_type.as_str() {
                "relay_session_closed" => relay_session = Some(event.data),
                _ => relay_hops.push(relay_hop_view(event)),
            }
        }
        self.project_grant_effect_outcomes(std::slice::from_mut(&mut view));
        // The same derivation the list row's suffix carries, from the same one read — so the per-id
        // answer can never disagree with the list's about how a request ended.
        self.project_grant_effect_states(std::slice::from_mut(&mut view))?;
        Ok(crate::types::RequestEvidenceView {
            relay_hops,
            relay_session,
            effect_state: view.effect_state,
            justification: self.request_justification(request_id)?,
            request_id: request_id.to_string(),
            grant_id: view.grant_id,
            provider: view.provider,
            action: view.action,
            resource: view.resource,
            status: view.status,
            decision: view.decision,
            integrity_ok: true,
            effect_id: view.effect_id,
            effect_outcome: view.effect_outcome,
            events,
        })
    }

    /// The justification the agent supplied with a request, read back from its own row — the grant
    /// does not carry it. `None` for a request that supplied none, or one this daemon never
    /// recorded.
    fn request_justification(&self, request_id: &str) -> Result<Option<String>> {
        Ok(self
            .state
            .query_row(
                "SELECT justification FROM requests WHERE id = ?1",
                rusqlite::params![request_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    /// Every relay event this daemon chained, NEWEST FIRST — the operator's
    /// `cermet log --hops` view. Cross-session by design: a burn is diagnosed by reading the
    /// session's whole life (opened → hops → refusal → closed), and the unauthenticated pokes at
    /// the loopback port that carry no grant at all are visible here and nowhere else.
    pub fn relay_hops(&self) -> Result<Vec<crate::types::RelayHopView>> {
        let mut rows: Vec<crate::types::RelayHopView> = self
            .audit
            .verified_relay_events(None)?
            .into_iter()
            .map(relay_hop_view)
            .collect();
        rows.reverse();
        Ok(rows)
    }

    /// Surface WHICH rule allowed. The `requests` row stores the evaluator's own reason, the
    /// corpus digest it was decided against, and the admitting rule's canonical text; a
    /// grant row carries none of them, so `cermet log` could only say "a standing sentence". This is a
    /// READ of stored columns onto the existing view, and it runs only in `history()`, the operator's
    /// ctl surface. The agent-facing grant projections are untouched (redaction unchanged).
    fn project_request_authority(&self, grants: &mut [GrantView]) -> Result<()> {
        let mut stmt = self.state.prepare(
            "SELECT reason, policy_fingerprint, matched_rule, justification, agent_model FROM requests WHERE id = ?1",
        )?;
        for grant in grants.iter_mut() {
            if grant.reason.is_some() {
                continue; // a denial row already carries its own reason
            }
            let Some(request_id) = grant.request_id.clone() else {
                continue;
            };
            let row = stmt
                .query_row(rusqlite::params![request_id], |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                })
                .optional()?;
            if let Some((reason, fingerprint, matched_rule, justification, agent_model)) = row {
                grant.reason = reason;
                grant.authority_fingerprint = fingerprint;
                grant.matched_rule = matched_rule;
                grant.justification = justification;
                // The claim the agent attached to THIS request, unauthenticated and read by nothing.
                grant.request_model = agent_model;
            }
        }
        Ok(())
    }

    /// Say WHY a failed effect failed, on the operator's receipt log.
    ///
    /// ONE read for the whole log, joined by grant id. The class is derived from the provider's own
    /// typed signals — the status it sent, or the class the seam typed where no response existed —
    /// so this classifies every row the daemon has ever written, including the ones recorded before
    /// the classification existed: nothing new had to be stored for a status that was already
    /// recorded. A row whose grant HMAC does not authenticate is left unclassified; its story is
    /// "untrusted", not "failed with a reason".
    fn project_grant_failure_classes(&self, grants: &mut [GrantView]) -> Result<()> {
        if !grants.iter().any(|view| view.integrity_ok) {
            return Ok(());
        }
        let classes = self.audit.effect_failure_classes()?;
        for view in grants.iter_mut().filter(|view| view.integrity_ok) {
            view.failure_class = classes.get(&view.grant_id).copied();
        }
        Ok(())
    }

    /// Stamp each row with when its effect ENDED, from the terminal execution event's own timestamp.
    ///
    /// The same one-read shape as [`Self::project_grant_failure_classes`], and the same scope: a row
    /// whose grant HMAC did not authenticate is not evidence of anything, so it is left alone. A
    /// grant with no terminal event keeps `None` — an effect that has not ended has no end.
    fn project_grant_terminal_times(&self, grants: &mut [GrantView]) -> Result<()> {
        if !grants.iter().any(|view| view.integrity_ok) {
            return Ok(());
        }
        let ends = self.audit.effect_terminal_times()?;
        for view in grants.iter_mut().filter(|view| view.integrity_ok) {
            view.terminal_at = ends.get(&view.grant_id).cloned();
        }
        Ok(())
    }

    /// Stamp each row with WHAT BECAME OF ITS EFFECT — the derivation that turns the recorded
    /// signals into the one word a receipt row can carry.
    ///
    /// The same one-read shape as [`Self::project_grant_failure_classes`], and the same scope: a row
    /// whose grant HMAC did not authenticate is not evidence of anything, so it is left alone.
    fn project_grant_effect_states(&self, grants: &mut [GrantView]) -> Result<()> {
        if !grants.iter().any(|view| view.integrity_ok) {
            return Ok(());
        }
        let signals = self.audit.effect_signals()?;
        let now = self.now_epoch();
        for view in grants.iter_mut().filter(|view| view.integrity_ok) {
            let Some(recorded) = signals.get(&view.grant_id) else {
                continue;
            };
            view.effect_state = effect_state(recorded, now);
            if view.effect_state == Some(crate::types::EffectState::Burned) {
                view.burn_reason = recorded.burned.clone();
            }
        }
        Ok(())
    }

    fn project_grant_effect_outcomes(&self, grants: &mut [GrantView]) {
        for view in grants {
            if view.effect_id.is_none() || !view.integrity_ok {
                continue;
            }
            let Ok(grant) = self.load_grant(&view.grant_id) else {
                continue;
            };
            let recovered = if matches!(view.status.as_str(), "executing" | "executed") {
                self.reconcile_terminal_execution(&view.grant_id, &grant)
                    .ok()
                    .flatten()
            } else {
                None
            };
            let Ok(money) = crate::money::MoneyMetadata::from_canonical_json(&grant.money_json)
            else {
                continue;
            };
            view.effect_outcome = self
                .verified_logical_money_effect_outcome(&view.grant_id, &grant, &money)
                .ok()
                .flatten();
            if recovered.is_some() {
                view.status = "executed".into();
            }
        }
    }

    /// THE denial projection — requests that resolved to `deny`/`unsupported`/`unregistered` and
    /// therefore minted no grant. `None` renders every one of them (the `cermet log --denied` list);
    /// `Some(id)` renders exactly one (the per-id `cermet log <request_id>`). ONE query
    /// serves both zoom levels so the per-id answer can never drift from the list's.
    ///
    /// The stored resource renders AS STORED — it was already redacted at write time by
    /// [`Broker::record_request`] (a secret-classed field carries its marker; an unresolved action's
    /// values are size-capped), and a second pass here would only blank values that persist at rest
    /// anyway. The row's job is to say what was asked for.
    fn denial_views(
        &self,
        request_id: Option<&str>,
    ) -> Result<Vec<crate::types::DeniedRequestView>> {
        let mut stmt = self.state.prepare(
            "SELECT id, session_id, provider, action, resource_json, decision, reason, principal, created_at, policy_fingerprint, justification, deny_reason_json, agent_model
             FROM requests
             WHERE decision IN ('deny','unsupported','unregistered')
               AND (?1 IS NULL OR id = ?1)
               AND NOT EXISTS (SELECT 1 FROM grants g WHERE g.request_id = requests.id)",
        )?;
        let rows = stmt.query_map(rusqlite::params![request_id], |r| {
            let resource_json: String = r.get(4)?;
            let principal_id: Option<String> = r.get(7)?;
            Ok(crate::types::DeniedRequestView {
                // A denial row IS the request; its handle is the request id itself.
                request_id: r.get(0)?,
                session_id: r.get(1)?,
                provider: r.get(2)?,
                action: r.get(3)?,
                resource: serde_json::from_str(&resource_json).unwrap_or(Value::Null),
                decision: r.get(5)?,
                reason: r.get(6)?,
                // The stored typed refusal, read back through its own serde. A row that carries
                // none — or one whose stored shape this build no longer knows — projects `None`
                // rather than a guess.
                deny_reason: r
                    .get::<_, Option<String>>(11)?
                    .and_then(|json| serde_json::from_str(&json).ok()),
                justification: r.get(10)?,
                created_at: r.get(8)?,
                authority_fingerprint: r.get(9)?,
                principal_label: principal_id.as_deref().and_then(resolve_principal_label),
                principal_id,
                request_model: r.get(12)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Error::from)
    }

    /// The denial rows for [`Broker::history`], projected onto the read-only [`GrantView`] shape the
    /// receipt list renders (`status = "denied"`, `reason` set). Same rows, same query — only the
    /// shape differs.
    fn denial_history_views(&self) -> Result<Vec<GrantView>> {
        Ok(self
            .denial_views(None)?
            .into_iter()
            .map(|denial| GrantView {
                client_name: None,
                client_version: None,
                agent_model: None,
                agent_session: false,
                // The list is keyed by the row's handle, and a denial's handle is its request id.
                grant_id: denial.request_id.clone(),
                request_id: Some(denial.request_id),
                request_model: denial.request_model,
                // A refusal minted no grant and ran no effect, so it has no end.
                terminal_at: None,
                session_id: denial.session_id,
                provider: denial.provider,
                action: denial.action,
                effect_id: None,
                effect_outcome: None,
                // A refusal never ran an effect, so there is no effect failure to classify and
                // nothing became of an effect that never existed.
                failure_class: None,
                effect_state: None,
                burn_reason: None,
                environment: None,
                resource: denial.resource,
                status: "denied".to_string(),
                decision: denial.decision,
                approved_by_kind: None,
                approver: None,
                approved_at: None,
                reason: Some(denial.reason),
                deny_reason: denial.deny_reason,
                justification: denial.justification,
                authority_fingerprint: denial.authority_fingerprint,
                // A denial had no admitting rule; the stored column is NULL for exactly this reason.
                matched_rule: None,
                created_at: denial.created_at,
                // A request row carries no per-grant HMAC; it is a plain log line, not a claim.
                integrity_ok: true,
                principal_label: denial.principal_label,
                principal_id: denial.principal_id,
            })
            .collect())
    }
}

/// THE derivation: recorded signals plus a clock read, in, one [`EffectState`] out.
///
/// It is a free function and a pure one so the whole rule is readable in one place and testable
/// without a broker. Order is the rule, and each step is a claim the record supports:
///
/// 1. **The effect landed.** The last word about an effect-bearing hop (or a plain verb's terminal
///    event) is a success. This outranks a burn: a window whose deploy landed and which then refused
///    a probe on a later read hop DID deploy, and a row that said only `burned` there would be the
///    same disclosure failure in the other direction. An effect whose own response contradicted the
///    approval is not a success — the mismatch is recorded as a failure and the burn below names it.
/// 2. **A refusal ended it.** A burning class stopped the session and nothing recorded an
///    effect-bearing hop landing. This is the case that read as a bare `ALLOW` before: authority
///    said yes, and the session ended anyway. It is NOT a claim the effect did not land — an effect
///    hop that never got a response head is spent with its outcome unknown, and the retry that
///    burns as `effect_already_used` lands here with its `failure_class` beside it saying to
///    reconcile.
/// 3. **The window ended empty.** Terminated with zero hops forwarded — the grant was spent minting
///    authority nothing ever drove.
/// 4. **The window ended without a verdict.** Terminated after hops, with nothing recorded saying
///    whether the effect landed.
///
/// Anything else is `None`, and that is load-bearing: a live window, a request decided and never
/// executed, a denial. Silence means the record does not say, never "nothing happened".
///
/// A row whose effect the record says FAILED lands in none of these — step 1 does not fire, nothing
/// burned, and a `failed` token would only repeat the `failure_class` the same row already renders.
/// The suffix is what the row could not otherwise say.
///
/// **Termination is derived, not read.** A window ends when its terminal record exists OR the clock
/// is past the `expires_at` the approval set. The second half matters: a daemon that restarts drops
/// its live sessions from memory without closing them, and a window with no terminal record would
/// otherwise read as in-flight forever.
fn effect_state(signals: &crate::audit::EffectSignals, now: i64) -> Option<EffectState> {
    if signals.landed() == Some(true) {
        return Some(EffectState::Ok);
    }
    if signals.burned.is_some() {
        return Some(EffectState::Burned);
    }
    if !signals.relay {
        return None;
    }
    // Only `Some(false)` can reach here, and it is a DETERMINED outcome: the record says the effect
    // failed, and the same row renders its `failure_class`. A token repeating that adds nothing.
    if signals.landed().is_some() {
        return None;
    }
    let ended =
        signals.closed.is_some() || signals.expires_at.is_some_and(|deadline| now > deadline);
    if !ended {
        return None;
    }
    Some(if signals.hops == 0 {
        EffectState::ExpiredUnused
    } else {
        EffectState::Unresolved
    })
}

/// Project ONE chain-verified relay event onto the closed operator view. Every field is
/// read by name off the row the broker itself wrote — an event that never carried a field simply
/// leaves it absent, so a new relay event type renders as much as it declares and never guesses.
fn relay_hop_view(event: crate::audit::RelayAuditEvent) -> crate::types::RelayHopView {
    let data = event.data;
    let text = |key: &str| data.get(key).and_then(Value::as_str).map(str::to_string);
    crate::types::RelayHopView {
        event_type: event.event_type,
        at: event.at,
        provider: text("provider"),
        action: text("action"),
        grant_id: text("grant_id"),
        method: text("method"),
        target: text("target"),
        upstream_status: data.get("upstream_status").and_then(Value::as_u64),
        // A refusal names its reason; a forwarded hop that died mid-body names its stream error.
        reason: text("reason").or_else(|| text("stream_error")).or_else(|| {
            data.get("error")
                .and_then(Value::as_str)
                .filter(|error| !error.is_empty())
                .map(str::to_string)
        }),
        // What the refusal disclosed beside its reason word, when the class had something further
        // to say. Absent otherwise, exactly like every other field read by name here.
        detail: text("detail"),
        effect: data.get("effect").and_then(Value::as_bool),
        response_bytes: data.get("response_bytes").and_then(Value::as_u64),
        // What a FORWARDED hop carried outside its shape's declared vocabulary — an observation the
        // broker wrote, read by name like everything else here, so a row that never carried it
        // simply leaves it absent.
        undeclared_keys: data
            .get("undeclared_keys")
            .and_then(Value::as_array)
            .map(|keys| {
                keys.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            }),
        burned: data.get("burned").and_then(Value::as_bool),
        closed: text("closed"),
    }
}
