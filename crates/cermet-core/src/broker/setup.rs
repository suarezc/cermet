use super::helpers::*;
use super::*;

static BROKER_SENTENCE_SETS: crate::sets::VendoredSetResolver = crate::sets::VendoredSetResolver;

impl Broker {
    /// Evaluate sentence authority without minting. The explicit sentence-backed request seam uses
    /// the same evaluator before joining the broker's ordinary durable grant lifecycle.
    pub fn evaluate_sentence(
        &self,
        rules: &crate::sentence::RuleSet,
        provider: &str,
        action: &str,
        resource: &crate::contract::CanonicalResource,
    ) -> crate::sentence::Decision {
        crate::sentence::SentenceEvaluator::new(&crate::sets::VendoredSetResolver, &self.providers)
            .evaluate(rules, provider, action, resource)
    }

    /// Bind a sentence ruleset to the broker's contract/set resolvers.
    pub fn sentence_policy<'a>(
        &'a self,
        rules: &'a crate::sentence::RuleSet,
    ) -> crate::policy::SentencePolicy<'a> {
        crate::policy::SentencePolicy::new(rules, &BROKER_SENTENCE_SETS, &self.providers)
    }

    /// A broker hint is valid only for a structurally evaluated out-of-bounds allow. Explicit or
    /// unresolved denies, unknown selectors, bad resources, and unsupported versions stay hintless.
    pub(super) fn sentence_widen_hint_for_denial(
        &self,
        rules: &crate::sentence::RuleSet,
        provider: &str,
        action: &str,
        resource: &crate::contract::CanonicalResource,
    ) -> Option<crate::sentence::WidenHint> {
        let evaluator =
            crate::sentence::SentenceEvaluator::new(&BROKER_SENTENCE_SETS, &self.providers);
        evaluator
            .evaluate_with_widen_hint(rules, provider, action, resource)
            .widen_hint
    }

    /// Non-authorizing satisfiability preflight for a request one field is not yet known for. The
    /// agent's own fields stay exact; every name in `unknown_fields` is present-but-unknown. `false`
    /// can avoid credential I/O, but `true` never allows or mints anything.
    ///
    /// Both seams that spend the credential BEFORE the sentence decides ask this one question: the
    /// evidence path with the profile's outputs unknown, and request-time canonicalization with the
    /// profile's field unknown.
    pub(super) fn shape_has_possible_allow(
        &self,
        rules: &crate::sentence::RuleSet,
        provider: &str,
        action: &str,
        resource: &crate::contract::CanonicalResource,
        unknown_fields: &BTreeSet<String>,
    ) -> bool {
        let known_fields: BTreeMap<String, Value> = resource
            .as_match_value()
            .as_object()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|(field, _)| !unknown_fields.contains(field))
            .collect();
        crate::sentence::SentenceEvaluator::new(&BROKER_SENTENCE_SETS, &self.providers)
            .resource_shape_is_discoverable(
                rules,
                provider,
                action,
                &known_fields,
                unknown_fields,
                unknown_fields,
            )
    }

    /// The SHA-256 of the loaded descriptor bytes for `provider`, frozen onto its grants and
    /// re-checked at claim/execute. `None` for a provider with no loaded descriptor.
    pub(super) fn descriptor_hash(&self, provider: &str) -> Option<&str> {
        self.descriptor_hashes.get(provider).map(String::as_str)
    }

    /// The OPERATOR view: every vaulted credential, including a shelved provider's. The operator
    /// must be able to see a pre-ruling row in order to `secure`/revoke it, so this is deliberately
    /// NOT filtered. Never carries a secret — `SafeCredential` is reference + provider + label.
    pub fn list_credentials(&self) -> Result<Vec<SafeCredential>> {
        self.vault.list()
    }

    /// The AGENT view. An install upgraded after a provider was disabled still holds pre-disable
    /// vault rows, and advertising them to the model is a lie it can act on — it would be told
    /// `github` is connected and then be unable to request a single github verb. Project only
    /// product-enabled providers here; the operator surface above keeps full visibility.
    pub fn list_credentials_for_agent(&self) -> Result<Vec<SafeCredential>> {
        let mut credentials = self.list_credentials()?;
        credentials
            .retain(|credential| !self.provider_is_product_disabled(&credential.provider, ""));
        Ok(credentials)
    }

    pub fn verify_integrity(&self) -> Result<IntegrityReport> {
        self.audit.verify()
    }

    /// The `catalog` verb: the per-verb schema of every action an agent can author against or request
    /// — this broker's LOADED templates (`requestable: true`) unioned with the vendored stdlib
    /// (`requestable: false` when not loaded here). Schema only: no HTTP step bodies, no values, and
    /// no credential — a secret-classed field is described, never valued.
    pub fn catalog(&self) -> Result<Vec<crate::templates::CatalogEntry>> {
        let mut catalog = crate::templates::catalog_of(&self.templates, self.temporal_clauses);
        catalog.retain(|entry| !self.provider_is_product_disabled(&entry.provider, &entry.action));
        Ok(catalog)
    }

    /// The agent discovery listing, with discoverability derived from the current authenticated
    /// sentence corpus for every provider.
    pub fn catalog_listing(&self) -> Result<crate::types::CatalogListing> {
        let mut catalog = self.catalog()?;
        let sentence_rules = self
            .current_sentence_authority()
            .ok()
            .map(|(rules, _)| rules);
        let sentence_evaluator =
            crate::sentence::SentenceEvaluator::new(&BROKER_SENTENCE_SETS, &self.providers);
        for e in &mut catalog {
            // Name the standing sentences that select this verb — BOTH effects, by
            // their canonical text (no rule numbers: the sentence IS the name). The ONE corpus, the
            // existing set machinery, one join. Presentation only: the agent surface reports the
            // authority the broker already holds instead of saying "requestable" and leaving the
            // agent to guess the bounds. Every entry is joined, including a non-requestable one, so
            // the dictionary view never mislabels a covered-but-unavailable verb as unruled — and
            // joining DENIES too is what keeps it from calling an explicitly denied verb unruled or
            // hiding a carve-out that narrows a live allow.
            let selecting = |effect: crate::sentence::RuleEffect| -> Vec<String> {
                sentence_rules
                    .as_ref()
                    .map(|rules| {
                        rules
                            .rules
                            .iter()
                            .filter(|rule| {
                                rule.effect == effect
                                    && sentence_evaluator.covers(rule, &e.provider, &e.action)
                            })
                            .map(crate::sentence::print_rule)
                            .collect()
                    })
                    .unwrap_or_default()
            };
            e.admitted_by = selecting(crate::sentence::RuleEffect::Allow);
            e.denied_by = selecting(crate::sentence::RuleEffect::Deny);
            if !e.requestable {
                continue;
            }
            e.sentence_denied = !sentence_rules.as_ref().is_some_and(|rules| {
                sentence_evaluator.action_is_discoverable(rules, &e.provider, &e.action)
            });
        }
        Ok(crate::types::CatalogListing { catalog })
    }

    /// real `denied` from the `requests` table instead of "no such request".
    pub fn request_status(&self, request_id: &str) -> Result<RequestStatusView> {
        // Grant-first: resolve only the opaque row id, then load and authenticate every signed field
        // before any lifecycle, phase, abandonment, or ownership projection.
        if let Some(grant_id) = self
            .state
            .query_row(
                "SELECT id FROM grants WHERE request_id=?1",
                rusqlite::params![request_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            let grant = self.load_grant(&grant_id)?;
            self.assert_grant_integrity(&grant_id, &grant)?;
            return self.project_grant_status(request_id, &grant_id, &grant);
        }
        // No grant row: a recorded refusal answers `denied`; anything else is genuinely unknown.
        let decision: Option<String> = self
            .state
            .query_row(
                "SELECT decision FROM requests WHERE id=?1",
                rusqlite::params![request_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        match decision.as_deref() {
            Some("deny") | Some("unsupported") | Some("unregistered") => "denied",
            Some(_) => {
                return Err(Error::Denied(
                    "request has no executable sentence grant".into(),
                ))
            }
            None => return Err(Error::NotFound(format!("no request {request_id}"))),
        };
        let outcome = Some("denied".to_string());
        Ok(RequestStatusView {
            request_id: request_id.to_string(),
            status: "terminal".to_string(),
            effect_id: None,
            effect_outcome: None,
            deny_reason: None,
            phase: Some("terminal".to_string()),
            outcome: outcome.clone(),
            termination: outcome,
            terminal_receipt: None,
        })
    }

    /// Build the agent-facing lifecycle view only from an already-authenticated grant row.
    fn project_grant_status(
        &self,
        request_id: &str,
        grant_id: &str,
        grant: &GrantRow,
    ) -> Result<RequestStatusView> {
        let expired = grant.expiry_epoch.is_some_and(|e| self.now_epoch() > e);
        // Complete an audit-first terminal write before projecting liveness. This is also the status
        // path's trust source for the money-effect outcome; grant status alone never supplies it.
        let terminal_evidence =
            if matches!(grant.status, GrantStatus::Executing | GrantStatus::Executed) {
                // Audit corruption or mismatched evidence cannot heal the row. Keep an executing grant
                // unresolved/running (never abandonment/retry advice); an already-executed row remains a
                // terminal UNKNOWN through the existing receipt projection.
                self.reconcile_terminal_execution(grant_id, grant)
                    .unwrap_or(None)
            } else {
                None
            };
        let recovered_terminal =
            grant.status == GrantStatus::Executing && terminal_evidence.is_some();
        // A deadline makes an executing lease eligible for the custody sweep; it is not
        // itself terminal evidence. Until that sweep persists an authenticated Expired lifecycle and
        // an exact verified abandonment event, status remains unresolved/running and never teaches a
        // duplicate retry.
        let lifecycle_status = if recovered_terminal {
            "executed"
        } else {
            match grant.status {
                GrantStatus::Requested if expired => "expired",
                GrantStatus::Requested => "unavailable",
                GrantStatus::Approved if expired => "expired",
                GrantStatus::Approved => "ready",
                GrantStatus::Denied => "denied",
                GrantStatus::Executing => "running",
                GrantStatus::Executed => "executed",
                GrantStatus::Expired => match (grant.lease_opened_at, grant.lease_deadline) {
                    (None, None) => "expired",
                    (Some(lease_opened_at), Some(lease_deadline)) => {
                        let executing_digest = self.redigest(grant_id, grant, "executing");
                        if self.audit.lease_abandoned_event_exists(
                            grant_id,
                            &grant.request_id,
                            &executing_digest,
                            Some(lease_opened_at),
                            Some(lease_deadline),
                        )? {
                            "abandoned"
                        } else {
                            "unavailable"
                        }
                    }
                    _ => "unavailable",
                },
            }
        };
        let deny_reason = if grant.status == GrantStatus::Denied {
            self.audit.capability_denied_reason(grant_id)?
        } else {
            None
        };
        let (phase, outcome, termination, terminal_receipt) =
            if lifecycle_status == "executed" && terminal_evidence.is_none() {
                // A terminal row is not execution evidence. If the exact verifier rejected or could
                // not find the event, withhold even a loosely reconstructable receipt and classify
                // the outcome as unknown.
                ("terminal".into(), None, None, None)
            } else {
                self.async_phase_projection(lifecycle_status, grant_id)?
            };
        let money = crate::money::MoneyMetadata::from_canonical_json(&grant.money_json)
            .map_err(Error::Integrity)?;
        let effect_id = money.effect_id().map(str::to_string);
        let effect_outcome = effect_id.as_ref().and_then(|_| {
            self.verified_logical_money_effect_outcome(grant_id, grant, &money)
                .unwrap_or(None)
        });
        Ok(RequestStatusView {
            request_id: request_id.to_string(),
            status: phase.clone(),
            effect_id,
            effect_outcome,
            deny_reason,
            phase: Some(phase),
            outcome,
            termination,
            terminal_receipt,
        })
    }

    /// Map a grant-backed liveness `status` to the agent-facing
    /// async PHASE, and — for a `terminal` phase — rebuild the outcome/termination + DURABLE receipt
    /// from the VERIFIED audit chain (never from grant status/clock; a chain that fails to verify
    /// end-to-end yields no receipt, fail closed). Returns `(phase, outcome, termination, receipt)`.
    #[allow(clippy::type_complexity)]
    fn async_phase_projection(
        &self,
        status: &str,
        grant_id: &str,
    ) -> Result<(
        String,
        Option<String>,
        Option<String>,
        Option<serde_json::Value>,
    )> {
        let phase = match status {
            "ready" => "ready",
            "running" => "running",
            _ => "terminal",
        };
        if phase != "terminal" {
            return Ok((phase.to_string(), None, None, None));
        }
        match status {
            "denied" => Ok((
                "terminal".into(),
                Some("denied".into()),
                Some("denied".into()),
                None,
            )),
            "expired" | "abandoned" => Ok((
                "terminal".into(),
                Some("abandoned".into()),
                Some("abandoned".into()),
                None,
            )),
            // "executed": the real terminal record. Read the verified terminal event bytes.
            _ => match self.audit.terminal_receipt(grant_id)? {
                Some(data) => {
                    let ok = data.get("outcome").and_then(|o| o.as_str()) == Some("ok");
                    let canceled = data
                        .get("canceled")
                        .and_then(|c| c.as_bool())
                        .unwrap_or(false);
                    let outcome = if ok { "succeeded" } else { "failed" };
                    let termination = if canceled { "canceled" } else { "exited" };
                    let mut receipt = reconstruct_terminal_receipt(&data);
                    // Executing a relay verb OPENS a session — the
                    // terminal receipt above is the open, and everything that then happened over the
                    // loopback is in the session's CLOSE receipt. The native `vercel` CLI swallows
                    // the relay's refusal bodies and prints its own guess, so this is the agent's
                    // only honest mirror of why its deploy stopped. Read only for a receipt that
                    // opened a relay session, so no other verb pays for the scan.
                    if let Some(receipt) = receipt
                        .as_mut()
                        .filter(|receipt| receipt.pointer("/result/relay").is_some())
                    {
                        if let Some(closed) = self.relay_session_receipt(grant_id)? {
                            receipt["relay_session"] = closed;
                        }
                    }
                    Ok((
                        "terminal".into(),
                        Some(outcome.into()),
                        Some(termination.into()),
                        receipt,
                    ))
                }
                // Executed grant with no chain-verifiable terminal event: terminal, but nothing honest
                // to report — never fabricate an outcome from the grant status alone.
                None => Ok(("terminal".into(), None, None, None)),
            },
        }
    }

    /// The close receipt of the relay session this grant opened, or `None` while it is still live.
    /// Chain-verified like every other receipt read, and derived entirely from what the relay
    /// itself observed — never from anything the agent claimed.
    fn relay_session_receipt(&self, grant_id: &str) -> Result<Option<serde_json::Value>> {
        Ok(self
            .audit
            .verified_relay_events(Some(grant_id))?
            .into_iter()
            .rev()
            .find(|event| event.event_type == "relay_session_closed")
            .map(|event| event.data))
    }

    /// As [`Broker::request_status`], but principal-bound: the authenticated stored owner
    /// must equal `principal` before any state is projected. An unknown id, an ownerless row, and a
    /// FOREIGN owner all return the SAME `NotFound` — indistinguishable, so a leaked/guessed request_id
    /// can never be probed for state. This is the ONLY status form the agent surface may serve.
    pub fn request_status_for_principal(
        &self,
        request_id: &str,
        principal: &str,
    ) -> Result<RequestStatusView> {
        let grant_id: Option<String> = self
            .state
            .query_row(
                "SELECT id FROM grants WHERE request_id=?1",
                rusqlite::params![request_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(grant_id) = grant_id {
            let grant = self.load_grant(&grant_id)?;
            self.assert_grant_integrity(&grant_id, &grant)?;
            return match grant.principal_id.as_deref() {
                Some(stored) if stored == principal => {
                    self.project_grant_status(request_id, &grant_id, &grant)
                }
                _ => Err(Error::NotFound(format!("no request {request_id}"))),
            };
        }
        // No grant row: the request log (a sentence/unsupported/unregistered deny) owns the id.
        let stored: Option<Option<String>> = self
            .state
            .query_row(
                "SELECT principal FROM requests WHERE id=?1",
                rusqlite::params![request_id],
                |r| r.get(0),
            )
            .optional()?;
        match stored {
            Some(Some(p)) if p == principal => self.request_status(request_id),
            // Fail closed, one indistinguishable answer: unknown id == ownerless row == foreign owner.
            _ => Err(Error::NotFound(format!("no request {request_id}"))),
        }
    }

    /// The `language` verb: the action-template grammar primer, carried in the
    /// binary via `include_str!`. Static teaching text — no state, no secret.
    /// The contract the suggestion shaper scopes against: this broker's registry (built-in OR
    /// ratified template) first, else the registered provider's own seam. The seam fallback is
    /// what lets an EXTRA-registered provider (the daemon `files` provider) be shaped exactly
    /// like a built-in — `templates.resolve` never sees a provider-seam contract, so a files run
    /// would otherwise be silently un-suggestable.
    pub(super) fn suggestion_contract(
        &self,
        provider: &str,
        action: &str,
    ) -> Option<&'static ActionContract> {
        self.templates.resolve(provider, action).or_else(|| {
            self.providers
                .get(provider)
                .and_then(|p| p.action_contract(action))
        })
    }

    /// Register an EXTRA provider onto the live registry after construction — the hook the daemon uses
    /// to add its own `files` provider (which holds the workspace root) so the SAME broker actor serves
    /// it on both agent.sock and ctl. A duplicate provider name is a HARD error: a late registration
    /// may never silently shadow a built-in (fail closed).
    pub fn register_provider(&mut self, provider: Box<dyn Provider>) -> Result<()> {
        let name = provider.name().to_string();
        if self.providers.contains_key(&name) {
            return Err(Error::Invalid(format!(
                "provider `{name}` is already registered; refusing to shadow it"
            )));
        }
        // A provider registered outside the descriptor set (the daemon's local `files` provider,
        // or a test double) still needs a descriptor hash so its grants can mint and carry the
        // descriptor binding. These providers have no descriptor DOCUMENT — bind a stable synthetic
        // hash keyed on the provider identity. That is honest: there is no auth/origin/egress
        // descriptor to replace here (a credential-free local provider), so the identity IS the
        // binding, and it is stable across daemon restarts.
        self.descriptor_hashes
            .entry(name.clone())
            .or_insert_with(|| {
                super::helpers::sha256_hex(format!("registered-provider:{name}").as_bytes())
            });
        self.providers.insert(name, provider);
        Ok(())
    }

    pub fn connect_credential(
        &self,
        provider: &str,
        account_label: Option<&str>,
        token: &str,
    ) -> Result<ConnectOutcome> {
        if self.provider_is_product_disabled(provider, "") {
            self.audit.record(NewEvent {
                session_id: None,
                event_type: "provider_connect_refused",
                severity: "medium",
                summary: "provider_disabled",
                data: json!({ "provider": provider, "reason": "provider_disabled" }),
                secrets: &[],
            })?;
            return Err(Error::ProviderDisabled);
        }
        // Connect honesty: a credential is ONLY ever vaulted for a provider that has a ratified
        // descriptor loaded — otherwise there is no origin the token could ever be brokered to, so
        // refuse rather than silently vault an unusable "unsupported" credential. Fail closed.
        let Some(prov) = self.providers.get(provider) else {
            self.audit.record(NewEvent {
                session_id: None,
                event_type: "provider_connect_refused",
                severity: "medium",
                summary: &format!("{provider} connect refused: no descriptor"),
                data: json!({ "provider": provider, "reason": "no_descriptor" }),
                secrets: &self.vault.all_secrets()?,
            })?;
            return Err(Error::Invalid(format!(
                "cannot connect `{provider}`: no ratified provider descriptor is loaded for it — a \
                 credential is only ever vaulted for a descriptor-backed provider (add and ratify a \
                 providers.d/{provider}.yaml descriptor first)"
            )));
        };
        // Connect honesty: vaulting a token for a provider that brokers no credential is meaningless.
        if !prov.requires_credential() {
            self.audit.record(NewEvent {
                session_id: None,
                event_type: "provider_connect_refused",
                severity: "medium",
                summary: &format!("{provider} connect refused: brokers no credential"),
                data: json!({ "provider": provider, "reason": "no_credential" }),
                secrets: &self.vault.all_secrets()?,
            })?;
            return Err(Error::Invalid(format!(
                "cannot connect `{provider}`: it brokers no credential, so there is nothing to store"
            )));
        }
        let replaced = self.credential_exists(provider)?;
        let cred = self
            .vault
            .connect(&credential_ref(provider), provider, account_label, token)?;
        self.audit.record(NewEvent {
            session_id: None,
            event_type: "provider_connected",
            severity: "info",
            summary: &format!("connected {provider}"),
            data: json!({
                "provider": provider,
                "reference": cred.reference,
                "account_label": account_label,
                "replaced": replaced,
            }),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(ConnectOutcome {
            stored: true,
            account_label: account_label.map(str::to_string),
            reference: cred.reference,
            provider: provider.to_string(),
            replaced,
        })
    }

    fn credential_exists(&self, provider: &str) -> Result<bool> {
        Ok(self
            .list_credentials()?
            .iter()
            .any(|c| c.provider.as_str() == provider))
    }
}

/// Rebuild a renderable HTTP receipt Value from a VERIFIED
/// terminal audit event's `data` payload. The agent renders it through the SAME `render` path as a
/// live receipt, so a durable fetch reads identically to the inline one.
fn reconstruct_terminal_receipt(data: &Value) -> Option<Value> {
    let provider = data.get("provider").and_then(Value::as_str)?;
    let action = data.get("action").and_then(Value::as_str)?;
    let ok = data.get("outcome").and_then(Value::as_str) == Some("ok");
    let mut v = json!({
        "kind": "executed",
        "ok": ok,
        "provider": provider,
        "action": action,
        "result": data.get("result").cloned().unwrap_or(Value::Null),
    });
    if let Some(effect_id) = data.get("effect_id").and_then(Value::as_str) {
        v["effect_id"] = json!(effect_id);
    }
    // The durable word IS the rendered word: `EffectOutcome`'s serde form and its `as_str` both
    // spell the pre-effect disposition `definitely_pre_effect`, so a reconstructed receipt passes
    // the recorded value through instead of translating it.
    if let Some(effect_outcome) = data.get("effect_outcome").and_then(Value::as_str) {
        v["effect_outcome"] = json!(effect_outcome);
    }
    if let Some(a) = data.get("artifact").and_then(Value::as_str) {
        v["artifact"] = json!(a);
    }
    if let Some(ws) = data.get("wire_stats") {
        v["wire_stats"] = ws.clone();
    }
    // Identity is mandatory on a live receipt, so a RECONSTRUCTED one carries it too. The
    // terminal event has always recorded `request_id` beside the envelope, so a row written before
    // the stamp existed still rebuilds into a receipt the agent can chase.
    let mut envelope = data
        .get("envelope")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(request_id) = data.get("request_id").and_then(Value::as_str) {
        envelope.insert("request_id".into(), json!(request_id));
    }
    // A row with neither identity nor metadata gets NO envelope — an empty object is a
    // field the agent has to read to learn it says nothing.
    if !envelope.is_empty() {
        v["envelope"] = Value::Object(envelope);
    }
    if let Some(err) = data.get("error").and_then(Value::as_str) {
        v["error"] = json!(err);
    }
    Some(v)
}

#[cfg(test)]
mod async_receipt_tests {
    use super::reconstruct_terminal_receipt;
    use serde_json::json;

    #[test]
    fn http_terminal_event_rebuilds_an_executed() {
        let data = json!({
            "grant_id": "g1", "provider": "vercel", "action": "deploy",
            "outcome": "ok", "result": { "url": "https://x" }, "artifact": "art_2",
            "digest": "d", "wire_stats": { "total_bytes": 100, "kept_bytes": 10 }
        });
        let r = reconstruct_terminal_receipt(&data).expect("executed rebuilt");
        assert_eq!(r["kind"], "executed");
        assert_eq!(r["ok"], true);
        assert_eq!(r["result"]["url"], "https://x");
        assert_eq!(r["artifact"], "art_2");
        assert_eq!(r["wire_stats"]["kept_bytes"], 10);
    }

    /// A reconstructed receipt (read back after background completion or supervisor eviction) must
    /// carry the same broker-authored `envelope` — including its `cermet:` line — that an inline
    /// receipt would. A receipt that changes depending on when you ask for it is not a receipt.
    #[test]
    fn a_reconstructed_receipt_carries_the_envelope_the_inline_one_did() {
        let data = json!({
            "grant_id": "g1", "provider": "stripe", "action": "fixture_dispute_charge_create",
            "outcome": "ok",
            "result": { "data": [{ "id": "dp_1" }], "has_more": false },
            "envelope": { "created_charge": "ch_1" },
        });
        let r = reconstruct_terminal_receipt(&data).expect("executed rebuilt");
        assert_eq!(
            r["envelope"],
            json!({ "created_charge": "ch_1" }),
            "the durable receipt must carry the same envelope the inline one did"
        );
    }

    /// A row that names its request_id rebuilds into a receipt the agent can chase, even
    /// if it predates the stamp — the terminal event has always recorded the id beside the envelope.
    #[test]
    fn a_reconstructed_receipt_is_stamped_from_the_rows_own_request_id() {
        let data = json!({
            "grant_id": "g1", "request_id": "rq_7f3a", "provider": "vercel", "action": "deploy",
            "outcome": "ok", "result": { "relay": { "handle": "cermet_relay_Ab3" } },
        });
        let r = reconstruct_terminal_receipt(&data).expect("executed rebuilt");
        assert_eq!(r["envelope"]["request_id"], "rq_7f3a");
    }

    /// A row that names NO request_id and carried no envelope gets NO envelope. An
    /// empty object is a field the agent has to read to learn it says nothing.
    #[test]
    fn a_row_with_neither_identity_nor_metadata_gets_no_envelope() {
        let data = json!({
            "grant_id": "g1", "provider": "vercel", "action": "deploy",
            "outcome": "ok", "result": { "url": "https://x" },
        });
        let r = reconstruct_terminal_receipt(&data).expect("executed rebuilt");
        assert!(
            r.get("envelope").is_none(),
            "no identity and no metadata means no envelope at all: {r}"
        );
    }

    #[test]
    fn a_degraded_event_without_verb_identity_yields_none() {
        let data = json!({ "grant_id": "g1", "outcome": "ok" });
        assert!(reconstruct_terminal_receipt(&data).is_none());
    }
}
