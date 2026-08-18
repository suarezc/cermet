use super::helpers::*;
use super::*;

#[derive(Clone, Copy)]
enum CapabilityDecisionSource<'a> {
    Sentence {
        rules: &'a crate::sentence::RuleSet,
        fingerprint: &'a str,
    },
    SentenceRefusal {
        reason: &'a str,
        authority_fingerprint: &'a str,
        supplied_fingerprint: Option<&'a str>,
    },
}

type ValidatedResolvedEvidence = (
    CanonicalResource,
    BTreeMap<String, EnvelopeField>,
    Vec<EnvelopeSource>,
);

struct RetryParent {
    grant_id: String,
    grant: GrantRow,
    money: crate::money::MoneyMetadata,
    reservation_owner_id: String,
    reservation_owner_grant: GrantRow,
    lineage_grant_ids: BTreeSet<String>,
    lineage_request_ids: BTreeSet<String>,
}

#[derive(Clone)]
struct RetryNode {
    grant_id: String,
    grant: GrantRow,
    money: crate::money::MoneyMetadata,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RetryExecutionState {
    Ambiguous,
    DefinitelyPreEffect,
    Final,
}

fn validate_retry_transition(child: &RetryNode, parent: &RetryNode) -> Result<()> {
    let same_evidence = match (
        EvidenceEnvelope::from_canonical_json(&child.grant.evidence_json)
            .map_err(Error::Integrity)?,
        EvidenceEnvelope::from_canonical_json(&parent.grant.evidence_json)
            .map_err(Error::Integrity)?,
    ) {
        (EvidenceEnvelope::None { .. }, EvidenceEnvelope::None { .. }) => true,
        (EvidenceEnvelope::ProviderResolved(child), EvidenceEnvelope::ProviderResolved(parent)) => {
            child.profile == parent.profile
                && child.profile_fingerprint == parent.profile_fingerprint
        }
        _ => false,
    };
    if child.money.parent_grant_id() != Some(parent.grant_id.as_str())
        || child.money.effect_id() != parent.money.effect_id()
        || child.money.idempotency_key() != parent.money.idempotency_key()
        || child.money.precondition_fingerprint() != parent.money.precondition_fingerprint()
        || child.money.retry_deadline_epoch() != parent.money.retry_deadline_epoch()
        || child.grant.principal_id != parent.grant.principal_id
        || child.grant.provider != parent.grant.provider
        || child.grant.action != parent.grant.action
        || child.grant.resource_json != parent.grant.resource_json
        || child.grant.template_hash != parent.grant.template_hash
        || child.grant.descriptor_hash != parent.grant.descriptor_hash
        || !same_evidence
    {
        return Err(Error::Denied("retry effect lineage is unavailable".into()));
    }
    Ok(())
}

fn exact_retry_event_object<'a>(
    event: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>> {
    let object = event
        .as_object()
        .ok_or_else(|| Error::Integrity("money retry event is not an object".into()))?;
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let required: BTreeSet<&str> = required.iter().copied().collect();
    let allowed: BTreeSet<&str> = required
        .iter()
        .copied()
        .chain(optional.iter().copied())
        .collect();
    if !required.is_subset(&actual) || !actual.is_subset(&allowed) {
        return Err(Error::Integrity(
            "money retry event has a malformed schema".into(),
        ));
    }
    Ok(object)
}

fn retry_event_str<'a>(object: &'a serde_json::Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Integrity(format!("money retry event has invalid {field}")))
}

fn validate_money_effect_start(broker: &Broker, node: &RetryNode, event: &Value) -> Result<String> {
    const KEYS: &[&str] = &[
        "grant_id",
        "request_id",
        "provider",
        "action",
        "authority_digest",
        "resource",
        "resource_binding",
        "agent_request_fields",
        "provider_resolved_fields",
        "request_session",
        "executing_session",
        "evidence_receipt_id",
        "evidence_resolution_digest",
        "effect_id",
    ];
    let object = exact_retry_event_object(event, KEYS, &[])?;
    let envelope = EvidenceEnvelope::from_canonical_json(&node.grant.evidence_json)
        .map_err(Error::Integrity)?;
    let EvidenceEnvelope::ProviderResolved(evidence) = envelope else {
        return Err(Error::Integrity(
            "money effect start has no provider evidence".into(),
        ));
    };
    let resource: Value = serde_json::from_str(&node.grant.resource_json)
        .map_err(|error| Error::Integrity(format!("money grant resource is malformed: {error}")))?;
    let provider_fields: Vec<String> = evidence.fields.keys().cloned().collect();
    let agent_fields: Vec<String> = resource
        .as_object()
        .map(|fields| {
            fields
                .keys()
                .filter(|field| !evidence.fields.contains_key(*field))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let executing_session = retry_event_str(object, "executing_session")?;
    if retry_event_str(object, "grant_id")? != node.grant_id
        || retry_event_str(object, "request_id")? != node.grant.request_id
        || retry_event_str(object, "effect_id")? != node.money.effect_id().unwrap_or("")
        || retry_event_str(object, "provider")? != node.grant.provider
        || retry_event_str(object, "action")? != node.grant.action
        || retry_event_str(object, "authority_digest")? != node.grant.policy_fingerprint
        || retry_event_str(object, "request_session")? != node.grant.session_id
        || retry_event_str(object, "evidence_receipt_id")? != evidence.receipt_id
        || retry_event_str(object, "evidence_resolution_digest")? != evidence.resolution_digest
        || retry_event_str(object, "resource_binding")?
            != broker.effect_start_resource_binding(
                &node.grant_id,
                &node.grant,
                object
                    .get("resource")
                    .ok_or_else(|| Error::Integrity("money effect start has no resource".into()))?,
            )?
        || object.get("agent_request_fields") != Some(&json!(agent_fields))
        || object.get("provider_resolved_fields") != Some(&json!(provider_fields))
    {
        return Err(Error::Integrity(
            "money effect start does not match its grant and effect".into(),
        ));
    }
    Ok(executing_session.to_string())
}

fn validate_money_terminal(
    node: &RetryNode,
    event_type: &str,
    event: &Value,
) -> Result<(RetryExecutionState, bool, String, bool)> {
    const COMMON: &[&str] = &[
        "grant_id",
        "request_id",
        "provider",
        "action",
        "outcome",
        "mutation_invoked",
        "request_session",
        "executing_session",
        "effect_id",
        "effect_outcome",
    ];
    const OPTIONAL_RESPONSE: &[&str] = &[
        "executing_pid",
        "artifact",
        "digest",
        "wire_stats",
        "retention_error",
        // The broker-authored receipt envelope (identity, plus any per-verb metadata)
        // rides every response-bearing terminal event. Optional rather than required because this
        // validator reads DURABLE evidence, and a row written before the stamp existed has none.
        "envelope",
        // The typed WHY of a delivered failure. Optional for the same reason `envelope` is, and
        // never consulted by the retry decision.
        "failure_class",
        // The compiled success contract's OBSERVATION of this response, recorded beside the
        // disposition derived from it. Optional for the same reason the two above are — this
        // validator reads DURABLE evidence, including rows a daemon wrote before the field
        // existed. The retry decision reads the derived `effect_outcome`, whose consumers are
        // unchanged.
        "effect_proof",
    ];
    let has_error = event.get("error").is_some();
    let has_result = event.get("result").is_some();
    if has_error && has_result {
        return Err(Error::Integrity(
            "money terminal mixes error and result schemas".into(),
        ));
    }
    let mut required = COMMON.to_vec();
    let optional = if has_error {
        required.push("error");
        // A money attempt that got no response at all records the moment it entered the call, and
        // `failure_class` — the typed observation of WHY. Optional for the same reason `envelope`
        // is: this validator reads DURABLE evidence including rows written before the field
        // existed, and the retry decision never consults it.
        //
        // `transport_error` has no writer any more (the prose duplicated what the class now carries
        // typed). It stays listed for its ONE remaining consumer: audit rows written before the
        // class existed, which this validator must still read without calling them malformed.
        &[
            "executing_pid",
            "transport_error",
            "attempted_at",
            "failure_class",
        ][..]
    } else if has_result {
        required.push("result");
        OPTIONAL_RESPONSE
    } else {
        &[][..]
    };
    let object = exact_retry_event_object(event, &required, optional)?;
    let executing_session = retry_event_str(object, "executing_session")?;
    if retry_event_str(object, "grant_id")? != node.grant_id
        || retry_event_str(object, "request_id")? != node.grant.request_id
        || retry_event_str(object, "effect_id")? != node.money.effect_id().unwrap_or("")
        || retry_event_str(object, "provider")? != node.grant.provider
        || retry_event_str(object, "action")? != node.grant.action
        || retry_event_str(object, "request_session")? != node.grant.session_id
    {
        return Err(Error::Integrity(
            "money terminal does not match its grant and effect".into(),
        ));
    }
    if object
        .get("executing_pid")
        .is_some_and(|value| value.as_i64().is_none())
        || object
            .get("retention_error")
            .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err(Error::Integrity(
            "money terminal has malformed optional evidence".into(),
        ));
    }
    let artifact = object.get("artifact");
    let digest = object.get("digest");
    if artifact.is_some() != digest.is_some()
        || artifact.is_some_and(|value| value.as_str().is_none_or(str::is_empty))
        || digest.is_some_and(|value| value.as_str().is_none_or(str::is_empty))
        || object.get("retention_error").is_some() && artifact.is_some()
    {
        return Err(Error::Integrity(
            "money terminal has malformed artifact evidence".into(),
        ));
    }
    if let Some(wire_stats) = object.get("wire_stats") {
        let Some(wire_stats) = wire_stats.as_object() else {
            return Err(Error::Integrity(
                "money terminal has malformed wire statistics".into(),
            ));
        };
        let keys: BTreeSet<&str> = wire_stats.keys().map(String::as_str).collect();
        let total = wire_stats.get("total_bytes").and_then(Value::as_u64);
        let kept = wire_stats.get("kept_bytes").and_then(Value::as_u64);
        if keys != BTreeSet::from(["kept_bytes", "total_bytes"])
            || total.is_none()
            || kept.is_none()
            || kept > total
        {
            return Err(Error::Integrity(
                "money terminal has malformed wire statistics".into(),
            ));
        }
    }
    let mutation_invoked = object
        .get("mutation_invoked")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::Integrity("money terminal has invalid invocation state".into()))?;
    let outcome = retry_event_str(object, "outcome")?;
    let effect_outcome = retry_event_str(object, "effect_outcome")?;
    // A money terminal is `retention: none` by contract, so it can carry no artifact, no wire
    // counter, and no retention error — that RETENTION cap is unchanged. Its `result`, however, is
    // the provider's response verbatim: the verified body
    // on a success, the rejection on a failure. A money terminal whose result is null is therefore
    // no longer the only legal shape, and one carrying stored-artifact evidence is still impossible.
    if has_result
        && (artifact.is_some()
            || object.get("wire_stats").is_some()
            || object.get("retention_error").is_some())
    {
        return Err(Error::Integrity(
            "money terminal carries impossible response retention".into(),
        ));
    }
    let state = if has_error {
        if event_type != "provider_action_failed"
            || outcome != "error"
            || retry_event_str(object, "error").is_err()
        {
            return Err(Error::Integrity(
                "money error terminal is inconsistent".into(),
            ));
        }
        match (mutation_invoked, effect_outcome) {
            (true, "ambiguous") => RetryExecutionState::Ambiguous,
            (false, "definitely_pre_effect") => RetryExecutionState::DefinitelyPreEffect,
            _ => {
                return Err(Error::Integrity(
                    "money error terminal has an invalid outcome class".into(),
                ));
            }
        }
    } else if has_result {
        match (event_type, outcome, mutation_invoked, effect_outcome) {
            ("provider_action_succeeded", "ok", true, "succeeded") => RetryExecutionState::Final,
            ("provider_action_failed", "provider_error", true, "ambiguous") => {
                RetryExecutionState::Ambiguous
            }
            ("provider_action_failed", "provider_error", true, "definitely_failed") => {
                RetryExecutionState::Final
            }
            _ => {
                return Err(Error::Integrity(
                    "money response terminal has an invalid outcome class".into(),
                ));
            }
        }
    } else {
        if event_type != "provider_action_failed"
            || mutation_invoked
            || effect_outcome != "definitely_pre_effect"
            || !matches!(
                outcome,
                "lockdown_engaged"
                    | "authority_changed"
                    | "authority_unavailable"
                    | "precondition_credential_unavailable"
                    | "precondition_denied"
            )
        {
            return Err(Error::Integrity(
                "money pre-effect terminal has an invalid outcome class".into(),
            ));
        }
        RetryExecutionState::DefinitelyPreEffect
    };
    Ok((
        state,
        mutation_invoked,
        executing_session.to_string(),
        has_error || has_result,
    ))
}

impl Broker {
    fn authenticated_retry_ancestry(&self, start: &RetryNode) -> Option<BTreeSet<String>> {
        let effect_id = start.money.effect_id()?;
        let mut ids = BTreeSet::new();
        let mut node = start.clone();
        loop {
            self.assert_grant_integrity(&node.grant_id, &node.grant)
                .ok()?;
            if ids.len() >= 32 || !ids.insert(node.grant_id.clone()) {
                return None;
            }
            if !node.money.is_retry() {
                return Some(ids);
            }
            let parent_id = node.money.parent_grant_id()?;
            let parent_grant = self.load_grant(parent_id).ok()?;
            self.assert_grant_integrity(parent_id, &parent_grant).ok()?;
            let parent_money =
                crate::money::MoneyMetadata::from_canonical_json(&parent_grant.money_json).ok()?;
            if parent_money.effect_id() != Some(effect_id) {
                return None;
            }
            let parent = RetryNode {
                grant_id: parent_id.to_string(),
                grant: parent_grant,
                money: parent_money,
            };
            validate_retry_transition(&node, &parent).ok()?;
            node = parent;
        }
    }

    fn authenticated_retry_lineage_intersects(
        &self,
        target: &RetryNode,
        target_ids: &BTreeSet<String>,
        other_id: &str,
    ) -> bool {
        if target_ids.contains(other_id) {
            return true;
        }
        let Ok(other_grant) = self.load_grant(other_id) else {
            return false;
        };
        if self.assert_grant_integrity(other_id, &other_grant).is_err() {
            return false;
        }
        let Ok(other_money) =
            crate::money::MoneyMetadata::from_canonical_json(&other_grant.money_json)
        else {
            return false;
        };
        if other_money.effect_id() != target.money.effect_id() {
            return false;
        }
        let other = RetryNode {
            grant_id: other_id.to_string(),
            grant: other_grant,
            money: other_money,
        };
        self.authenticated_retry_ancestry(&other)
            .is_some_and(|ids| !ids.is_disjoint(target_ids))
    }

    fn verified_money_events_for_node(
        &self,
        node: &RetryNode,
    ) -> Result<Vec<crate::audit::MoneyRetryAuditEvent>> {
        let effect_id = node
            .money
            .effect_id()
            .ok_or_else(|| Error::Integrity("money lineage has no effect id".into()))?;
        let events = self.audit.verified_money_retry_events(
            &node.grant_id,
            &node.grant.request_id,
            effect_id,
        )?;
        let target_ids = self.authenticated_retry_ancestry(node).ok_or_else(|| {
            Error::Integrity("money retry lineage has invalid authenticated ancestry".into())
        })?;
        let mut classified = HashMap::new();
        let mut relevant = Vec::new();
        for event in events.events {
            let other_id = event.data.get("grant_id").and_then(Value::as_str);
            let claims_target = other_id == Some(node.grant_id.as_str())
                || event.data.get("request_id").and_then(Value::as_str)
                    == Some(node.grant.request_id.as_str());
            let connected_sibling = other_id.is_some_and(|other_id| {
                *classified.entry(other_id.to_string()).or_insert_with(|| {
                    self.authenticated_retry_lineage_intersects(node, &target_ids, other_id)
                })
            });
            if claims_target || !connected_sibling {
                relevant.push(event);
            }
        }
        Ok(relevant)
    }

    fn authenticate_retry_parent(
        &self,
        effect_id: &str,
        principal: &str,
        provider: &str,
        action: &str,
    ) -> Result<RetryParent> {
        let pattern = format!("%\"effect_id\":\"{effect_id}\"%");
        let mut stmt = self
            .state
            .prepare("SELECT id FROM grants WHERE money_json LIKE ?1 ORDER BY rowid DESC")?;
        let ids = stmt
            .query_map([pattern], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let newest_grant_id = ids
            .first()
            .ok_or_else(|| Error::Denied("retry effect lineage is unavailable".into()))?
            .clone();
        let retry_now = self.now_epoch();
        let mut lineage_grant_ids = BTreeSet::new();
        let mut lineage_request_ids = BTreeSet::new();

        let mut node = self.load_retry_node(
            &newest_grant_id,
            effect_id,
            principal,
            provider,
            action,
            retry_now,
        )?;
        let eligible_id = loop {
            if lineage_grant_ids.len() >= 32 || !lineage_grant_ids.insert(node.grant_id.clone()) {
                return Err(Error::Denied("retry effect lineage is unavailable".into()));
            }
            lineage_request_ids.insert(node.grant.request_id.clone());
            self.reconcile_terminal_execution(&node.grant_id, &node.grant)?;
            match self.authenticated_retry_state(&node)? {
                RetryExecutionState::Ambiguous => break node.grant_id.clone(),
                RetryExecutionState::Final => {
                    return Err(Error::Denied("retry effect lineage is unavailable".into()));
                }
                RetryExecutionState::DefinitelyPreEffect => {
                    let parent_id = node.money.parent_grant_id().ok_or_else(|| {
                        Error::Denied("retry effect lineage is unavailable".into())
                    })?;
                    let parent = self.load_retry_node(
                        parent_id, effect_id, principal, provider, action, retry_now,
                    )?;
                    validate_retry_transition(&node, &parent)?;
                    node = parent;
                }
            }
        };

        // Eligibility and debit ownership are separate facts. The newest ambiguous outcome is the
        // child's parent; the original Mutation grant reached through HMAC-bound links owns the mint.
        let mut owner_node = self.load_retry_node(
            &eligible_id,
            effect_id,
            principal,
            provider,
            action,
            retry_now,
        )?;
        let mut owner_seen = BTreeSet::new();
        let reservation_owner = loop {
            if owner_seen.len() >= 32 || !owner_seen.insert(owner_node.grant_id.clone()) {
                return Err(Error::Denied("retry effect lineage is unavailable".into()));
            }
            lineage_grant_ids.insert(owner_node.grant_id.clone());
            lineage_request_ids.insert(owner_node.grant.request_id.clone());
            if !owner_node.money.is_retry() {
                break owner_node;
            }
            let parent_id = owner_node
                .money
                .parent_grant_id()
                .ok_or_else(|| Error::Denied("retry effect lineage is unavailable".into()))?;
            let parent =
                self.load_retry_node(parent_id, effect_id, principal, provider, action, retry_now)?;
            validate_retry_transition(&owner_node, &parent)?;
            owner_node = parent;
        };

        let eligible = self.load_retry_node(
            &eligible_id,
            effect_id,
            principal,
            provider,
            action,
            retry_now,
        )?;
        Ok(RetryParent {
            grant_id: eligible.grant_id,
            grant: eligible.grant,
            money: eligible.money,
            reservation_owner_id: reservation_owner.grant_id,
            reservation_owner_grant: reservation_owner.grant,
            lineage_grant_ids,
            lineage_request_ids,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn load_retry_node(
        &self,
        grant_id: &str,
        effect_id: &str,
        principal: &str,
        provider: &str,
        action: &str,
        retry_now: i64,
    ) -> Result<RetryNode> {
        let grant = self.load_grant(grant_id)?;
        self.assert_grant_integrity(grant_id, &grant)?;
        let money = crate::money::MoneyMetadata::from_canonical_json(&grant.money_json)
            .map_err(Error::Integrity)?;
        if money.effect_id() != Some(effect_id)
            || grant.principal_id.as_deref() != Some(principal)
            || grant.provider != provider
            || grant.action != action
            || retry_now > money.retry_deadline_epoch().unwrap_or(-1)
            || grant.template_hash.as_deref()
                != self.templates.content_hash(provider, action).as_deref()
            || self.descriptor_hash(provider) != Some(grant.descriptor_hash.as_str())
        {
            return Err(Error::Denied("retry effect lineage is unavailable".into()));
        }
        Ok(RetryNode {
            grant_id: grant_id.to_string(),
            grant,
            money,
        })
    }

    fn authenticated_retry_state(&self, node: &RetryNode) -> Result<RetryExecutionState> {
        let events = self.verified_money_events_for_node(node)?;
        let starts: Vec<_> = events
            .iter()
            .filter(|event| event.event_type == "capability_effect_starting")
            .collect();
        let terminals: Vec<_> = events
            .iter()
            .filter(|event| event.event_type != "capability_effect_starting")
            .collect();
        if starts.len() > 1 || terminals.len() > 1 {
            return Err(Error::Integrity(
                "money retry lineage has duplicate execution evidence".into(),
            ));
        }
        let start = match starts.first() {
            Some(event) => {
                if event.session_id.as_deref() != Some(node.grant.session_id.as_str()) {
                    return Err(Error::Integrity(
                        "money effect start has the wrong audit session".into(),
                    ));
                }
                let executing_session = validate_money_effect_start(self, node, &event.data)?;
                Some((*event, executing_session))
            }
            None => None,
        };
        if let Some(event) = terminals.first() {
            if event.session_id.as_deref() != Some(node.grant.session_id.as_str()) {
                return Err(Error::Integrity(
                    "money terminal has the wrong audit session".into(),
                ));
            }
            let (state, mutation_invoked, terminal_session, requires_start) =
                validate_money_terminal(node, &event.event_type, &event.data)?;
            // Effect-start precedes the final lockdown/vault-open checks, so its authenticated
            // same-session terminal may still prove that no mutation adapter was invoked.
            match &start {
                Some((start, start_session))
                    if start.rowid < event.rowid && start_session == &terminal_session => {}
                None if !mutation_invoked && !requires_start => {}
                _ => {
                    return Err(Error::Integrity(
                        "money retry execution evidence has an invalid sequence".into(),
                    ));
                }
            }
            return Ok(state);
        }
        if start.is_some()
            && matches!(
                node.grant.status,
                GrantStatus::Executing | GrantStatus::Expired
            )
        {
            return Ok(RetryExecutionState::Ambiguous);
        }
        Err(Error::Denied("retry effect lineage is unavailable".into()))
    }

    pub(super) fn verified_money_terminal_effect_outcome(
        &self,
        grant_id: &str,
        grant: &GrantRow,
        money: &crate::money::MoneyMetadata,
    ) -> Result<Option<EffectOutcome>> {
        let node = RetryNode {
            grant_id: grant_id.to_string(),
            grant: grant.clone(),
            money: money.clone(),
        };
        let events = self.verified_money_events_for_node(&node)?;
        let starts: Vec<_> = events
            .iter()
            .filter(|event| event.event_type == "capability_effect_starting")
            .collect();
        let terminals: Vec<_> = events
            .iter()
            .filter(|event| event.event_type != "capability_effect_starting")
            .collect();
        if starts.len() > 1 || terminals.len() > 1 {
            return Err(Error::Integrity(format!(
                "grant {grant_id} has duplicate money execution evidence"
            )));
        }
        let start = match starts.first() {
            Some(event) => {
                if event.session_id.as_deref() != Some(grant.session_id.as_str()) {
                    return Err(Error::Integrity(format!(
                        "grant {grant_id} effect start has the wrong audit session"
                    )));
                }
                Some((
                    *event,
                    validate_money_effect_start(self, &node, &event.data)?,
                ))
            }
            None => None,
        };
        let Some(terminal) = terminals.first() else {
            return Ok(None);
        };
        if terminal.session_id.as_deref() != Some(grant.session_id.as_str()) {
            return Err(Error::Integrity(format!(
                "grant {grant_id} terminal has the wrong audit session"
            )));
        }
        let (_, mutation_invoked, terminal_session, requires_start) =
            validate_money_terminal(&node, &terminal.event_type, &terminal.data)?;
        match &start {
            Some((start, start_session))
                if start.rowid < terminal.rowid && start_session == &terminal_session => {}
            None if !mutation_invoked && !requires_start => {}
            _ => {
                return Err(Error::Integrity(format!(
                    "grant {grant_id} money execution evidence has an invalid sequence"
                )))
            }
        }
        let outcome = match terminal.data.get("effect_outcome").and_then(Value::as_str) {
            Some("definitely_pre_effect") => EffectOutcome::PreEffect,
            Some("succeeded") => EffectOutcome::Succeeded,
            Some("definitely_failed") => EffectOutcome::DefinitelyFailed,
            Some("ambiguous") => EffectOutcome::Ambiguous,
            _ => {
                return Err(Error::Integrity(format!(
                    "grant {grant_id} terminal has an invalid effect outcome"
                )))
            }
        };
        Ok(Some(outcome))
    }

    pub(super) fn verified_abandoned_money_effect_outcome(
        &self,
        grant_id: &str,
        grant: &GrantRow,
        money: &crate::money::MoneyMetadata,
    ) -> Result<Option<EffectOutcome>> {
        let node = RetryNode {
            grant_id: grant_id.to_string(),
            grant: grant.clone(),
            money: money.clone(),
        };
        let events = self.verified_money_events_for_node(&node)?;
        let starts: Vec<_> = events
            .iter()
            .filter(|event| event.event_type == "capability_effect_starting")
            .collect();
        let terminals: Vec<_> = events
            .iter()
            .filter(|event| event.event_type != "capability_effect_starting")
            .collect();
        if starts.len() > 1 || !terminals.is_empty() {
            return Err(Error::Integrity(format!(
                "grant {grant_id} has invalid abandoned execution evidence"
            )));
        }
        let Some(start) = starts.first() else {
            return Ok(None);
        };
        if start.session_id.as_deref() != Some(grant.session_id.as_str()) {
            return Err(Error::Integrity(format!(
                "grant {grant_id} effect start has the wrong audit session"
            )));
        }
        validate_money_effect_start(self, &node, &start.data)?;
        Ok(Some(EffectOutcome::Ambiguous))
    }

    pub(super) fn verified_logical_money_effect_outcome(
        &self,
        grant_id: &str,
        grant: &GrantRow,
        money: &crate::money::MoneyMetadata,
    ) -> Result<Option<EffectOutcome>> {
        let effect_id = money
            .effect_id()
            .ok_or_else(|| Error::Integrity("money grant has no effect id".into()))?;
        let mut node = RetryNode {
            grant_id: grant_id.to_string(),
            grant: grant.clone(),
            money: money.clone(),
        };
        let mut seen = BTreeSet::new();
        loop {
            if seen.len() >= 32 || !seen.insert(node.grant_id.clone()) {
                return Err(Error::Integrity("money effect lineage is invalid".into()));
            }
            self.assert_grant_integrity(&node.grant_id, &node.grant)?;
            let mut outcome = self.verified_money_terminal_effect_outcome(
                &node.grant_id,
                &node.grant,
                &node.money,
            )?;
            if outcome.is_none() && node.grant.status == GrantStatus::Expired {
                if let (Some(opened), Some(deadline)) =
                    (node.grant.lease_opened_at, node.grant.lease_deadline)
                {
                    let executing_digest = self.redigest(&node.grant_id, &node.grant, "executing");
                    if self.audit.lease_abandoned_event_exists(
                        &node.grant_id,
                        &node.grant.request_id,
                        &executing_digest,
                        Some(opened),
                        Some(deadline),
                    )? {
                        outcome = self.verified_abandoned_money_effect_outcome(
                            &node.grant_id,
                            &node.grant,
                            &node.money,
                        )?;
                    }
                }
            }
            match outcome {
                Some(EffectOutcome::PreEffect) if node.money.is_retry() => {
                    let parent_id = node.money.parent_grant_id().ok_or_else(|| {
                        Error::Integrity("money retry has no parent grant".into())
                    })?;
                    let parent_grant = self.load_grant(parent_id)?;
                    self.assert_grant_integrity(parent_id, &parent_grant)?;
                    let parent_money =
                        crate::money::MoneyMetadata::from_canonical_json(&parent_grant.money_json)
                            .map_err(Error::Integrity)?;
                    if parent_money.effect_id() != Some(effect_id) {
                        return Err(Error::Integrity(
                            "money retry parent has the wrong effect".into(),
                        ));
                    }
                    let parent = RetryNode {
                        grant_id: parent_id.to_string(),
                        grant: parent_grant,
                        money: parent_money,
                    };
                    validate_retry_transition(&node, &parent)?;
                    node = parent;
                }
                other => return Ok(other),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn deny_evidence_request(
        &self,
        session: &str,
        request_id: &str,
        req: &CapabilityRequest,
        failure: Option<EvidenceFailure>,
        secrets: &[String],
        principal: &str,
        authority_kind: AuthorityKind,
        authority_fingerprint: &str,
        profile: &EvidenceProfile,
    ) -> Result<RequestOutcome> {
        if let Some(failure) = failure {
            let mut data = json!({
                "request_id": request_id,
                "provider": req.provider,
                "action": req.action,
                "profile": profile.id,
                "failure_class": failure.class.as_str(),
            });
            if let Some(status) = failure.http_status {
                data["http_status"] = json!(status);
            }
            self.audit.record(NewEvent {
                session_id: Some(session),
                event_type: "provider_evidence_failed",
                severity: "high",
                summary: &format!(
                    "{}.{} evidence resolution failed: {}",
                    req.provider,
                    req.action,
                    failure.class.as_str()
                ),
                data,
                secrets,
            })?;
        }
        // This deny is lossless like every other seam. It
        // records BEFORE canonicalization, so the submitted values are capped here; `record_request`
        // then redacts by field class — the template carrying the evidence profile is loaded by
        // construction (every caller reached this through `templates.loaded`), so its contract
        // resolves and a secret-classed value still never persists.
        let mut safe_request = req.clone();
        safe_request.resource = cap_field_values(req.resource.clone());
        self.deny(
            session,
            request_id,
            &safe_request,
            crate::evidence::EVIDENCE_DENIAL_REASON,
            "evidence",
            None,
            None,
            secrets,
            principal,
            authority_kind,
            authority_fingerprint,
            // This refusal precedes sentence evaluation: no typed reason exists.
            None,
        )
    }

    /// THE one answer to "this retry's lineage cannot carry this request" — every site that decides
    /// it, whether at the lineage boundary or in the mint window after policy, routes here.
    ///
    /// A money verb declares an evidence profile, so in practice this renders the value-free
    /// evidence denial every other money refusal wears; `retry_lineage` is the class for anything
    /// else. Two of the four sites used to `return Err(..)` with this same prose, which the agent
    /// wire flattens to "internal error" — so the identical condition answered differently
    /// depending only on where the clock crossed. One owner, one answer.
    #[allow(clippy::too_many_arguments)]
    fn deny_retry_lineage(
        &self,
        session: &str,
        request_id: &str,
        req: &CapabilityRequest,
        reason: &str,
        secrets: &[String],
        principal: &str,
        authority_kind: AuthorityKind,
        authority_fingerprint: &str,
        evidence_profile: Option<&EvidenceProfile>,
    ) -> Result<RequestOutcome> {
        if let Some(profile) = evidence_profile {
            return self.deny_evidence_request(
                session,
                request_id,
                req,
                None,
                secrets,
                principal,
                authority_kind,
                authority_fingerprint,
                profile,
            );
        }
        self.deny(
            session,
            request_id,
            req,
            reason,
            "retry_lineage",
            None,
            None,
            secrets,
            principal,
            authority_kind,
            authority_fingerprint,
            // This refusal precedes sentence evaluation: no typed reason exists.
            None,
        )
    }

    /// Request-time field canonicalization, run on the COMPLETE canonical resource just
    /// before anything judges it.
    ///
    /// `Ok(Ok(resource))` is the resource to carry forward (byte-identical to the input when the
    /// request already named the canonical form). `Ok(Err(outcome))` is a finished, audited,
    /// fail-closed denial: an unresolvable value NEVER becomes a guess, and never becomes access.
    ///
    /// Adversary: T2 — an agent supplying the human-legible name the task and the provider's own
    /// dashboard use. This cannot widen authority; it decides only how the requested value is SPELT
    /// before the sentence judges it, and the sentence judges the provider's own identifier either
    /// way.
    ///
    /// Resolution itself is a credentialed hop, so it is gated on the operator having already
    /// extended SOME authority over the verb — see the shape-feasibility check below.
    #[allow(clippy::too_many_arguments)]
    fn canonicalize_request(
        &self,
        session: &str,
        request_id: &str,
        req: &CapabilityRequest,
        provider: &dyn crate::provider::Provider,
        decision_source: CapabilityDecisionSource<'_>,
        resource: CanonicalResource,
        secrets: &[String],
        principal: &str,
        authority_kind: AuthorityKind,
        authority_fingerprint: &str,
    ) -> Result<std::result::Result<CanonicalResource, RequestOutcome>> {
        let Some(profile) = self
            .templates
            .loaded(&req.provider, &req.action)
            .and_then(|loaded| loaded.template.canonicalization_profile())
        else {
            return Ok(Ok(resource));
        };
        let supplied = match resource.req_str(profile.field) {
            Ok(supplied) => supplied.to_string(),
            // The field is required by the template that carries the profile, so canonicalization
            // ran on a resource the contract says cannot exist. Refuse rather than skip.
            Err(error) => {
                return Ok(Err(self.deny(
                    session,
                    request_id,
                    req,
                    &error.to_string(),
                    "invalid",
                    None,
                    None,
                    secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    // This refusal precedes sentence evaluation: no typed reason exists.
                    None,
                )?));
            }
        };
        // The pure short-circuit: a request naming the canonical identifier costs no vault open, no
        // provider hop, and no receipt — it is the same request it was before this profile existed.
        if profile.resolver.is_canonical(&supplied) {
            return Ok(Ok(resource));
        }
        // Everything below this point spends the operator's credential on an authenticated provider
        // read, so ask the SAME non-authorizing
        // question the evidence seam asks before its own credentialed resolution — with this
        // profile's field held UNKNOWN, could any rule in the standing corpus admit this verb at
        // all? A corpus that cannot is refused here, uncredentialed: no vault open, no provider hop,
        // nothing resolved. `true` authorizes nothing; the sentence still judges the exact canonical
        // value below.
        //
        // Adversary: T1 — third-party content steering the agent into looping guessed values. Each
        // well-formed guess otherwise bought an authenticated provider read with the operator's token
        // and an existence bit back, on a verb the operator never spoke about.
        let feasible = match decision_source {
            CapabilityDecisionSource::Sentence { rules, .. } => self.shape_has_possible_allow(
                rules,
                &req.provider,
                &req.action,
                &resource,
                &BTreeSet::from([profile.field.to_string()]),
            ),
            CapabilityDecisionSource::SentenceRefusal { .. } => false,
        };
        if !feasible {
            // The refusal names the CORPUS, never the provider: nothing was resolved, so there is no
            // provider state to describe. It carries no widening hint either — the only value this
            // deny knows is the agent's own spelling, and a suggestion to widen onto a spelling that
            // resolution would immediately rewrite is a hint that cannot work.
            let reason = format!(
                "{}.{}: no standing sentence can admit this request, so `{}` was never resolved. \
                 Ask your operator to extend authority over this verb first.",
                req.provider, req.action, profile.field
            );
            return Ok(Err(self.deny(
                session,
                request_id,
                req,
                &reason,
                "policy",
                Some(&resource.as_match_value()),
                None,
                secrets,
                principal,
                authority_kind,
                authority_fingerprint,
                // The evaluator never ran on this request: no typed reason exists.
                None,
            )?));
        }
        let opened = self
            .vault
            .open_secret_with_generation(&credential_ref(&req.provider), &req.provider);
        let (secret, credential_generation) = match opened {
            Ok(opened) => opened,
            Err(_) => {
                return Ok(Err(self.deny_canonicalization(
                    session,
                    request_id,
                    req,
                    profile,
                    &supplied,
                    EvidenceFailure::new(EvidenceFailureClass::CredentialUnavailable),
                    secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                )?));
            }
        };
        let resolved =
            provider.canonicalize_request_field(profile, secret.expose_secret(), &supplied);
        drop(secret);
        let canonical = match resolved {
            Ok(canonical) => canonical,
            Err(failure) => {
                return Ok(Err(self.deny_canonicalization(
                    session,
                    request_id,
                    req,
                    profile,
                    &supplied,
                    failure,
                    secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                )?));
            }
        };
        self.audit.record(NewEvent {
            session_id: Some(session),
            event_type: crate::canonicalize::CANONICALIZATION_RECEIPT_EVENT_TYPE,
            severity: "info",
            summary: &format!(
                "{}.{} `{}` resolved to its canonical {} identifier",
                req.provider, req.action, profile.field, req.provider
            ),
            data: json!({
                "request_id": request_id,
                "provider": req.provider,
                "action": req.action,
                "profile": profile.id,
                "field": profile.field,
                "supplied": supplied,
                "canonical": canonical,
                "source": profile.source,
                "credential_generation": credential_generation,
            }),
            secrets,
        })?;
        let resource = resource
            .replaced(BTreeMap::from([(
                profile.field.to_string(),
                crate::contract::Scalar::Str(canonical),
            )]))
            .map_err(|error| Error::Integrity(error.to_string()))?;
        Ok(Ok(resource))
    }

    /// The fail-closed half of [`Self::canonicalize_request`]: one high-severity receipt naming the
    /// typed failure, then an ordinary deny. Unlike the money path's evidence denial this keeps its
    /// reason — nothing about the operator's provider state is disclosed by saying that the value
    /// the AGENT supplied did not resolve, and the whole cost of this defect was agents not being
    /// told what to do next.
    #[allow(clippy::too_many_arguments)]
    fn deny_canonicalization(
        &self,
        session: &str,
        request_id: &str,
        req: &CapabilityRequest,
        profile: &'static crate::canonicalize::CanonicalizationProfile,
        supplied: &str,
        failure: EvidenceFailure,
        secrets: &[String],
        principal: &str,
        authority_kind: AuthorityKind,
        authority_fingerprint: &str,
    ) -> Result<RequestOutcome> {
        let mut data = json!({
            "request_id": request_id,
            "provider": req.provider,
            "action": req.action,
            "profile": profile.id,
            "field": profile.field,
            "supplied": supplied,
            "failure_class": failure.class.as_str(),
        });
        if let Some(status) = failure.http_status {
            data["http_status"] = json!(status);
        }
        self.audit.record(NewEvent {
            session_id: Some(session),
            event_type: crate::canonicalize::CANONICALIZATION_FAILED_EVENT_TYPE,
            severity: "high",
            summary: &format!(
                "{}.{} could not resolve `{}` to a canonical {} identifier: {}",
                req.provider,
                req.action,
                profile.field,
                req.provider,
                failure.class.as_str()
            ),
            data,
            secrets,
        })?;
        let reason = format!(
            "{}.{}: `{}` could not be resolved to a canonical {} identifier ({}). Supply the \
             identifier itself, or a name this connection reaches.",
            req.provider,
            req.action,
            profile.field,
            req.provider,
            failure.class.as_str()
        );
        self.deny(
            session,
            request_id,
            req,
            &reason,
            "invalid",
            None,
            None,
            secrets,
            principal,
            authority_kind,
            authority_fingerprint,
            // This refusal precedes sentence evaluation: no typed reason exists.
            None,
        )
    }

    fn validate_resolved_evidence(
        &self,
        profile: &EvidenceProfile,
        partial: &CanonicalResource,
        resolved: ResolvedEvidence,
        secrets: &[String],
    ) -> std::result::Result<ValidatedResolvedEvidence, EvidenceFailure> {
        if resolved.fields.len() != profile.outputs.len() {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
        }
        let mut envelope_fields = BTreeMap::new();
        for output in profile.outputs {
            let Some(value) = resolved.fields.get(output.field) else {
                return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
            };
            if value.kind() != output.ty {
                return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
            }
            let raw = value.to_json();
            if crate::redaction::redacted(raw.clone(), secrets) != raw {
                return Err(EvidenceFailure::new(EvidenceFailureClass::Integrity));
            }
            if partial.contains(output.field) {
                return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
            }
            envelope_fields.insert(
                output.field.to_string(),
                EnvelopeField {
                    source: output.source.to_string(),
                    value: value.to_json(),
                },
            );
        }
        if resolved
            .fields
            .keys()
            .any(|field| profile.output(field).is_none())
        {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
        }

        if resolved.sources.len() != profile.sources.len() {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
        }
        let mut by_kind = BTreeMap::new();
        for source in resolved.sources {
            if by_kind.insert(source.kind, source.id).is_some() {
                return Err(EvidenceFailure::new(EvidenceFailureClass::Ambiguous));
            }
        }
        let mut envelope_sources = Vec::with_capacity(profile.sources.len());
        for source in profile.sources {
            let expected_id = partial
                .req_str(source.id_field)
                .map_err(|_| EvidenceFailure::new(EvidenceFailureClass::Malformed))?;
            let Some(observed_id) = by_kind.remove(source.kind) else {
                return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
            };
            if observed_id != expected_id {
                return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
            }
            envelope_sources.push(EnvelopeSource {
                id: observed_id,
                kind: source.kind.to_string(),
            });
        }
        if !by_kind.is_empty() {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
        }

        let complete = partial
            .merged(resolved.fields)
            .map_err(|_| EvidenceFailure::new(EvidenceFailureClass::Mismatch))?;
        let loaded = self
            .templates
            .loaded(profile.provider, profile.action)
            .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::Integrity))?;
        let Value::Object(complete_fields) = complete.as_match_value() else {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Integrity));
        };
        crate::provider::validate_template_resource(loaded, &complete_fields)
            .map_err(|_| EvidenceFailure::new(EvidenceFailureClass::Malformed))?;
        Ok((complete, envelope_fields, envelope_sources))
    }

    fn request_evidence_is_current(
        &self,
        request_id: &str,
        provider: &str,
        action: &str,
        envelope: &EvidenceEnvelope,
    ) -> Result<bool> {
        let EvidenceEnvelope::ProviderResolved(payload) = envelope else {
            return Ok(true);
        };
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
        let Some(profile) = crate::evidence::profile(profile_id) else {
            return Ok(false);
        };
        let live_profile_fingerprint = profile.semantics_fingerprint();
        let current_profile = self
            .templates
            .loaded(provider, action)
            .and_then(|loaded| loaded.template.request_evidence_id());
        let Some(template_hash) = self.templates.content_hash(provider, action) else {
            return Ok(false);
        };
        let Some(descriptor_hash) = self.descriptor_hash(provider) else {
            return Ok(false);
        };
        let current_digest = crate::evidence::resolution_digest(
            request_id,
            provider,
            action,
            profile.id,
            &live_profile_fingerprint,
            &template_hash,
            descriptor_hash,
            credential_generation,
            *oldest_observed_at_epoch,
            *mint_deadline_epoch,
            fields,
            sources,
        );
        Ok(profile.provider == provider
            && profile.action == action
            && current_profile == Some(profile.id)
            && *profile_fingerprint == live_profile_fingerprint
            && self.now_epoch() <= *mint_deadline_epoch
            && current_digest == *resolution_digest
            && self.vault.matches_generation(
                &credential_ref(provider),
                provider,
                credential_generation,
            )?)
    }

    fn evaluate_capability(
        &self,
        source: CapabilityDecisionSource<'_>,
        provider_name: &str,
        action: &str,
        _contract: Option<&ActionContract>,
        match_value: &Value,
    ) -> crate::policy::PolicyVerdict {
        let q = Query {
            provider: provider_name,
            action,
            resource: match_value,
        };
        match source {
            CapabilityDecisionSource::Sentence { rules, .. } => {
                crate::policy::PolicyEvaluator::evaluate(&self.sentence_policy(rules), &q)
            }
            CapabilityDecisionSource::SentenceRefusal { reason, .. } => {
                // A refusal decided before the evaluator ran (the corpus itself is unusable).
                // There is no typed `DenyReason` for it, and manufacturing one would claim an
                // evaluation that never happened.
                crate::policy::PolicyVerdict {
                    decision: Decision::Deny,
                    reason: reason.to_string(),
                    matched_rule: None,
                    deny_reason: None,
                }
            }
        }
    }

    pub fn request_capability(
        &self,
        session_id: &str,
        req: CapabilityRequest,
    ) -> Result<RequestOutcome> {
        self.request_capability_for_principal(session_id, LOCAL_REQUESTER, req)
    }

    /// Mint through trusted, human-authored sentence authority while retaining the broker's durable
    /// grant kernel. This selects only the decision source; it adds no credential, execution, approval,
    /// or rule-write channel, and every non-Allow sentence result follows the ordinary deny path.
    pub fn request_capability_with_sentence(
        &self,
        session_id: &str,
        rules: &crate::sentence::RuleSet,
        req: CapabilityRequest,
    ) -> Result<RequestOutcome> {
        let supplied_fingerprint = crate::sentence::authority_digest(rules);
        let (authority_rules, authority_fingerprint) = match self.current_sentence_authority() {
            Ok(authority) => authority,
            Err(error) => {
                let reason = error.to_string();
                return self.request_capability_for_principal_owned_with_source(
                    session_id,
                    LOCAL_REQUESTER,
                    req,
                    None,
                    None,
                    CapabilityDecisionSource::SentenceRefusal {
                        reason: &reason,
                        authority_fingerprint: "unavailable",
                        supplied_fingerprint: Some(&supplied_fingerprint),
                    },
                );
            }
        };
        if supplied_fingerprint != authority_fingerprint {
            let reason = format!(
                "supplied sentence ruleset fingerprint `{supplied_fingerprint}` does not match \
                 current authority `{authority_fingerprint}`"
            );
            return self.request_capability_for_principal_owned_with_source(
                session_id,
                LOCAL_REQUESTER,
                req,
                None,
                None,
                CapabilityDecisionSource::SentenceRefusal {
                    reason: &reason,
                    authority_fingerprint: &authority_fingerprint,
                    supplied_fingerprint: Some(&supplied_fingerprint),
                },
            );
        }
        self.request_capability_for_principal_owned_with_source(
            session_id,
            LOCAL_REQUESTER,
            req,
            None,
            None,
            CapabilityDecisionSource::Sentence {
                rules: &authority_rules,
                fingerprint: &authority_fingerprint,
            },
        )
    }

    /// As [`Broker::request_capability`], stamping the caller's attested peer uid as the owner of a
    /// lazily-created session row — the daemon ctl `Request` path, where the operator's
    /// peercred is known but no principal is threaded.
    pub fn request_capability_owned(
        &self,
        session_id: &str,
        req: CapabilityRequest,
        owner_uid: Option<i64>,
    ) -> Result<RequestOutcome> {
        self.request_capability_for_principal_owned(session_id, LOCAL_REQUESTER, req, owner_uid)
    }

    /// As [`Broker::request_capability_owned`], naming the prior effect this request RETRIES — the
    /// operator path's half of the referenced-retry channel (`cermet run --retry-effect`).
    ///
    /// It supplies only the safe effect handle. Everything that makes a retry safe is unchanged and
    /// happens below: a fresh full sentence decision, byte-identical frozen fields against the
    /// referenced attempt, verbatim reuse of that attempt's persisted idempotency key, adoption of
    /// its budget debit rather than a second one, and a plain typed deny if any of it fails. The
    /// operator principal owns the lineage it may name, exactly as an agent principal does.
    pub fn request_retry_capability_owned(
        &self,
        session_id: &str,
        req: CapabilityRequest,
        owner_uid: Option<i64>,
        effect_id: &str,
    ) -> Result<RequestOutcome> {
        self.request_capability_for_principal_owned_with_retry(
            session_id,
            LOCAL_REQUESTER,
            req,
            owner_uid,
            Some(effect_id),
        )
    }

    /// As [`Broker::request_capability_for_principal`], but when `require_session_open` the
    /// caller-supplied `session_id` MUST already reference an OPEN session row — verified atomically
    /// in this same core call (the single broker thread runs it to completion, so no concurrent
    /// sweep/close can interleave in the daemon's preflight gap). A closed/unknown supplied
    /// session fails closed with [`Error::SessionExpired`] and mints NO grant. A daemon-minted
    /// (per-connection / Hello) session passes `false`, keeping the lazy `ensure_session` auto-create.
    pub fn request_capability_for_principal_open(
        &self,
        session_id: &str,
        principal: &str,
        req: CapabilityRequest,
        require_session_open: bool,
        peer_uid: Option<i64>,
    ) -> Result<RequestOutcome> {
        // A caller-supplied session must be OPEN and owned by the attested peer. The
        // same attested uid also stamps a lazily-created (daemon-minted-path) session's owner.
        if require_session_open && !self.session_open_for_peer(session_id.trim(), peer_uid)? {
            return Err(Error::SessionExpired);
        }
        self.request_capability_for_principal_owned(session_id, principal, req, peer_uid)
    }

    /// Explicit request-time retry lineage. The caller supplies only a safe effect handle; the broker
    /// authenticates and reuses the private key from the prior grant.
    #[allow(clippy::too_many_arguments)]
    pub fn request_retry_capability_for_principal_open(
        &self,
        session_id: &str,
        principal: &str,
        effect_id: &str,
        req: CapabilityRequest,
        require_session_open: bool,
        peer_uid: Option<i64>,
    ) -> Result<RequestOutcome> {
        if require_session_open && !self.session_open_for_peer(session_id.trim(), peer_uid)? {
            return Err(Error::SessionExpired);
        }
        if let Some(refusal) =
            self.agent_pre_sentence_refusal(session_id.trim(), principal, &req, peer_uid)
        {
            return refusal;
        }
        self.request_capability_for_principal_owned_with_retry(
            session_id,
            principal,
            req,
            peer_uid,
            Some(effect_id),
        )
    }

    /// Mint a grant stamped with the passed `principal` rather than the v0 `LOCAL_REQUESTER`.
    pub fn request_capability_for_principal(
        &self,
        session_id: &str,
        principal: &str,
        req: CapabilityRequest,
    ) -> Result<RequestOutcome> {
        self.request_capability_for_principal_owned(session_id, principal, req, None)
    }

    /// As above, stamping `owner_uid` (the caller's attested peer) on a lazily-created session row.
    /// Peerless callers — the local same-uid convenience path and tests — pass `None`.
    pub fn request_capability_for_principal_owned(
        &self,
        session_id: &str,
        principal: &str,
        req: CapabilityRequest,
        owner_uid: Option<i64>,
    ) -> Result<RequestOutcome> {
        if let Some(refusal) =
            self.agent_pre_sentence_refusal(session_id.trim(), principal, &req, owner_uid)
        {
            return refusal;
        }
        self.request_capability_for_principal_owned_with_retry(
            session_id, principal, req, owner_uid, None,
        )
    }

    /// The refusals an AGENT-facing request entry answers with a typed, receipted deny instead of an
    /// `Err` — `Some(..)` when one applies, `None` to fall through to the ordinary path.
    ///
    /// Both of these are DECISIONS the broker means, and both used to travel the `Err` channel,
    /// which the agent wire flattens into its infrastructure catch-all. An agent read
    /// `internal error` for "run git instead" and for "the owner stopped everything" alike, and
    /// neither attempt left a receipt — so a fleet knocking on a closed box was invisible to the
    /// very operator who closed it. They are answered here, at the entry, through the ordinary
    /// audited `deny` their pre-sentence sibling `provider_disabled` takes: deny class `invalid`
    /// (no authority was consulted, and the generic `deny` decision is the right receipt), a
    /// sentinel where the authority fingerprint would go, and no typed reason, because there is no
    /// sentence verdict to carry.
    ///
    /// Deliberately NOT applied to the git plane's own entry (`request_capability_from_git_plane`),
    /// which keeps `enforce_not_locked_down`'s `Err`: its hook renders a plain deny as "no standing
    /// authority … add a rule like …", and telling an operator to widen a sentence is the wrong
    /// advice for a box under deny-all. Nor to a SESSIONLESS caller, which has no session row to
    /// hang a receipt on — the agent wire never lands there, since its transport stamps a session
    /// on every request before dispatch.
    fn agent_pre_sentence_refusal(
        &self,
        session: &str,
        principal: &str,
        req: &CapabilityRequest,
        owner_uid: Option<i64>,
    ) -> Option<Result<RequestOutcome>> {
        if session.is_empty() {
            return None;
        }
        // Lockdown first: it closes every door, including the one a git verb would be sent to.
        let (reason, authority) = if self.lockdown_engaged() {
            (LOCKDOWN_REFUSAL.to_string(), "lockdown")
        } else {
            // GIT-NATIVE: a `git:` verb has no agent-facing request path at all. Its decision is
            // git's own `update` hook (the sanctioned per-ref policy seam) on a daemon-held mirror,
            // driven by an ordinary `git push` — so there is no request an agent could make here,
            // and admitting one would be a second authorization surface for the same effect. The
            // refusal says what to run instead.
            (
                self.git_kind_refusal(&req.provider, &req.action)?,
                "git_plane",
            )
        };
        Some(self.deny_pre_sentence(session, principal, req, owner_uid, &reason, authority))
    }

    /// One audited, receipted deny for a refusal reached before any authority is consulted.
    fn deny_pre_sentence(
        &self,
        session: &str,
        principal: &str,
        req: &CapabilityRequest,
        owner_uid: Option<i64>,
        reason: &str,
        authority: &str,
    ) -> Result<RequestOutcome> {
        self.ensure_session_with_fingerprint(session, owner_uid, authority)?;
        self.deny(
            session,
            &new_id("req"),
            req,
            reason,
            "invalid",
            None,
            None,
            &[],
            principal,
            AuthorityKind::Sentence,
            authority,
            // This refusal precedes sentence evaluation: no typed reason exists.
            None,
        )
    }

    /// The refusal a GIT-kind verb answers an agent request with, or `None` for every other verb.
    ///
    /// It speaks the STEP the verb declares: a fetch that describes itself as a push sends the agent
    /// to the wrong command, and "a repository wired by `cermet connect
    /// github`" is a state, not something an agent in a new repo can run — so the wiring command is
    /// stated literally.
    fn git_kind_refusal(&self, provider: &str, action: &str) -> Option<String> {
        let loaded = self.templates.loaded(provider, action)?;
        let spec = loaded.template.git_spec()?;
        let wiring = cermet_lang::provider::GIT_WIRING_COMMAND;
        Some(if spec.push.is_some() {
            format!(
                "{provider}.{action} is not requestable: a git push is decided by git's update \
                 hook. Run `git push <remote> <branch>` in a repository whose remote is a \
                 `cermet::` URL — wire one with `{wiring}` (or `git remote add origin \
                 cermet::github/<owner>/<repo>` in a fresh repo). The refusal, if any, arrives in \
                 git's own output."
            )
        } else {
            format!(
                "{provider}.{action} is not requestable: a fetch/clone is decided by the broker's \
                 git plane. Run `git fetch` / `git clone` against a `cermet::github/<owner>/<repo>` \
                 remote — wire an existing repository with `{wiring}`, or clone straight from \
                 `cermet::github/<owner>/<repo>`. The refusal, if any, arrives in git's own output."
            )
        })
    }

    /// The GIT PLANE's entry into the ordinary sentence machinery — the same corpus, audit, grant
    /// kernel, and receipt an agent request gets, entered from git's update hook instead of the
    /// agent socket. Deliberately not public: only the hook bridge reaches it.
    pub(super) fn request_capability_from_git_plane(
        &self,
        session_id: &str,
        principal: &str,
        req: CapabilityRequest,
        owner_uid: Option<i64>,
    ) -> Result<RequestOutcome> {
        self.request_capability_for_principal_owned_with_retry(
            session_id, principal, req, owner_uid, None,
        )
    }

    fn request_capability_for_principal_owned_with_retry(
        &self,
        session_id: &str,
        principal: &str,
        req: CapabilityRequest,
        owner_uid: Option<i64>,
        retry_effect: Option<&str>,
    ) -> Result<RequestOutcome> {
        // Product disablement is provider-scoped and precedes every authority/provider/action
        // lookup. Establish session ownership first so this never widens the request-handle oracle,
        // then persist one definite denial without consulting sentence custody.
        self.enforce_not_locked_down("capability requests")?;
        let session = session_id.trim();
        if session.is_empty() {
            return Err(Error::Denied(
                "no server session; request_capability requires a session stamped by the transport"
                    .into(),
            ));
        }
        if self.provider_is_product_disabled(&req.provider, &req.action) {
            self.ensure_session_with_fingerprint(session, owner_uid, "provider_disabled")?;
            return self.deny(
                session,
                &new_id("req"),
                &req,
                "provider_disabled",
                "provider_disabled",
                None,
                None,
                &[],
                principal,
                AuthorityKind::Sentence,
                "provider_disabled",
                // This refusal precedes sentence evaluation: no typed reason exists.
                None,
            );
        }
        match self.current_sentence_authority() {
            Ok((rules, fingerprint)) => self.request_capability_for_principal_owned_with_source(
                session_id,
                principal,
                req,
                owner_uid,
                retry_effect,
                CapabilityDecisionSource::Sentence {
                    rules: &rules,
                    fingerprint: &fingerprint,
                },
            ),
            Err(error) => {
                let reason = error.to_string();
                self.request_capability_for_principal_owned_with_source(
                    session_id,
                    principal,
                    req,
                    owner_uid,
                    retry_effect,
                    CapabilityDecisionSource::SentenceRefusal {
                        reason: &reason,
                        authority_fingerprint: "unavailable",
                        supplied_fingerprint: None,
                    },
                )
            }
        }
    }

    fn request_capability_for_principal_owned_with_source(
        &self,
        session_id: &str,
        principal: &str,
        req: CapabilityRequest,
        owner_uid: Option<i64>,
        retry_effect: Option<&str>,
        decision_source: CapabilityDecisionSource<'_>,
    ) -> Result<RequestOutcome> {
        self.enforce_not_locked_down("capability requests")?;
        let session = session_id.trim();
        if session.is_empty() {
            return Err(Error::Denied(
                "no server session; request_capability requires a session stamped by the transport"
                    .into(),
            ));
        }
        let (authority_kind, authority_fingerprint) = match decision_source {
            CapabilityDecisionSource::Sentence { fingerprint, .. } => {
                (AuthorityKind::Sentence, fingerprint)
            }
            CapabilityDecisionSource::SentenceRefusal {
                authority_fingerprint,
                ..
            } => (AuthorityKind::Sentence, authority_fingerprint),
        };
        let session = session.to_string();
        let request_id = new_id("req");
        self.ensure_session(&session, owner_uid)?;
        if self.provider_is_product_disabled(&req.provider, &req.action) {
            return self.deny(
                &session,
                &request_id,
                &req,
                "provider_disabled",
                "provider_disabled",
                None,
                None,
                &[],
                principal,
                authority_kind,
                authority_fingerprint,
                // This refusal precedes sentence evaluation: no typed reason exists.
                None,
            );
        }
        let Some(provider) = self.providers.get(&req.provider) else {
            return self.deny(
                &session,
                &request_id,
                &req,
                &format!(
                    "provider {} not registered — no verb targets it yet. Verbs arrive vendored in \
                     the packaged catalog; call the `catalog` tool (scope=\"all\") for the verbs \
                     that exist and the standing sentence, if any, that admits each one. If the \
                     verb you need does not exist at all, submit it with the `request_vocabulary` \
                     tool — it records the gap and forms the request for your operator.",
                    req.provider
                ),
                "unregistered",
                None,
                None,
                &[],
                principal,
                authority_kind,
                authority_fingerprint,
                // This refusal precedes sentence evaluation: no typed reason exists.
                None,
            );
        };
        if !provider.supports_action(&req.action) {
            return self.deny(
                &session,
                &request_id,
                &req,
                &format!(
                    "unsupported action {} — no verb matches this intent. Verbs arrive vendored in \
                     the packaged catalog; call the `catalog` tool (scope=\"all\") for the verbs \
                     that exist and the standing sentence, if any, that admits each one. If the \
                     verb you need does not exist at all, submit it with the `request_vocabulary` \
                     tool — it records the gap and forms the request for your operator.",
                    req.action
                ),
                "unsupported",
                None,
                None,
                &[],
                principal,
                authority_kind,
                authority_fingerprint,
                // This refusal precedes sentence evaluation: no typed reason exists.
                None,
            );
        }

        let evidence_profile = self
            .templates
            .loaded(&req.provider, &req.action)
            .and_then(|loaded| loaded.template.evidence_profile());
        let retry_parent = if let Some(effect_id) = retry_effect {
            match self.authenticate_retry_parent(effect_id, principal, &req.provider, &req.action) {
                Ok(parent) => Some(parent),
                Err(_) => {
                    return self.deny_retry_lineage(
                        &session,
                        &request_id,
                        &req,
                        "retry effect lineage is unavailable",
                        &[],
                        principal,
                        authority_kind,
                        authority_fingerprint,
                        evidence_profile,
                    );
                }
            }
        } else {
            None
        };
        if let CapabilityDecisionSource::Sentence { rules, .. } = decision_source {
            if crate::sentence::validate_money_authority(
                rules,
                &crate::sets::VendoredSetResolver,
                &self.providers,
            )
            .is_err()
            {
                if let Some(profile) = evidence_profile {
                    return self.deny_evidence_request(
                        &session,
                        &request_id,
                        &req,
                        None,
                        &[],
                        principal,
                        authority_kind,
                        authority_fingerprint,
                        profile,
                    );
                }
                return self.deny(
                    &session,
                    &request_id,
                    &req,
                    "sentence authority contains an invalid money allow",
                    "policy",
                    None,
                    None,
                    &[],
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    // This refusal precedes sentence evaluation: no typed reason exists.
                    None,
                );
            }
        }
        // An evidence-backed request uses structural field redaction and value-free preflight
        // receipts, so no vault-wide redaction read is needed until symbolic feasibility succeeds.
        let mut secrets = if evidence_profile.is_some() {
            Vec::new()
        } else {
            self.vault.all_secrets()?
        };
        let (resource, evidence_json) = if let Some(profile) = evidence_profile {
            let folded = match canonical_resource(&req) {
                Ok(resource) => resource,
                Err(_) => {
                    return self.deny_evidence_request(
                        &session,
                        &request_id,
                        &req,
                        Some(EvidenceFailure::new(EvidenceFailureClass::Malformed)),
                        &secrets,
                        principal,
                        authority_kind,
                        authority_fingerprint,
                        profile,
                    )
                }
            };
            if folded
                .as_object()
                .is_some_and(|fields| fields.keys().any(|field| profile.is_output(field)))
            {
                return self.deny_evidence_request(
                    &session,
                    &request_id,
                    &req,
                    Some(EvidenceFailure::new(EvidenceFailureClass::Mismatch)),
                    &secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    profile,
                );
            }
            let partial = match provider.canonicalize_present_fields(&req.action, &folded) {
                Ok(resource) => resource,
                Err(_) => {
                    return self.deny_evidence_request(
                        &session,
                        &request_id,
                        &req,
                        Some(EvidenceFailure::new(EvidenceFailureClass::Malformed)),
                        &secrets,
                        principal,
                        authority_kind,
                        authority_fingerprint,
                        profile,
                    )
                }
            };
            let contract = provider.action_contract(&req.action).ok_or_else(|| {
                Error::Integrity(format!(
                    "evidence-backed action {}.{} lost its contract",
                    req.provider, req.action
                ))
            })?;
            if contract.schema.iter().any(|field| {
                field.required && !profile.is_output(field.name) && !partial.contains(field.name)
            }) {
                return self.deny_evidence_request(
                    &session,
                    &request_id,
                    &req,
                    Some(EvidenceFailure::new(EvidenceFailureClass::Malformed)),
                    &secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    profile,
                );
            }
            let resolved_fields: BTreeSet<String> = profile
                .outputs
                .iter()
                .map(|output| output.field.to_string())
                .collect();
            let possible = match decision_source {
                CapabilityDecisionSource::Sentence { rules, .. } => self.shape_has_possible_allow(
                    rules,
                    &req.provider,
                    &req.action,
                    &partial,
                    &resolved_fields,
                ),
                CapabilityDecisionSource::SentenceRefusal { .. } => false,
            };
            if !possible {
                return self.deny_evidence_request(
                    &session,
                    &request_id,
                    &req,
                    None,
                    &secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    profile,
                );
            }

            secrets = self.vault.all_secrets()?;

            let (secret, credential_generation) = match self
                .vault
                .open_secret_with_generation(&credential_ref(&req.provider), &req.provider)
            {
                Ok(opened) => opened,
                Err(_) => {
                    return self.deny_evidence_request(
                        &session,
                        &request_id,
                        &req,
                        Some(EvidenceFailure::new(
                            EvidenceFailureClass::CredentialUnavailable,
                        )),
                        &secrets,
                        principal,
                        authority_kind,
                        authority_fingerprint,
                        profile,
                    )
                }
            };
            let oldest_observed_at_epoch = self.now_epoch();
            let mint_deadline_epoch = oldest_observed_at_epoch + crate::evidence::EVIDENCE_TTL_SECS;
            let resolved = provider.resolve_request(profile, secret.expose_secret(), &partial);
            drop(secret);
            let resolved = match resolved {
                Ok(resolved) => resolved,
                Err(failure) => {
                    return self.deny_evidence_request(
                        &session,
                        &request_id,
                        &req,
                        Some(failure),
                        &secrets,
                        principal,
                        authority_kind,
                        authority_fingerprint,
                        profile,
                    )
                }
            };
            let (complete, fields, sources) =
                match self.validate_resolved_evidence(profile, &partial, resolved, &secrets) {
                    Ok(validated) => validated,
                    Err(failure) => {
                        return self.deny_evidence_request(
                            &session,
                            &request_id,
                            &req,
                            Some(failure),
                            &secrets,
                            principal,
                            authority_kind,
                            authority_fingerprint,
                            profile,
                        )
                    }
                };
            let template_hash = self
                .templates
                .content_hash(&req.provider, &req.action)
                .ok_or_else(|| {
                    Error::Integrity("evidence template vanished during request".into())
                })?;
            let descriptor_hash = self.descriptor_hash(&req.provider).ok_or_else(|| {
                Error::Integrity("evidence descriptor vanished during request".into())
            })?;
            let profile_fingerprint = profile.semantics_fingerprint();
            let resolution_digest = crate::evidence::resolution_digest(
                &request_id,
                &req.provider,
                &req.action,
                profile.id,
                &profile_fingerprint,
                &template_hash,
                descriptor_hash,
                &credential_generation,
                oldest_observed_at_epoch,
                mint_deadline_epoch,
                &fields,
                &sources,
            );
            let (receipt_id, receipt_event_hash) =
                self.audit.record_durable_with_hash(NewEvent {
                    session_id: Some(&session),
                    event_type: crate::evidence::EVIDENCE_RECEIPT_EVENT_TYPE,
                    severity: "info",
                    summary: &format!("{}.{} provider evidence resolved", req.provider, req.action),
                    data: json!({
                        "request_id": request_id,
                        "provider": req.provider,
                        "action": req.action,
                        "profile": profile.id,
                        "profile_fingerprint": profile_fingerprint,
                        "oldest_observed_at_epoch": oldest_observed_at_epoch,
                        "mint_deadline_epoch": mint_deadline_epoch,
                        "fields": fields,
                        "sources": sources,
                        "credential_generation": credential_generation,
                        "resolution_digest": resolution_digest,
                    }),
                    secrets: &secrets,
                })?;
            let envelope = EvidenceEnvelope::ProviderResolved(Box::new(ProviderResolvedEnvelope {
                version: crate::evidence::EVIDENCE_ENVELOPE_VERSION,
                credential_generation: credential_generation.clone(),
                fields,
                mint_deadline_epoch,
                oldest_observed_at_epoch,
                profile: profile.id.to_string(),
                profile_fingerprint,
                receipt_event_hash,
                receipt_id,
                resolution_digest,
                sources,
            }));
            let current_profile = self
                .templates
                .loaded(&req.provider, &req.action)
                .and_then(|loaded| loaded.template.request_evidence_id());
            let fresh = self.now_epoch() <= mint_deadline_epoch
                && current_profile == Some(profile.id)
                && self
                    .templates
                    .content_hash(&req.provider, &req.action)
                    .as_deref()
                    == Some(template_hash.as_str())
                && self.descriptor_hash(&req.provider) == Some(descriptor_hash)
                && self.vault.matches_generation(
                    &credential_ref(&req.provider),
                    &req.provider,
                    &credential_generation,
                )?;
            if !fresh {
                return self.deny_evidence_request(
                    &session,
                    &request_id,
                    &req,
                    Some(EvidenceFailure::new(EvidenceFailureClass::Stale)),
                    &secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    profile,
                );
            }
            (complete, envelope.to_canonical_json())
        } else {
            let resource = match canonical_resource(&req)
                .and_then(|folded| provider.canonicalize(&req.action, &folded))
            {
                Ok(resource) => resource,
                Err(error) => {
                    // An invalid request is still owed its next move. The canonicalize
                    // error names the FIRST absent field and stops; the hint names every one.
                    let hint = missing_required_fields_hint(
                        self.suggestion_contract(&req.provider, &req.action),
                        &req.resource,
                    );
                    return self.deny(
                        &session,
                        &request_id,
                        &req,
                        &error.to_string(),
                        "invalid",
                        None,
                        hint.as_deref(),
                        &secrets,
                        principal,
                        authority_kind,
                        authority_fingerprint,
                        // This refusal precedes sentence evaluation: no typed reason exists.
                        None,
                    );
                }
            };
            // The last thing that happens to the resource before ANYTHING judges it. A
            // supplied value that already names the provider's canonical identifier is returned
            // untouched without opening the vault; anything else is resolved here, once, with the
            // credential inside the daemon — and it is the CANONICAL value that the sentence
            // evaluates, the grant freezes, and every later hop is bound to.
            let resource = match self.canonicalize_request(
                &session,
                &request_id,
                &req,
                provider.as_ref(),
                decision_source,
                resource,
                &secrets,
                principal,
                authority_kind,
                authority_fingerprint,
            )? {
                Ok(resource) => resource,
                Err(outcome) => return Ok(outcome),
            };
            (resource, EvidenceEnvelope::none().to_canonical_json())
        };
        if let Some(parent) = &retry_parent {
            let parent_evidence =
                EvidenceEnvelope::from_canonical_json(&parent.grant.evidence_json)
                    .map_err(Error::Integrity)?;
            let current_evidence =
                EvidenceEnvelope::from_canonical_json(&evidence_json).map_err(Error::Integrity)?;
            let same_evidence_semantics = match (&parent_evidence, &current_evidence) {
                (EvidenceEnvelope::None { .. }, EvidenceEnvelope::None { .. }) => true,
                (
                    EvidenceEnvelope::ProviderResolved(parent),
                    EvidenceEnvelope::ProviderResolved(current),
                ) => {
                    parent.profile == current.profile
                        && parent.profile_fingerprint == current.profile_fingerprint
                }
                _ => false,
            };
            if parent.grant.resource_json != resource.to_canonical_json()
                || !same_evidence_semantics
            {
                return self.deny_retry_lineage(
                    &session,
                    &request_id,
                    &req,
                    "retry effect lineage does not match the complete frozen request",
                    &secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    evidence_profile,
                );
            }
        }
        let match_value = resource.as_match_value();

        let crate::policy::PolicyVerdict {
            mut decision,
            mut reason,
            mut matched_rule,
            mut deny_reason,
        } = self.evaluate_capability(
            decision_source,
            &req.provider,
            &req.action,
            provider.action_contract(&req.action),
            &match_value,
        );

        // Credentialed resolution may take arbitrarily long. Re-read the authenticated authority
        // after it and require the exact source fingerprint before any budget evidence or grant write.
        if let Some(profile) = evidence_profile {
            let authority_unchanged = match decision_source {
                CapabilityDecisionSource::Sentence { fingerprint, .. } => self
                    .current_sentence_authority()
                    .is_ok_and(|(_, current)| current == fingerprint),
                CapabilityDecisionSource::SentenceRefusal { .. } => false,
            };
            if !authority_unchanged {
                return self.deny_evidence_request(
                    &session,
                    &request_id,
                    &req,
                    Some(EvidenceFailure::new(EvidenceFailureClass::Stale)),
                    &secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    profile,
                );
            }
        }

        if decision == Decision::Allow
            && retry_parent.as_ref().is_some_and(|parent| {
                self.now_epoch() > parent.money.retry_deadline_epoch().unwrap_or(-1)
            })
        {
            decision = Decision::Deny;
            reason = "retry effect lineage is unavailable".into();
        }

        // Budget/rate admission gate — the ONLY seam holding both the ledger and `now`. It runs
        // on the serialized broker thread AFTER `evaluate()` returned Allow and BEFORE the single
        // `policy_decision` emit below (so there is never an allowed-then-denied audit pair) and before
        // `insert_grant`. It downgrades an exhausted/invalid aggregate to a value-free deny here; on
        // admit the `budget_mint` is appended by the Allow arm, durably, BEFORE the grant row. No grant
        // is ever minted for an aggregate rule without this gate passing (never fail-open).
        let mut budget_admit: Option<Box<super::budget::AdmitTicket>> = None;
        let mut retry_budget_substitution: Option<super::budget::RetryBudgetSubstitutionTicket> =
            None;
        let mut budget_exceeded: Option<crate::types::BudgetWindow> = None;
        if decision == Decision::Allow {
            if let CapabilityDecisionSource::Sentence { rules, .. } = decision_source {
                if let Some(parent) = &retry_parent {
                    match self.retry_budget_substitution(
                        super::budget::RetryBudgetLineage::new(
                            &parent.grant_id,
                            &parent.reservation_owner_id,
                            &parent.reservation_owner_grant,
                            &parent.lineage_grant_ids,
                            &parent.lineage_request_ids,
                        ),
                        rules,
                        &req.provider,
                        &req.action,
                        &resource,
                    ) {
                        Ok(ticket) => retry_budget_substitution = Some(ticket),
                        Err(_) => {
                            decision = Decision::Deny;
                            reason = "retry effect lineage is unavailable".into();
                            // Not a sentence refusal at all — the lineage is unusable. No typed
                            // reason, because none of the eight describes this.
                            deny_reason = None;
                        }
                    }
                } else {
                    let gate = self.budget_gate(
                        rules,
                        &req.provider,
                        &req.action,
                        &resource,
                        &secrets,
                        &session,
                    )?;
                    match gate {
                        super::budget::BudgetGate::NoAggregate => {}
                        super::budget::BudgetGate::Admit(ticket) => budget_admit = Some(ticket),
                        super::budget::BudgetGate::Exceeded { window } => {
                            decision = Decision::Deny;
                            reason = format!(
                                "{}.{} budget exhausted for the {} window",
                                req.provider,
                                req.action,
                                super::budget::window_str(window)
                            );
                            budget_exceeded = Some(super::budget::budget_window(window));
                            // The one refusal `evaluate()` cannot produce: the sentence's
                            // predicates all matched and the LEDGER downgraded it. It is a
                            // `DenyReason` all the same, and the window is the whole of it — never
                            // a figure (anti-oracle §6).
                            deny_reason =
                                Some(crate::sentence::DenyReason::BudgetExceeded { window });
                        }
                        super::budget::BudgetGate::Invalid => {
                            decision = Decision::Deny;
                            reason = format!(
                                "{}.{} denied: budget evidence could not be verified",
                                req.provider, req.action
                            );
                            // Unverifiable evidence is not one of the eight sentence refusals.
                            deny_reason = None;
                        }
                    }
                }
            }
        }

        // Recheck after policy/budget computation and immediately before the decision append/mint
        // sequence. No budget debit or grant may survive a 30-second, credential, template, profile,
        // or descriptor drift that occurred while the complete resource was being evaluated.
        if let Some(profile) = evidence_profile {
            let envelope =
                EvidenceEnvelope::from_canonical_json(&evidence_json).map_err(Error::Integrity)?;
            if !self.request_evidence_is_current(
                &request_id,
                &req.provider,
                &req.action,
                &envelope,
            )? {
                return self.deny_evidence_request(
                    &session,
                    &request_id,
                    &req,
                    Some(EvidenceFailure::new(EvidenceFailureClass::Stale)),
                    &secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    profile,
                );
            }
        }

        // A post-evaluator downgrade (budget exhaustion, retry lineage) is a deny: no rule admitted
        // it, so it carries no matched-rule provenance.
        if decision != Decision::Allow {
            matched_rule = None;
        }

        let mut decision_data = json!({ "decision": decision_str(decision), "provider": req.provider, "action": req.action, "environment": resource.get_str("environment") });
        decision_data["authority_kind"] = json!(authority_kind);
        decision_data["authority_fingerprint"] = json!(authority_fingerprint);
        if let Some(rule) = &matched_rule {
            decision_data["matched_rule"] = json!(rule);
        }
        if let CapabilityDecisionSource::SentenceRefusal {
            supplied_fingerprint: Some(supplied_fingerprint),
            ..
        } = decision_source
        {
            decision_data["supplied_authority_fingerprint"] = json!(supplied_fingerprint);
        }
        self.audit.record(NewEvent {
            session_id: Some(&session),
            event_type: "policy_decision",
            severity: "info",
            summary: &reason,
            data: decision_data,
            secrets: &secrets,
        })?;

        match decision {
            Decision::Deny => {
                // A budget/rate downgrade suppresses the widen hint: no numeric widen
                // suggestion may leak, and its underlying sentence decision was an Allow (predicates
                // matched), so a hint would be misleading anyway.
                let hint = if budget_exceeded.is_some() || evidence_profile.is_some() {
                    None
                } else {
                    match decision_source {
                        CapabilityDecisionSource::Sentence { rules, .. } => self
                            .sentence_widen_hint_for_denial(
                                rules,
                                &req.provider,
                                &req.action,
                                &resource,
                            )
                            .map(|hint| hint.command),
                        CapabilityDecisionSource::SentenceRefusal { .. } => None,
                    }
                };
                let agent_reason = if evidence_profile.is_some() {
                    crate::evidence::EVIDENCE_DENIAL_REASON
                } else {
                    &reason
                };
                let mut outcome = self.deny(
                    &session,
                    &request_id,
                    &req,
                    agent_reason,
                    "policy",
                    Some(&match_value),
                    hint.as_deref(),
                    &secrets,
                    principal,
                    authority_kind,
                    authority_fingerprint,
                    deny_reason.as_ref(),
                )?;
                if evidence_profile.is_some() {
                    outcome.authority_kind = None;
                }
                // The ONLY budget signal that crosses the agent boundary: the window classification,
                // never a number (anti-oracle). `None` for a plain deny.
                outcome.budget_exceeded = if evidence_profile.is_some() {
                    None
                } else {
                    budget_exceeded
                };
                Ok(outcome)
            }
            Decision::Allow => {
                let grant_id = new_id("grant");
                let fingerprint = match decision_source {
                    CapabilityDecisionSource::Sentence { fingerprint, .. } => fingerprint,
                    CapabilityDecisionSource::SentenceRefusal { .. } => {
                        unreachable!("a sentence-authority refusal cannot allow")
                    }
                };
                // Crash-window invariant: the `budget_mint` is appended DURABLY (WAL) BEFORE
                // the grant row is inserted / leaves the broker. Boot performs NO reconciliation — a
                // crash before this append leaves no debit and no grant; a crash after it but before
                // `insert_grant` leaves a phantom orphan debit that `expires_at_epoch` releases and
                // window rollover self-heals. This also closes the race-the-last-dollar: the next
                // serialized request's evidence includes this now-durable mint, appended AFTER the
                // decision but BEFORE the grant row. The mint ticket's SINGLE captured expiry carries
                // into the grant row so the grant's `expiry_epoch` == the `budget_mint`'s
                // `expires_at_epoch`. Independently re-sampling `now_epoch()` here would make the
                // grant outlive its mint's sweep window.
                let mut expiry_override = budget_admit.as_ref().map(|t| t.grant_expiry_epoch());
                if let Some(parent) = &retry_parent {
                    let retry_deadline = parent.money.retry_deadline_epoch().ok_or_else(|| {
                        Error::Integrity("retry parent lost its authenticated deadline".into())
                    })?;
                    expiry_override = Some(
                        expiry_override.map_or(retry_deadline, |expiry| expiry.min(retry_deadline)),
                    );
                }
                if let Some(ticket) = &budget_admit {
                    self.record_budget_mint(&session, &grant_id, &request_id, ticket, &secrets)?;
                }
                // Recheck at the insertion boundary, after every potentially slow policy/audit/budget
                // write. Execute repeats the deadline check to close the remaining sample-to-INSERT
                // scheduling window, so a grant inserted after its deadline is never usable.
                if let Some(profile) = evidence_profile {
                    let envelope = EvidenceEnvelope::from_canonical_json(&evidence_json)
                        .map_err(Error::Integrity)?;
                    if !self.request_evidence_is_current(
                        &request_id,
                        &req.provider,
                        &req.action,
                        &envelope,
                    )? {
                        if budget_admit.is_some() {
                            self.release_budget_for_grant(
                                &grant_id,
                                super::budget::BudgetReleaseCause::EvidenceStaleBeforeGrant,
                            )?;
                        }
                        return self.deny_evidence_request(
                            &session,
                            &request_id,
                            &req,
                            Some(EvidenceFailure::new(EvidenceFailureClass::Stale)),
                            &secrets,
                            principal,
                            authority_kind,
                            authority_fingerprint,
                            profile,
                        );
                    }
                }
                let money_metadata = match self
                    .templates
                    .loaded(&req.provider, &req.action)
                    .filter(|loaded| loaded.template.is_money())
                {
                    Some(loaded) => {
                        if let Some(parent) = &retry_parent {
                            parent.money.retry(parent.grant_id.clone()).ok_or_else(|| {
                                Error::Integrity(
                                    "retry parent lost its private money metadata".into(),
                                )
                            })?
                        } else {
                            let retry_deadline = expiry_override
                                .unwrap_or_else(|| self.now_epoch() + GRANT_TTL_SECS);
                            crate::money::MoneyMetadata::fresh(
                                loaded.template.precondition_fingerprint().ok_or_else(|| {
                                    Error::Integrity(
                                        "money precondition profile vanished before mint".into(),
                                    )
                                })?,
                                retry_deadline,
                            )
                        }
                    }
                    None => crate::money::MoneyMetadata::none(),
                };
                let effect_id = money_metadata.effect_id().map(str::to_string);
                let money_json = money_metadata.to_canonical_json();
                // The deadline can elapse INSIDE this window — after the lineage authenticated,
                // before the grant exists. Same condition as the boundary above, so the same
                // answer: a definite deny with a receipt. The budget mint, if one was taken, is
                // left to its own expiry sweep exactly as it was before.
                if money_metadata.is_retry()
                    && money_metadata
                        .retry_deadline_epoch()
                        .is_some_and(|deadline| self.now_epoch() > deadline)
                {
                    return self.deny_retry_lineage(
                        &session,
                        &request_id,
                        &req,
                        "retry effect lineage is unavailable",
                        &secrets,
                        principal,
                        authority_kind,
                        authority_fingerprint,
                        evidence_profile,
                    );
                }
                if let Some(ticket) = &retry_budget_substitution {
                    let parent = retry_parent.as_ref().ok_or_else(|| {
                        Error::Integrity("retry budget ticket has no authenticated parent".into())
                    })?;
                    if ticket.parent_grant_id() != parent.grant_id {
                        return Err(Error::Integrity(
                            "retry budget ticket names another parent".into(),
                        ));
                    }
                    let effect = effect_id.as_deref().ok_or_else(|| {
                        Error::Integrity("retry grant has no authenticated effect id".into())
                    })?;
                    self.record_money_retry_link(
                        &session,
                        &grant_id,
                        effect,
                        fingerprint,
                        ticket,
                        &secrets,
                    )?;
                }
                // The same recheck once more at the insertion boundary, after the retry-link write.
                if money_metadata.is_retry()
                    && money_metadata
                        .retry_deadline_epoch()
                        .is_some_and(|deadline| self.now_epoch() > deadline)
                {
                    return self.deny_retry_lineage(
                        &session,
                        &request_id,
                        &req,
                        "retry effect lineage is unavailable",
                        &secrets,
                        principal,
                        authority_kind,
                        authority_fingerprint,
                        evidence_profile,
                    );
                }
                self.insert_grant(
                    &grant_id,
                    &request_id,
                    &session,
                    &req,
                    &resource,
                    &evidence_json,
                    &money_json,
                    GrantStatus::Approved,
                    decision,
                    Some(principal),
                    fingerprint,
                    expiry_override,
                )?;
                self.record_request(
                    &request_id,
                    &req,
                    "allow",
                    &reason,
                    principal,
                    &session,
                    Some(authority_fingerprint),
                    matched_rule.as_deref(),
                    None,
                )?;
                Ok(RequestOutcome {
                    request_id,
                    decision,
                    reason,
                    budget_exceeded: None,
                    hint: None,
                    grant_id: Some(grant_id),
                    effect_id,
                    authority_kind: Some(authority_kind),
                })
            }
        }
    }
}
