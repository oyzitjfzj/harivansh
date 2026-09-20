use super::runtime::EffectRuntime as RawEffectRuntime;
use crate::{
    AdapterQualificationEvidence, CancelResolution, CancelState, CompensationState, DispatchLease,
    DispatchTicket, DurationKnowledge, EffectError, EffectIntent, EffectView, IdempotencyBinding,
    LifecycleState, ObservationOutcome, OperatingClass, ReconcileOutcome, RetryDecision,
    RetryPolicy, TransportResult,
};
use noerith_storage::{DatabaseKeyPurpose, KeyProvider};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Public S03 effect runtime.
///
/// The lower-level state machine is deliberately private. This boundary binds
/// qualification evidence to the exact adapter assurance profile, binds each
/// effect's immutable Foundation inputs to its retry/qualification evidence,
/// checks canonical-vs-indexed state on every exposed transition, and enforces
/// adapter request-age/idempotency freshness at the dispatch boundary.
pub struct EffectRuntime {
    inner: RawEffectRuntime,
    guard: Connection,
}

impl EffectRuntime {
    pub fn open(path: impl AsRef<Path>, provider: &impl KeyProvider) -> Result<Self, EffectError> {
        let path = path.as_ref();
        let inner = RawEffectRuntime::open(path, provider)?;
        let key = provider
            .database_passphrase(DatabaseKeyPurpose::EffectLedger)
            .map_err(|error| EffectError::KeyProvider(error.to_string()))?;
        if key.trim().is_empty() {
            return Err(EffectError::KeyProvider("empty effect-ledger key".into()));
        }

        let guard = Connection::open(path)?;
        guard.pragma_update(None, "key", key.as_str())?;
        let cipher_version: String =
            guard.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if cipher_version.trim().is_empty() {
            return Err(EffectError::ExecutionUnhealthy);
        }
        guard.pragma_update(None, "foreign_keys", "ON")?;
        guard.pragma_update(None, "synchronous", "FULL")?;
        guard.pragma_update(None, "busy_timeout", 5000_i64)?;
        guard.execute_batch(
            "CREATE TABLE IF NOT EXISTS adapter_qualification_bindings(\
                tenant_namespace TEXT NOT NULL,\
                evidence_identity_digest TEXT NOT NULL,\
                adapter_ref TEXT NOT NULL,\
                adapter_version TEXT NOT NULL,\
                qualification_digest TEXT NOT NULL,\
                assurance_profile_digest TEXT NOT NULL,\
                created_at INTEGER NOT NULL,\
                PRIMARY KEY(tenant_namespace,evidence_identity_digest));\
             CREATE TABLE IF NOT EXISTS effect_integrity_bindings(\
                tenant_namespace TEXT NOT NULL,\
                intent_id TEXT NOT NULL,\
                foundation_binding_digest TEXT NOT NULL,\
                created_at INTEGER NOT NULL,\
                PRIMARY KEY(tenant_namespace,intent_id));",
        )?;

        Ok(Self { inner, guard })
    }

    pub fn register_intent(
        &mut self,
        tenant_namespace: &str,
        intent: &EffectIntent,
        qualification: &AdapterQualificationEvidence,
        retry_policy: &RetryPolicy,
        now_ms: u64,
    ) -> Result<OperatingClass, EffectError> {
        let operating_class = intent.validate_static(qualification)?;
        retry_policy.validate_for(operating_class, intent)?;

        let evidence_identity = qualification_evidence_identity(qualification)?;
        let qualification_digest = digest_json(qualification)?;
        let profile_digest = digest_json(&intent.assurance_profile)?;
        self.bind_qualification(
            tenant_namespace,
            qualification,
            &evidence_identity,
            &qualification_digest,
            &profile_digest,
            now_ms,
        )?;

        let class = self.inner.register_intent(
            tenant_namespace,
            intent,
            qualification,
            retry_policy,
            now_ms,
        )?;
        if class != operating_class {
            return Err(EffectError::ExecutionUnhealthy);
        }

        let foundation_digest =
            foundation_binding_digest(intent, qualification, retry_policy, operating_class)?;
        let existing: Option<String> = self
            .guard
            .query_row(
                "SELECT foundation_binding_digest FROM effect_integrity_bindings WHERE tenant_namespace=?1 AND intent_id=?2",
                params![tenant_namespace, intent.effect_intent_id],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(value) if value != foundation_digest => {
                return Err(EffectError::DuplicateIntentConflict);
            }
            Some(_) => {}
            None => {
                self.guard.execute(
                    "INSERT INTO effect_integrity_bindings(tenant_namespace,intent_id,foundation_binding_digest,created_at) VALUES(?1,?2,?3,?4)",
                    params![
                        tenant_namespace,
                        intent.effect_intent_id,
                        foundation_digest,
                        as_i64(now_ms)?
                    ],
                )?;
            }
        }
        self.verify_effect(tenant_namespace, &intent.effect_intent_id)?;
        Ok(class)
    }

    pub fn prepare(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        self.inner
            .prepare(tenant_namespace, intent_id, evidence_ref, now_ms)?;
        self.verify_effect(tenant_namespace, intent_id).map(|_| ())
    }

    pub fn authorize(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        decision_snapshot_ref: &str,
        decision_snapshot_digest: &str,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        self.inner.authorize(
            tenant_namespace,
            intent_id,
            decision_snapshot_ref,
            decision_snapshot_digest,
            now_ms,
        )?;
        self.verify_effect(tenant_namespace, intent_id).map(|_| ())
    }

    pub fn acquire_dispatch_lease(
        &mut self,
        tenant_namespace: &str,
        owner: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<DispatchLease, EffectError> {
        self.inner
            .acquire_dispatch_lease(tenant_namespace, owner, now_ms, ttl_ms)
    }

    pub fn commit_ready(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        lease: &DispatchLease,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        self.inner
            .commit_ready(tenant_namespace, intent_id, lease, now_ms)?;
        self.verify_effect(tenant_namespace, intent_id).map(|_| ())
    }

    pub fn begin_dispatch(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        lease: &DispatchLease,
        now_ms: u64,
    ) -> Result<DispatchTicket, EffectError> {
        let verified = self.verify_effect(tenant_namespace, intent_id)?;
        enforce_dispatch_freshness(
            &verified.intent,
            verified.operating_class,
            verified.created_at_ms,
            now_ms,
        )?;
        let ticket = self
            .inner
            .begin_dispatch(tenant_namespace, intent_id, lease, now_ms)?;
        self.verify_effect(tenant_namespace, intent_id)?;
        Ok(ticket)
    }

    pub fn record_transport_result(
        &mut self,
        ticket: &DispatchTicket,
        result: TransportResult,
        now_ms: u64,
    ) -> Result<LifecycleState, EffectError> {
        self.verify_effect(&ticket.tenant_namespace, &ticket.effect_intent_id)?;
        let state = self.inner.record_transport_result(ticket, result, now_ms)?;
        self.verify_effect(&ticket.tenant_namespace, &ticket.effect_intent_id)?;
        Ok(state)
    }

    pub fn recover_inflight(
        &mut self,
        tenant_namespace: &str,
        now_ms: u64,
    ) -> Result<usize, EffectError> {
        self.verify_all_effects(tenant_namespace)?;
        let count = self.inner.recover_inflight(tenant_namespace, now_ms)?;
        self.verify_all_effects(tenant_namespace)?;
        Ok(count)
    }

    pub fn retry_decision(
        &self,
        tenant_namespace: &str,
        intent_id: &str,
        now_ms: u64,
    ) -> Result<RetryDecision, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        self.inner
            .retry_decision(tenant_namespace, intent_id, now_ms)
    }

    pub fn schedule_same_intent_retry(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        lease: &DispatchLease,
        fresh_snapshot_ref: &str,
        fresh_snapshot_digest: &str,
        now_ms: u64,
    ) -> Result<u64, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        let available_at = self.inner.schedule_same_intent_retry(
            tenant_namespace,
            intent_id,
            lease,
            fresh_snapshot_ref,
            fresh_snapshot_digest,
            now_ms,
        )?;
        self.verify_effect(tenant_namespace, intent_id)?;
        Ok(available_at)
    }

    pub fn start_reconciliation(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        self.inner
            .start_reconciliation(tenant_namespace, intent_id, evidence_ref, now_ms)?;
        self.verify_effect(tenant_namespace, intent_id).map(|_| ())
    }

    pub fn resolve_reconciliation(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        outcome: ReconcileOutcome,
        now_ms: u64,
    ) -> Result<LifecycleState, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        let state =
            self.inner
                .resolve_reconciliation(tenant_namespace, intent_id, outcome, now_ms)?;
        self.verify_effect(tenant_namespace, intent_id)?;
        Ok(state)
    }

    pub fn observe(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        outcome: ObservationOutcome,
        now_ms: u64,
    ) -> Result<LifecycleState, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        let state = self
            .inner
            .observe(tenant_namespace, intent_id, outcome, now_ms)?;
        self.verify_effect(tenant_namespace, intent_id)?;
        Ok(state)
    }

    pub fn request_cancel(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        authenticated_request_evidence: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        let state = self.inner.request_cancel(
            tenant_namespace,
            intent_id,
            authenticated_request_evidence,
            now_ms,
        )?;
        self.verify_effect(tenant_namespace, intent_id)?;
        Ok(state)
    }

    pub fn mark_cancel_forwarded(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        provider_request_evidence: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        let state = self.inner.mark_cancel_forwarded(
            tenant_namespace,
            intent_id,
            provider_request_evidence,
            now_ms,
        )?;
        self.verify_effect(tenant_namespace, intent_id)?;
        Ok(state)
    }

    pub fn mark_cancel_unforwardable_unknown(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        let state = self.inner.mark_cancel_unforwardable_unknown(
            tenant_namespace,
            intent_id,
            evidence_ref,
            now_ms,
        )?;
        self.verify_effect(tenant_namespace, intent_id)?;
        Ok(state)
    }

    pub fn resolve_cancel_provider_result(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        resolution: CancelResolution,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        let state = self.inner.resolve_cancel_provider_result(
            tenant_namespace,
            intent_id,
            resolution,
            evidence_ref,
            now_ms,
        )?;
        self.verify_effect(tenant_namespace, intent_id)?;
        Ok(state)
    }

    pub fn resolve_cancel_after_reconciliation(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        resolution: CancelResolution,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        let state = self.inner.resolve_cancel_after_reconciliation(
            tenant_namespace,
            intent_id,
            resolution,
            evidence_ref,
            now_ms,
        )?;
        self.verify_effect(tenant_namespace, intent_id)?;
        Ok(state)
    }

    pub fn plan_compensation(
        &mut self,
        tenant_namespace: &str,
        original_intent_id: &str,
        compensation_intent_id: &str,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        self.verify_effect(tenant_namespace, original_intent_id)?;
        self.inner.plan_compensation(
            tenant_namespace,
            original_intent_id,
            compensation_intent_id,
            evidence_ref,
            now_ms,
        )?;
        self.verify_effect(tenant_namespace, original_intent_id)
            .map(|_| ())
    }

    pub fn effect_view(
        &self,
        tenant_namespace: &str,
        intent_id: &str,
    ) -> Result<EffectView, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        self.inner.effect_view(tenant_namespace, intent_id)
    }

    pub fn event_count(&self, tenant_namespace: &str, intent_id: &str) -> Result<u64, EffectError> {
        self.verify_effect(tenant_namespace, intent_id)?;
        self.inner.event_count(tenant_namespace, intent_id)
    }

    fn bind_qualification(
        &mut self,
        tenant_namespace: &str,
        qualification: &AdapterQualificationEvidence,
        evidence_identity_digest: &str,
        qualification_digest: &str,
        profile_digest: &str,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        let tx = self
            .guard
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, String, String)> = tx
            .query_row(
                "SELECT adapter_ref,adapter_version,qualification_digest,assurance_profile_digest FROM adapter_qualification_bindings WHERE tenant_namespace=?1 AND evidence_identity_digest=?2",
                params![tenant_namespace, evidence_identity_digest],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        match existing {
            Some((adapter_ref, adapter_version, bound_qualification, bound_profile))
                if adapter_ref == qualification.adapter_ref
                    && adapter_version == qualification.adapter_version
                    && bound_qualification == qualification_digest
                    && bound_profile == profile_digest => {}
            Some(_) => return Err(EffectError::UnqualifiedAdapter),
            None => {
                tx.execute(
                    "INSERT INTO adapter_qualification_bindings(tenant_namespace,evidence_identity_digest,adapter_ref,adapter_version,qualification_digest,assurance_profile_digest,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        tenant_namespace,
                        evidence_identity_digest,
                        qualification.adapter_ref,
                        qualification.adapter_version,
                        qualification_digest,
                        profile_digest,
                        as_i64(now_ms)?
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn verify_all_effects(&self, tenant_namespace: &str) -> Result<(), EffectError> {
        let mut statement = self
            .guard
            .prepare("SELECT intent_id FROM effects WHERE tenant_namespace=?1")?;
        let rows = statement.query_map([tenant_namespace], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        drop(statement);
        for intent_id in ids {
            self.verify_effect(tenant_namespace, &intent_id)?;
        }
        Ok(())
    }

    fn verify_effect(
        &self,
        tenant_namespace: &str,
        intent_id: &str,
    ) -> Result<VerifiedEffect, EffectError> {
        let row: Option<RawEffectRow> = self
            .guard
            .query_row(
                "SELECT record_json,record_digest,qualification_json,retry_policy_json,operating_class,state,cancel_state,compensation_state,attempt_count,current_fence,created_at FROM effects WHERE tenant_namespace=?1 AND intent_id=?2",
                params![tenant_namespace, intent_id],
                |row| {
                    Ok(RawEffectRow {
                        record_json: row.get(0)?,
                        record_digest: row.get(1)?,
                        qualification_json: row.get(2)?,
                        retry_policy_json: row.get(3)?,
                        operating_class: row.get(4)?,
                        state: row.get(5)?,
                        cancel_state: row.get(6)?,
                        compensation_state: row.get(7)?,
                        attempt_count: row.get(8)?,
                        current_fence: row.get(9)?,
                        created_at: row.get(10)?,
                    })
                },
            )
            .optional()?;
        let row = row.ok_or(EffectError::NotFound)?;

        if digest_text(&row.record_json) != row.record_digest {
            return Err(EffectError::ExecutionUnhealthy);
        }
        let intent: EffectIntent =
            serde_json::from_str(&row.record_json).map_err(|_| EffectError::ExecutionUnhealthy)?;
        if intent.effect_intent_id != intent_id {
            return Err(EffectError::ExecutionUnhealthy);
        }
        let qualification: AdapterQualificationEvidence =
            serde_json::from_str(&row.qualification_json)
                .map_err(|_| EffectError::ExecutionUnhealthy)?;
        let retry_policy: RetryPolicy = serde_json::from_str(&row.retry_policy_json)
            .map_err(|_| EffectError::ExecutionUnhealthy)?;
        let operating_class = OperatingClass::parse(&row.operating_class)
            .map_err(|_| EffectError::ExecutionUnhealthy)?;
        let derived = intent
            .validate_static(&qualification)
            .map_err(|_| EffectError::ExecutionUnhealthy)?;
        if derived != operating_class {
            return Err(EffectError::ExecutionUnhealthy);
        }
        retry_policy
            .validate_for(operating_class, &intent)
            .map_err(|_| EffectError::ExecutionUnhealthy)?;

        let attempt_count =
            u32::try_from(row.attempt_count).map_err(|_| EffectError::ExecutionUnhealthy)?;
        let expected_fence = intent
            .current_fence
            .map(as_i64)
            .transpose()
            .map_err(|_| EffectError::ExecutionUnhealthy)?;
        if row.state != intent.lifecycle_state.as_db()
            || row.cancel_state != intent.cancellation.state.as_db()
            || row.compensation_state != compensation_state_db(intent.compensation.state)
            || row.current_fence != expected_fence
            || usize::try_from(attempt_count).ok() != Some(intent.dispatch_attempt_refs.len())
        {
            return Err(EffectError::ExecutionUnhealthy);
        }

        let foundation_digest =
            foundation_binding_digest(&intent, &qualification, &retry_policy, operating_class)?;
        let bound: Option<String> = self
            .guard
            .query_row(
                "SELECT foundation_binding_digest FROM effect_integrity_bindings WHERE tenant_namespace=?1 AND intent_id=?2",
                params![tenant_namespace, intent_id],
                |row| row.get(0),
            )
            .optional()?;
        if bound.as_deref() != Some(foundation_digest.as_str()) {
            return Err(EffectError::ExecutionUnhealthy);
        }

        let evidence_identity = qualification_evidence_identity(&qualification)?;
        let qualification_digest = digest_json(&qualification)?;
        let profile_digest = digest_json(&intent.assurance_profile)?;
        let qualification_binding: Option<(String, String)> = self
            .guard
            .query_row(
                "SELECT qualification_digest,assurance_profile_digest FROM adapter_qualification_bindings WHERE tenant_namespace=?1 AND evidence_identity_digest=?2",
                params![tenant_namespace, evidence_identity],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match qualification_binding {
            Some((bound_qualification, bound_profile))
                if bound_qualification == qualification_digest
                    && bound_profile == profile_digest => {}
            _ => return Err(EffectError::ExecutionUnhealthy),
        }

        Ok(VerifiedEffect {
            intent,
            operating_class,
            created_at_ms: u64::try_from(row.created_at)
                .map_err(|_| EffectError::ExecutionUnhealthy)?,
        })
    }
}

struct RawEffectRow {
    record_json: String,
    record_digest: String,
    qualification_json: String,
    retry_policy_json: String,
    operating_class: String,
    state: String,
    cancel_state: String,
    compensation_state: String,
    attempt_count: i64,
    current_fence: Option<i64>,
    created_at: i64,
}

struct VerifiedEffect {
    intent: EffectIntent,
    operating_class: OperatingClass,
    created_at_ms: u64,
}

fn enforce_dispatch_freshness(
    intent: &EffectIntent,
    operating_class: OperatingClass,
    created_at_ms: u64,
    now_ms: u64,
) -> Result<(), EffectError> {
    if now_ms < created_at_ms {
        return Err(EffectError::InvalidTransition);
    }
    if let DurationKnowledge::Known(maximum_age_ms) = intent.assurance_profile.maximum_request_age
        && (maximum_age_ms == 0 || now_ms.saturating_sub(created_at_ms) > maximum_age_ms)
    {
        return Err(EffectError::InvalidTransition);
    }

    if matches!(
        operating_class,
        OperatingClass::E2DedupWrite
            | OperatingClass::E3ObservableWrite
            | OperatingClass::E4CompensatableWrite
    ) {
        match &intent.idempotency {
            IdempotencyBinding::Supported { valid_until_ms, .. } if *valid_until_ms > now_ms => {}
            IdempotencyBinding::Supported { .. } => return Err(EffectError::IdempotencyExpired),
            IdempotencyBinding::Unsupported => return Err(EffectError::MissingIdempotencyKey),
        }
    }
    Ok(())
}

fn qualification_evidence_identity(
    qualification: &AdapterQualificationEvidence,
) -> Result<String, EffectError> {
    let value = json!({
        "adapter_ref": qualification.adapter_ref,
        "adapter_version": qualification.adapter_version,
        "evidence_refs": qualification.evidence_refs,
    });
    Ok(digest_bytes(&serde_json::to_vec(&value)?))
}

fn foundation_binding_digest(
    intent: &EffectIntent,
    qualification: &AdapterQualificationEvidence,
    retry_policy: &RetryPolicy,
    operating_class: OperatingClass,
) -> Result<String, EffectError> {
    let value = json!({
        "effect_intent_id": intent.effect_intent_id,
        "operation_type": intent.operation_type,
        "principal_context": intent.principal_context,
        "goal": intent.goal,
        "work": intent.work,
        "target_resources": intent.target_resources,
        "target_accounts": intent.target_accounts,
        "target_principals": intent.target_principals,
        "payload_schema": intent.payload_schema,
        "payload_canonical_digest": intent.payload_canonical_digest,
        "payload_ref": intent.payload_ref,
        "purpose": intent.purpose,
        "data_classes": intent.data_classes,
        "disclosure_classes": intent.disclosure_classes,
        "effect_class": intent.effect_class,
        "reversibility": intent.reversibility,
        "adapter_ref": intent.adapter_ref,
        "adapter_version": intent.adapter_version,
        "assurance_profile": intent.assurance_profile,
        "idempotency": intent.idempotency,
        "expected_evidence_plan_ref": intent.expected_evidence_plan_ref,
        "created_by_message_ref": intent.created_by_message_ref,
        "adapter_qualification": qualification,
        "retry_policy": retry_policy,
        "derived_operating_class": operating_class.as_db()
    });
    Ok(digest_bytes(&serde_json::to_vec(&value)?))
}

fn digest_json<T: serde::Serialize>(value: &T) -> Result<String, EffectError> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

fn digest_text(value: &str) -> String {
    digest_bytes(value.as_bytes())
}

fn digest_bytes(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn compensation_state_db(state: CompensationState) -> &'static str {
    match state {
        CompensationState::NotApplicable => "NOT_APPLICABLE",
        CompensationState::Available => "AVAILABLE",
        CompensationState::Planned => "PLANNED",
        CompensationState::Authorized => "AUTHORIZED",
        CompensationState::Running => "RUNNING",
        CompensationState::Compensated => "COMPENSATED",
        CompensationState::Failed => "FAILED",
        CompensationState::Unavailable => "UNAVAILABLE",
    }
}

fn as_i64(value: u64) -> Result<i64, EffectError> {
    i64::try_from(value).map_err(|_| EffectError::InvalidField("u64_overflow"))
}
