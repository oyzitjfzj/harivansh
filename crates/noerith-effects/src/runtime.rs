use crate::{
    AcceptanceReceipt, AdapterQualificationEvidence, CancelAfterAcceptance, CancelBeforeAcceptance,
    CancelResolution, CancelState, CompensationCapability, CompensationState, DispatchLease,
    DispatchTicket, EffectError, EffectIntent, EffectView, IdempotencyBinding, LifecycleState,
    ObservationOutcome, OperatingClass, ReconcileOutcome, RetryDecision, RetryPolicy, StatusQuery,
    TransportResult,
};
use noerith_storage::{DatabaseKeyPurpose, KeyProvider};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;

const SCHEMA_VERSION: i64 = 1;

pub struct EffectRuntime {
    connection: Connection,
}

struct TransitionSpec<'a> {
    tenant_namespace: &'a str,
    intent_id: &'a str,
    allowed_from: &'a [LifecycleState],
    next: LifecycleState,
    event_type: &'a str,
    evidence_ref: &'a str,
    now_ms: u64,
}

impl EffectRuntime {
    pub fn open(path: impl AsRef<Path>, provider: &impl KeyProvider) -> Result<Self, EffectError> {
        let key = provider
            .database_passphrase(DatabaseKeyPurpose::EffectLedger)
            .map_err(|error| EffectError::KeyProvider(error.to_string()))?;
        if key.trim().is_empty() {
            return Err(EffectError::KeyProvider("empty effect-ledger key".into()));
        }

        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "key", key.as_str())?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if cipher_version.trim().is_empty() {
            return Err(EffectError::ExecutionUnhealthy);
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.pragma_update(None, "busy_timeout", 5000_i64)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(EffectError::ExecutionUnhealthy);
        }
        initialize_schema(&mut connection)?;
        Ok(Self { connection })
    }

    pub fn register_intent(
        &mut self,
        tenant_namespace: &str,
        intent: &EffectIntent,
        qualification: &AdapterQualificationEvidence,
        retry_policy: &RetryPolicy,
        now_ms: u64,
    ) -> Result<OperatingClass, EffectError> {
        require_text(tenant_namespace, "tenant_namespace")?;
        if intent.lifecycle_state != LifecycleState::Proposed
            || intent.cancellation.state != CancelState::None
            || intent.current_fence.is_some()
        {
            return Err(EffectError::InvalidTransition);
        }
        if qualification.adapter_ref != intent.adapter_ref
            || qualification.adapter_version != intent.adapter_version
        {
            return Err(EffectError::QualificationAdapterMismatch);
        }
        let operating_class = intent.validate_static(qualification)?;
        retry_policy.validate_for(operating_class, intent)?;
        validate_idempotency_window(intent, operating_class, now_ms)?;

        let record_json = serde_json::to_string(intent)?;
        let qualification_json = serde_json::to_string(qualification)?;
        let retry_json = serde_json::to_string(retry_policy)?;
        let creation_digest = creation_digest(intent)?;
        let record_digest = digest_text(&record_json);
        let now = as_i64(now_ms)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_tenant(&tx, tenant_namespace, now)?;
        let existing: Option<(String, String, String, String)> = tx
            .query_row(
                "SELECT creation_digest,qualification_json,retry_policy_json,operating_class FROM effects \
                 WHERE tenant_namespace=?1 AND intent_id=?2",
                params![tenant_namespace, intent.effect_intent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((existing_creation, existing_qualification, existing_retry, existing_class)) =
            existing
        {
            if existing_creation == creation_digest
                && existing_qualification == qualification_json
                && existing_retry == retry_json
                && existing_class == operating_class.as_db()
            {
                tx.commit()?;
                return Ok(operating_class);
            }
            return Err(EffectError::DuplicateIntentConflict);
        }

        tx.execute(
            "INSERT INTO effects(tenant_namespace,intent_id,creation_digest,record_json,record_digest,qualification_json,retry_policy_json,operating_class,state,cancel_state,compensation_state,attempt_count,current_fence,created_at,updated_at) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,NULL,?12,?12)",
            params![
                tenant_namespace,
                intent.effect_intent_id,
                creation_digest,
                record_json,
                record_digest,
                qualification_json,
                retry_json,
                operating_class.as_db(),
                intent.lifecycle_state.as_db(),
                intent.cancellation.state.as_db(),
                compensation_state_db(intent.compensation.state),
                now
            ],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            &intent.effect_intent_id,
            "EFFECT_INTENT_REGISTERED",
            now,
            Some(&creation_digest),
        )?;
        tx.commit()?;
        Ok(operating_class)
    }

    pub fn prepare(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        self.transition(TransitionSpec {
            tenant_namespace,
            intent_id,
            allowed_from: &[LifecycleState::Proposed],
            next: LifecycleState::Prepared,
            event_type: "EFFECT_PREPARED",
            evidence_ref,
            now_ms,
        })
    }

    pub fn authorize(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        decision_snapshot_ref: &str,
        decision_snapshot_digest: &str,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        require_text(decision_snapshot_ref, "decision_snapshot_ref")?;
        require_text(decision_snapshot_digest, "decision_snapshot_digest")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if loaded.intent.lifecycle_state != LifecycleState::Prepared {
            return Err(EffectError::InvalidTransition);
        }
        loaded.intent.lifecycle_state = LifecycleState::Authorized;
        loaded.intent.decision_snapshot_refs.push(crate::DigestRef {
            ref_id: decision_snapshot_ref.to_owned(),
            digest: decision_snapshot_digest.to_owned(),
        });
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "EFFECT_AUTHORIZED",
            as_i64(now_ms)?,
            Some(decision_snapshot_digest),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn acquire_dispatch_lease(
        &mut self,
        tenant_namespace: &str,
        owner: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<DispatchLease, EffectError> {
        require_text(tenant_namespace, "tenant_namespace")?;
        require_text(owner, "owner")?;
        if ttl_ms == 0 {
            return Err(EffectError::InvalidField("ttl_ms"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_tenant(&tx, tenant_namespace, as_i64(now_ms)?)?;
        require_execution_healthy(&tx, tenant_namespace)?;
        let current: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT owner,fence,expires_at FROM dispatch_leases WHERE tenant_namespace=?1",
                [tenant_namespace],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let now = as_i64(now_ms)?;
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        let expires_at = as_i64(expires_at_ms)?;
        let fence = match current {
            Some((current_owner, _current_fence, current_expiry))
                if current_expiry > now && current_owner != owner =>
            {
                return Err(EffectError::LeaseBusy);
            }
            Some((current_owner, current_fence, current_expiry))
                if current_expiry > now && current_owner == owner =>
            {
                tx.execute(
                    "UPDATE dispatch_leases SET expires_at=?3 WHERE tenant_namespace=?1 AND owner=?2",
                    params![tenant_namespace, owner, expires_at],
                )?;
                u64::try_from(current_fence).map_err(|_| EffectError::StaleFence)?
            }
            Some((_, current_fence, _)) => {
                let next = current_fence
                    .checked_add(1)
                    .ok_or(EffectError::StaleFence)?;
                tx.execute(
                    "UPDATE dispatch_leases SET owner=?2,fence=?3,expires_at=?4 WHERE tenant_namespace=?1",
                    params![tenant_namespace, owner, next, expires_at],
                )?;
                u64::try_from(next).map_err(|_| EffectError::StaleFence)?
            }
            None => {
                tx.execute(
                    "INSERT INTO dispatch_leases(tenant_namespace,owner,fence,expires_at) VALUES(?1,?2,1,?3)",
                    params![tenant_namespace, owner, expires_at],
                )?;
                1
            }
        };
        tx.commit()?;
        Ok(DispatchLease {
            tenant_namespace: tenant_namespace.to_owned(),
            owner: owner.to_owned(),
            fence,
            expires_at_ms,
        })
    }

    pub fn commit_ready(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        lease: &DispatchLease,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&tx, tenant_namespace, lease, now_ms)?;
        require_execution_healthy(&tx, tenant_namespace)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if loaded.intent.lifecycle_state != LifecycleState::Authorized
            || loaded.intent.cancellation.state != CancelState::None
            || loaded.intent.decision_snapshot_refs.is_empty()
        {
            return Err(EffectError::InvalidTransition);
        }
        loaded.intent.lifecycle_state = LifecycleState::CommitReady;
        loaded.intent.current_fence = Some(lease.fence);
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        tx.execute(
            "INSERT INTO outbox(tenant_namespace,intent_id,state,available_at,claim_owner,claim_fence) \
             VALUES(?1,?2,'READY',?3,NULL,NULL) \
             ON CONFLICT(tenant_namespace,intent_id) DO UPDATE SET state='READY',available_at=excluded.available_at,claim_owner=NULL,claim_fence=NULL",
            params![tenant_namespace, intent_id, as_i64(now_ms)?],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "COMMIT_READY",
            as_i64(now_ms)?,
            loaded
                .intent
                .decision_snapshot_refs
                .last()
                .map(|snapshot| snapshot.digest.as_str()),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn begin_dispatch(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        lease: &DispatchLease,
        now_ms: u64,
    ) -> Result<DispatchTicket, EffectError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&tx, tenant_namespace, lease, now_ms)?;
        require_execution_healthy(&tx, tenant_namespace)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if loaded.intent.lifecycle_state != LifecycleState::CommitReady
            || loaded.intent.cancellation.state != CancelState::None
        {
            return Err(EffectError::InvalidTransition);
        }
        if loaded.attempt_count >= loaded.retry_policy.max_attempts {
            return Err(EffectError::RetryBudgetExhausted);
        }
        let outbox_ready: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM outbox WHERE tenant_namespace=?1 AND intent_id=?2 AND state='READY' AND available_at<=?3)",
                params![tenant_namespace, intent_id, as_i64(now_ms)?],
                |row| row.get(0),
            )?;
        if !outbox_ready {
            return Err(EffectError::InvalidTransition);
        }
        let next_attempt = loaded
            .attempt_count
            .checked_add(1)
            .ok_or(EffectError::RetryBudgetExhausted)?;
        let snapshot = loaded
            .intent
            .decision_snapshot_refs
            .last()
            .ok_or(EffectError::InvalidTransition)?;
        let request_digest = dispatch_request_digest(&loaded.intent, snapshot, lease.fence)?;

        loaded.intent.lifecycle_state = LifecycleState::Dispatching;
        loaded.intent.current_fence = Some(lease.fence);
        loaded
            .intent
            .dispatch_attempt_refs
            .push(format!("attempt:{intent_id}:{next_attempt}"));
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        tx.execute(
            "UPDATE effects SET attempt_count=?3 WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id, i64::from(next_attempt)],
        )?;
        tx.execute(
            "UPDATE outbox SET state='DISPATCHING',claim_owner=?3,claim_fence=?4 WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id, lease.owner, as_i64(lease.fence)?],
        )?;
        tx.execute(
            "INSERT INTO dispatch_attempts(tenant_namespace,intent_id,attempt_number,decision_snapshot_ref,decision_snapshot_digest,fence,request_digest,state,started_at,evidence_ref) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,'STARTED',?8,NULL)",
            params![
                tenant_namespace,
                intent_id,
                i64::from(next_attempt),
                snapshot.ref_id,
                snapshot.digest,
                as_i64(lease.fence)?,
                request_digest,
                as_i64(now_ms)?
            ],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "DISPATCH_BOUNDARY_MAY_BE_CROSSED",
            as_i64(now_ms)?,
            Some(&request_digest),
        )?;
        tx.commit()?;
        Ok(DispatchTicket {
            tenant_namespace: tenant_namespace.to_owned(),
            effect_intent_id: intent_id.to_owned(),
            attempt_number: next_attempt,
            fence: lease.fence,
            request_digest,
        })
    }

    pub fn record_transport_result(
        &mut self,
        ticket: &DispatchTicket,
        result: TransportResult,
        now_ms: u64,
    ) -> Result<LifecycleState, EffectError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_open_attempt(&tx, ticket)?;
        let mut loaded = load_effect_tx(&tx, &ticket.tenant_namespace, &ticket.effect_intent_id)?;
        if loaded.intent.lifecycle_state != LifecycleState::Dispatching
            || loaded.intent.current_fence != Some(ticket.fence)
        {
            return Err(EffectError::StaleFence);
        }

        let (next, attempt_state, evidence, outbox_state) = match &result {
            TransportResult::NotSentProven { evidence_ref }
            | TransportResult::LocalAbortNotSentProven { evidence_ref } => (
                LifecycleState::RejectedNoEffect,
                "NOT_SENT_PROVEN",
                evidence_ref.as_str(),
                "DONE",
            ),
            TransportResult::ResponseRejectedNoEffect { evidence_ref } => (
                LifecycleState::RejectedNoEffect,
                "REJECTED_NO_EFFECT",
                evidence_ref.as_str(),
                "DONE",
            ),
            TransportResult::ResponseAccepted { receipt_ref } => (
                LifecycleState::Accepted,
                "ACCEPTED",
                receipt_ref.as_str(),
                "DONE",
            ),
            TransportResult::ResponseLost { evidence_ref }
            | TransportResult::ConnectionFailedAmbiguous { evidence_ref } => (
                LifecycleState::AcceptanceUnknown,
                "UNKNOWN",
                evidence_ref.as_str(),
                "BLOCKED",
            ),
        };
        require_evidence(evidence)?;
        loaded.intent.lifecycle_state = next;
        if let TransportResult::ResponseAccepted { receipt_ref } = &result {
            loaded
                .intent
                .provider_receipt_refs
                .push(receipt_ref.clone());
        }
        save_intent_tx(
            &tx,
            &ticket.tenant_namespace,
            &loaded.intent,
            as_i64(now_ms)?,
        )?;
        tx.execute(
            "UPDATE dispatch_attempts SET state=?4,finished_at=?5,evidence_ref=?6 \
             WHERE tenant_namespace=?1 AND intent_id=?2 AND attempt_number=?3 AND state='STARTED'",
            params![
                ticket.tenant_namespace,
                ticket.effect_intent_id,
                i64::from(ticket.attempt_number),
                attempt_state,
                as_i64(now_ms)?,
                evidence
            ],
        )?;
        tx.execute(
            "UPDATE outbox SET state=?3 WHERE tenant_namespace=?1 AND intent_id=?2",
            params![
                ticket.tenant_namespace,
                ticket.effect_intent_id,
                outbox_state
            ],
        )?;
        append_event(
            &tx,
            &ticket.tenant_namespace,
            &ticket.effect_intent_id,
            "TRANSPORT_RESULT_RECORDED",
            as_i64(now_ms)?,
            Some(evidence),
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn recover_inflight(
        &mut self,
        tenant_namespace: &str,
        now_ms: u64,
    ) -> Result<usize, EffectError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement = tx.prepare(
            "SELECT intent_id FROM effects WHERE tenant_namespace=?1 AND state='DISPATCHING'",
        )?;
        let rows = statement.query_map([tenant_namespace], |row| row.get::<_, String>(0))?;
        let mut intent_ids = Vec::new();
        for row in rows {
            intent_ids.push(row?);
        }
        drop(statement);
        for intent_id in &intent_ids {
            let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
            loaded.intent.lifecycle_state = LifecycleState::AcceptanceUnknown;
            save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
            tx.execute(
                "UPDATE dispatch_attempts SET state='UNKNOWN',finished_at=?3,evidence_ref='recovered-after-dispatch-crash' \
                 WHERE tenant_namespace=?1 AND intent_id=?2 AND state='STARTED'",
                params![tenant_namespace, intent_id, as_i64(now_ms)?],
            )?;
            tx.execute(
                "UPDATE outbox SET state='BLOCKED' WHERE tenant_namespace=?1 AND intent_id=?2",
                params![tenant_namespace, intent_id],
            )?;
            append_event(
                &tx,
                tenant_namespace,
                intent_id,
                "RECOVERED_ACCEPTANCE_UNKNOWN",
                as_i64(now_ms)?,
                Some("recovered-after-dispatch-crash"),
            )?;
        }
        tx.commit()?;
        Ok(intent_ids.len())
    }

    pub fn retry_decision(
        &self,
        tenant_namespace: &str,
        intent_id: &str,
        now_ms: u64,
    ) -> Result<RetryDecision, EffectError> {
        let loaded = load_effect(&self.connection, tenant_namespace, intent_id)?;
        if loaded.intent.cancellation.state != CancelState::None {
            return Ok(RetryDecision::NoAutomaticRetry);
        }
        if !matches!(
            loaded.intent.lifecycle_state,
            LifecycleState::AcceptanceUnknown | LifecycleState::Unresolved
        ) {
            return Ok(RetryDecision::Terminal);
        }
        match loaded.operating_class {
            OperatingClass::E0ReadOnly => Ok(RetryDecision::Terminal),
            OperatingClass::E1OpaqueWrite => Ok(RetryDecision::NoAutomaticRetry),
            OperatingClass::E2DedupWrite => {
                if loaded.attempt_count >= loaded.retry_policy.max_attempts {
                    return Err(EffectError::RetryBudgetExhausted);
                }
                let valid_until = loaded
                    .intent
                    .idempotency
                    .valid_until_ms()
                    .ok_or(EffectError::MissingIdempotencyKey)?;
                if valid_until <= now_ms {
                    return Err(EffectError::IdempotencyExpired);
                }
                let delay = loaded
                    .retry_policy
                    .delay_after_attempt(loaded.attempt_count)?;
                if now_ms.saturating_add(delay) >= valid_until {
                    return Err(EffectError::IdempotencyExpired);
                }
                Ok(RetryDecision::RetrySameIntent { after_ms: delay })
            }
            OperatingClass::E3ObservableWrite | OperatingClass::E4CompensatableWrite => {
                Ok(RetryDecision::Reconcile)
            }
            OperatingClass::E5SharedAtomic => {
                if loaded.intent.assurance_profile.status_query != StatusQuery::None
                    || loaded.intent.assurance_profile.returns_acceptance_receipt
                        != AcceptanceReceipt::None
                {
                    Ok(RetryDecision::Reconcile)
                } else {
                    Ok(RetryDecision::ManualReview)
                }
            }
        }
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
        require_text(fresh_snapshot_ref, "fresh_snapshot_ref")?;
        require_text(fresh_snapshot_digest, "fresh_snapshot_digest")?;
        let delay = match self.retry_decision(tenant_namespace, intent_id, now_ms)? {
            RetryDecision::RetrySameIntent { after_ms } => after_ms,
            RetryDecision::NoAutomaticRetry
            | RetryDecision::Reconcile
            | RetryDecision::ManualReview => return Err(EffectError::RetryNotAllowed),
            RetryDecision::Terminal => return Err(EffectError::InvalidTransition),
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&tx, tenant_namespace, lease, now_ms)?;
        require_execution_healthy(&tx, tenant_namespace)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if !matches!(
            loaded.intent.lifecycle_state,
            LifecycleState::AcceptanceUnknown | LifecycleState::Unresolved
        ) {
            return Err(EffectError::InvalidTransition);
        }
        loaded.intent.lifecycle_state = LifecycleState::CommitReady;
        loaded.intent.current_fence = Some(lease.fence);
        loaded.intent.decision_snapshot_refs.push(crate::DigestRef {
            ref_id: fresh_snapshot_ref.to_owned(),
            digest: fresh_snapshot_digest.to_owned(),
        });
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        let available_at = now_ms.saturating_add(delay);
        tx.execute(
            "UPDATE outbox SET state='READY',available_at=?3,claim_owner=NULL,claim_fence=NULL \
             WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id, as_i64(available_at)?],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "SAFE_SAME_INTENT_RETRY_SCHEDULED",
            as_i64(now_ms)?,
            Some(fresh_snapshot_digest),
        )?;
        tx.commit()?;
        Ok(available_at)
    }

    pub fn start_reconciliation(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        self.transition(TransitionSpec {
            tenant_namespace,
            intent_id,
            allowed_from: &[
                LifecycleState::AcceptanceUnknown,
                LifecycleState::Unresolved,
                LifecycleState::OutcomeUnknown,
            ],
            next: LifecycleState::Reconciling,
            event_type: "RECONCILIATION_STARTED",
            evidence_ref,
            now_ms,
        })
    }

    pub fn resolve_reconciliation(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        outcome: ReconcileOutcome,
        now_ms: u64,
    ) -> Result<LifecycleState, EffectError> {
        let (next, evidence, receipt) = match &outcome {
            ReconcileOutcome::NotAccepted { evidence_ref } => (
                LifecycleState::RejectedNoEffect,
                evidence_ref.as_str(),
                None,
            ),
            ReconcileOutcome::Accepted { receipt_ref } => (
                LifecycleState::Accepted,
                receipt_ref.as_str(),
                Some(receipt_ref.as_str()),
            ),
            ReconcileOutcome::Unresolved { evidence_ref } => {
                (LifecycleState::Unresolved, evidence_ref.as_str(), None)
            }
        };
        require_evidence(evidence)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if loaded.intent.lifecycle_state != LifecycleState::Reconciling {
            return Err(EffectError::InvalidTransition);
        }
        loaded.intent.lifecycle_state = next;
        if let Some(receipt_ref) = receipt {
            loaded
                .intent
                .provider_receipt_refs
                .push(receipt_ref.to_owned());
        }
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "RECONCILIATION_RESULT",
            as_i64(now_ms)?,
            Some(evidence),
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn observe(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        outcome: ObservationOutcome,
        now_ms: u64,
    ) -> Result<LifecycleState, EffectError> {
        let (next, evidence) = match &outcome {
            ObservationOutcome::Pending { evidence_ref } => {
                (LifecycleState::OutcomePending, evidence_ref.as_str())
            }
            ObservationOutcome::Succeeded { evidence_ref } => {
                (LifecycleState::Succeeded, evidence_ref.as_str())
            }
            ObservationOutcome::Failed { evidence_ref } => {
                (LifecycleState::FailedAfterAccept, evidence_ref.as_str())
            }
            ObservationOutcome::Unknown { evidence_ref } => {
                (LifecycleState::OutcomeUnknown, evidence_ref.as_str())
            }
        };
        require_evidence(evidence)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if !matches!(
            loaded.intent.lifecycle_state,
            LifecycleState::Accepted
                | LifecycleState::OutcomePending
                | LifecycleState::FailedAfterAccept
                | LifecycleState::OutcomeUnknown
        ) {
            return Err(EffectError::InvalidTransition);
        }
        loaded.intent.lifecycle_state = next;
        loaded.intent.observation_refs.push(evidence.to_owned());
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "OBSERVATION_RECORDED",
            as_i64(now_ms)?,
            Some(evidence),
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn request_cancel(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        authenticated_request_evidence: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        require_evidence(authenticated_request_evidence)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if loaded.intent.cancellation.state != CancelState::None {
            return Err(EffectError::InvalidTransition);
        }
        loaded
            .intent
            .cancellation
            .evidence_refs
            .push(authenticated_request_evidence.to_owned());

        let cancel_state = match loaded.intent.lifecycle_state {
            LifecycleState::Proposed
            | LifecycleState::Prepared
            | LifecycleState::Authorized
            | LifecycleState::CommitReady => {
                loaded.intent.lifecycle_state = LifecycleState::CancelledPrecommit;
                tx.execute(
                    "UPDATE outbox SET state='BLOCKED' WHERE tenant_namespace=?1 AND intent_id=?2",
                    params![tenant_namespace, intent_id],
                )?;
                CancelState::BlockedBeforeCommit
            }
            LifecycleState::Accepted
            | LifecycleState::OutcomePending
            | LifecycleState::FailedAfterAccept
            | LifecycleState::OutcomeUnknown => {
                if loaded.intent.assurance_profile.cancel_after_acceptance
                    == CancelAfterAcceptance::Unsupported
                {
                    CancelState::TooLate
                } else {
                    CancelState::Requested
                }
            }
            LifecycleState::Succeeded => CancelState::TooLate,
            LifecycleState::Dispatching
            | LifecycleState::AcceptanceUnknown
            | LifecycleState::Reconciling
            | LifecycleState::Unresolved => CancelState::Requested,
            LifecycleState::RejectedNoEffect
            | LifecycleState::Abandoned
            | LifecycleState::Stale
            | LifecycleState::CancelledPrecommit => return Err(EffectError::InvalidTransition),
        };
        loaded.intent.cancellation.state = cancel_state;
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "CANCEL_REQUEST_HANDLED",
            as_i64(now_ms)?,
            Some(authenticated_request_evidence),
        )?;
        tx.commit()?;
        Ok(cancel_state)
    }

    pub fn mark_cancel_forwarded(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        provider_request_evidence: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        require_evidence(provider_request_evidence)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if loaded.intent.cancellation.state != CancelState::Requested {
            return Err(EffectError::InvalidTransition);
        }
        let acceptance_known = matches!(
            loaded.intent.lifecycle_state,
            LifecycleState::Accepted
                | LifecycleState::OutcomePending
                | LifecycleState::FailedAfterAccept
                | LifecycleState::OutcomeUnknown
                | LifecycleState::Succeeded
        );
        if acceptance_known {
            if loaded.intent.assurance_profile.cancel_after_acceptance
                == CancelAfterAcceptance::Unsupported
            {
                return Err(EffectError::InvalidTransition);
            }
        } else if loaded.intent.assurance_profile.cancel_before_acceptance
            == CancelBeforeAcceptance::Unsupported
        {
            return Err(EffectError::InvalidTransition);
        }
        loaded.intent.cancellation.state = CancelState::ForwardedToProvider;
        loaded
            .intent
            .cancellation
            .evidence_refs
            .push(provider_request_evidence.to_owned());
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "CANCEL_FORWARDED_TO_PROVIDER",
            as_i64(now_ms)?,
            Some(provider_request_evidence),
        )?;
        tx.commit()?;
        Ok(CancelState::ForwardedToProvider)
    }

    pub fn mark_cancel_unforwardable_unknown(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        require_evidence(evidence_ref)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if loaded.intent.cancellation.state != CancelState::Requested
            || !matches!(
                loaded.intent.lifecycle_state,
                LifecycleState::Dispatching
                    | LifecycleState::AcceptanceUnknown
                    | LifecycleState::Reconciling
                    | LifecycleState::Unresolved
            )
        {
            return Err(EffectError::InvalidTransition);
        }
        loaded.intent.cancellation.state = CancelState::CancelUnknown;
        loaded
            .intent
            .cancellation
            .evidence_refs
            .push(evidence_ref.to_owned());
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "CANCEL_RESULT_UNKNOWN",
            as_i64(now_ms)?,
            Some(evidence_ref),
        )?;
        tx.commit()?;
        Ok(CancelState::CancelUnknown)
    }

    pub fn resolve_cancel_provider_result(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        resolution: CancelResolution,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        require_evidence(evidence_ref)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if loaded.intent.cancellation.state != CancelState::ForwardedToProvider {
            return Err(EffectError::InvalidTransition);
        }
        let next = match resolution {
            CancelResolution::ConfirmedCancelled => CancelState::ConfirmedCancelled,
            CancelResolution::TooLate => CancelState::TooLate,
            CancelResolution::Unknown => CancelState::CancelUnknown,
        };
        loaded.intent.cancellation.state = next;
        loaded
            .intent
            .cancellation
            .evidence_refs
            .push(evidence_ref.to_owned());
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "CANCEL_PROVIDER_RESULT",
            as_i64(now_ms)?,
            Some(evidence_ref),
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn resolve_cancel_after_reconciliation(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        resolution: CancelResolution,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<CancelState, EffectError> {
        require_evidence(evidence_ref)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, intent_id)?;
        if loaded.intent.cancellation.state != CancelState::CancelUnknown {
            return Err(EffectError::InvalidTransition);
        }
        let next = match resolution {
            CancelResolution::ConfirmedCancelled => CancelState::ConfirmedCancelled,
            CancelResolution::TooLate => CancelState::TooLate,
            CancelResolution::Unknown => CancelState::CancelUnknown,
        };
        loaded.intent.cancellation.state = next;
        loaded
            .intent
            .cancellation
            .evidence_refs
            .push(evidence_ref.to_owned());
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        append_event(
            &tx,
            tenant_namespace,
            intent_id,
            "CANCEL_RECONCILIATION_RESULT",
            as_i64(now_ms)?,
            Some(evidence_ref),
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn plan_compensation(
        &mut self,
        tenant_namespace: &str,
        original_intent_id: &str,
        compensation_intent_id: &str,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<(), EffectError> {
        require_text(compensation_intent_id, "compensation_intent_id")?;
        require_evidence(evidence_ref)?;
        if compensation_intent_id == original_intent_id {
            return Err(EffectError::InvalidTransition);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, tenant_namespace, original_intent_id)?;
        if loaded.intent.assurance_profile.compensation == CompensationCapability::None
            || !matches!(
                loaded.intent.lifecycle_state,
                LifecycleState::Accepted
                    | LifecycleState::OutcomePending
                    | LifecycleState::Succeeded
                    | LifecycleState::FailedAfterAccept
                    | LifecycleState::OutcomeUnknown
            )
            || loaded
                .intent
                .compensation
                .linked_effect_intent_ref
                .is_some()
        {
            return Err(EffectError::InvalidTransition);
        }
        loaded.intent.compensation.state = CompensationState::Planned;
        loaded.intent.compensation.linked_effect_intent_ref =
            Some(compensation_intent_id.to_owned());
        loaded
            .intent
            .compensation
            .evidence_refs
            .push(evidence_ref.to_owned());
        save_intent_tx(&tx, tenant_namespace, &loaded.intent, as_i64(now_ms)?)?;
        append_event(
            &tx,
            tenant_namespace,
            original_intent_id,
            "COMPENSATION_PLANNED_AS_SEPARATE_EFFECT",
            as_i64(now_ms)?,
            Some(evidence_ref),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn effect_view(
        &self,
        tenant_namespace: &str,
        intent_id: &str,
    ) -> Result<EffectView, EffectError> {
        let loaded = load_effect(&self.connection, tenant_namespace, intent_id)?;
        Ok(EffectView {
            intent: loaded.intent,
            operating_class: loaded.operating_class,
            retry_policy: loaded.retry_policy,
            attempt_count: loaded.attempt_count,
            record_digest: loaded.record_digest,
        })
    }

    pub fn event_count(&self, tenant_namespace: &str, intent_id: &str) -> Result<u64, EffectError> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM effect_events WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| EffectError::ExecutionUnhealthy)
    }

    fn transition(&mut self, spec: TransitionSpec<'_>) -> Result<(), EffectError> {
        require_evidence(spec.evidence_ref)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut loaded = load_effect_tx(&tx, spec.tenant_namespace, spec.intent_id)?;
        if !spec.allowed_from.contains(&loaded.intent.lifecycle_state) {
            return Err(EffectError::InvalidTransition);
        }
        loaded.intent.lifecycle_state = spec.next;
        save_intent_tx(
            &tx,
            spec.tenant_namespace,
            &loaded.intent,
            as_i64(spec.now_ms)?,
        )?;
        append_event(
            &tx,
            spec.tenant_namespace,
            spec.intent_id,
            spec.event_type,
            as_i64(spec.now_ms)?,
            Some(spec.evidence_ref),
        )?;
        tx.commit()?;
        Ok(())
    }
}

struct LoadedEffect {
    intent: EffectIntent,
    operating_class: OperatingClass,
    retry_policy: RetryPolicy,
    attempt_count: u32,
    record_digest: String,
}

fn initialize_schema(connection: &mut Connection) -> Result<(), EffectError> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);\
         CREATE TABLE IF NOT EXISTS tenants(tenant_namespace TEXT PRIMARY KEY,health TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);\
         CREATE TABLE IF NOT EXISTS effects(\
            tenant_namespace TEXT NOT NULL,\
            intent_id TEXT NOT NULL,\
            creation_digest TEXT NOT NULL,\
            record_json TEXT NOT NULL,\
            record_digest TEXT NOT NULL,\
            qualification_json TEXT NOT NULL,\
            retry_policy_json TEXT NOT NULL,\
            operating_class TEXT NOT NULL,\
            state TEXT NOT NULL,\
            cancel_state TEXT NOT NULL,\
            compensation_state TEXT NOT NULL,\
            attempt_count INTEGER NOT NULL,\
            current_fence INTEGER NULL,\
            created_at INTEGER NOT NULL,\
            updated_at INTEGER NOT NULL,\
            PRIMARY KEY(tenant_namespace,intent_id),\
            FOREIGN KEY(tenant_namespace) REFERENCES tenants(tenant_namespace));\
         CREATE TABLE IF NOT EXISTS dispatch_leases(\
            tenant_namespace TEXT PRIMARY KEY,owner TEXT NOT NULL,fence INTEGER NOT NULL,expires_at INTEGER NOT NULL,\
            FOREIGN KEY(tenant_namespace) REFERENCES tenants(tenant_namespace));\
         CREATE TABLE IF NOT EXISTS outbox(\
            tenant_namespace TEXT NOT NULL,intent_id TEXT NOT NULL,state TEXT NOT NULL,available_at INTEGER NOT NULL,\
            claim_owner TEXT NULL,claim_fence INTEGER NULL,PRIMARY KEY(tenant_namespace,intent_id),\
            FOREIGN KEY(tenant_namespace,intent_id) REFERENCES effects(tenant_namespace,intent_id));\
         CREATE TABLE IF NOT EXISTS dispatch_attempts(\
            tenant_namespace TEXT NOT NULL,intent_id TEXT NOT NULL,attempt_number INTEGER NOT NULL,\
            decision_snapshot_ref TEXT NOT NULL,decision_snapshot_digest TEXT NOT NULL,fence INTEGER NOT NULL,\
            request_digest TEXT NOT NULL,state TEXT NOT NULL,started_at INTEGER NOT NULL,finished_at INTEGER NULL,evidence_ref TEXT NULL,\
            PRIMARY KEY(tenant_namespace,intent_id,attempt_number),\
            FOREIGN KEY(tenant_namespace,intent_id) REFERENCES effects(tenant_namespace,intent_id));\
         CREATE TABLE IF NOT EXISTS effect_events(\
            seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant_namespace TEXT NOT NULL,intent_id TEXT NOT NULL,event_type TEXT NOT NULL,\
            recorded_at INTEGER NOT NULL,evidence_ref TEXT NULL,\
            FOREIGN KEY(tenant_namespace,intent_id) REFERENCES effects(tenant_namespace,intent_id));\
         CREATE INDEX IF NOT EXISTS idx_effect_state ON effects(tenant_namespace,state);\
         CREATE INDEX IF NOT EXISTS idx_outbox_ready ON outbox(tenant_namespace,state,available_at);",
    )?;
    let version: Option<i64> = tx
        .query_row("SELECT version FROM schema_meta LIMIT 1", [], |row| {
            row.get(0)
        })
        .optional()?;
    match version {
        None => {
            tx.execute(
                "INSERT INTO schema_meta(version) VALUES(?1)",
                [SCHEMA_VERSION],
            )?;
        }
        Some(value) if value == SCHEMA_VERSION => {}
        Some(_) => return Err(EffectError::ExecutionUnhealthy),
    }
    tx.commit()?;
    Ok(())
}

fn ensure_tenant(tx: &Transaction<'_>, tenant: &str, now: i64) -> Result<(), EffectError> {
    tx.execute(
        "INSERT INTO tenants(tenant_namespace,health,created_at,updated_at) VALUES(?1,'HEALTHY',?2,?2) \
         ON CONFLICT(tenant_namespace) DO NOTHING",
        params![tenant, now],
    )?;
    Ok(())
}

fn require_execution_healthy(tx: &Transaction<'_>, tenant: &str) -> Result<(), EffectError> {
    let health: String = tx.query_row(
        "SELECT health FROM tenants WHERE tenant_namespace=?1",
        [tenant],
        |row| row.get(0),
    )?;
    if matches!(health.as_str(), "UNHEALTHY" | "QUARANTINED") {
        Err(EffectError::ExecutionUnhealthy)
    } else {
        Ok(())
    }
}

fn validate_lease(
    tx: &Transaction<'_>,
    tenant: &str,
    lease: &DispatchLease,
    now_ms: u64,
) -> Result<(), EffectError> {
    if lease.tenant_namespace != tenant || lease.expires_at_ms <= now_ms {
        return Err(EffectError::StaleFence);
    }
    let current: Option<(String, i64, i64)> = tx
        .query_row(
            "SELECT owner,fence,expires_at FROM dispatch_leases WHERE tenant_namespace=?1",
            [tenant],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match current {
        Some((owner, fence, expires_at))
            if owner == lease.owner
                && u64::try_from(fence).ok() == Some(lease.fence)
                && expires_at > as_i64(now_ms)? =>
        {
            Ok(())
        }
        _ => Err(EffectError::StaleFence),
    }
}

fn load_effect(
    connection: &Connection,
    tenant: &str,
    intent_id: &str,
) -> Result<LoadedEffect, EffectError> {
    connection
        .query_row(
            "SELECT record_json,operating_class,retry_policy_json,attempt_count,record_digest FROM effects \
             WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant, intent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(EffectError::NotFound)
        .and_then(decode_loaded)
}

fn load_effect_tx(
    tx: &Transaction<'_>,
    tenant: &str,
    intent_id: &str,
) -> Result<LoadedEffect, EffectError> {
    tx.query_row(
        "SELECT record_json,operating_class,retry_policy_json,attempt_count,record_digest FROM effects \
         WHERE tenant_namespace=?1 AND intent_id=?2",
        params![tenant, intent_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        },
    )
    .optional()?
    .ok_or(EffectError::NotFound)
    .and_then(decode_loaded)
}

fn decode_loaded(row: (String, String, String, i64, String)) -> Result<LoadedEffect, EffectError> {
    let attempt_count = u32::try_from(row.3).map_err(|_| EffectError::ExecutionUnhealthy)?;
    Ok(LoadedEffect {
        intent: serde_json::from_str(&row.0)?,
        operating_class: OperatingClass::parse(&row.1)?,
        retry_policy: serde_json::from_str(&row.2)?,
        attempt_count,
        record_digest: row.4,
    })
}

fn save_intent_tx(
    tx: &Transaction<'_>,
    tenant: &str,
    intent: &EffectIntent,
    now: i64,
) -> Result<(), EffectError> {
    let record_json = serde_json::to_string(intent)?;
    let record_digest = digest_text(&record_json);
    tx.execute(
        "UPDATE effects SET record_json=?3,record_digest=?4,state=?5,cancel_state=?6,compensation_state=?7,current_fence=?8,updated_at=?9 \
         WHERE tenant_namespace=?1 AND intent_id=?2",
        params![
            tenant,
            intent.effect_intent_id,
            record_json,
            record_digest,
            intent.lifecycle_state.as_db(),
            intent.cancellation.state.as_db(),
            compensation_state_db(intent.compensation.state),
            intent.current_fence.map(as_i64).transpose()?,
            now
        ],
    )?;
    Ok(())
}

fn require_open_attempt(tx: &Transaction<'_>, ticket: &DispatchTicket) -> Result<(), EffectError> {
    let state: Option<(String, i64, String)> = tx
        .query_row(
            "SELECT state,fence,request_digest FROM dispatch_attempts WHERE tenant_namespace=?1 AND intent_id=?2 AND attempt_number=?3",
            params![
                ticket.tenant_namespace,
                ticket.effect_intent_id,
                i64::from(ticket.attempt_number)
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match state {
        Some((state, fence, request_digest))
            if state == "STARTED"
                && u64::try_from(fence).ok() == Some(ticket.fence)
                && request_digest == ticket.request_digest =>
        {
            Ok(())
        }
        _ => Err(EffectError::StaleFence),
    }
}

fn append_event(
    tx: &Transaction<'_>,
    tenant: &str,
    intent_id: &str,
    event_type: &str,
    now: i64,
    evidence_ref: Option<&str>,
) -> Result<(), EffectError> {
    tx.execute(
        "INSERT INTO effect_events(tenant_namespace,intent_id,event_type,recorded_at,evidence_ref) VALUES(?1,?2,?3,?4,?5)",
        params![tenant, intent_id, event_type, now, evidence_ref],
    )?;
    Ok(())
}

fn creation_digest(intent: &EffectIntent) -> Result<String, EffectError> {
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
        "created_by_message_ref": intent.created_by_message_ref
    });
    Ok(digest_bytes(&serde_json::to_vec(&value)?))
}

fn dispatch_request_digest(
    intent: &EffectIntent,
    snapshot: &crate::DigestRef,
    fence: u64,
) -> Result<String, EffectError> {
    let value = json!({
        "effect_intent_id": intent.effect_intent_id,
        "operation_type": intent.operation_type,
        "targets": {
            "resources": intent.target_resources,
            "accounts": intent.target_accounts,
            "principals": intent.target_principals
        },
        "payload_digest": intent.payload_canonical_digest,
        "adapter_ref": intent.adapter_ref,
        "adapter_version": intent.adapter_version,
        "decision_snapshot_ref": snapshot.ref_id,
        "decision_snapshot_digest": snapshot.digest,
        "fence": fence
    });
    Ok(digest_bytes(&serde_json::to_vec(&value)?))
}

fn validate_idempotency_window(
    intent: &EffectIntent,
    operating_class: OperatingClass,
    now_ms: u64,
) -> Result<(), EffectError> {
    if !matches!(
        operating_class,
        OperatingClass::E2DedupWrite
            | OperatingClass::E3ObservableWrite
            | OperatingClass::E4CompensatableWrite
    ) {
        return Ok(());
    }
    let retention = intent
        .assurance_profile
        .dedup_retention
        .known_nonzero()
        .ok_or(EffectError::MissingIdempotencyKey)?;
    match &intent.idempotency {
        IdempotencyBinding::Supported {
            key,
            valid_until_ms,
        } if !key.trim().is_empty()
            && *valid_until_ms > now_ms
            && *valid_until_ms <= now_ms.saturating_add(retention) =>
        {
            Ok(())
        }
        _ => Err(EffectError::IdempotencyExpired),
    }
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

fn require_text(value: &str, field: &'static str) -> Result<(), EffectError> {
    if value.trim().is_empty() {
        Err(EffectError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn require_evidence(value: &str) -> Result<(), EffectError> {
    if value.trim().is_empty() {
        Err(EffectError::MissingEvidence)
    } else {
        Ok(())
    }
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

fn as_i64(value: u64) -> Result<i64, EffectError> {
    i64::try_from(value).map_err(|_| EffectError::InvalidField("u64_overflow"))
}
