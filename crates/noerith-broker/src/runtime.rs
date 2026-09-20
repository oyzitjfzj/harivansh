use crate::{
    AdapterOutcome, AdapterRequest, BrokerError, CaptureTimeEvidence, CapturedTransportResult,
    ControlledAdapter, CredentialHandle, CredentialSource, PostReturnTimeSource,
    PreparedReleaseBinding, ReleaseFreshnessAuthority, ReleaseFreshnessError,
    ReleaseFreshnessGuard, ReleaseFreshnessProof, ReleaseFreshnessSnapshot, ReleaseRequest,
    ReleaseState, TransportCaptureBinding, TransportCaptureError, TransportCaptureLedger,
    TypedCapturedTransportRecord, release_freshness_snapshot_digest, verify_release_freshness,
};
use noerith_effects::{
    AttemptNextAction, AttemptTransportResult, DispatchAttemptBinding, DispatchAttemptError,
    DispatchAttemptLedger, DispatchTicket, EffectIntent, EffectRuntime, IdempotencyBinding,
    LifecycleState, ProviderIdempotencyKey, RetryDecision, SynchronizationState, TransportResult,
    VersionedRef,
};
use noerith_storage::{DatabaseKeyPurpose, KeyProvider};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

const BROKER_SCHEMA_VERSION: i64 = 2;
const RECOVERY_AMBIGUITY_EVIDENCE: &str = "broker-recovery-consumed-send-uncertain";

pub struct ControlledReleaseBroker {
    effects: EffectRuntime,
    attempts: DispatchAttemptLedger,
    transport_capture: TransportCaptureLedger,
    connection: Connection,
}

impl ControlledReleaseBroker {
    pub fn open(path: impl AsRef<Path>, provider: &impl KeyProvider) -> Result<Self, BrokerError> {
        let path = path.as_ref();
        let effects = EffectRuntime::open(path, provider)?;
        let attempts = DispatchAttemptLedger::open(path, provider)?;
        let transport_capture = TransportCaptureLedger::open(path, provider)?;
        let key = provider
            .database_passphrase(DatabaseKeyPurpose::EffectLedger)
            .map_err(|error| BrokerError::KeyProvider(error.to_string()))?;
        if key.trim().is_empty() {
            return Err(BrokerError::KeyProvider("empty broker ledger key".into()));
        }
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "key", key.as_str())?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if cipher_version.trim().is_empty() {
            return Err(BrokerError::KeyProvider("SQLCipher unavailable".into()));
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.pragma_update(None, "busy_timeout", 5000_i64)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(BrokerError::KeyProvider("WAL unavailable".into()));
        }
        initialize_schema(&mut connection)?;
        Ok(Self {
            effects,
            attempts,
            transport_capture,
            connection,
        })
    }

    pub fn register_handle(
        &mut self,
        handle: &CredentialHandle,
        now_ms: u64,
    ) -> Result<bool, BrokerError> {
        handle.validate()?;
        if now_ms < handle.issued_at_ms || now_ms >= handle.expires_at_ms {
            return Err(BrokerError::HandleExpired);
        }
        let handle_json = serde_json::to_string(handle)?;
        let handle_digest = sha256_hex(handle_json.as_bytes());
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_epoch: Option<i64> = tx
            .query_row(
                "SELECT revocation_epoch FROM broker_revocation_epochs WHERE tenant_namespace=?1 AND authority_grant_ref=?2",
                params![handle.tenant_namespace, handle.authority_grant_ref],
                |row| row.get(0),
            )
            .optional()?;
        match current_epoch {
            Some(value)
                if u64::try_from(value).map_err(|_| BrokerError::CorruptRecord)?
                    != handle.revocation_epoch =>
            {
                return Err(BrokerError::HandleRevoked);
            }
            Some(_) => {}
            None => {
                tx.execute(
                    "INSERT INTO broker_revocation_epochs(tenant_namespace,authority_grant_ref,revocation_epoch,updated_at) VALUES(?1,?2,?3,?4)",
                    params![
                        handle.tenant_namespace,
                        handle.authority_grant_ref,
                        as_i64(handle.revocation_epoch)?,
                        as_i64(now_ms)?
                    ],
                )?;
            }
        }
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT handle_digest,handle_json FROM broker_credential_handles WHERE tenant_namespace=?1 AND handle_id=?2",
                params![handle.tenant_namespace, handle.handle_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((digest, json)) = existing {
            if digest == handle_digest && json == handle_json {
                tx.commit()?;
                return Ok(false);
            }
            return Err(BrokerError::CredentialBindingMismatch("handle_id reused"));
        }
        tx.execute(
            "INSERT INTO broker_credential_handles(tenant_namespace,handle_id,authority_grant_ref,revocation_epoch,handle_json,handle_digest,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                handle.tenant_namespace,
                handle.handle_id,
                handle.authority_grant_ref,
                as_i64(handle.revocation_epoch)?,
                handle_json,
                handle_digest,
                as_i64(now_ms)?
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn advance_revocation_epoch(
        &mut self,
        tenant_namespace: &str,
        authority_grant_ref: &str,
        new_epoch: u64,
        now_ms: u64,
    ) -> Result<(), BrokerError> {
        require_text(tenant_namespace, "tenant_namespace")?;
        require_text(authority_grant_ref, "authority_grant_ref")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<i64> = tx
            .query_row(
                "SELECT revocation_epoch FROM broker_revocation_epochs WHERE tenant_namespace=?1 AND authority_grant_ref=?2",
                params![tenant_namespace, authority_grant_ref],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(value) = current
            && new_epoch <= u64::try_from(value).map_err(|_| BrokerError::CorruptRecord)?
        {
            return Err(BrokerError::HandleRevoked);
        }
        tx.execute(
            "INSERT INTO broker_revocation_epochs(tenant_namespace,authority_grant_ref,revocation_epoch,updated_at) VALUES(?1,?2,?3,?4) \
             ON CONFLICT(tenant_namespace,authority_grant_ref) DO UPDATE SET revocation_epoch=excluded.revocation_epoch,updated_at=excluded.updated_at",
            params![tenant_namespace, authority_grant_ref, as_i64(new_epoch)?, as_i64(now_ms)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn dispatch(
        &mut self,
        request: &ReleaseRequest,
        freshness_snapshot: &ReleaseFreshnessSnapshot,
        freshness_authority: &mut impl ReleaseFreshnessAuthority,
        credential_source: &mut impl CredentialSource,
        adapter: &mut impl ControlledAdapter,
        post_return_time_source: &mut impl PostReturnTimeSource,
    ) -> Result<LifecycleState, BrokerError> {
        validate_release_request(request)?;
        let _ = release_freshness_snapshot_digest(freshness_snapshot)?;
        let view = self
            .effects
            .effect_view(&request.tenant_namespace, &request.effect_intent_id)?;
        require_dispatchable_view(&view.intent, &request.lease)?;
        let handle = self.load_current_handle(request, request.now_ms)?;
        validate_handle_binding(&handle, request, &view.intent)?;
        validate_freshness_snapshot_binding(freshness_snapshot, request, &view.intent, &handle)?;
        validate_adapter(adapter, &view.intent)?;

        let anticipated_ticket =
            anticipate_ticket(&view.intent, view.attempt_count, &request.lease)?;
        let attempt_binding = build_attempt_binding(request, &view.intent, &anticipated_ticket)?;
        let release = PreparedReleaseBinding {
            release_id: release_id(&request.tenant_namespace, &attempt_binding),
            tenant_namespace: request.tenant_namespace.clone(),
            ticket: (&anticipated_ticket).into(),
            attempt: attempt_binding,
            actor_ref: request.actor_ref.clone(),
            workload_ref: request.workload_ref.clone(),
            audience: request.audience.clone(),
            credential_handle_ref: request.credential_handle_ref.clone(),
            capability: request.capability.clone(),
            environment: request.environment.clone(),
            dispatch_owner: request.lease.owner.clone(),
            dispatch_lease_expires_at_ms: request.lease.expires_at_ms,
            adapter_ref: view.intent.adapter_ref.clone(),
            adapter_version: view.intent.adapter_version.clone(),
        };

        self.prepare_release(&release, request.now_ms)?;

        let actual_ticket = match self.effects.begin_dispatch(
            &request.tenant_namespace,
            &request.effect_intent_id,
            &request.lease,
            request.now_ms,
        ) {
            Ok(ticket) => ticket,
            Err(error) => {
                self.mark_release_finalized(
                    &request.tenant_namespace,
                    &release.release_id,
                    "broker-begin-dispatch-rejected-no-send",
                    request.now_ms,
                )?;
                return Err(error.into());
            }
        };
        if actual_ticket != anticipated_ticket {
            self.mark_release_finalized(
                &request.tenant_namespace,
                &release.release_id,
                "broker-attempt-mismatch-no-send",
                request.now_ms,
            )?;
            return Err(BrokerError::AttemptMismatch);
        }

        if let Err(error) =
            self.attempts
                .start_attempt(&request.tenant_namespace, &release.attempt, request.now_ms)
        {
            self.abort_after_effect_dispatch_started(
                &release,
                &actual_ticket,
                "canonical-attempt-persist-failed-no-send",
                request.now_ms,
            )?;
            return Err(error.into());
        }

        // Secret acquisition can fail or block, so it must happen before the
        // irreversible one-shot release is consumed. It grants no authority:
        // every material axis is re-read and checked under the final guard.
        let secret = match credential_source.resolve(&handle.handle_id) {
            Ok(value) => value,
            Err(error) => {
                self.abort_after_effect_dispatch_started(
                    &release,
                    &actual_ticket,
                    "credential-resolution-failed-no-send",
                    request.now_ms,
                )?;
                return Err(error.into());
            }
        };

        // The source-bound guard spans the last complete validation and durable
        // one-shot consumption. A resolved secret is dropped unused on failure.
        let freshness_guard = match freshness_authority.acquire(freshness_snapshot) {
            Ok(guard) => guard,
            Err(error) => {
                drop(secret);
                self.abort_after_effect_dispatch_started(
                    &release,
                    &actual_ticket,
                    "freshness-authority-unavailable-no-send",
                    request.now_ms,
                )?;
                return Err(error);
            }
        };
        let final_observed_at_ms = freshness_guard.observed_at_ms();

        let guarded_validation = (|| {
            let proof = verify_release_freshness(
                freshness_snapshot,
                freshness_guard.current_state(),
                final_observed_at_ms,
            )?;
            let current_view = self
                .effects
                .effect_view(&request.tenant_namespace, &request.effect_intent_id)?;
            if current_view.intent.lifecycle_state != LifecycleState::Dispatching
                || current_view.intent.cancellation.state != noerith_effects::CancelState::None
                || current_view.intent.current_fence != Some(request.lease.fence)
            {
                return Err(BrokerError::ReleaseNotPrepared);
            }
            let fresh_handle = self.load_current_handle(request, final_observed_at_ms)?;
            validate_handle_binding(&fresh_handle, request, &current_view.intent)?;
            validate_freshness_snapshot_binding(
                freshness_snapshot,
                request,
                &current_view.intent,
                &fresh_handle,
            )?;
            validate_adapter(adapter, &current_view.intent)?;
            self.attempts
                .verify_binding(&request.tenant_namespace, &release.attempt.attempt_id)?;
            let adapter_request =
                adapter_request(&current_view.intent, &request.audience, &actual_ticket);
            Ok::<_, BrokerError>((proof, adapter_request))
        })();

        let (freshness_proof, adapter_request) = match guarded_validation {
            Ok(value) => value,
            Err(error) => {
                drop(freshness_guard);
                drop(secret);
                self.abort_after_effect_dispatch_started(
                    &release,
                    &actual_ticket,
                    "broker-final-freshness-rejected-no-send",
                    final_observed_at_ms,
                )?;
                return Err(error);
            }
        };

        let consume_result = self.consume_release(
            &request.tenant_namespace,
            &release.release_id,
            &freshness_proof,
            final_observed_at_ms,
        );
        drop(freshness_guard);
        if let Err(error) = consume_result {
            drop(secret);
            return Err(error);
        }

        let outcome = adapter.send(&adapter_request, secret.expose());
        drop(secret);

        // The response fact is primary evidence. Time is sampled only after the
        // adapter returns; clock failure is represented, not used to discard the
        // response or to relabel the pre-send freshness timestamp as capture time.
        let post_return_time = post_return_time_source.observe_after_return();
        let processing_time_ms = post_return_time.conservative_processing_time_ms();
        let capture_time = CaptureTimeEvidence::from(post_return_time);
        let captured_result = captured_from_adapter(outcome);
        let capture_binding = transport_capture_binding(&release);
        self.transport_capture.capture_once_with_evidence(
            &capture_binding,
            &captured_result,
            &capture_time,
        )?;
        let captured = self
            .transport_capture
            .load_with_evidence(&request.tenant_namespace, &release.release_id)?;
        let Some(processing_time_ms) = processing_time_ms else {
            return Err(BrokerError::PostReturnTimeUnavailable);
        };
        self.converge_captured_transport(&release, &actual_ticket, &captured, processing_time_ms)
    }

    /// Recover one interrupted release from durable local truth. `recovery_time_ms`
    /// is supplied only by the source-bound facade after validating a typed,
    /// uncertainty-aware recovery observation. PREPARED proves local no-send;
    /// CONSUMED never permits blind replay.
    pub fn recover_release(
        &mut self,
        tenant_namespace: &str,
        release_id: &str,
        recovery_time_ms: u64,
    ) -> Result<LifecycleState, BrokerError> {
        require_text(tenant_namespace, "tenant_namespace")?;
        require_text(release_id, "release_id")?;
        let (binding, state) = self.load_release(tenant_namespace, release_id)?;
        let ticket = DispatchTicket::from(&binding.ticket);
        match state {
            ReleaseState::Prepared => {
                let current = self
                    .effects
                    .effect_view(tenant_namespace, &ticket.effect_intent_id)?;
                if current.intent.lifecycle_state == LifecycleState::CommitReady {
                    self.mark_release_finalized(
                        tenant_namespace,
                        release_id,
                        "broker-recovery-before-dispatch-no-send",
                        recovery_time_ms,
                    )?;
                    return Ok(LifecycleState::CommitReady);
                }
                if current.intent.lifecycle_state != LifecycleState::Dispatching
                    || current.attempt_count != ticket.attempt_number
                    || current.intent.current_fence != Some(ticket.fence)
                {
                    return Err(BrokerError::CorruptRecord);
                }
                self.attempts.start_attempt(
                    tenant_namespace,
                    &binding.attempt,
                    recovery_time_ms,
                )?;
                self.abort_after_effect_dispatch_started(
                    &binding,
                    &ticket,
                    "broker-recovery-prepared-no-send",
                    recovery_time_ms,
                )
            }
            ReleaseState::Consumed => {
                self.validate_consumed_freshness_proof(&binding)?;
                match self
                    .transport_capture
                    .load_with_evidence(tenant_namespace, release_id)
                {
                    Ok(captured) => {
                        let processing_time_ms =
                            captured_processing_time(&captured, recovery_time_ms)?;
                        self.converge_captured_transport(
                            &binding,
                            &ticket,
                            &captured,
                            processing_time_ms,
                        )
                    }
                    Err(TransportCaptureError::NotFound) => {
                        self.converge_uncaptured_ambiguity(&binding, &ticket, recovery_time_ms)
                    }
                    Err(error) => Err(error.into()),
                }
            }
            ReleaseState::Finalized => Err(BrokerError::ReleaseReplay),
        }
    }

    pub fn release_state(
        &self,
        tenant_namespace: &str,
        release_id: &str,
    ) -> Result<&'static str, BrokerError> {
        let (_, state) = self.load_release(tenant_namespace, release_id)?;
        Ok(state.as_db())
    }

    pub fn release_freshness_proof(
        &self,
        tenant_namespace: &str,
        release_id: &str,
    ) -> Result<Option<ReleaseFreshnessProof>, BrokerError> {
        require_text(tenant_namespace, "tenant_namespace")?;
        require_text(release_id, "release_id")?;
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT proof_json,proof_digest FROM broker_release_freshness_proofs WHERE tenant_namespace=?1 AND release_id=?2",
                params![tenant_namespace, release_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((proof_json, stored_digest)) = row else {
            return Ok(None);
        };
        if sha256_hex(proof_json.as_bytes()) != stored_digest {
            return Err(BrokerError::CorruptRecord);
        }
        let proof: ReleaseFreshnessProof = serde_json::from_str(&proof_json)?;
        Ok(Some(proof))
    }

    fn validate_consumed_freshness_proof(
        &self,
        release: &PreparedReleaseBinding,
    ) -> Result<(), BrokerError> {
        let proof = self
            .release_freshness_proof(&release.tenant_namespace, &release.release_id)?
            .ok_or(BrokerError::CorruptRecord)?;
        if proof.decision_snapshot() != &release.attempt.decision_snapshot
            || proof.dispatch_owner() != release.dispatch_owner
            || proof.dispatch_lease_expires_at_ms() != release.dispatch_lease_expires_at_ms
            || proof.fence() != release.ticket.fence
        {
            return Err(BrokerError::CorruptRecord);
        }
        Ok(())
    }

    fn converge_captured_transport(
        &mut self,
        release: &PreparedReleaseBinding,
        ticket: &DispatchTicket,
        captured: &TypedCapturedTransportRecord,
        processing_time_ms: u64,
    ) -> Result<LifecycleState, BrokerError> {
        validate_transport_capture_binding(release, &captured.binding)?;
        self.attempts.start_attempt(
            &release.tenant_namespace,
            &release.attempt,
            processing_time_ms,
        )?;

        let current = self
            .effects
            .effect_view(&release.tenant_namespace, &ticket.effect_intent_id)?;
        if current.attempt_count != ticket.attempt_number
            || current.intent.current_fence != Some(ticket.fence)
        {
            return Err(BrokerError::CorruptRecord);
        }

        let state = if current.intent.lifecycle_state == LifecycleState::Dispatching {
            self.effects.record_transport_result(
                ticket,
                effect_transport_result(&captured.result),
                processing_time_ms,
            )?
        } else if effect_state_matches_capture(&current.intent, &captured.result) {
            current.intent.lifecycle_state
        } else {
            return Err(BrokerError::CorruptRecord);
        };

        let next_action = next_action_from_runtime(
            &self.effects,
            &release.tenant_namespace,
            &ticket.effect_intent_id,
            processing_time_ms,
        )?;
        self.finalize_attempt_from_capture(release, captured, next_action, processing_time_ms)?;
        self.mark_release_finalized(
            &release.tenant_namespace,
            &release.release_id,
            captured.result.evidence_ref(),
            processing_time_ms,
        )?;
        Ok(state)
    }

    fn converge_uncaptured_ambiguity(
        &mut self,
        release: &PreparedReleaseBinding,
        ticket: &DispatchTicket,
        now_ms: u64,
    ) -> Result<LifecycleState, BrokerError> {
        self.attempts
            .start_attempt(&release.tenant_namespace, &release.attempt, now_ms)?;

        let current = self
            .effects
            .effect_view(&release.tenant_namespace, &ticket.effect_intent_id)?;
        if current.attempt_count != ticket.attempt_number
            || current.intent.current_fence != Some(ticket.fence)
        {
            return Err(BrokerError::CorruptRecord);
        }

        let state = if current.intent.lifecycle_state == LifecycleState::Dispatching {
            self.effects.record_transport_result(
                ticket,
                TransportResult::ConnectionFailedAmbiguous {
                    evidence_ref: RECOVERY_AMBIGUITY_EVIDENCE.into(),
                },
                now_ms,
            )?
        } else if current.intent.lifecycle_state == LifecycleState::AcceptanceUnknown {
            current.intent.lifecycle_state
        } else {
            return Err(BrokerError::CorruptRecord);
        };

        let next_action = next_action_from_runtime(
            &self.effects,
            &release.tenant_namespace,
            &ticket.effect_intent_id,
            now_ms,
        )?;
        self.finalize_uncaptured_attempt(release, next_action, now_ms)?;
        self.mark_release_finalized(
            &release.tenant_namespace,
            &release.release_id,
            RECOVERY_AMBIGUITY_EVIDENCE,
            now_ms,
        )?;
        Ok(state)
    }

    fn finalize_attempt_from_capture(
        &mut self,
        release: &PreparedReleaseBinding,
        captured: &TypedCapturedTransportRecord,
        next_action: AttemptNextAction,
        finalized_at_ms: u64,
    ) -> Result<(), BrokerError> {
        let expected_result = attempt_transport_result(&captured.result);
        let expected_evidence = attempt_evidence_refs(&captured.result);
        match self
            .attempts
            .finalized_attempt(&release.tenant_namespace, &release.attempt.attempt_id)
        {
            Ok(existing) => {
                if existing.binding != release.attempt
                    || existing.transport_result != expected_result
                    || existing.provider_status_receipt_refs != expected_evidence
                    || existing.next_action != next_action
                {
                    return Err(BrokerError::CorruptRecord);
                }
                Ok(())
            }
            Err(DispatchAttemptError::NotFound) => {
                self.attempts.finalize_once(
                    &release.tenant_namespace,
                    &release.attempt.attempt_id,
                    expected_result,
                    &expected_evidence,
                    next_action,
                    captured.result.evidence_ref(),
                    finalized_at_ms,
                )?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn finalize_uncaptured_attempt(
        &mut self,
        release: &PreparedReleaseBinding,
        next_action: AttemptNextAction,
        finalized_at_ms: u64,
    ) -> Result<(), BrokerError> {
        let expected_result = AttemptTransportResult::ConnectionFailedAmbiguous;
        match self
            .attempts
            .finalized_attempt(&release.tenant_namespace, &release.attempt.attempt_id)
        {
            Ok(existing) => {
                if existing.binding != release.attempt
                    || existing.transport_result != expected_result
                    || !existing.provider_status_receipt_refs.is_empty()
                    || existing.next_action != next_action
                {
                    return Err(BrokerError::CorruptRecord);
                }
                Ok(())
            }
            Err(DispatchAttemptError::NotFound) => {
                self.attempts.finalize_once(
                    &release.tenant_namespace,
                    &release.attempt.attempt_id,
                    expected_result,
                    &[],
                    next_action,
                    RECOVERY_AMBIGUITY_EVIDENCE,
                    finalized_at_ms,
                )?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn load_current_handle(
        &self,
        request: &ReleaseRequest,
        observed_at_ms: u64,
    ) -> Result<CredentialHandle, BrokerError> {
        let row: Option<(String, String, i64)> = self
            .connection
            .query_row(
                "SELECT handle_json,handle_digest,revocation_epoch FROM broker_credential_handles WHERE tenant_namespace=?1 AND handle_id=?2",
                params![request.tenant_namespace, request.credential_handle_ref],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((handle_json, stored_digest, stored_epoch)) = row else {
            return Err(BrokerError::CredentialBindingMismatch("handle not found"));
        };
        if sha256_hex(handle_json.as_bytes()) != stored_digest {
            return Err(BrokerError::CorruptRecord);
        }
        let handle: CredentialHandle = serde_json::from_str(&handle_json)?;
        handle.validate()?;
        if u64::try_from(stored_epoch).map_err(|_| BrokerError::CorruptRecord)?
            != handle.revocation_epoch
        {
            return Err(BrokerError::CorruptRecord);
        }
        if observed_at_ms < handle.issued_at_ms || observed_at_ms >= handle.expires_at_ms {
            return Err(BrokerError::HandleExpired);
        }
        let current_epoch: i64 = self.connection.query_row(
            "SELECT revocation_epoch FROM broker_revocation_epochs WHERE tenant_namespace=?1 AND authority_grant_ref=?2",
            params![handle.tenant_namespace, handle.authority_grant_ref],
            |row| row.get(0),
        )?;
        if u64::try_from(current_epoch).map_err(|_| BrokerError::CorruptRecord)?
            != handle.revocation_epoch
        {
            return Err(BrokerError::HandleRevoked);
        }
        Ok(handle)
    }

    fn prepare_release(
        &mut self,
        binding: &PreparedReleaseBinding,
        now_ms: u64,
    ) -> Result<(), BrokerError> {
        let binding_json = serde_json::to_string(binding)?;
        let binding_digest = sha256_hex(binding_json.as_bytes());
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, String)> = tx
            .query_row(
                "SELECT binding_json,binding_digest,state FROM broker_releases WHERE tenant_namespace=?1 AND release_id=?2",
                params![binding.tenant_namespace, binding.release_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((json, digest, state)) = existing {
            if json == binding_json
                && digest == binding_digest
                && state == ReleaseState::Prepared.as_db()
            {
                tx.commit()?;
                return Ok(());
            }
            return Err(BrokerError::ReleaseReplay);
        }
        tx.execute(
            "INSERT INTO broker_releases(tenant_namespace,release_id,effect_intent_id,attempt_id,handle_id,binding_json,binding_digest,state,created_at,consumed_at,finalized_at,evidence_ref) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,'PREPARED',?8,NULL,NULL,NULL)",
            params![
                binding.tenant_namespace,
                binding.release_id,
                binding.ticket.effect_intent_id,
                binding.attempt.attempt_id,
                binding.credential_handle_ref,
                binding_json,
                binding_digest,
                as_i64(now_ms)?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn consume_release(
        &mut self,
        tenant_namespace: &str,
        release_id: &str,
        freshness_proof: &ReleaseFreshnessProof,
        now_ms: u64,
    ) -> Result<(), BrokerError> {
        let proof_json = serde_json::to_string(freshness_proof)?;
        let proof_digest = sha256_hex(proof_json.as_bytes());
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE broker_releases SET state='CONSUMED',consumed_at=?3 WHERE tenant_namespace=?1 AND release_id=?2 AND state='PREPARED'",
            params![tenant_namespace, release_id, as_i64(now_ms)?],
        )?;
        if changed != 1 {
            return Err(BrokerError::ReleaseReplay);
        }
        tx.execute(
            "INSERT INTO broker_release_freshness_proofs(tenant_namespace,release_id,proof_json,proof_digest,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![
                tenant_namespace,
                release_id,
                proof_json,
                proof_digest,
                as_i64(now_ms)?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn abort_after_effect_dispatch_started(
        &mut self,
        release: &PreparedReleaseBinding,
        ticket: &DispatchTicket,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<LifecycleState, BrokerError> {
        let state = self.effects.record_transport_result(
            ticket,
            TransportResult::LocalAbortNotSentProven {
                evidence_ref: evidence_ref.to_owned(),
            },
            now_ms,
        )?;
        self.attempts.finalize_once(
            &ticket.tenant_namespace,
            &release.attempt.attempt_id,
            AttemptTransportResult::LocalAbort,
            &[],
            AttemptNextAction::None,
            evidence_ref,
            now_ms,
        )?;
        self.mark_release_finalized(
            &release.tenant_namespace,
            &release.release_id,
            evidence_ref,
            now_ms,
        )?;
        Ok(state)
    }

    fn mark_release_finalized(
        &mut self,
        tenant_namespace: &str,
        release_id: &str,
        evidence_ref: &str,
        now_ms: u64,
    ) -> Result<(), BrokerError> {
        require_text(tenant_namespace, "tenant_namespace")?;
        require_text(evidence_ref, "evidence_ref")?;
        let changed = self.connection.execute(
            "UPDATE broker_releases SET state='FINALIZED',finalized_at=?3,evidence_ref=?4 WHERE tenant_namespace=?1 AND release_id=?2 AND state IN ('PREPARED','CONSUMED')",
            params![tenant_namespace, release_id, as_i64(now_ms)?, evidence_ref],
        )?;
        if changed != 1 {
            return Err(BrokerError::ReleaseReplay);
        }
        Ok(())
    }

    fn load_release(
        &self,
        tenant_namespace: &str,
        release_id: &str,
    ) -> Result<(PreparedReleaseBinding, ReleaseState), BrokerError> {
        let row: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT binding_json,binding_digest,state FROM broker_releases WHERE tenant_namespace=?1 AND release_id=?2",
                params![tenant_namespace, release_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((binding_json, stored_digest, state)) = row else {
            return Err(BrokerError::ReleaseNotPrepared);
        };
        if sha256_hex(binding_json.as_bytes()) != stored_digest {
            return Err(BrokerError::CorruptRecord);
        }
        let binding: PreparedReleaseBinding = serde_json::from_str(&binding_json)?;
        if binding.tenant_namespace != tenant_namespace || binding.release_id != release_id {
            return Err(BrokerError::CorruptRecord);
        }
        Ok((binding, ReleaseState::parse(&state)?))
    }
}

fn captured_processing_time(
    captured: &TypedCapturedTransportRecord,
    qualified_recovery_time_ms: u64,
) -> Result<u64, BrokerError> {
    match &captured.time_evidence {
        CaptureTimeEvidence::Observed {
            unix_time_ms,
            uncertainty_after_ms,
            synchronization_state,
            ..
        } if *synchronization_state == SynchronizationState::Synced => unix_time_ms
            .checked_add(*uncertainty_after_ms)
            .ok_or(BrokerError::PostReturnTimeUnavailable),
        CaptureTimeEvidence::Observed { .. }
        | CaptureTimeEvidence::Unavailable { .. }
        | CaptureTimeEvidence::LegacyScalar { .. } => Ok(qualified_recovery_time_ms),
    }
}

fn captured_from_adapter(outcome: AdapterOutcome) -> CapturedTransportResult {
    match outcome {
        AdapterOutcome::NotSentProven { evidence_ref } => {
            CapturedTransportResult::NotSentProven { evidence_ref }
        }
        AdapterOutcome::Accepted { receipt_ref } => {
            CapturedTransportResult::Accepted { receipt_ref }
        }
        AdapterOutcome::RejectedNoEffect { evidence_ref } => {
            CapturedTransportResult::RejectedNoEffect { evidence_ref }
        }
        AdapterOutcome::ResponseLost { evidence_ref } => {
            CapturedTransportResult::ResponseLost { evidence_ref }
        }
        AdapterOutcome::ConnectionFailedAmbiguous { evidence_ref } => {
            CapturedTransportResult::ConnectionFailedAmbiguous { evidence_ref }
        }
    }
}

fn effect_transport_result(captured: &CapturedTransportResult) -> TransportResult {
    match captured {
        CapturedTransportResult::NotSentProven { evidence_ref } => TransportResult::NotSentProven {
            evidence_ref: evidence_ref.clone(),
        },
        CapturedTransportResult::Accepted { receipt_ref } => TransportResult::ResponseAccepted {
            receipt_ref: receipt_ref.clone(),
        },
        CapturedTransportResult::RejectedNoEffect { evidence_ref } => {
            TransportResult::ResponseRejectedNoEffect {
                evidence_ref: evidence_ref.clone(),
            }
        }
        CapturedTransportResult::ResponseLost { evidence_ref } => TransportResult::ResponseLost {
            evidence_ref: evidence_ref.clone(),
        },
        CapturedTransportResult::ConnectionFailedAmbiguous { evidence_ref } => {
            TransportResult::ConnectionFailedAmbiguous {
                evidence_ref: evidence_ref.clone(),
            }
        }
    }
}

fn attempt_transport_result(captured: &CapturedTransportResult) -> AttemptTransportResult {
    match captured {
        CapturedTransportResult::NotSentProven { .. } => AttemptTransportResult::NotSentProven,
        CapturedTransportResult::Accepted { .. }
        | CapturedTransportResult::RejectedNoEffect { .. } => {
            AttemptTransportResult::ResponseReceived
        }
        CapturedTransportResult::ResponseLost { .. } => AttemptTransportResult::ResponseLost,
        CapturedTransportResult::ConnectionFailedAmbiguous { .. } => {
            AttemptTransportResult::ConnectionFailedAmbiguous
        }
    }
}

fn attempt_evidence_refs(captured: &CapturedTransportResult) -> Vec<String> {
    match captured {
        CapturedTransportResult::Accepted { receipt_ref } => vec![receipt_ref.clone()],
        CapturedTransportResult::RejectedNoEffect { evidence_ref } => vec![evidence_ref.clone()],
        CapturedTransportResult::NotSentProven { .. }
        | CapturedTransportResult::ResponseLost { .. }
        | CapturedTransportResult::ConnectionFailedAmbiguous { .. } => Vec::new(),
    }
}

fn effect_state_matches_capture(intent: &EffectIntent, captured: &CapturedTransportResult) -> bool {
    match captured {
        CapturedTransportResult::NotSentProven { .. }
        | CapturedTransportResult::RejectedNoEffect { .. } => {
            intent.lifecycle_state == LifecycleState::RejectedNoEffect
        }
        CapturedTransportResult::Accepted { receipt_ref } => {
            intent.lifecycle_state == LifecycleState::Accepted
                && intent
                    .provider_receipt_refs
                    .iter()
                    .any(|item| item == receipt_ref)
        }
        CapturedTransportResult::ResponseLost { .. }
        | CapturedTransportResult::ConnectionFailedAmbiguous { .. } => {
            intent.lifecycle_state == LifecycleState::AcceptanceUnknown
        }
    }
}

fn transport_capture_binding(release: &PreparedReleaseBinding) -> TransportCaptureBinding {
    TransportCaptureBinding {
        tenant_namespace: release.tenant_namespace.clone(),
        release_id: release.release_id.clone(),
        effect_intent_id: release.ticket.effect_intent_id.clone(),
        attempt_id: release.attempt.attempt_id.clone(),
        attempt_number: release.ticket.attempt_number,
        decision_snapshot: release.attempt.decision_snapshot.clone(),
        fencing_token: release.ticket.fence,
        request_digest: release.ticket.request_digest.clone(),
        adapter_ref: release.adapter_ref.clone(),
        adapter_version: release.adapter_version.clone(),
    }
}

fn validate_transport_capture_binding(
    release: &PreparedReleaseBinding,
    actual: &TransportCaptureBinding,
) -> Result<(), BrokerError> {
    if actual != &transport_capture_binding(release) {
        return Err(BrokerError::CorruptRecord);
    }
    Ok(())
}

fn validate_release_request(request: &ReleaseRequest) -> Result<(), BrokerError> {
    for (name, value) in [
        ("tenant_namespace", request.tenant_namespace.as_str()),
        ("effect_intent_id", request.effect_intent_id.as_str()),
        ("actor_ref", request.actor_ref.as_str()),
        ("workload_ref", request.workload_ref.as_str()),
        ("audience", request.audience.as_str()),
        (
            "credential_handle_ref",
            request.credential_handle_ref.as_str(),
        ),
        ("capability.ref_id", request.capability.ref_id.as_str()),
        ("environment.ref_id", request.environment.ref_id.as_str()),
        ("dispatch_lease.owner", request.lease.owner.as_str()),
        (
            "started_at.utc_timestamp",
            request.started_at.utc_timestamp.as_str(),
        ),
        (
            "monotonic_deadline.clock_ref",
            request.monotonic_deadline.clock_ref.as_str(),
        ),
    ] {
        require_text(value, name)?;
    }
    if request.lease.tenant_namespace != request.tenant_namespace
        || request.lease.fence == 0
        || request.lease.expires_at_ms <= request.now_ms
    {
        return Err(BrokerError::CredentialBindingMismatch("dispatch lease"));
    }
    if request.monotonic_deadline.deadline_tick == 0 {
        return Err(BrokerError::InvalidField("monotonic_deadline"));
    }
    Ok(())
}

fn require_dispatchable_view(
    intent: &EffectIntent,
    lease: &noerith_effects::DispatchLease,
) -> Result<(), BrokerError> {
    if intent.lifecycle_state != LifecycleState::CommitReady
        || intent.cancellation.state != noerith_effects::CancelState::None
        || intent.current_fence != Some(lease.fence)
    {
        return Err(BrokerError::ReleaseNotPrepared);
    }
    Ok(())
}

fn validate_handle_binding(
    handle: &CredentialHandle,
    request: &ReleaseRequest,
    intent: &EffectIntent,
) -> Result<(), BrokerError> {
    let resources: BTreeSet<String> = intent.target_resources.iter().cloned().collect();
    let accounts: BTreeSet<String> = intent.target_accounts.iter().cloned().collect();
    let principals: BTreeSet<String> = intent.target_principals.iter().cloned().collect();
    let checks = [
        (
            handle.tenant_namespace == request.tenant_namespace,
            "tenant_namespace",
        ),
        (handle.actor_ref == request.actor_ref, "actor_ref"),
        (handle.workload_ref == request.workload_ref, "workload_ref"),
        (handle.purpose == intent.purpose, "purpose"),
        (handle.audience == request.audience, "audience"),
        (
            intent.disclosure_classes.contains(&request.audience),
            "audience not disclosed",
        ),
        (
            handle.operation_type == intent.operation_type,
            "operation_type",
        ),
        (
            handle.effect_intent_id == intent.effect_intent_id,
            "effect_intent_id",
        ),
        (handle.capability == request.capability, "capability"),
        (handle.target_resources == resources, "target_resources"),
        (handle.target_accounts == accounts, "target_accounts"),
        (handle.target_principals == principals, "target_principals"),
    ];
    for (passed, field) in checks {
        if !passed {
            return Err(BrokerError::CredentialBindingMismatch(field));
        }
    }
    Ok(())
}

fn validate_freshness_snapshot_binding(
    snapshot: &ReleaseFreshnessSnapshot,
    request: &ReleaseRequest,
    intent: &EffectIntent,
    handle: &CredentialHandle,
) -> Result<(), BrokerError> {
    if snapshot.tenant_namespace != request.tenant_namespace
        || snapshot.effect_intent_id != request.effect_intent_id
        || snapshot.effect_intent_id != intent.effect_intent_id
    {
        return Err(ReleaseFreshnessError::ScopeChanged.into());
    }
    let latest_snapshot = intent
        .decision_snapshot_refs
        .last()
        .ok_or(BrokerError::MissingSnapshot)?;
    if &snapshot.decision_snapshot != latest_snapshot {
        return Err(ReleaseFreshnessError::DecisionSnapshotChanged.into());
    }
    if snapshot.principal_context != intent.principal_context {
        return Err(ReleaseFreshnessError::StalePrincipal.into());
    }
    if snapshot.goal != intent.goal {
        return Err(ReleaseFreshnessError::StaleGoal.into());
    }
    if snapshot.work != intent.work {
        return Err(ReleaseFreshnessError::StaleWork.into());
    }
    if snapshot.payload_digest != intent.payload_canonical_digest {
        return Err(ReleaseFreshnessError::PayloadChanged.into());
    }
    let resources: BTreeSet<String> = intent.target_resources.iter().cloned().collect();
    let accounts: BTreeSet<String> = intent.target_accounts.iter().cloned().collect();
    let principals: BTreeSet<String> = intent.target_principals.iter().cloned().collect();
    if snapshot.target_resources != resources
        || snapshot.target_accounts != accounts
        || snapshot.target_principals != principals
    {
        return Err(ReleaseFreshnessError::TargetsChanged.into());
    }
    if snapshot.authority_grant_ref != handle.authority_grant_ref {
        return Err(ReleaseFreshnessError::StaleGrant.into());
    }
    if snapshot.revocation_epoch != handle.revocation_epoch {
        return Err(ReleaseFreshnessError::StaleRevocationEpoch.into());
    }
    if snapshot.capability.ref_id != request.capability.ref_id
        || snapshot.capability.version != request.capability.version.to_string()
    {
        return Err(ReleaseFreshnessError::CapabilityChanged.into());
    }
    if snapshot.environment.ref_id != request.environment.ref_id
        || snapshot.environment.version != request.environment.version.to_string()
    {
        return Err(ReleaseFreshnessError::EnvironmentChanged.into());
    }
    if snapshot.dispatch_owner != request.lease.owner
        || snapshot.dispatch_lease_expires_at_ms != request.lease.expires_at_ms
    {
        return Err(ReleaseFreshnessError::StaleDispatchClaim.into());
    }
    if snapshot.fence != request.lease.fence || intent.current_fence != Some(snapshot.fence) {
        return Err(ReleaseFreshnessError::StaleFence.into());
    }
    Ok(())
}

fn validate_adapter(
    adapter: &impl ControlledAdapter,
    intent: &EffectIntent,
) -> Result<(), BrokerError> {
    let identity = adapter.identity();
    if identity.ref_id != intent.adapter_ref {
        return Err(BrokerError::AdapterMismatch);
    }
    let expected_version = intent
        .adapter_version
        .parse::<u64>()
        .map_err(|_| BrokerError::VersionNotRepresentable)?;
    if identity.version != expected_version {
        return Err(BrokerError::AdapterMismatch);
    }
    Ok(())
}

fn anticipate_ticket(
    intent: &EffectIntent,
    current_attempt_count: u32,
    lease: &noerith_effects::DispatchLease,
) -> Result<DispatchTicket, BrokerError> {
    let attempt_number = current_attempt_count
        .checked_add(1)
        .ok_or(BrokerError::AttemptMismatch)?;
    let snapshot = intent
        .decision_snapshot_refs
        .last()
        .ok_or(BrokerError::MissingSnapshot)?;
    let request_digest = dispatch_request_digest(intent, snapshot, lease.fence)?;
    Ok(DispatchTicket {
        tenant_namespace: lease.tenant_namespace.clone(),
        effect_intent_id: intent.effect_intent_id.clone(),
        attempt_number,
        fence: lease.fence,
        request_digest,
    })
}

fn build_attempt_binding(
    request: &ReleaseRequest,
    intent: &EffectIntent,
    ticket: &DispatchTicket,
) -> Result<DispatchAttemptBinding, BrokerError> {
    let snapshot = intent
        .decision_snapshot_refs
        .last()
        .ok_or(BrokerError::MissingSnapshot)?;
    let adapter_version = intent
        .adapter_version
        .parse::<u64>()
        .map_err(|_| BrokerError::VersionNotRepresentable)?;
    Ok(DispatchAttemptBinding {
        attempt_id: format!(
            "attempt:{}:{}",
            intent.effect_intent_id, ticket.attempt_number
        ),
        effect_intent_id: intent.effect_intent_id.clone(),
        decision_snapshot: snapshot.clone(),
        dispatch_claim_revision: u64::from(ticket.attempt_number),
        fencing_token: ticket.fence,
        adapter: VersionedRef {
            ref_id: intent.adapter_ref.clone(),
            version: adapter_version,
        },
        capability: request.capability.clone(),
        environment: request.environment.clone(),
        credential_handle_ref: request.credential_handle_ref.clone(),
        provider_idempotency_key: ProviderIdempotencyKey::from_binding(&intent.idempotency),
        request_digest: ticket.request_digest.clone(),
        started_at: request.started_at.clone(),
        monotonic_deadline: request.monotonic_deadline.clone(),
    })
}

fn release_id(tenant_namespace: &str, binding: &DispatchAttemptBinding) -> String {
    let value = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        tenant_namespace,
        binding.attempt_id,
        binding.credential_handle_ref,
        binding.capability.ref_id,
        binding.capability.version,
        binding.environment.ref_id,
        binding.environment.version
    );
    format!("release:{}", &sha256_hex(value.as_bytes())[..24])
}

fn adapter_request(
    intent: &EffectIntent,
    audience: &str,
    ticket: &DispatchTicket,
) -> AdapterRequest {
    let provider_idempotency_key = match &intent.idempotency {
        IdempotencyBinding::Supported { key, .. } => Some(key.clone()),
        IdempotencyBinding::Unsupported => None,
    };
    AdapterRequest {
        effect_intent_id: intent.effect_intent_id.clone(),
        operation_type: intent.operation_type.clone(),
        target_resources: intent.target_resources.clone(),
        target_accounts: intent.target_accounts.clone(),
        target_principals: intent.target_principals.clone(),
        payload_ref: intent.payload_ref.clone(),
        payload_digest: intent.payload_canonical_digest.clone(),
        audience: audience.to_owned(),
        provider_idempotency_key,
        request_digest: ticket.request_digest.clone(),
    }
}

fn next_action_from_runtime(
    effects: &EffectRuntime,
    tenant_namespace: &str,
    intent_id: &str,
    now_ms: u64,
) -> Result<AttemptNextAction, BrokerError> {
    Ok(
        match effects.retry_decision(tenant_namespace, intent_id, now_ms)? {
            RetryDecision::Terminal => AttemptNextAction::None,
            RetryDecision::RetrySameIntent { .. } => AttemptNextAction::RetrySameIntent,
            RetryDecision::Reconcile => AttemptNextAction::Reconcile,
            RetryDecision::NoAutomaticRetry | RetryDecision::ManualReview => {
                AttemptNextAction::ManualReview
            }
        },
    )
}

fn dispatch_request_digest(
    intent: &EffectIntent,
    snapshot: &noerith_effects::DigestRef,
    fence: u64,
) -> Result<String, BrokerError> {
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
    Ok(sha256_hex(&serde_json::to_vec(&value)?))
}

fn initialize_schema(connection: &mut Connection) -> Result<(), BrokerError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS broker_schema_meta(\
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),\
            schema_version INTEGER NOT NULL);\
         CREATE TABLE IF NOT EXISTS broker_revocation_epochs(\
            tenant_namespace TEXT NOT NULL,\
            authority_grant_ref TEXT NOT NULL,\
            revocation_epoch INTEGER NOT NULL,\
            updated_at INTEGER NOT NULL,\
            PRIMARY KEY(tenant_namespace,authority_grant_ref));\
         CREATE TABLE IF NOT EXISTS broker_credential_handles(\
            tenant_namespace TEXT NOT NULL,\
            handle_id TEXT NOT NULL,\
            authority_grant_ref TEXT NOT NULL,\
            revocation_epoch INTEGER NOT NULL,\
            handle_json TEXT NOT NULL,\
            handle_digest TEXT NOT NULL,\
            created_at INTEGER NOT NULL,\
            PRIMARY KEY(tenant_namespace,handle_id));\
         CREATE TABLE IF NOT EXISTS broker_releases(\
            tenant_namespace TEXT NOT NULL,\
            release_id TEXT NOT NULL,\
            effect_intent_id TEXT NOT NULL,\
            attempt_id TEXT NOT NULL,\
            handle_id TEXT NOT NULL,\
            binding_json TEXT NOT NULL,\
            binding_digest TEXT NOT NULL,\
            state TEXT NOT NULL CHECK(state IN ('PREPARED','CONSUMED','FINALIZED')),\
            created_at INTEGER NOT NULL,\
            consumed_at INTEGER,\
            finalized_at INTEGER,\
            evidence_ref TEXT,\
            PRIMARY KEY(tenant_namespace,release_id));",
    )?;

    let existing: Option<i64> = connection
        .query_row(
            "SELECT schema_version FROM broker_schema_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(BROKER_SCHEMA_VERSION) => {
            if !table_exists(connection, "broker_release_freshness_proofs")? {
                return Err(BrokerError::CorruptRecord);
            }
        }
        Some(1) => {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            create_freshness_proof_table(&tx)?;
            tx.execute(
                "UPDATE broker_schema_meta SET schema_version=?1 WHERE singleton=1 AND schema_version=1",
                [BROKER_SCHEMA_VERSION],
            )?;
            tx.commit()?;
        }
        Some(_) => return Err(BrokerError::CorruptRecord),
        None => {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            create_freshness_proof_table(&tx)?;
            tx.execute(
                "INSERT INTO broker_schema_meta(singleton,schema_version) VALUES(1,?1)",
                [BROKER_SCHEMA_VERSION],
            )?;
            tx.commit()?;
        }
    }
    Ok(())
}

fn create_freshness_proof_table(connection: &Connection) -> Result<(), BrokerError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS broker_release_freshness_proofs(\
            tenant_namespace TEXT NOT NULL,\
            release_id TEXT NOT NULL,\
            proof_json TEXT NOT NULL,\
            proof_digest TEXT NOT NULL,\
            created_at INTEGER NOT NULL,\
            PRIMARY KEY(tenant_namespace,release_id));",
    )?;
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, BrokerError> {
    let exists: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

fn require_text(value: &str, name: &'static str) -> Result<(), BrokerError> {
    if value.trim().is_empty() {
        return Err(BrokerError::InvalidField(name));
    }
    Ok(())
}

fn as_i64(value: u64) -> Result<i64, BrokerError> {
    i64::try_from(value).map_err(|_| BrokerError::CorruptRecord)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
