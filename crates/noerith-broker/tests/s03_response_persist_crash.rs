use noerith_broker::{
    AdapterOutcome, AdapterRequest, BrokerError, CapturedTransportResult, ControlledAdapter,
    ControlledReleaseBroker, CredentialHandle, CredentialSource, CredentialSourceError,
    CurrentReleaseState, OpaqueVersionRef, PostReturnTimeEvidence, PostReturnTimeSource,
    ReleaseFreshnessAuthority, ReleaseFreshnessGuard, ReleaseFreshnessSnapshot, ReleaseRequest,
    ReleaseTimeObservation, SecretMaterial, TransportCaptureBinding, TransportCaptureError,
    TransportCaptureLedger,
};
use noerith_effects::{
    AcceptanceReceipt, AdapterAssuranceProfile, AdapterQualificationEvidence, AttemptNextAction,
    AttemptTransportResult, CallbackSemantics, CancelAfterAcceptance, CancelBeforeAcceptance,
    CompensationCapability, CompensationRecord, CompensationState, DigestRef,
    DispatchAttemptBinding, DispatchAttemptLedger, DispatchTicket, DurationKnowledge, EffectClass,
    EffectIntent, EffectRuntime, IdempotencyBinding, LifecycleState, MonotonicDeadline,
    RetryPolicy, RetryStrategy, Reversibility, StartedAt, StatusQuery, SynchronizationState,
    TransactionBoundary, TransportResult, VersionedRef,
};
use noerith_storage::SyntheticKeyProvider;
use rusqlite::Connection;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static CASE_ID: AtomicU64 = AtomicU64::new(1);
const DB_KEY: &str = "effect-ledger-response-crash-key";

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn temp_db(label: &str) -> PathBuf {
    let id = CASE_ID.fetch_add(1, Ordering::Relaxed);
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "noerith-response-persist-crash-{label}-{}-{id}-{clock}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp directory");
    dir.join("effects.db")
}

fn provider() -> SyntheticKeyProvider {
    SyntheticKeyProvider::uniform(DB_KEY, [0x61_u8; 32]).with_effect_ledger_key(DB_KEY)
}

fn profile() -> AdapterAssuranceProfile {
    AdapterAssuranceProfile {
        mutates_external_state: true,
        accepts_stable_idempotency_key: true,
        dedup_retention: DurationKnowledge::Known(60_000),
        returns_acceptance_receipt: AcceptanceReceipt::Verifiable,
        status_query: StatusQuery::ByIntent,
        callback_semantics: CallbackSemantics::ReplayProtected,
        cancel_before_acceptance: CancelBeforeAcceptance::Supported,
        cancel_after_acceptance: CancelAfterAcceptance::BestEffort,
        compensation: CompensationCapability::None,
        transaction_boundary: TransactionBoundary::ProviderLocal,
        maximum_request_age: DurationKnowledge::Known(30_000),
        replay_controls: set(&["request-age", "nonce"]),
        known_ambiguity_failure_modes: set(&["crash-after-response-persist"]),
    }
}

fn qualification() -> AdapterQualificationEvidence {
    AdapterQualificationEvidence {
        adapter_ref: "adapter-a".into(),
        adapter_version: "7".into(),
        evidence_refs: set(&["adapter-conformance-a"]),
        exact_shared_atomic_boundary_ref: None,
        verified: true,
    }
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        strategy: RetryStrategy::Exponential,
        base_delay_ms: 100,
        max_delay_ms: 2_000,
        max_attempts: 3,
        qualification_ref: "retry-policy-a".into(),
    }
}

fn intent() -> EffectIntent {
    EffectIntent {
        effect_intent_id: "intent-response-crash".into(),
        operation_type: "external-write".into(),
        principal_context: DigestRef {
            ref_id: "principal-a".into(),
            digest: "principal-digest-a".into(),
        },
        goal: VersionedRef {
            ref_id: "goal-a".into(),
            version: 4,
        },
        work: VersionedRef {
            ref_id: "work-a".into(),
            version: 3,
        },
        target_resources: vec!["resource-a".into()],
        target_accounts: vec!["account-a".into()],
        target_principals: vec!["target-a".into()],
        payload_schema: "urn:noerith:test-payload:1".into(),
        payload_canonical_digest: "payload-digest-a".into(),
        payload_ref: "sealed-payload-a".into(),
        purpose: "user-requested-effect".into(),
        data_classes: set(&["synthetic-private"]),
        disclosure_classes: set(&["target-service"]),
        effect_class: EffectClass::ExternalConsequential,
        reversibility: Reversibility::Unknown,
        adapter_ref: "adapter-a".into(),
        adapter_version: "7".into(),
        assurance_profile: profile(),
        idempotency: IdempotencyBinding::Supported {
            key: "idem-response-crash".into(),
            valid_until_ms: 60_000,
        },
        expected_evidence_plan_ref: "evidence-plan-a".into(),
        created_by_message_ref: "message-a".into(),
        lifecycle_state: LifecycleState::Proposed,
        decision_snapshot_refs: Vec::new(),
        dispatch_attempt_refs: Vec::new(),
        provider_receipt_refs: Vec::new(),
        observation_refs: Vec::new(),
        cancellation: Default::default(),
        compensation: CompensationRecord {
            state: CompensationState::NotApplicable,
            linked_effect_intent_ref: None,
            evidence_refs: Vec::new(),
        },
        current_fence: None,
    }
}

fn prepare_effect(path: &PathBuf, now: u64) -> noerith_effects::DispatchLease {
    let mut runtime = EffectRuntime::open(path, &provider()).expect("open effect runtime");
    runtime
        .register_intent(
            "tenant-a",
            &intent(),
            &qualification(),
            &retry_policy(),
            now,
        )
        .expect("register intent");
    runtime
        .prepare(
            "tenant-a",
            "intent-response-crash",
            "prepare-evidence",
            now + 1,
        )
        .expect("prepare");
    runtime
        .authorize(
            "tenant-a",
            "intent-response-crash",
            "snapshot-a",
            "snapshot-digest-a",
            now + 2,
        )
        .expect("authorize");
    let lease = runtime
        .acquire_dispatch_lease("tenant-a", "worker-a", now + 3, 5_000)
        .expect("lease");
    runtime
        .commit_ready("tenant-a", "intent-response-crash", &lease, now + 4)
        .expect("commit ready");
    lease
}

fn handle(now: u64) -> CredentialHandle {
    CredentialHandle {
        handle_id: "handle-a".into(),
        tenant_namespace: "tenant-a".into(),
        actor_ref: "principal-a".into(),
        workload_ref: "dispatcher-workload-a".into(),
        purpose: "user-requested-effect".into(),
        audience: "target-service".into(),
        operation_type: "external-write".into(),
        target_resources: set(&["resource-a"]),
        target_accounts: set(&["account-a"]),
        target_principals: set(&["target-a"]),
        authority_grant_ref: "authority-a".into(),
        effect_intent_id: "intent-response-crash".into(),
        capability: VersionedRef {
            ref_id: "capability-a".into(),
            version: 11,
        },
        issued_at_ms: now.saturating_sub(10),
        expires_at_ms: now + 10_000,
        revocation_epoch: 5,
        issuer_evidence_ref: "handle-issuer-evidence-a".into(),
    }
}

fn request(lease: noerith_effects::DispatchLease, now: u64) -> ReleaseRequest {
    ReleaseRequest {
        tenant_namespace: "tenant-a".into(),
        effect_intent_id: "intent-response-crash".into(),
        actor_ref: "principal-a".into(),
        workload_ref: "dispatcher-workload-a".into(),
        audience: "target-service".into(),
        credential_handle_ref: "handle-a".into(),
        capability: VersionedRef {
            ref_id: "capability-a".into(),
            version: 11,
        },
        environment: VersionedRef {
            ref_id: "sandbox-a".into(),
            version: 3,
        },
        lease,
        started_at: StartedAt {
            utc_timestamp: "2026-09-09T04:30:00Z".into(),
            uncertainty_before: "PT0.001S".into(),
            uncertainty_after: "PT0.001S".into(),
            clock_source: "ci-clock-a".into(),
            synchronization_state: SynchronizationState::Synced,
        },
        monotonic_deadline: MonotonicDeadline {
            clock_ref: "ci-monotonic-a".into(),
            deadline_tick: 999_999,
        },
        now_ms: now,
    }
}

fn freshness_for(request: &ReleaseRequest) -> (ReleaseFreshnessSnapshot, StaticAuthority) {
    let snapshot = ReleaseFreshnessSnapshot {
        tenant_namespace: request.tenant_namespace.clone(),
        effect_intent_id: request.effect_intent_id.clone(),
        decision_snapshot: DigestRef {
            ref_id: "snapshot-a".into(),
            digest: "snapshot-digest-a".into(),
        },
        principal_context: DigestRef {
            ref_id: "principal-a".into(),
            digest: "principal-digest-a".into(),
        },
        goal: VersionedRef {
            ref_id: "goal-a".into(),
            version: 4,
        },
        work: VersionedRef {
            ref_id: "work-a".into(),
            version: 3,
        },
        state_revision: 17,
        policy: OpaqueVersionRef {
            ref_id: "policy-a".into(),
            version: "policy-2026.09".into(),
        },
        authority_grant_ref: "authority-a".into(),
        revocation_epoch: 5,
        interrupt_watermark: 9,
        payload_digest: "payload-digest-a".into(),
        target_resources: set(&["resource-a"]),
        target_accounts: set(&["account-a"]),
        target_principals: set(&["target-a"]),
        capability: OpaqueVersionRef {
            ref_id: request.capability.ref_id.clone(),
            version: request.capability.version.to_string(),
        },
        environment: OpaqueVersionRef {
            ref_id: request.environment.ref_id.clone(),
            version: request.environment.version.to_string(),
        },
        dispatch_owner: request.lease.owner.clone(),
        dispatch_lease_expires_at_ms: request.lease.expires_at_ms,
        fence: request.lease.fence,
        expires_at_ms: request.now_ms + 5_000,
    };
    let current = CurrentReleaseState {
        tenant_namespace: snapshot.tenant_namespace.clone(),
        effect_intent_id: snapshot.effect_intent_id.clone(),
        decision_snapshot: snapshot.decision_snapshot.clone(),
        principal_context: snapshot.principal_context.clone(),
        goal: snapshot.goal.clone(),
        work: snapshot.work.clone(),
        state_revision: snapshot.state_revision,
        policy: snapshot.policy.clone(),
        authority_grant_ref: snapshot.authority_grant_ref.clone(),
        revocation_epoch: snapshot.revocation_epoch,
        interrupt_watermark: snapshot.interrupt_watermark,
        payload_digest: snapshot.payload_digest.clone(),
        target_resources: snapshot.target_resources.clone(),
        target_accounts: snapshot.target_accounts.clone(),
        target_principals: snapshot.target_principals.clone(),
        capability: snapshot.capability.clone(),
        environment: snapshot.environment.clone(),
        dispatch_owner: snapshot.dispatch_owner.clone(),
        dispatch_lease_expires_at_ms: snapshot.dispatch_lease_expires_at_ms,
        fence: snapshot.fence,
        cancel_before_release: false,
        execution_healthy: true,
    };
    (
        snapshot,
        StaticAuthority {
            current,
            observed_at_ms: request.now_ms,
        },
    )
}

struct StaticGuard<'a> {
    current: &'a CurrentReleaseState,
    observed_at_ms: u64,
    pinned: ReleaseFreshnessSnapshot,
    time: ReleaseTimeObservation,
}

impl ReleaseFreshnessGuard for StaticGuard<'_> {
    fn current_state(&self) -> &CurrentReleaseState {
        self.current
    }

    fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    fn pinned_snapshot(&self) -> Option<&ReleaseFreshnessSnapshot> {
        Some(&self.pinned)
    }

    fn time_observation(&self) -> Option<&ReleaseTimeObservation> {
        Some(&self.time)
    }
}

struct StaticAuthority {
    current: CurrentReleaseState,
    observed_at_ms: u64,
}

impl ReleaseFreshnessAuthority for StaticAuthority {
    type Guard<'a>
        = StaticGuard<'a>
    where
        Self: 'a;

    fn acquire<'a>(
        &'a mut self,
        expected: &ReleaseFreshnessSnapshot,
    ) -> Result<Self::Guard<'a>, BrokerError> {
        Ok(StaticGuard {
            current: &self.current,
            observed_at_ms: self.observed_at_ms,
            pinned: expected.clone(),
            time: ReleaseTimeObservation {
                unix_time_ms: self.observed_at_ms,
                uncertainty_before_ms: 0,
                uncertainty_after_ms: 0,
                clock_source: "qualified-ci-clock".into(),
                synchronization_state: SynchronizationState::Synced,
                monotonic_clock_ref: "ci-monotonic-a".into(),
                monotonic_tick: 1,
            },
        })
    }
}

struct FixedPostReturnTime {
    observed_at_ms: u64,
}

impl PostReturnTimeSource for FixedPostReturnTime {
    fn observe_after_return(&mut self) -> PostReturnTimeEvidence {
        PostReturnTimeEvidence::Observed {
            unix_time_ms: self.observed_at_ms,
            uncertainty_before_ms: 0,
            uncertainty_after_ms: 0,
            clock_source: "qualified-post-return-ci-clock".into(),
            synchronization_state: SynchronizationState::Synced,
        }
    }
}

fn recovery_observation(unix_time_ms: u64) -> ReleaseTimeObservation {
    ReleaseTimeObservation {
        unix_time_ms,
        uncertainty_before_ms: 0,
        uncertainty_after_ms: 0,
        clock_source: "qualified-recovery-ci-clock".into(),
        synchronization_state: SynchronizationState::Synced,
        monotonic_clock_ref: "ci-recovery-monotonic".into(),
        monotonic_tick: 1,
    }
}

struct CredentialSourceImpl;

impl CredentialSource for CredentialSourceImpl {
    fn resolve(&mut self, handle_id: &str) -> Result<SecretMaterial, CredentialSourceError> {
        if handle_id != "handle-a" {
            return Err(CredentialSourceError::NotFound);
        }
        SecretMaterial::new(b"SYNTHETIC_SECRET".to_vec())
    }
}

struct PanicAfterReleaseAdapter;

impl ControlledAdapter for PanicAfterReleaseAdapter {
    fn identity(&self) -> VersionedRef {
        VersionedRef {
            ref_id: "adapter-a".into(),
            version: 7,
        }
    }

    fn send(&mut self, _request: &AdapterRequest, _credential: &[u8]) -> AdapterOutcome {
        panic!("synthetic crash after broker release consumption")
    }
}

struct ConsumedFixture {
    path: PathBuf,
    release_id: String,
    ticket: DispatchTicket,
    attempt: DispatchAttemptBinding,
    capture_binding: TransportCaptureBinding,
}

fn consume_then_crash(label: &str, now: u64) -> ConsumedFixture {
    let path = temp_db(label);
    let lease = prepare_effect(&path, now);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).expect("open broker");
    broker
        .register_handle(&handle(now + 10), now + 10)
        .expect("register handle");
    let request = request(lease, now + 20);
    let (freshness, mut authority) = freshness_for(&request);
    let mut credentials = CredentialSourceImpl;
    let mut transport = PanicAfterReleaseAdapter;
    let mut post_return = FixedPostReturnTime {
        observed_at_ms: now + 21,
    };
    let crash = catch_unwind(AssertUnwindSafe(|| {
        let _ = broker.dispatch(
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport,
            &mut post_return,
        );
    }));
    assert!(crash.is_err());
    drop(broker);

    let connection = Connection::open(&path).expect("open SQLCipher database");
    connection
        .pragma_update(None, "key", DB_KEY)
        .expect("apply SQLCipher key");
    let (release_id, binding_json): (String, String) = connection
        .query_row(
            "SELECT release_id,binding_json FROM broker_releases WHERE tenant_namespace='tenant-a' AND state='CONSUMED'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("consumed release");
    drop(connection);

    let value: Value = serde_json::from_str(&binding_json).expect("decode prepared release");
    let ticket_value = &value["ticket"];
    let ticket = DispatchTicket {
        tenant_namespace: ticket_value["tenant_namespace"]
            .as_str()
            .expect("ticket tenant")
            .to_owned(),
        effect_intent_id: ticket_value["effect_intent_id"]
            .as_str()
            .expect("ticket effect")
            .to_owned(),
        attempt_number: u32::try_from(
            ticket_value["attempt_number"]
                .as_u64()
                .expect("attempt number"),
        )
        .expect("attempt number fits u32"),
        fence: ticket_value["fence"].as_u64().expect("fence"),
        request_digest: ticket_value["request_digest"]
            .as_str()
            .expect("request digest")
            .to_owned(),
    };
    let attempt: DispatchAttemptBinding =
        serde_json::from_value(value["attempt"].clone()).expect("decode attempt binding");
    let capture_binding = TransportCaptureBinding {
        tenant_namespace: "tenant-a".into(),
        release_id: release_id.clone(),
        effect_intent_id: ticket.effect_intent_id.clone(),
        attempt_id: attempt.attempt_id.clone(),
        attempt_number: ticket.attempt_number,
        decision_snapshot: attempt.decision_snapshot.clone(),
        fencing_token: ticket.fence,
        request_digest: ticket.request_digest.clone(),
        adapter_ref: value["adapter_ref"]
            .as_str()
            .expect("adapter ref")
            .to_owned(),
        adapter_version: value["adapter_version"]
            .as_str()
            .expect("adapter version")
            .to_owned(),
    };

    ConsumedFixture {
        path,
        release_id,
        ticket,
        attempt,
        capture_binding,
    }
}

fn persist_acceptance_capture(fixture: &ConsumedFixture, receipt: &str, captured_at_ms: u64) {
    let mut capture =
        TransportCaptureLedger::open(&fixture.path, &provider()).expect("open transport capture");
    assert!(
        capture
            .capture_once(
                &fixture.capture_binding,
                &CapturedTransportResult::Accepted {
                    receipt_ref: receipt.into(),
                },
                captured_at_ms,
            )
            .expect("persist legacy transport capture")
    );
}

#[test]
fn s03_recovery_applies_durable_capture_when_effect_update_never_happened() {
    let fixture = consume_then_crash("capture-only", 10_000);
    let receipt = "provider-receipt-captured";
    persist_acceptance_capture(&fixture, receipt, 10_021);

    let mut recovered =
        ControlledReleaseBroker::open(&fixture.path, &provider()).expect("reopen broker");
    let state = recovered
        .recover_release(
            "tenant-a",
            &fixture.release_id,
            &recovery_observation(10_100),
        )
        .expect("captured response must converge without a resend");
    assert_eq!(state, LifecycleState::Accepted);
    assert_eq!(
        recovered
            .release_state("tenant-a", &fixture.release_id)
            .expect("release state"),
        "FINALIZED"
    );
    drop(recovered);

    let runtime = EffectRuntime::open(&fixture.path, &provider()).expect("open effect runtime");
    let view = runtime
        .effect_view("tenant-a", "intent-response-crash")
        .expect("effect view");
    assert_eq!(view.intent.lifecycle_state, LifecycleState::Accepted);
    assert_eq!(view.intent.provider_receipt_refs, vec![receipt.to_owned()]);

    let ledger = DispatchAttemptLedger::open(&fixture.path, &provider()).expect("attempt ledger");
    let finalized = ledger
        .finalized_attempt("tenant-a", &fixture.attempt.attempt_id)
        .expect("attempt finalized from capture");
    assert_eq!(
        finalized.transport_result,
        AttemptTransportResult::ResponseReceived
    );
    assert_eq!(finalized.next_action, AttemptNextAction::None);
    assert_eq!(
        finalized.provider_status_receipt_refs,
        vec![receipt.to_owned()]
    );
}

#[test]
fn s03_recovery_finishes_when_effect_result_was_persisted_after_capture() {
    let fixture = consume_then_crash("effect-persisted", 20_000);
    let receipt = "provider-receipt-effect-persisted";
    persist_acceptance_capture(&fixture, receipt, 20_021);

    let mut effects = EffectRuntime::open(&fixture.path, &provider()).expect("effect runtime");
    effects
        .record_transport_result(
            &fixture.ticket,
            TransportResult::ResponseAccepted {
                receipt_ref: receipt.into(),
            },
            20_021,
        )
        .expect("persist effect acceptance");
    drop(effects);

    let mut recovered =
        ControlledReleaseBroker::open(&fixture.path, &provider()).expect("reopen broker");
    let state = recovered
        .recover_release(
            "tenant-a",
            &fixture.release_id,
            &recovery_observation(20_100),
        )
        .expect("recovery must trust matching capture plus canonical effect state");
    assert_eq!(state, LifecycleState::Accepted);
    assert_eq!(
        recovered
            .release_state("tenant-a", &fixture.release_id)
            .expect("release state"),
        "FINALIZED"
    );

    let ledger = DispatchAttemptLedger::open(&fixture.path, &provider()).expect("attempt ledger");
    let finalized = ledger
        .finalized_attempt("tenant-a", &fixture.attempt.attempt_id)
        .expect("attempt finalized");
    assert_eq!(
        finalized.provider_status_receipt_refs,
        vec![receipt.to_owned()]
    );
}

#[test]
fn s03_recovery_accepts_semantically_identical_finalized_attempt_even_with_later_timestamp() {
    let fixture = consume_then_crash("attempt-finalized", 30_000);
    let receipt = "provider-receipt-attempt-finalized";
    persist_acceptance_capture(&fixture, receipt, 30_021);

    let mut effects = EffectRuntime::open(&fixture.path, &provider()).expect("effect runtime");
    effects
        .record_transport_result(
            &fixture.ticket,
            TransportResult::ResponseAccepted {
                receipt_ref: receipt.into(),
            },
            30_021,
        )
        .expect("persist effect acceptance");
    drop(effects);

    let mut attempts =
        DispatchAttemptLedger::open(&fixture.path, &provider()).expect("attempt ledger");
    attempts
        .finalize_once(
            "tenant-a",
            &fixture.attempt.attempt_id,
            AttemptTransportResult::ResponseReceived,
            &[receipt.to_owned()],
            AttemptNextAction::None,
            receipt,
            30_050,
        )
        .expect("simulate crash after attempt finalization");
    drop(attempts);

    let mut recovered =
        ControlledReleaseBroker::open(&fixture.path, &provider()).expect("reopen broker");
    let state = recovered
        .recover_release(
            "tenant-a",
            &fixture.release_id,
            &recovery_observation(30_100),
        )
        .expect("semantic equality must survive a different finalization timestamp");
    assert_eq!(state, LifecycleState::Accepted);
    assert_eq!(
        recovered
            .release_state("tenant-a", &fixture.release_id)
            .expect("release state"),
        "FINALIZED"
    );
}

#[test]
fn s03_recovery_without_provider_return_keeps_transport_capture_absent() {
    let fixture = consume_then_crash("no-provider-capture", 40_000);

    let capture =
        TransportCaptureLedger::open(&fixture.path, &provider()).expect("open transport capture");
    assert_eq!(
        capture.load("tenant-a", &fixture.release_id),
        Err(TransportCaptureError::NotFound)
    );
    drop(capture);

    let mut recovered =
        ControlledReleaseBroker::open(&fixture.path, &provider()).expect("reopen broker");
    let state = recovered
        .recover_release(
            "tenant-a",
            &fixture.release_id,
            &recovery_observation(40_100),
        )
        .expect("missing provider result must converge as uncertainty without fake capture");
    assert_eq!(state, LifecycleState::AcceptanceUnknown);
    assert_eq!(
        recovered
            .release_state("tenant-a", &fixture.release_id)
            .expect("release state"),
        "FINALIZED"
    );
    drop(recovered);

    let capture =
        TransportCaptureLedger::open(&fixture.path, &provider()).expect("reopen transport capture");
    assert_eq!(
        capture.load("tenant-a", &fixture.release_id),
        Err(TransportCaptureError::NotFound),
        "recovery inference must never masquerade as a provider-return capture"
    );

    let runtime = EffectRuntime::open(&fixture.path, &provider()).expect("effect runtime");
    let view = runtime
        .effect_view("tenant-a", "intent-response-crash")
        .expect("effect view");
    assert_eq!(
        view.intent.lifecycle_state,
        LifecycleState::AcceptanceUnknown
    );

    let attempts = DispatchAttemptLedger::open(&fixture.path, &provider()).expect("attempt ledger");
    let finalized = attempts
        .finalized_attempt("tenant-a", &fixture.attempt.attempt_id)
        .expect("attempt finalized conservatively");
    assert_eq!(
        finalized.transport_result,
        AttemptTransportResult::ConnectionFailedAmbiguous
    );
    assert!(finalized.provider_status_receipt_refs.is_empty());
    assert_eq!(finalized.next_action, AttemptNextAction::Reconcile);
}

#[test]
fn s03_uncaptured_recovery_is_idempotent_after_effect_truth_was_already_persisted() {
    let fixture = consume_then_crash("no-capture-effect-persisted", 50_000);
    let mut effects = EffectRuntime::open(&fixture.path, &provider()).expect("effect runtime");
    effects
        .record_transport_result(
            &fixture.ticket,
            TransportResult::ConnectionFailedAmbiguous {
                evidence_ref: "broker-recovery-consumed-send-uncertain".into(),
            },
            50_050,
        )
        .expect("simulate crash after conservative effect update");
    drop(effects);

    let mut recovered =
        ControlledReleaseBroker::open(&fixture.path, &provider()).expect("reopen broker");
    let state = recovered
        .recover_release(
            "tenant-a",
            &fixture.release_id,
            &recovery_observation(50_100),
        )
        .expect("recovery must finish from existing conservative effect truth");
    assert_eq!(state, LifecycleState::AcceptanceUnknown);
    drop(recovered);

    let capture =
        TransportCaptureLedger::open(&fixture.path, &provider()).expect("transport capture");
    assert_eq!(
        capture.load("tenant-a", &fixture.release_id),
        Err(TransportCaptureError::NotFound)
    );
}

#[test]
fn s03_uncaptured_recovery_accepts_matching_finalized_attempt_without_fabricating_capture() {
    let fixture = consume_then_crash("no-capture-attempt-finalized", 55_000);
    let mut effects = EffectRuntime::open(&fixture.path, &provider()).expect("effect runtime");
    effects
        .record_transport_result(
            &fixture.ticket,
            TransportResult::ConnectionFailedAmbiguous {
                evidence_ref: "broker-recovery-consumed-send-uncertain".into(),
            },
            55_050,
        )
        .expect("persist conservative effect truth");
    drop(effects);

    let mut attempts =
        DispatchAttemptLedger::open(&fixture.path, &provider()).expect("attempt ledger");
    attempts
        .finalize_once(
            "tenant-a",
            &fixture.attempt.attempt_id,
            AttemptTransportResult::ConnectionFailedAmbiguous,
            &[],
            AttemptNextAction::Reconcile,
            "broker-recovery-consumed-send-uncertain",
            55_075,
        )
        .expect("simulate crash after attempt finalization");
    drop(attempts);

    let mut recovered =
        ControlledReleaseBroker::open(&fixture.path, &provider()).expect("reopen broker");
    let state = recovered
        .recover_release(
            "tenant-a",
            &fixture.release_id,
            &recovery_observation(55_100),
        )
        .expect("semantic attempt equality must allow release finalization");
    assert_eq!(state, LifecycleState::AcceptanceUnknown);
    drop(recovered);

    let capture =
        TransportCaptureLedger::open(&fixture.path, &provider()).expect("transport capture");
    assert_eq!(
        capture.load("tenant-a", &fixture.release_id),
        Err(TransportCaptureError::NotFound)
    );
}
