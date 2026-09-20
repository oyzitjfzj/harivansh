use noerith_broker::{
    AdapterOutcome, AdapterRequest, BrokerError, ControlledAdapter, CredentialHandle,
    CredentialSource, CredentialSourceError, CurrentReleaseState, OpaqueVersionRef,
    PostReturnTimeEvidence, PostReturnTimeSource, ReleaseFreshnessAuthority, ReleaseFreshnessGuard,
    ReleaseFreshnessSnapshot, ReleaseRequest, ReleaseTimeObservation, SecretMaterial,
    SourceBoundReleaseBroker as ControlledReleaseBroker,
};
use noerith_effects::{
    AcceptanceReceipt, AdapterAssuranceProfile, AdapterQualificationEvidence, AttemptNextAction,
    AttemptTransportResult, CallbackSemantics, CancelAfterAcceptance, CancelBeforeAcceptance,
    CompensationCapability, CompensationRecord, CompensationState, DigestRef,
    DispatchAttemptLedger, DurationKnowledge, EffectClass, EffectIntent, EffectRuntime,
    IdempotencyBinding, LifecycleState, MonotonicDeadline, RetryPolicy, RetryStrategy,
    Reversibility, StartedAt, StatusQuery, SynchronizationState, TransactionBoundary, VersionedRef,
};
use noerith_storage::SyntheticKeyProvider;
use rusqlite::Connection;
use std::{
    collections::BTreeSet,
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static CASE_ID: AtomicU64 = AtomicU64::new(1);
const DB_KEY: &str = "effect-ledger-ci-key";

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
        "noerith-broker-{label}-{}-{id}-{clock}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir.join("effects.db")
}

fn provider() -> SyntheticKeyProvider {
    SyntheticKeyProvider::uniform(DB_KEY, [31_u8; 32]).with_effect_ledger_key(DB_KEY)
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
        known_ambiguity_failure_modes: set(&["response-lost-after-acceptance"]),
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

fn retry() -> RetryPolicy {
    RetryPolicy {
        strategy: RetryStrategy::Exponential,
        base_delay_ms: 100,
        max_delay_ms: 2_000,
        max_attempts: 3,
        qualification_ref: "retry-policy-a".into(),
    }
}

fn intent(id: &str) -> EffectIntent {
    EffectIntent {
        effect_intent_id: id.into(),
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
            key: format!("idem-{id}"),
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

fn prepare_effect(path: &PathBuf, id: &str, now: u64) -> noerith_effects::DispatchLease {
    let mut runtime = EffectRuntime::open(path, &provider()).expect("open runtime");
    runtime
        .register_intent("tenant-a", &intent(id), &qualification(), &retry(), now)
        .expect("register");
    runtime
        .prepare("tenant-a", id, "prepare-evidence", now + 1)
        .expect("prepare");
    runtime
        .authorize("tenant-a", id, "snapshot-a", "snapshot-digest-a", now + 2)
        .expect("authorize");
    let lease = runtime
        .acquire_dispatch_lease("tenant-a", "worker-a", now + 3, 5_000)
        .expect("lease");
    runtime
        .commit_ready("tenant-a", id, &lease, now + 4)
        .expect("commit ready");
    lease
}

fn handle(id: &str, intent_id: &str, now: u64) -> CredentialHandle {
    CredentialHandle {
        handle_id: id.into(),
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
        effect_intent_id: intent_id.into(),
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

fn request(
    intent_id: &str,
    handle_id: &str,
    lease: noerith_effects::DispatchLease,
    now: u64,
) -> ReleaseRequest {
    ReleaseRequest {
        tenant_namespace: "tenant-a".into(),
        effect_intent_id: intent_id.into(),
        actor_ref: "principal-a".into(),
        workload_ref: "dispatcher-workload-a".into(),
        audience: "target-service".into(),
        credential_handle_ref: handle_id.into(),
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
            utc_timestamp: "2026-09-09T03:30:00Z".into(),
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
    let authority = StaticAuthority {
        current: current_from(&snapshot),
        observed_at_ms: request.now_ms,
        fail: false,
        acquisitions: 0,
    };
    (snapshot, authority)
}

fn current_from(snapshot: &ReleaseFreshnessSnapshot) -> CurrentReleaseState {
    CurrentReleaseState {
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
    }
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
    fail: bool,
    acquisitions: u32,
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
        self.acquisitions += 1;
        if self.fail {
            return Err(BrokerError::FreshnessAuthorityUnavailable);
        }
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
    evidence: PostReturnTimeEvidence,
    observations: u32,
}

impl FixedPostReturnTime {
    fn observed(unix_time_ms: u64) -> Self {
        Self {
            evidence: PostReturnTimeEvidence::Observed {
                unix_time_ms,
                uncertainty_before_ms: 0,
                uncertainty_after_ms: 0,
                clock_source: "qualified-post-return-ci-clock".into(),
                synchronization_state: SynchronizationState::Synced,
            },
            observations: 0,
        }
    }
}

impl PostReturnTimeSource for FixedPostReturnTime {
    fn observe_after_return(&mut self) -> PostReturnTimeEvidence {
        self.observations += 1;
        self.evidence.clone()
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

fn run_dispatch(
    broker: &mut ControlledReleaseBroker,
    request: &ReleaseRequest,
    freshness: &ReleaseFreshnessSnapshot,
    authority: &mut impl ReleaseFreshnessAuthority,
    credentials: &mut impl CredentialSource,
    transport: &mut impl ControlledAdapter,
) -> Result<LifecycleState, BrokerError> {
    let mut post_return = FixedPostReturnTime::observed(request.now_ms.saturating_add(1));
    broker.dispatch(
        request,
        freshness,
        authority,
        credentials,
        transport,
        &mut post_return,
    )
}

struct SyntheticCredentialSource {
    handle_id: String,
    secret: Vec<u8>,
    resolves: u32,
}

impl CredentialSource for SyntheticCredentialSource {
    fn resolve(&mut self, handle_id: &str) -> Result<SecretMaterial, CredentialSourceError> {
        if handle_id != self.handle_id {
            return Err(CredentialSourceError::NotFound);
        }
        self.resolves += 1;
        SecretMaterial::new(self.secret.clone())
    }
}

struct RecordingAdapter {
    identity: VersionedRef,
    expected_secret: Vec<u8>,
    outcome: AdapterOutcome,
    calls: u32,
}

impl ControlledAdapter for RecordingAdapter {
    fn identity(&self) -> VersionedRef {
        self.identity.clone()
    }

    fn send(&mut self, request: &AdapterRequest, credential: &[u8]) -> AdapterOutcome {
        assert_eq!(credential, self.expected_secret.as_slice());
        assert_eq!(request.effect_intent_id, "intent-a");
        assert_eq!(request.audience, "target-service");
        self.calls += 1;
        self.outcome.clone()
    }
}

struct PanicAdapter {
    identity: VersionedRef,
}

impl ControlledAdapter for PanicAdapter {
    fn identity(&self) -> VersionedRef {
        self.identity.clone()
    }

    fn send(&mut self, _request: &AdapterRequest, _credential: &[u8]) -> AdapterOutcome {
        panic!("synthetic crash exactly after broker release consumption")
    }
}

fn source(handle_id: &str) -> SyntheticCredentialSource {
    SyntheticCredentialSource {
        handle_id: handle_id.into(),
        secret: b"BROKER_SYNTHETIC_SECRET".to_vec(),
        resolves: 0,
    }
}

fn adapter(outcome: AdapterOutcome) -> RecordingAdapter {
    RecordingAdapter {
        identity: VersionedRef {
            ref_id: "adapter-a".into(),
            version: 7,
        },
        expected_secret: b"BROKER_SYNTHETIC_SECRET".to_vec(),
        outcome,
        calls: 0,
    }
}

#[test]
fn s03_broker_success_binds_handle_attempt_transport_and_freshness_evidence() {
    let path = temp_db("success");
    let lease = prepare_effect(&path, "intent-a", 1_000);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 1_010), 1_010)
        .unwrap();
    let request = request("intent-a", "handle-a", lease, 1_020);
    let (freshness, mut authority) = freshness_for(&request);
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "provider-receipt-a".into(),
    });
    let state = run_dispatch(
        &mut broker,
        &request,
        &freshness,
        &mut authority,
        &mut credentials,
        &mut transport,
    )
    .unwrap();
    assert_eq!(state, LifecycleState::Accepted);
    assert_eq!(authority.acquisitions, 1);
    assert_eq!(credentials.resolves, 1);
    assert_eq!(transport.calls, 1);

    let connection = Connection::open(&path).unwrap();
    connection.pragma_update(None, "key", DB_KEY).unwrap();
    let release_id: String = connection
        .query_row(
            "SELECT release_id FROM broker_releases WHERE tenant_namespace='tenant-a' AND state='FINALIZED'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let proof = broker
        .release_freshness_proof("tenant-a", &release_id)
        .unwrap()
        .expect("durable freshness proof");
    assert_eq!(proof.decision_snapshot(), &freshness.decision_snapshot);
    assert_eq!(proof.dispatch_owner(), freshness.dispatch_owner);
    assert_eq!(
        proof.dispatch_lease_expires_at_ms(),
        freshness.dispatch_lease_expires_at_ms
    );
    assert_eq!(proof.fence(), freshness.fence);
    drop(broker);

    let runtime = EffectRuntime::open(&path, &provider()).unwrap();
    let view = runtime.effect_view("tenant-a", "intent-a").unwrap();
    assert_eq!(view.intent.lifecycle_state, LifecycleState::Accepted);
    assert_eq!(view.attempt_count, 1);
    assert_eq!(
        view.intent.provider_receipt_refs,
        vec!["provider-receipt-a"]
    );

    let ledger = DispatchAttemptLedger::open(&path, &provider()).unwrap();
    let finalized = ledger
        .finalized_attempt("tenant-a", "attempt:intent-a:1")
        .unwrap();
    assert_eq!(
        finalized.transport_result,
        AttemptTransportResult::ResponseReceived
    );
    assert_eq!(finalized.next_action, AttemptNextAction::None);
    assert_eq!(finalized.binding.credential_handle_ref, "handle-a");
    assert_eq!(finalized.binding.capability.ref_id, "capability-a");
    assert_eq!(finalized.binding.environment.ref_id, "sandbox-a");
}

#[test]
fn s03_broker_wrong_identity_scope_or_capability_never_calls_adapter() {
    for field in ["actor", "target", "capability"] {
        let path = temp_db(field);
        let lease = prepare_effect(&path, "intent-a", 2_000);
        let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
        let mut bound_handle = handle("handle-a", "intent-a", 2_010);
        match field {
            "actor" => bound_handle.actor_ref = "other-principal".into(),
            "target" => bound_handle.target_resources = set(&["other-resource"]),
            "capability" => bound_handle.capability.version = 99,
            _ => unreachable!(),
        }
        broker.register_handle(&bound_handle, 2_010).unwrap();
        let request = request("intent-a", "handle-a", lease, 2_020);
        let (freshness, mut authority) = freshness_for(&request);
        let mut credentials = source("handle-a");
        let mut transport = adapter(AdapterOutcome::Accepted {
            receipt_ref: "should-not-send".into(),
        });
        let result = run_dispatch(
            &mut broker,
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport,
        );
        assert!(matches!(
            result,
            Err(BrokerError::CredentialBindingMismatch(_))
        ));
        assert_eq!(credentials.resolves, 0);
        assert_eq!(transport.calls, 0);
    }
}

#[test]
fn s03_broker_expired_or_revoked_handle_fails_before_secret_resolution() {
    let path = temp_db("revocation");
    let lease = prepare_effect(&path, "intent-a", 3_000);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 3_010), 3_010)
        .unwrap();
    broker
        .advance_revocation_epoch("tenant-a", "authority-a", 6, 3_015)
        .unwrap();
    let revoked_request = request("intent-a", "handle-a", lease, 3_020);
    let (freshness, mut authority) = freshness_for(&revoked_request);
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "should-not-send".into(),
    });
    assert!(matches!(
        run_dispatch(
            &mut broker,
            &revoked_request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport
        ),
        Err(BrokerError::HandleRevoked)
    ));
    assert_eq!(credentials.resolves, 0);
    assert_eq!(transport.calls, 0);

    let path = temp_db("expiry");
    let lease = prepare_effect(&path, "intent-a", 4_000);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    let mut expiring = handle("handle-a", "intent-a", 4_010);
    expiring.expires_at_ms = 4_025;
    broker.register_handle(&expiring, 4_010).unwrap();
    let request = request("intent-a", "handle-a", lease, 4_025);
    let (freshness, mut authority) = freshness_for(&request);
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "should-not-send".into(),
    });
    assert!(matches!(
        run_dispatch(
            &mut broker,
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport
        ),
        Err(BrokerError::HandleExpired)
    ));
    assert_eq!(credentials.resolves, 0);
    assert_eq!(transport.calls, 0);
}

#[test]
fn s03_final_gate_rechecks_handle_expiry_using_authority_time() {
    let path = temp_db("final-handle-expiry");
    let lease = prepare_effect(&path, "intent-a", 4_500);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    let mut expiring = handle("handle-a", "intent-a", 4_510);
    expiring.expires_at_ms = 4_525;
    broker.register_handle(&expiring, 4_510).unwrap();
    let request = request("intent-a", "handle-a", lease, 4_520);
    let (freshness, mut authority) = freshness_for(&request);
    authority.observed_at_ms = 4_525;
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "should-not-send".into(),
    });
    assert!(matches!(
        run_dispatch(
            &mut broker,
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport
        ),
        Err(BrokerError::HandleExpired)
    ));
    assert_eq!(credentials.resolves, 1);
    assert_eq!(transport.calls, 0);
}

#[test]
fn s03_broker_cancelled_or_stale_fence_never_releases_secret() {
    let path = temp_db("cancelled");
    let lease = prepare_effect(&path, "intent-a", 5_000);
    let mut runtime = EffectRuntime::open(&path, &provider()).unwrap();
    runtime
        .request_cancel("tenant-a", "intent-a", "authenticated-cancel", 5_010)
        .unwrap();
    drop(runtime);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 5_011), 5_011)
        .unwrap();
    let cancelled_request = request("intent-a", "handle-a", lease, 5_020);
    let (freshness, mut authority) = freshness_for(&cancelled_request);
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "should-not-send".into(),
    });
    assert!(
        run_dispatch(
            &mut broker,
            &cancelled_request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport
        )
        .is_err()
    );
    assert_eq!(credentials.resolves, 0);
    assert_eq!(transport.calls, 0);

    let path = temp_db("stale-fence");
    let lease = prepare_effect(&path, "intent-a", 6_000);
    let mut stale = lease.clone();
    stale.fence = stale.fence.saturating_add(1);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 6_010), 6_010)
        .unwrap();
    let request = request("intent-a", "handle-a", stale, 6_020);
    let (freshness, mut authority) = freshness_for(&request);
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "should-not-send".into(),
    });
    assert!(
        run_dispatch(
            &mut broker,
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport
        )
        .is_err()
    );
    assert_eq!(credentials.resolves, 0);
    assert_eq!(transport.calls, 0);
}

#[test]
fn s03_broker_adapter_version_mismatch_fails_closed() {
    let path = temp_db("adapter-mismatch");
    let lease = prepare_effect(&path, "intent-a", 7_000);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 7_010), 7_010)
        .unwrap();
    let request = request("intent-a", "handle-a", lease, 7_020);
    let (freshness, mut authority) = freshness_for(&request);
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "should-not-send".into(),
    });
    transport.identity.version = 8;
    assert!(matches!(
        run_dispatch(
            &mut broker,
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport
        ),
        Err(BrokerError::AdapterMismatch)
    ));
    assert_eq!(credentials.resolves, 0);
    assert_eq!(transport.calls, 0);
}

#[test]
fn s03_final_authority_blocks_every_stale_axis_before_adapter_after_secret_prefetch() {
    for field in [
        "tenant",
        "effect",
        "decision",
        "principal",
        "goal",
        "work",
        "state",
        "policy",
        "grant",
        "revocation",
        "interrupt",
        "payload",
        "targets",
        "capability",
        "environment",
        "owner",
        "lease",
        "fence",
        "cancel",
        "health",
    ] {
        let path = temp_db(&format!("freshness-{field}"));
        let lease = prepare_effect(&path, "intent-a", 9_000);
        let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
        broker
            .register_handle(&handle("handle-a", "intent-a", 9_010), 9_010)
            .unwrap();
        let request = request("intent-a", "handle-a", lease, 9_020);
        let (freshness, mut authority) = freshness_for(&request);
        match field {
            "tenant" => authority.current.tenant_namespace = "tenant-b".into(),
            "effect" => authority.current.effect_intent_id = "intent-b".into(),
            "decision" => authority.current.decision_snapshot.digest = "changed".into(),
            "principal" => authority.current.principal_context.digest = "changed".into(),
            "goal" => authority.current.goal.version += 1,
            "work" => authority.current.work.version += 1,
            "state" => authority.current.state_revision += 1,
            "policy" => authority.current.policy.version = "policy-new".into(),
            "grant" => authority.current.authority_grant_ref = "authority-b".into(),
            "revocation" => authority.current.revocation_epoch += 1,
            "interrupt" => authority.current.interrupt_watermark += 1,
            "payload" => authority.current.payload_digest = "changed".into(),
            "targets" => authority.current.target_resources = set(&["resource-b"]),
            "capability" => authority.current.capability.version = "12".into(),
            "environment" => authority.current.environment.version = "4".into(),
            "owner" => authority.current.dispatch_owner = "worker-b".into(),
            "lease" => authority.current.dispatch_lease_expires_at_ms -= 1,
            "fence" => authority.current.fence += 1,
            "cancel" => authority.current.cancel_before_release = true,
            "health" => authority.current.execution_healthy = false,
            _ => unreachable!(),
        }
        let mut credentials = source("handle-a");
        let mut transport = adapter(AdapterOutcome::Accepted {
            receipt_ref: "should-not-send".into(),
        });
        let result = run_dispatch(
            &mut broker,
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport,
        );
        assert!(result.is_err(), "{field} must fail closed");
        assert_eq!(
            credentials.resolves, 1,
            "{field} did not prefetch credential"
        );
        assert_eq!(transport.calls, 0, "{field} called the adapter");
    }
}

#[test]
fn s03_final_gate_uses_authority_time_not_request_entry_time() {
    let path = temp_db("final-lease-expiry");
    let lease = prepare_effect(&path, "intent-a", 9_500);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 9_510), 9_510)
        .unwrap();
    let request = request("intent-a", "handle-a", lease, 9_520);
    let (freshness, mut authority) = freshness_for(&request);
    authority.observed_at_ms = freshness.dispatch_lease_expires_at_ms;
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "should-not-send".into(),
    });
    assert!(matches!(
        run_dispatch(
            &mut broker,
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport
        ),
        Err(BrokerError::Freshness(_))
    ));
    assert_eq!(credentials.resolves, 1);
    assert_eq!(transport.calls, 0);
}

#[test]
fn s03_final_authority_unavailable_and_snapshot_forgery_fail_closed() {
    let path = temp_db("authority-unavailable");
    let lease = prepare_effect(&path, "intent-a", 10_000);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 10_010), 10_010)
        .unwrap();
    let unavailable_request = request("intent-a", "handle-a", lease, 10_020);
    let (freshness, mut authority) = freshness_for(&unavailable_request);
    authority.fail = true;
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "should-not-send".into(),
    });
    assert!(matches!(
        run_dispatch(
            &mut broker,
            &unavailable_request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport
        ),
        Err(BrokerError::FreshnessAuthorityUnavailable)
    ));
    assert_eq!(credentials.resolves, 1);
    assert_eq!(transport.calls, 0);

    let path = temp_db("forged-snapshot");
    let lease = prepare_effect(&path, "intent-a", 11_000);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 11_010), 11_010)
        .unwrap();
    let request = request("intent-a", "handle-a", lease, 11_020);
    let (mut freshness, _) = freshness_for(&request);
    freshness.decision_snapshot.digest = "forged-snapshot-digest".into();
    freshness.payload_digest = "forged-payload-digest".into();
    let mut authority = StaticAuthority {
        current: current_from(&freshness),
        observed_at_ms: request.now_ms,
        fail: false,
        acquisitions: 0,
    };
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "should-not-send".into(),
    });
    assert!(
        run_dispatch(
            &mut broker,
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport
        )
        .is_err()
    );
    assert_eq!(authority.acquisitions, 0);
    assert_eq!(credentials.resolves, 0);
    assert_eq!(transport.calls, 0);
}

#[test]
fn s03_post_return_clock_unavailable_preserves_result_and_never_resends() {
    let path = temp_db("post-return-time-unavailable");
    let lease = prepare_effect(&path, "intent-a", 11_500);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 11_510), 11_510)
        .unwrap();
    let request = request("intent-a", "handle-a", lease, 11_520);
    let (freshness, mut authority) = freshness_for(&request);
    let mut credentials = source("handle-a");
    let mut transport = adapter(AdapterOutcome::Accepted {
        receipt_ref: "provider-receipt-clock-unavailable".into(),
    });
    let mut post_return = FixedPostReturnTime {
        evidence: PostReturnTimeEvidence::Unavailable {
            reason: "synthetic-clock-unavailable".into(),
            evidence_ref: "clock-health-evidence-a".into(),
        },
        observations: 0,
    };
    assert!(matches!(
        broker.dispatch(
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport,
            &mut post_return,
        ),
        Err(BrokerError::PostReturnTimeUnavailable)
    ));
    assert_eq!(credentials.resolves, 1);
    assert_eq!(transport.calls, 1);
    assert_eq!(post_return.observations, 1);

    let connection = Connection::open(&path).unwrap();
    connection.pragma_update(None, "key", DB_KEY).unwrap();
    let release_id: String = connection
        .query_row(
            "SELECT release_id FROM broker_releases WHERE tenant_namespace='tenant-a' AND state='CONSUMED'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let result_json: String = connection
        .query_row(
            "SELECT result_json FROM broker_transport_capture_v01 WHERE tenant_namespace='tenant-a' AND release_id=?1",
            [&release_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(result_json.contains("provider-receipt-clock-unavailable"));
    drop(connection);

    let state = broker
        .recover_release("tenant-a", &release_id, &recovery_observation(11_600))
        .unwrap();
    assert_eq!(state, LifecycleState::Accepted);
    assert_eq!(transport.calls, 1, "recovery must never resend");
}

#[test]
fn s03_secret_debug_and_errors_do_not_expose_secret_material() {
    let secret = SecretMaterial::new(b"DO_NOT_PRINT_THIS_SECRET".to_vec()).unwrap();
    let rendered = format!("{secret:?}");
    assert!(!rendered.contains("DO_NOT_PRINT_THIS_SECRET"));
    assert!(rendered.contains("REDACTED"));

    let source_error = CredentialSourceError::InvalidSecret;
    assert!(!source_error.to_string().contains("SECRET"));
}

#[test]
fn s03_crash_after_release_consumption_recovers_as_ambiguous_not_success() {
    let path = temp_db("consumed-crash");
    let lease = prepare_effect(&path, "intent-a", 12_000);
    let mut broker = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    broker
        .register_handle(&handle("handle-a", "intent-a", 12_010), 12_010)
        .unwrap();
    let request = request("intent-a", "handle-a", lease, 12_020);
    let (freshness, mut authority) = freshness_for(&request);
    let mut credentials = source("handle-a");
    let mut transport = PanicAdapter {
        identity: VersionedRef {
            ref_id: "adapter-a".into(),
            version: 7,
        },
    };
    let mut post_return = FixedPostReturnTime::observed(12_021);
    let call = catch_unwind(AssertUnwindSafe(|| {
        let _ = broker.dispatch(
            &request,
            &freshness,
            &mut authority,
            &mut credentials,
            &mut transport,
            &mut post_return,
        );
    }));
    assert!(call.is_err());
    assert_eq!(post_return.observations, 0);
    drop(broker);

    let connection = Connection::open(&path).unwrap();
    connection.pragma_update(None, "key", DB_KEY).unwrap();
    let release_id: String = connection
        .query_row(
            "SELECT release_id FROM broker_releases WHERE tenant_namespace='tenant-a' AND state='CONSUMED'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let proof_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM broker_release_freshness_proofs WHERE tenant_namespace='tenant-a' AND release_id=?1",
            [&release_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(proof_count, 1);
    let capture_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM broker_transport_capture_v01 WHERE tenant_namespace='tenant-a' AND release_id=?1",
            [&release_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(capture_count, 0);
    drop(connection);

    let mut recovered = ControlledReleaseBroker::open(&path, &provider()).unwrap();
    let state = recovered
        .recover_release("tenant-a", &release_id, &recovery_observation(12_100))
        .unwrap();
    assert_eq!(state, LifecycleState::AcceptanceUnknown);
    assert_eq!(
        recovered.release_state("tenant-a", &release_id).unwrap(),
        "FINALIZED"
    );
    drop(recovered);

    let runtime = EffectRuntime::open(&path, &provider()).unwrap();
    assert_eq!(
        runtime
            .effect_view("tenant-a", "intent-a")
            .unwrap()
            .intent
            .lifecycle_state,
        LifecycleState::AcceptanceUnknown
    );
    let ledger = DispatchAttemptLedger::open(&path, &provider()).unwrap();
    let attempt = ledger
        .finalized_attempt("tenant-a", "attempt:intent-a:1")
        .unwrap();
    assert_eq!(
        attempt.transport_result,
        AttemptTransportResult::ConnectionFailedAmbiguous
    );
    assert_eq!(attempt.next_action, AttemptNextAction::Reconcile);
}
