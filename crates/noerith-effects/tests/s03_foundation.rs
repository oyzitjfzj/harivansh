use noerith_effects::{
    AcceptanceReceipt, AdapterAssuranceProfile, AdapterQualificationEvidence, CallbackSemantics,
    CancelAfterAcceptance, CancelBeforeAcceptance, CancelResolution, CancelState,
    CompensationCapability, CompensationRecord, CompensationState, DigestRef, DurationKnowledge,
    EffectClass, EffectError, EffectIntent, EffectRuntime, IdempotencyBinding, LifecycleState,
    ObservationOutcome, OperatingClass, ReconcileOutcome, RetryDecision, RetryPolicy,
    RetryStrategy, Reversibility, StatusQuery, TransactionBoundary, TransportResult, VersionedRef,
};
use noerith_storage::SyntheticKeyProvider;
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static CASE_ID: AtomicU64 = AtomicU64::new(1);

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
        "noerith-effects-{label}-{}-{id}-{clock}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir.join("effects.db")
}

fn provider() -> SyntheticKeyProvider {
    SyntheticKeyProvider::uniform("effect-ledger-ci-key", [17_u8; 32])
        .with_effect_ledger_key("effect-ledger-ci-key")
}

fn open(label: &str) -> (EffectRuntime, PathBuf) {
    let path = temp_db(label);
    let runtime = EffectRuntime::open(&path, &provider()).expect("open effect runtime");
    (runtime, path)
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

fn retry(max_attempts: u32) -> RetryPolicy {
    RetryPolicy {
        strategy: RetryStrategy::Exponential,
        base_delay_ms: 100,
        max_delay_ms: 2_000,
        max_attempts,
        qualification_ref: "retry-policy-qualification-a".into(),
    }
}

fn intent(id: &str, work: &str, payload: &str, profile: AdapterAssuranceProfile) -> EffectIntent {
    EffectIntent {
        effect_intent_id: id.into(),
        operation_type: "external-write".into(),
        principal_context: DigestRef {
            ref_id: "principal-context-a".into(),
            digest: "principal-digest-a".into(),
        },
        goal: VersionedRef {
            ref_id: "goal-a".into(),
            version: 4,
        },
        work: VersionedRef {
            ref_id: work.into(),
            version: 3,
        },
        target_resources: vec!["resource-a".into()],
        target_accounts: vec!["account-a".into()],
        target_principals: vec!["target-a".into()],
        payload_schema: "urn:noerith:test-payload:1".into(),
        payload_canonical_digest: payload.into(),
        payload_ref: "sealed-payload-a".into(),
        purpose: "user-requested-effect".into(),
        data_classes: set(&["synthetic-private"]),
        disclosure_classes: set(&["target-service"]),
        effect_class: EffectClass::ExternalConsequential,
        reversibility: Reversibility::Unknown,
        adapter_ref: "adapter-a".into(),
        adapter_version: "7".into(),
        assurance_profile: profile,
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

fn authorize(
    runtime: &mut EffectRuntime,
    id: &str,
    work: &str,
    profile: AdapterAssuranceProfile,
    now: u64,
) {
    let record = intent(id, work, "payload-a", profile);
    runtime
        .register_intent("tenant-a", &record, &qualification(), &retry(3), now)
        .expect("register");
    runtime
        .prepare("tenant-a", id, "prepare-evidence", now + 1)
        .expect("prepare");
    runtime
        .authorize("tenant-a", id, "snapshot-a", "snapshot-digest-a", now + 2)
        .expect("authorize");
}

fn dispatch(
    runtime: &mut EffectRuntime,
    id: &str,
    work: &str,
    profile: AdapterAssuranceProfile,
    now: u64,
) -> noerith_effects::DispatchTicket {
    authorize(runtime, id, work, profile, now);
    let lease = runtime
        .acquire_dispatch_lease("tenant-a", "worker-a", now + 3, 500)
        .expect("lease");
    runtime
        .commit_ready("tenant-a", id, &lease, now + 4)
        .expect("commit ready");
    runtime
        .begin_dispatch("tenant-a", id, &lease, now + 5)
        .expect("dispatch")
}

#[test]
fn s03_01_operating_class_is_derived_from_qualified_profile_not_caller_claim() {
    let (mut runtime, _) = open("derived-class");
    let record = intent("intent-a", "work-a", "payload-a", profile());
    assert_eq!(
        runtime
            .register_intent("tenant-a", &record, &qualification(), &retry(3), 1_000)
            .unwrap(),
        OperatingClass::E3ObservableWrite
    );
    assert_eq!(
        runtime
            .effect_view("tenant-a", "intent-a")
            .unwrap()
            .operating_class,
        OperatingClass::E3ObservableWrite
    );
}

#[test]
fn s03_02_same_payload_different_user_intents_remain_distinct() {
    let (mut runtime, _) = open("intent-identity");
    let first = intent("intent-one", "work-a", "same-payload", profile());
    let second = intent("intent-two", "work-b", "same-payload", profile());
    runtime
        .register_intent("tenant-a", &first, &qualification(), &retry(3), 1_000)
        .unwrap();
    runtime
        .register_intent("tenant-a", &second, &qualification(), &retry(3), 1_000)
        .unwrap();
    assert_ne!(
        runtime
            .effect_view("tenant-a", "intent-one")
            .unwrap()
            .record_digest,
        runtime
            .effect_view("tenant-a", "intent-two")
            .unwrap()
            .record_digest
    );
}

#[test]
fn s03_03_same_intent_identity_with_changed_binding_fails_closed() {
    let (mut runtime, _) = open("intent-conflict");
    let first = intent("intent-one", "work-a", "payload-a", profile());
    runtime
        .register_intent("tenant-a", &first, &qualification(), &retry(3), 1_000)
        .unwrap();
    let mut changed = first.clone();
    changed.target_accounts = vec!["different-account".into()];
    assert_eq!(
        runtime.register_intent("tenant-a", &changed, &qualification(), &retry(3), 1_001),
        Err(EffectError::DuplicateIntentConflict)
    );
}

#[test]
fn s03_04_crash_after_dispatch_boundary_recovers_to_acceptance_unknown() {
    let (mut runtime, path) = open("crash-unknown");
    let _ticket = dispatch(&mut runtime, "intent-crash", "work-crash", profile(), 1_000);
    drop(runtime);

    let mut reopened = EffectRuntime::open(&path, &provider()).unwrap();
    assert_eq!(reopened.recover_inflight("tenant-a", 2_000).unwrap(), 1);
    assert_eq!(reopened.recover_inflight("tenant-a", 2_001).unwrap(), 0);
    assert_eq!(
        reopened
            .effect_view("tenant-a", "intent-crash")
            .unwrap()
            .intent
            .lifecycle_state,
        LifecycleState::AcceptanceUnknown
    );
}

#[test]
fn s03_05_e1_opaque_write_never_blind_retries() {
    let (mut runtime, _) = open("opaque-no-retry");
    let mut opaque = profile();
    opaque.accepts_stable_idempotency_key = false;
    opaque.dedup_retention = DurationKnowledge::Unknown;
    opaque.returns_acceptance_receipt = AcceptanceReceipt::None;
    opaque.status_query = StatusQuery::None;
    let mut record = intent("intent-opaque", "work-opaque", "payload", opaque.clone());
    record.idempotency = IdempotencyBinding::Unsupported;
    runtime
        .register_intent("tenant-a", &record, &qualification(), &retry(1), 1_000)
        .unwrap();
    runtime
        .prepare("tenant-a", "intent-opaque", "prepare", 1_001)
        .unwrap();
    runtime
        .authorize(
            "tenant-a",
            "intent-opaque",
            "snapshot",
            "snapshot-digest",
            1_002,
        )
        .unwrap();
    let lease = runtime
        .acquire_dispatch_lease("tenant-a", "worker", 1_003, 500)
        .unwrap();
    runtime
        .commit_ready("tenant-a", "intent-opaque", &lease, 1_004)
        .unwrap();
    let ticket = runtime
        .begin_dispatch("tenant-a", "intent-opaque", &lease, 1_005)
        .unwrap();
    runtime
        .record_transport_result(
            &ticket,
            TransportResult::ResponseLost {
                evidence_ref: "lost-response".into(),
            },
            1_006,
        )
        .unwrap();
    assert_eq!(
        runtime
            .retry_decision("tenant-a", "intent-opaque", 1_007)
            .unwrap(),
        RetryDecision::NoAutomaticRetry
    );
}

#[test]
fn s03_06_e2_retry_uses_explicit_qualified_policy_and_fresh_fence() {
    let (mut runtime, _) = open("dedup-retry");
    let mut dedup = profile();
    dedup.returns_acceptance_receipt = AcceptanceReceipt::None;
    dedup.status_query = StatusQuery::None;
    let ticket = dispatch(&mut runtime, "intent-retry", "work-retry", dedup, 1_000);
    runtime
        .record_transport_result(
            &ticket,
            TransportResult::ConnectionFailedAmbiguous {
                evidence_ref: "ambiguous-connect".into(),
            },
            1_010,
        )
        .unwrap();
    assert_eq!(
        runtime
            .retry_decision("tenant-a", "intent-retry", 1_011)
            .unwrap(),
        RetryDecision::RetrySameIntent { after_ms: 100 }
    );
    let lease = runtime
        .acquire_dispatch_lease("tenant-a", "worker-a", 1_012, 50)
        .unwrap();
    let available_at = runtime
        .schedule_same_intent_retry(
            "tenant-a",
            "intent-retry",
            &lease,
            "snapshot-fresh",
            "snapshot-fresh-digest",
            1_012,
        )
        .unwrap();
    assert_eq!(available_at, 1_112);
    assert!(matches!(
        runtime.begin_dispatch("tenant-a", "intent-retry", &lease, available_at),
        Err(EffectError::StaleFence)
    ));
    let fresh = runtime
        .acquire_dispatch_lease("tenant-a", "worker-a", available_at, 500)
        .unwrap();
    assert!(fresh.fence > lease.fence);
    let retry_ticket = runtime
        .begin_dispatch("tenant-a", "intent-retry", &fresh, available_at)
        .unwrap();
    assert_eq!(retry_ticket.effect_intent_id, ticket.effect_intent_id);
    assert_eq!(retry_ticket.attempt_number, 2);
}

#[test]
fn s03_07_e3_ambiguous_write_reconciles_instead_of_blind_retry() {
    let (mut runtime, _) = open("observable-reconcile");
    let ticket = dispatch(
        &mut runtime,
        "intent-observable",
        "work-observable",
        profile(),
        1_000,
    );
    runtime
        .record_transport_result(
            &ticket,
            TransportResult::ResponseLost {
                evidence_ref: "response-lost".into(),
            },
            1_010,
        )
        .unwrap();
    assert_eq!(
        runtime
            .retry_decision("tenant-a", "intent-observable", 1_011)
            .unwrap(),
        RetryDecision::Reconcile
    );
    runtime
        .start_reconciliation(
            "tenant-a",
            "intent-observable",
            "status-query-started",
            1_012,
        )
        .unwrap();
    assert_eq!(
        runtime
            .resolve_reconciliation(
                "tenant-a",
                "intent-observable",
                ReconcileOutcome::Unresolved {
                    evidence_ref: "status-unavailable".into(),
                },
                1_013,
            )
            .unwrap(),
        LifecycleState::Unresolved
    );
}

#[test]
fn s03_08_acceptance_is_not_success_without_outcome_observation() {
    let (mut runtime, _) = open("acceptance-not-success");
    let ticket = dispatch(
        &mut runtime,
        "intent-observe",
        "work-observe",
        profile(),
        1_000,
    );
    assert_eq!(
        runtime
            .record_transport_result(
                &ticket,
                TransportResult::ResponseAccepted {
                    receipt_ref: "provider-receipt".into(),
                },
                1_010,
            )
            .unwrap(),
        LifecycleState::Accepted
    );
    assert_eq!(
        runtime
            .effect_view("tenant-a", "intent-observe")
            .unwrap()
            .intent
            .lifecycle_state,
        LifecycleState::Accepted
    );
    assert_eq!(
        runtime
            .observe(
                "tenant-a",
                "intent-observe",
                ObservationOutcome::Succeeded {
                    evidence_ref: "independent-outcome-proof".into(),
                },
                1_011,
            )
            .unwrap(),
        LifecycleState::Succeeded
    );
}

#[test]
fn s03_09_precommit_cancel_is_blocked_before_commit_not_fake_provider_cancel() {
    let (mut runtime, _) = open("cancel-precommit");
    authorize(
        &mut runtime,
        "intent-cancel-pre",
        "work-cancel-pre",
        profile(),
        1_000,
    );
    assert_eq!(
        runtime
            .request_cancel(
                "tenant-a",
                "intent-cancel-pre",
                "authenticated-cancel",
                1_010,
            )
            .unwrap(),
        CancelState::BlockedBeforeCommit
    );
    let view = runtime
        .effect_view("tenant-a", "intent-cancel-pre")
        .unwrap();
    assert_eq!(
        view.intent.lifecycle_state,
        LifecycleState::CancelledPrecommit
    );
    assert_eq!(
        view.intent.cancellation.state,
        CancelState::BlockedBeforeCommit
    );
}

#[test]
fn s03_10_postsend_cancel_requires_forward_and_result_evidence() {
    let (mut runtime, _) = open("cancel-postsend");
    let _ticket = dispatch(
        &mut runtime,
        "intent-cancel-post",
        "work-cancel-post",
        profile(),
        1_000,
    );
    assert_eq!(
        runtime
            .request_cancel(
                "tenant-a",
                "intent-cancel-post",
                "authenticated-cancel",
                1_010,
            )
            .unwrap(),
        CancelState::Requested
    );
    assert_eq!(
        runtime
            .mark_cancel_forwarded(
                "tenant-a",
                "intent-cancel-post",
                "provider-cancel-request",
                1_011,
            )
            .unwrap(),
        CancelState::ForwardedToProvider
    );
    assert_eq!(
        runtime
            .resolve_cancel_provider_result(
                "tenant-a",
                "intent-cancel-post",
                CancelResolution::ConfirmedCancelled,
                "provider-cancel-proof",
                1_012,
            )
            .unwrap(),
        CancelState::ConfirmedCancelled
    );
}

#[test]
fn s03_11_cancel_unknown_remains_truthful_and_can_resolve_after_reconcile() {
    let (mut runtime, _) = open("cancel-unknown");
    let mut no_cancel = profile();
    no_cancel.cancel_before_acceptance = CancelBeforeAcceptance::Unsupported;
    let _ticket = dispatch(
        &mut runtime,
        "intent-cancel-unknown",
        "work-cancel-unknown",
        no_cancel,
        1_000,
    );
    runtime
        .request_cancel(
            "tenant-a",
            "intent-cancel-unknown",
            "authenticated-cancel",
            1_010,
        )
        .unwrap();
    assert_eq!(
        runtime
            .mark_cancel_unforwardable_unknown(
                "tenant-a",
                "intent-cancel-unknown",
                "adapter-cannot-stop-unknown-acceptance",
                1_011,
            )
            .unwrap(),
        CancelState::CancelUnknown
    );
    assert_eq!(
        runtime
            .resolve_cancel_after_reconciliation(
                "tenant-a",
                "intent-cancel-unknown",
                CancelResolution::TooLate,
                "target-observation-too-late",
                1_012,
            )
            .unwrap(),
        CancelState::TooLate
    );
}

#[test]
fn s03_12_known_unsupported_cancel_after_acceptance_is_too_late_not_success() {
    let (mut runtime, _) = open("cancel-unsupported");
    let mut unsupported = profile();
    unsupported.cancel_after_acceptance = CancelAfterAcceptance::Unsupported;
    let ticket = dispatch(
        &mut runtime,
        "intent-unsupported-cancel",
        "work-unsupported-cancel",
        unsupported,
        1_000,
    );
    runtime
        .record_transport_result(
            &ticket,
            TransportResult::ResponseAccepted {
                receipt_ref: "accepted-receipt".into(),
            },
            1_010,
        )
        .unwrap();
    assert_eq!(
        runtime
            .request_cancel(
                "tenant-a",
                "intent-unsupported-cancel",
                "authenticated-cancel",
                1_011,
            )
            .unwrap(),
        CancelState::TooLate
    );
}

#[test]
fn s03_13_compensation_is_linked_separate_effect_not_history_rewrite() {
    let (mut runtime, _) = open("compensation");
    let mut compensatable = profile();
    compensatable.compensation = CompensationCapability::CompensatingAction;
    let ticket = dispatch(
        &mut runtime,
        "intent-original",
        "work-original",
        compensatable.clone(),
        1_000,
    );
    runtime
        .record_transport_result(
            &ticket,
            TransportResult::ResponseAccepted {
                receipt_ref: "accepted-receipt".into(),
            },
            1_010,
        )
        .unwrap();
    runtime
        .plan_compensation(
            "tenant-a",
            "intent-original",
            "intent-compensation",
            "compensation-plan-evidence",
            1_011,
        )
        .unwrap();
    let original = runtime.effect_view("tenant-a", "intent-original").unwrap();
    assert_eq!(original.intent.lifecycle_state, LifecycleState::Accepted);
    assert_eq!(
        original.intent.compensation.state,
        CompensationState::Planned
    );
    assert_eq!(
        original
            .intent
            .compensation
            .linked_effect_intent_ref
            .as_deref(),
        Some("intent-compensation")
    );

    let compensation = intent(
        "intent-compensation",
        "work-compensation",
        "compensation-payload",
        compensatable,
    );
    runtime
        .register_intent(
            "tenant-a",
            &compensation,
            &qualification(),
            &retry(3),
            1_012,
        )
        .unwrap();
    assert_eq!(
        runtime
            .effect_view("tenant-a", "intent-compensation")
            .unwrap()
            .intent
            .lifecycle_state,
        LifecycleState::Proposed
    );
}

#[test]
fn s03_14_e5_requires_exact_shared_atomic_boundary_evidence() {
    let (mut runtime, _) = open("shared-atomic");
    let mut shared = profile();
    shared.transaction_boundary = TransactionBoundary::SharedAtomic;
    let record = intent("intent-e5", "work-e5", "payload", shared);
    assert_eq!(
        runtime.register_intent("tenant-a", &record, &qualification(), &retry(3), 1_000),
        Err(EffectError::SharedAtomicBoundaryUnproved)
    );
    let mut proof = qualification();
    proof.exact_shared_atomic_boundary_ref = Some("exact-transaction-boundary-proof".into());
    assert_eq!(
        runtime
            .register_intent("tenant-a", &record, &proof, &retry(3), 1_000)
            .unwrap(),
        OperatingClass::E5SharedAtomic
    );
}

#[test]
fn s03_15_idempotency_validity_cannot_claim_beyond_qualified_dedup_retention() {
    let (mut runtime, _) = open("dedup-window");
    let mut record = intent("intent-window", "work-window", "payload", profile());
    record.idempotency = IdempotencyBinding::Supported {
        key: "idem-window".into(),
        valid_until_ms: 100_000,
    };
    assert_eq!(
        runtime.register_intent("tenant-a", &record, &qualification(), &retry(3), 1_000),
        Err(EffectError::IdempotencyExpired)
    );
}

#[test]
fn s03_16_record_and_event_history_survive_reopen() {
    let (mut runtime, path) = open("reopen");
    authorize(
        &mut runtime,
        "intent-persist",
        "work-persist",
        profile(),
        1_000,
    );
    let before = runtime.event_count("tenant-a", "intent-persist").unwrap();
    assert!(before >= 3);
    drop(runtime);
    let reopened = EffectRuntime::open(&path, &provider()).unwrap();
    let view = reopened.effect_view("tenant-a", "intent-persist").unwrap();
    assert_eq!(view.intent.lifecycle_state, LifecycleState::Authorized);
    assert_eq!(
        reopened.event_count("tenant-a", "intent-persist").unwrap(),
        before
    );
}
