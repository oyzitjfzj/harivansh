use noerith_effects::{
    AcceptanceReceipt, AdapterAssuranceProfile, AdapterQualificationEvidence, CallbackSemantics,
    CancelAfterAcceptance, CancelBeforeAcceptance, CompensationCapability, CompensationRecord,
    DigestRef, DurationKnowledge, EffectClass, EffectIntent, EffectRuntime, IdempotencyBinding,
    LifecycleState, RetryPolicy, RetryStrategy, Reversibility, StatusQuery, TransactionBoundary,
    VersionedRef,
};
use noerith_storage::SyntheticKeyProvider;
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static CASE_ID: AtomicU64 = AtomicU64::new(1);

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn temp_db(label: &str) -> PathBuf {
    let id = CASE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "noerith-effect-freshness-{label}-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temp root");
    root.join("effects.db")
}

fn provider() -> SyntheticKeyProvider {
    SyntheticKeyProvider::uniform("freshness-key", [0x41; 32])
        .with_effect_ledger_key("freshness-key")
}

fn profile(maximum_request_age: DurationKnowledge) -> AdapterAssuranceProfile {
    AdapterAssuranceProfile {
        mutates_external_state: true,
        accepts_stable_idempotency_key: true,
        dedup_retention: DurationKnowledge::Known(60_000),
        returns_acceptance_receipt: AcceptanceReceipt::None,
        status_query: StatusQuery::None,
        callback_semantics: CallbackSemantics::None,
        cancel_before_acceptance: CancelBeforeAcceptance::Unknown,
        cancel_after_acceptance: CancelAfterAcceptance::Unknown,
        compensation: CompensationCapability::None,
        transaction_boundary: TransactionBoundary::ProviderLocal,
        maximum_request_age,
        replay_controls: set(&["qualified-request-age-control"]),
        known_ambiguity_failure_modes: set(&["response-lost-after-send"]),
    }
}

fn qualification() -> AdapterQualificationEvidence {
    AdapterQualificationEvidence {
        adapter_ref: "adapter-fresh".into(),
        adapter_version: "1".into(),
        evidence_refs: set(&["freshness-qualification-evidence"]),
        exact_shared_atomic_boundary_ref: None,
        verified: true,
    }
}

fn retry() -> RetryPolicy {
    RetryPolicy {
        strategy: RetryStrategy::Fixed,
        base_delay_ms: 100,
        max_delay_ms: 100,
        max_attempts: 2,
        qualification_ref: "retry-qualification".into(),
    }
}

fn intent(id: &str, maximum_request_age: DurationKnowledge) -> EffectIntent {
    EffectIntent {
        effect_intent_id: id.into(),
        operation_type: "synthetic-write".into(),
        principal_context: DigestRef {
            ref_id: "principal-context".into(),
            digest: "principal-digest".into(),
        },
        goal: VersionedRef {
            ref_id: "goal".into(),
            version: 1,
        },
        work: VersionedRef {
            ref_id: "work".into(),
            version: 1,
        },
        target_resources: vec!["resource".into()],
        target_accounts: vec!["account".into()],
        target_principals: vec!["principal".into()],
        payload_schema: "urn:noerith:test:freshness".into(),
        payload_canonical_digest: "payload-digest".into(),
        payload_ref: "sealed-payload".into(),
        purpose: "purpose".into(),
        data_classes: set(&["private"]),
        disclosure_classes: set(&["provider"]),
        effect_class: EffectClass::ExternalConsequential,
        reversibility: Reversibility::Unknown,
        adapter_ref: "adapter-fresh".into(),
        adapter_version: "1".into(),
        assurance_profile: profile(maximum_request_age),
        idempotency: IdempotencyBinding::Supported {
            key: format!("idem-{id}"),
            valid_until_ms: 50_000,
        },
        expected_evidence_plan_ref: "evidence-plan".into(),
        created_by_message_ref: "message".into(),
        lifecycle_state: LifecycleState::Proposed,
        decision_snapshot_refs: Vec::new(),
        dispatch_attempt_refs: Vec::new(),
        provider_receipt_refs: Vec::new(),
        observation_refs: Vec::new(),
        cancellation: Default::default(),
        compensation: CompensationRecord::default(),
        current_fence: None,
    }
}

fn ready(
    runtime: &mut EffectRuntime,
    record: &EffectIntent,
    now: u64,
) -> noerith_effects::DispatchLease {
    runtime
        .register_intent("tenant", record, &qualification(), &retry(), now)
        .expect("register");
    runtime
        .prepare(
            "tenant",
            &record.effect_intent_id,
            "prepare-evidence",
            now + 1,
        )
        .expect("prepare");
    runtime
        .authorize(
            "tenant",
            &record.effect_intent_id,
            "snapshot",
            "snapshot-digest",
            now + 2,
        )
        .expect("authorize");
    let lease = runtime
        .acquire_dispatch_lease("tenant", "worker", now + 3, 20_000)
        .expect("lease");
    runtime
        .commit_ready("tenant", &record.effect_intent_id, &lease, now + 4)
        .expect("commit ready");
    lease
}

#[test]
fn known_adapter_maximum_request_age_is_checked_at_dispatch_not_confused_with_idempotency_expiry() {
    let path = temp_db("known-age");
    let mut runtime = EffectRuntime::open(&path, &provider()).expect("open runtime");
    let record = intent("effect-known-age", DurationKnowledge::Known(5_000));
    let lease = ready(&mut runtime, &record, 1_000);

    // The idempotency key is still valid at 7,000 ms; only the adapter's
    // independently qualified 5,000 ms maximum request age is stale.
    assert!(
        runtime
            .begin_dispatch("tenant", &record.effect_intent_id, &lease, 7_000)
            .is_err()
    );
}

#[test]
fn unknown_request_age_does_not_invent_a_universal_timeout() {
    let path = temp_db("unknown-age");
    let mut runtime = EffectRuntime::open(&path, &provider()).expect("open runtime");
    let record = intent("effect-unknown-age", DurationKnowledge::Unknown);
    let lease = ready(&mut runtime, &record, 1_000);

    runtime
        .begin_dispatch("tenant", &record.effect_intent_id, &lease, 7_000)
        .expect("no invented global request-age threshold");
}
