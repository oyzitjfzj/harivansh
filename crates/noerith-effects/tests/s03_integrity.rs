use noerith_effects::{
    AcceptanceReceipt, AdapterAssuranceProfile, AdapterQualificationEvidence, CallbackSemantics,
    CancelAfterAcceptance, CancelBeforeAcceptance, CompensationCapability, CompensationRecord,
    DigestRef, DurationKnowledge, EffectClass, EffectError, EffectIntent, EffectRuntime,
    IdempotencyBinding, LifecycleState, RetryPolicy, RetryStrategy, Reversibility, StatusQuery,
    TransactionBoundary, VersionedRef,
};
use noerith_storage::SyntheticKeyProvider;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static CASE_ID: AtomicU64 = AtomicU64::new(1);
const DB_KEY: &str = "synthetic-s03-integrity-key";

fn temp_db(label: &str) -> PathBuf {
    let id = CASE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "noerith-s03-integrity-{label}-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temp root");
    root.join("effects.db")
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn profile() -> AdapterAssuranceProfile {
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
        maximum_request_age: DurationKnowledge::Known(60_000),
        replay_controls: set(&["bounded-request-age"]),
        known_ambiguity_failure_modes: set(&["response-lost-after-send"]),
    }
}

fn qualification() -> AdapterQualificationEvidence {
    AdapterQualificationEvidence {
        adapter_ref: "adapter-a".into(),
        adapter_version: "1".into(),
        evidence_refs: set(&["adapter-evidence-a"]),
        exact_shared_atomic_boundary_ref: None,
        verified: true,
    }
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        strategy: RetryStrategy::Fixed,
        base_delay_ms: 100,
        max_delay_ms: 500,
        max_attempts: 2,
        qualification_ref: "retry-policy-evidence-a".into(),
    }
}

fn intent() -> EffectIntent {
    EffectIntent {
        effect_intent_id: "effect-integrity-a".into(),
        operation_type: "synthetic-external-write".into(),
        principal_context: DigestRef {
            ref_id: "principal-context-a".into(),
            digest: "principal-digest-a".into(),
        },
        goal: VersionedRef {
            ref_id: "goal-a".into(),
            version: 3,
        },
        work: VersionedRef {
            ref_id: "work-a".into(),
            version: 7,
        },
        target_resources: vec!["resource-a".into()],
        target_accounts: vec!["account-a".into()],
        target_principals: vec!["principal-a".into()],
        payload_schema: "urn:noerith:test:payload".into(),
        payload_canonical_digest: "payload-digest-a".into(),
        payload_ref: "sealed-payload-a".into(),
        purpose: "purpose-a".into(),
        data_classes: set(&["private"]),
        disclosure_classes: set(&["provider-a"]),
        effect_class: EffectClass::ExternalConsequential,
        reversibility: Reversibility::Unknown,
        adapter_ref: "adapter-a".into(),
        adapter_version: "1".into(),
        assurance_profile: profile(),
        idempotency: IdempotencyBinding::Supported {
            key: "idem-effect-integrity-a".into(),
            valid_until_ms: 50_000,
        },
        expected_evidence_plan_ref: "evidence-plan-a".into(),
        created_by_message_ref: "message-a".into(),
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

fn provider() -> SyntheticKeyProvider {
    SyntheticKeyProvider::uniform(DB_KEY, [0x31; 32])
}

fn register(path: &PathBuf) {
    let provider = provider();
    let mut runtime = EffectRuntime::open(path, &provider).expect("open effect runtime");
    runtime
        .register_intent(
            "tenant-a",
            &intent(),
            &qualification(),
            &retry_policy(),
            1_000,
        )
        .expect("register canonical effect");
}

fn raw_open(path: &PathBuf) -> Connection {
    let connection = Connection::open(path).expect("open raw SQLCipher database");
    connection
        .pragma_update(None, "key", DB_KEY)
        .expect("apply SQLCipher key");
    connection
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("format digest");
    }
    out
}

#[test]
fn s03_integrity_retry_policy_binding_cannot_be_silently_rewritten() {
    let path = temp_db("retry-policy");
    register(&path);

    let connection = raw_open(&path);
    let forged = serde_json::json!({
        "strategy": "FIXED",
        "base_delay_ms": 1,
        "max_delay_ms": 1,
        "max_attempts": 999,
        "qualification_ref": "retry-policy-evidence-a"
    })
    .to_string();
    connection
        .execute(
            "UPDATE effects SET retry_policy_json=?3 WHERE tenant_namespace=?1 AND intent_id=?2",
            params!["tenant-a", "effect-integrity-a", forged],
        )
        .expect("inject synthetic logical tamper");
    drop(connection);

    let provider = provider();
    let runtime = EffectRuntime::open(&path, &provider).expect("reopen effect runtime");
    assert!(matches!(
        runtime.effect_view("tenant-a", "effect-integrity-a"),
        Err(EffectError::ExecutionUnhealthy)
    ));
}

#[test]
fn s03_integrity_immutable_effect_binding_survives_matching_record_digest_rewrite() {
    let path = temp_db("creation-binding");
    register(&path);

    let connection = raw_open(&path);
    let record_json: String = connection
        .query_row(
            "SELECT record_json FROM effects WHERE tenant_namespace=?1 AND intent_id=?2",
            params!["tenant-a", "effect-integrity-a"],
            |row| row.get(0),
        )
        .expect("read canonical record");
    let mut value: serde_json::Value = serde_json::from_str(&record_json).expect("decode record");
    value["payload_canonical_digest"] = serde_json::Value::String("forged-payload".into());
    let forged_record = serde_json::to_string(&value).expect("encode forged record");
    let forged_record_digest = sha256_hex(forged_record.as_bytes());
    connection
        .execute(
            "UPDATE effects SET record_json=?3,record_digest=?4 WHERE tenant_namespace=?1 AND intent_id=?2",
            params![
                "tenant-a",
                "effect-integrity-a",
                forged_record,
                forged_record_digest
            ],
        )
        .expect("inject synthetic matching-digest tamper");
    drop(connection);

    let provider = provider();
    let runtime = EffectRuntime::open(&path, &provider).expect("reopen effect runtime");
    assert!(matches!(
        runtime.effect_view("tenant-a", "effect-integrity-a"),
        Err(EffectError::ExecutionUnhealthy)
    ));
}

#[test]
fn s03_integrity_indexed_shadow_state_cannot_disagree_with_canonical_record() {
    let path = temp_db("shadow-state");
    register(&path);

    let connection = raw_open(&path);
    connection
        .execute(
            "UPDATE effects SET state='SUCCEEDED' WHERE tenant_namespace=?1 AND intent_id=?2",
            params!["tenant-a", "effect-integrity-a"],
        )
        .expect("inject synthetic state divergence");
    drop(connection);

    let provider = provider();
    let runtime = EffectRuntime::open(&path, &provider).expect("reopen effect runtime");
    assert!(matches!(
        runtime.effect_view("tenant-a", "effect-integrity-a"),
        Err(EffectError::ExecutionUnhealthy)
    ));
}

#[test]
fn s03_integrity_qualification_evidence_cannot_certify_a_different_assurance_profile() {
    let path = temp_db("profile-binding");
    let provider = provider();
    let mut runtime = EffectRuntime::open(&path, &provider).expect("open effect runtime");

    let first = intent();
    runtime
        .register_intent("tenant-a", &first, &qualification(), &retry_policy(), 1_000)
        .expect("qualification applies to audited profile");

    let mut changed = intent();
    changed.effect_intent_id = "effect-integrity-profile-change".into();
    changed.idempotency = IdempotencyBinding::Supported {
        key: "idem-effect-integrity-profile-change".into(),
        valid_until_ms: 50_000,
    };
    changed.assurance_profile.compensation = CompensationCapability::CompensatingAction;

    assert!(
        runtime
            .register_intent(
                "tenant-a",
                &changed,
                &qualification(),
                &retry_policy(),
                1_000
            )
            .is_err()
    );
}

#[test]
fn s03_integrity_adapter_maximum_request_age_blocks_stale_dispatch() {
    let path = temp_db("request-age");
    let provider = provider();
    let mut runtime = EffectRuntime::open(&path, &provider).expect("open effect runtime");
    let record = intent();
    runtime
        .register_intent(
            "tenant-a",
            &record,
            &qualification(),
            &retry_policy(),
            1_000,
        )
        .expect("register effect");
    runtime
        .prepare(
            "tenant-a",
            &record.effect_intent_id,
            "prepare-evidence",
            1_001,
        )
        .expect("prepare");
    runtime
        .authorize(
            "tenant-a",
            &record.effect_intent_id,
            "snapshot-stale-age",
            "snapshot-digest-stale-age",
            1_002,
        )
        .expect("authorize");

    let stale_time = 61_001;
    let lease = runtime
        .acquire_dispatch_lease("tenant-a", "worker-a", stale_time, 1_000)
        .expect("lease is not request-age authority");
    runtime
        .commit_ready("tenant-a", &record.effect_intent_id, &lease, stale_time)
        .expect("commit-ready still requires dispatch-time adapter check");

    assert!(
        runtime
            .begin_dispatch("tenant-a", &record.effect_intent_id, &lease, stale_time + 1,)
            .is_err()
    );
}
