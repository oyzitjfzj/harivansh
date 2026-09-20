use noerith_effects::{
    AttemptNextAction, AttemptTransportResult, DigestRef, DispatchAttemptBinding,
    DispatchAttemptError, DispatchAttemptLedger, MonotonicDeadline, ProviderIdempotencyKey,
    StartedAt, SynchronizationState, VersionedRef,
};
use noerith_storage::SyntheticKeyProvider;
use rusqlite::{Connection, params};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static CASE_ID: AtomicU64 = AtomicU64::new(1);
const DB_KEY: &str = "synthetic-dispatch-attempt-key";

fn temp_db(label: &str) -> PathBuf {
    let id = CASE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "noerith-dispatch-attempt-{label}-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create test directory");
    root.join("effects.db")
}

fn provider() -> SyntheticKeyProvider {
    SyntheticKeyProvider::uniform(DB_KEY, [0x51; 32])
}

fn binding(attempt_id: &str) -> DispatchAttemptBinding {
    DispatchAttemptBinding {
        attempt_id: attempt_id.into(),
        effect_intent_id: "effect-1".into(),
        decision_snapshot: DigestRef {
            ref_id: "snapshot-1".into(),
            digest: "snapshot-digest-1".into(),
        },
        dispatch_claim_revision: 3,
        fencing_token: 7,
        adapter: VersionedRef {
            ref_id: "adapter-1".into(),
            version: 2,
        },
        capability: VersionedRef {
            ref_id: "capability-1".into(),
            version: 4,
        },
        environment: VersionedRef {
            ref_id: "environment-1".into(),
            version: 5,
        },
        credential_handle_ref: "credential-handle-1".into(),
        provider_idempotency_key: ProviderIdempotencyKey::Supported("idem-effect-1".into()),
        request_digest: "request-digest-1".into(),
        started_at: StartedAt {
            utc_timestamp: "2026-09-09T00:00:00Z".into(),
            uncertainty_before: "PT0S".into(),
            uncertainty_after: "PT0S".into(),
            clock_source: "clock-1".into(),
            synchronization_state: SynchronizationState::Synced,
        },
        monotonic_deadline: MonotonicDeadline {
            clock_ref: "mono-1".into(),
            deadline_tick: 10_000,
        },
    }
}

fn raw_open(path: &PathBuf) -> Connection {
    let connection = Connection::open(path).expect("open raw SQLCipher DB");
    connection
        .pragma_update(None, "key", DB_KEY)
        .expect("apply SQLCipher key");
    connection
}

#[test]
fn dispatch_attempt_requires_complete_bound_identity_before_transport() {
    let mut record = binding("attempt-invalid");
    record.credential_handle_ref.clear();
    assert_eq!(
        record.validate(),
        Err(DispatchAttemptError::InvalidField("credential_handle_ref"))
    );

    let mut record = binding("attempt-invalid-fence");
    record.fencing_token = 0;
    assert_eq!(record.validate(), Err(DispatchAttemptError::InvalidClaim));
}

#[test]
fn dispatch_attempt_same_identity_same_binding_is_idempotent_but_changed_binding_conflicts() {
    let path = temp_db("identity");
    let provider = provider();
    let mut ledger = DispatchAttemptLedger::open(&path, &provider).expect("open ledger");
    let original = binding("attempt-1");
    assert!(ledger.start_attempt("tenant-a", &original, 1_000).unwrap());
    assert!(!ledger.start_attempt("tenant-a", &original, 1_000).unwrap());

    let mut changed = original;
    changed.request_digest = "changed-request-digest".into();
    assert_eq!(
        ledger.start_attempt("tenant-a", &changed, 1_000),
        Err(DispatchAttemptError::DuplicateAttemptConflict)
    );
}

#[test]
fn dispatch_attempt_transport_result_is_single_assignment_and_evidence_is_preserved() {
    let path = temp_db("finalize");
    let provider = provider();
    let mut ledger = DispatchAttemptLedger::open(&path, &provider).expect("open ledger");
    ledger
        .start_attempt("tenant-a", &binding("attempt-finalize"), 1_000)
        .unwrap();
    let refs = vec![
        "provider-receipt-1".to_owned(),
        "provider-status-1".to_owned(),
    ];
    assert!(
        ledger
            .finalize_once(
                "tenant-a",
                "attempt-finalize",
                AttemptTransportResult::ResponseReceived,
                &refs,
                AttemptNextAction::None,
                "transport-evidence-1",
                1_100,
            )
            .unwrap()
    );
    assert!(
        !ledger
            .finalize_once(
                "tenant-a",
                "attempt-finalize",
                AttemptTransportResult::ResponseReceived,
                &refs,
                AttemptNextAction::None,
                "transport-evidence-1",
                1_100,
            )
            .unwrap()
    );
    assert_eq!(
        ledger.finalize_once(
            "tenant-a",
            "attempt-finalize",
            AttemptTransportResult::ResponseLost,
            &[],
            AttemptNextAction::Reconcile,
            "later-conflicting-story",
            1_101,
        ),
        Err(DispatchAttemptError::AlreadyFinalized)
    );

    let final_record = ledger
        .finalized_attempt("tenant-a", "attempt-finalize")
        .expect("finalized attempt");
    assert_eq!(
        final_record.transport_result,
        AttemptTransportResult::ResponseReceived
    );
    assert_eq!(final_record.next_action, AttemptNextAction::None);
    assert_eq!(
        final_record.provider_status_receipt_refs,
        vec![
            "provider-receipt-1".to_owned(),
            "provider-status-1".to_owned()
        ]
    );
}

#[test]
fn ambiguous_transport_never_permits_new_intent_retry_action() {
    let path = temp_db("ambiguous");
    let provider = provider();
    let mut ledger = DispatchAttemptLedger::open(&path, &provider).expect("open ledger");
    ledger
        .start_attempt("tenant-a", &binding("attempt-ambiguous"), 2_000)
        .unwrap();

    assert_eq!(
        ledger.finalize_once(
            "tenant-a",
            "attempt-ambiguous",
            AttemptTransportResult::ResponseLost,
            &[],
            AttemptNextAction::None,
            "response-lost-evidence",
            2_100,
        ),
        Err(DispatchAttemptError::InvalidField("next_action"))
    );
    ledger
        .finalize_once(
            "tenant-a",
            "attempt-ambiguous",
            AttemptTransportResult::ResponseLost,
            &[],
            AttemptNextAction::Reconcile,
            "response-lost-evidence",
            2_100,
        )
        .expect("ambiguity reconciles");
}

#[test]
fn unsupported_provider_idempotency_is_explicit_not_missing() {
    let path = temp_db("unsupported-idempotency");
    let provider = provider();
    let mut ledger = DispatchAttemptLedger::open(&path, &provider).expect("open ledger");
    let mut record = binding("attempt-opaque");
    record.provider_idempotency_key = ProviderIdempotencyKey::Unsupported;
    ledger
        .start_attempt("tenant-a", &record, 3_000)
        .expect("unsupported is an explicit valid state");
}

#[test]
fn dispatch_attempt_binding_tamper_is_detected_after_reopen() {
    let path = temp_db("tamper");
    let provider = provider();
    let mut ledger = DispatchAttemptLedger::open(&path, &provider).expect("open ledger");
    ledger
        .start_attempt("tenant-a", &binding("attempt-tamper"), 4_000)
        .unwrap();
    drop(ledger);

    let connection = raw_open(&path);
    let mut value: serde_json::Value = serde_json::from_str(
        &connection
            .query_row(
                "SELECT binding_json FROM dispatch_attempt_v01 WHERE tenant_namespace=?1 AND attempt_id=?2",
                params!["tenant-a", "attempt-tamper"],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    value["request_digest"] = serde_json::Value::String("forged-request".into());
    connection
        .execute(
            "UPDATE dispatch_attempt_v01 SET binding_json=?3 WHERE tenant_namespace=?1 AND attempt_id=?2",
            params!["tenant-a", "attempt-tamper", serde_json::to_string(&value).unwrap()],
        )
        .unwrap();
    drop(connection);

    let ledger = DispatchAttemptLedger::open(&path, &provider).expect("reopen ledger");
    assert_eq!(
        ledger.verify_binding("tenant-a", "attempt-tamper"),
        Err(DispatchAttemptError::CorruptRecord)
    );
}
