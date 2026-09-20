use noerith_broker::{
    CaptureTimeEvidence, CapturedTransportResult, TransportCaptureBinding, TransportCaptureError,
    TransportCaptureLedger,
};
use noerith_effects::{DigestRef, SynchronizationState};
use noerith_storage::SyntheticKeyProvider;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static CASE_ID: AtomicU64 = AtomicU64::new(1);
const DB_KEY: &str = "transport-capture-ci-key";

fn temp_db(label: &str) -> PathBuf {
    let id = CASE_ID.fetch_add(1, Ordering::Relaxed);
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "noerith-transport-capture-{label}-{}-{id}-{clock}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp directory");
    dir.join("effects.db")
}

fn provider() -> SyntheticKeyProvider {
    SyntheticKeyProvider::uniform(DB_KEY, [0x71_u8; 32]).with_effect_ledger_key(DB_KEY)
}

fn binding(release_id: &str) -> TransportCaptureBinding {
    TransportCaptureBinding {
        tenant_namespace: "tenant-a".into(),
        release_id: release_id.into(),
        effect_intent_id: "effect-a".into(),
        attempt_id: "attempt:effect-a:1".into(),
        attempt_number: 1,
        decision_snapshot: DigestRef {
            ref_id: "snapshot-a".into(),
            digest: "snapshot-digest-a".into(),
        },
        fencing_token: 7,
        request_digest: "request-digest-a".into(),
        adapter_ref: "provider-adapter-a".into(),
        adapter_version: "1.2.0+build.7".into(),
    }
}

fn observed_time(unix_time_ms: u64) -> CaptureTimeEvidence {
    CaptureTimeEvidence::Observed {
        unix_time_ms,
        uncertainty_before_ms: 2,
        uncertainty_after_ms: 3,
        clock_source: "qualified-ci-clock".into(),
        synchronization_state: SynchronizationState::Synced,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write digest");
    }
    out
}

#[test]
fn transport_capture_preserves_opaque_adapter_version_and_exact_result() {
    let path = temp_db("opaque-version");
    let mut ledger = TransportCaptureLedger::open(&path, &provider()).expect("open capture ledger");
    let binding = binding("release-a");
    let result = CapturedTransportResult::Accepted {
        receipt_ref: "provider-receipt-a".into(),
    };
    assert!(ledger.capture_once(&binding, &result, 1_000).unwrap());
    assert!(!ledger.capture_once(&binding, &result, 1_000).unwrap());

    let loaded = ledger.load("tenant-a", "release-a").expect("load capture");
    assert_eq!(loaded.binding.adapter_version, "1.2.0+build.7");
    assert_eq!(loaded.result, result);
    assert_eq!(loaded.captured_at_ms, 1_000);

    let typed = ledger
        .load_with_evidence("tenant-a", "release-a")
        .expect("typed loader preserves legacy semantics");
    assert_eq!(
        typed.time_evidence,
        CaptureTimeEvidence::LegacyScalar {
            captured_at_ms: 1_000
        }
    );
    assert_eq!(typed.local_order, None);
}

#[test]
fn typed_capture_preserves_post_return_time_and_allocates_local_order() {
    let path = temp_db("typed-observed");
    let mut ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    let binding = binding("release-typed-a");
    let result = CapturedTransportResult::Accepted {
        receipt_ref: "provider-receipt-typed".into(),
    };
    let time = observed_time(6_000);

    assert!(
        ledger
            .capture_once_with_evidence(&binding, &result, &time)
            .unwrap()
    );
    assert!(
        !ledger
            .capture_once_with_evidence(&binding, &result, &time)
            .unwrap()
    );

    let loaded = ledger
        .load_with_evidence("tenant-a", "release-typed-a")
        .unwrap();
    assert_eq!(loaded.binding, binding);
    assert_eq!(loaded.result, result);
    assert_eq!(loaded.time_evidence, time);
    assert_eq!(loaded.local_order, Some(1));
    assert_eq!(
        ledger.load("tenant-a", "release-typed-a"),
        Err(TransportCaptureError::TypedEvidenceRequired)
    );
}

#[test]
fn unavailable_physical_time_does_not_erase_returned_result() {
    let path = temp_db("typed-unavailable");
    let mut ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    let unavailable = CaptureTimeEvidence::Unavailable {
        reason: "wall clock unavailable after provider return".into(),
        evidence_ref: "clock-health-check-a".into(),
    };
    let first_result = CapturedTransportResult::Accepted {
        receipt_ref: "provider-receipt-without-clock".into(),
    };
    ledger
        .capture_once_with_evidence(&binding("release-time-a"), &first_result, &unavailable)
        .unwrap();
    ledger
        .capture_once_with_evidence(
            &binding("release-time-b"),
            &CapturedTransportResult::RejectedNoEffect {
                evidence_ref: "provider-rejected-b".into(),
            },
            &observed_time(7_000),
        )
        .unwrap();

    let first = ledger
        .load_with_evidence("tenant-a", "release-time-a")
        .unwrap();
    let second = ledger
        .load_with_evidence("tenant-a", "release-time-b")
        .unwrap();
    assert_eq!(first.result, first_result);
    assert_eq!(first.time_evidence, unavailable);
    assert_eq!(first.local_order, Some(1));
    assert_eq!(second.local_order, Some(2));
}

#[test]
fn typed_capture_rejects_legacy_scalar_as_new_clock_evidence() {
    let path = temp_db("legacy-write-rejected");
    let mut ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    let result = CapturedTransportResult::NotSentProven {
        evidence_ref: "local-proof".into(),
    };
    assert_eq!(
        ledger.capture_once_with_evidence(
            &binding("release-legacy-write"),
            &result,
            &CaptureTimeEvidence::LegacyScalar {
                captured_at_ms: 8_000
            },
        ),
        Err(TransportCaptureError::LegacyTimeWriteRejected)
    );
}

#[test]
fn transport_capture_is_single_assignment_even_if_result_changes() {
    let path = temp_db("result-conflict");
    let mut ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    let binding = binding("release-b");
    ledger
        .capture_once(
            &binding,
            &CapturedTransportResult::ResponseLost {
                evidence_ref: "socket-closed-after-write".into(),
            },
            2_000,
        )
        .unwrap();

    assert_eq!(
        ledger.capture_once(
            &binding,
            &CapturedTransportResult::Accepted {
                receipt_ref: "later-conflicting-receipt".into(),
            },
            2_001,
        ),
        Err(TransportCaptureError::DuplicateCaptureConflict)
    );
}

#[test]
fn transport_capture_rejects_same_release_with_changed_protected_binding() {
    let path = temp_db("binding-conflict");
    let mut ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    let original = binding("release-c");
    let result = CapturedTransportResult::ConnectionFailedAmbiguous {
        evidence_ref: "connection-reset".into(),
    };
    ledger.capture_once(&original, &result, 3_000).unwrap();

    let mut changed = original;
    changed.fencing_token = 8;
    assert_eq!(
        ledger.capture_once(&changed, &result, 3_000),
        Err(TransportCaptureError::DuplicateCaptureConflict)
    );
}

#[test]
fn transport_capture_detects_storage_tamper_on_read() {
    let path = temp_db("tamper");
    let mut ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    ledger
        .capture_once(
            &binding("release-d"),
            &CapturedTransportResult::RejectedNoEffect {
                evidence_ref: "provider-rejected".into(),
            },
            4_000,
        )
        .unwrap();
    drop(ledger);

    let connection = Connection::open(&path).expect("open raw SQLCipher database");
    connection
        .pragma_update(None, "key", DB_KEY)
        .expect("apply SQLCipher key");
    connection
        .execute(
            "UPDATE broker_transport_capture_v01 SET result_json=?3 WHERE tenant_namespace=?1 AND release_id=?2",
            params![
                "tenant-a",
                "release-d",
                r#"{"result":"ACCEPTED","receipt_ref":"forged"}"#
            ],
        )
        .expect("inject synthetic tamper");
    drop(connection);

    let ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    assert_eq!(
        ledger.load("tenant-a", "release-d"),
        Err(TransportCaptureError::CorruptRecord)
    );
}

#[test]
fn typed_capture_detects_time_and_index_tamper() {
    let path = temp_db("typed-tamper");
    let mut ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    ledger
        .capture_once_with_evidence(
            &binding("release-typed-tamper"),
            &CapturedTransportResult::Accepted {
                receipt_ref: "receipt-a".into(),
            },
            &observed_time(9_000),
        )
        .unwrap();
    drop(ledger);

    let connection = Connection::open(&path).unwrap();
    connection.pragma_update(None, "key", DB_KEY).unwrap();
    connection
        .execute(
            "UPDATE broker_transport_capture_v01 SET time_evidence_json=?3 WHERE tenant_namespace=?1 AND release_id=?2",
            params!["tenant-a", "release-typed-tamper", r#"{"time_kind":"UNAVAILABLE","reason":"forged","evidence_ref":"forged"}"#],
        )
        .unwrap();
    drop(connection);

    let ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    assert_eq!(
        ledger.load_with_evidence("tenant-a", "release-typed-tamper"),
        Err(TransportCaptureError::CorruptRecord)
    );
}

#[test]
fn v1_schema_migrates_without_upgrading_legacy_time_claims() {
    let path = temp_db("v1-migration");
    let connection = Connection::open(&path).unwrap();
    connection.pragma_update(None, "key", DB_KEY).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE broker_transport_capture_meta(\
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),\
                schema_version INTEGER NOT NULL);\
             INSERT INTO broker_transport_capture_meta(singleton,schema_version) VALUES(1,1);\
             CREATE TABLE broker_transport_capture_v01(\
                tenant_namespace TEXT NOT NULL,\
                release_id TEXT NOT NULL,\
                effect_intent_id TEXT NOT NULL,\
                attempt_id TEXT NOT NULL,\
                attempt_number INTEGER NOT NULL CHECK(attempt_number>0),\
                binding_json TEXT NOT NULL,\
                binding_digest TEXT NOT NULL,\
                result_json TEXT NOT NULL,\
                result_digest TEXT NOT NULL,\
                captured_at INTEGER NOT NULL,\
                PRIMARY KEY(tenant_namespace,release_id));",
        )
        .unwrap();
    let legacy_binding = binding("release-v1");
    let legacy_result = CapturedTransportResult::Accepted {
        receipt_ref: "legacy-receipt".into(),
    };
    let binding_json = serde_json::to_string(&legacy_binding).unwrap();
    let result_json = serde_json::to_string(&legacy_result).unwrap();
    connection
        .execute(
            "INSERT INTO broker_transport_capture_v01(\
                tenant_namespace,release_id,effect_intent_id,attempt_id,attempt_number,\
                binding_json,binding_digest,result_json,result_digest,captured_at)\
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                legacy_binding.tenant_namespace,
                legacy_binding.release_id,
                legacy_binding.effect_intent_id,
                legacy_binding.attempt_id,
                i64::from(legacy_binding.attempt_number),
                binding_json,
                sha256_hex(binding_json.as_bytes()),
                result_json,
                sha256_hex(result_json.as_bytes()),
                10_000_i64,
            ],
        )
        .unwrap();
    drop(connection);

    let ledger = TransportCaptureLedger::open(&path, &provider()).expect("migrate v1");
    let typed = ledger
        .load_with_evidence("tenant-a", "release-v1")
        .expect("legacy row survives migration");
    assert_eq!(typed.binding.adapter_version, "1.2.0+build.7");
    assert_eq!(typed.result, legacy_result);
    assert_eq!(
        typed.time_evidence,
        CaptureTimeEvidence::LegacyScalar {
            captured_at_ms: 10_000
        }
    );
    assert_eq!(typed.local_order, None);
    assert_eq!(
        ledger
            .load("tenant-a", "release-v1")
            .unwrap()
            .captured_at_ms,
        10_000
    );

    let connection = Connection::open(&path).unwrap();
    connection.pragma_update(None, "key", DB_KEY).unwrap();
    let version: i64 = connection
        .query_row(
            "SELECT schema_version FROM broker_transport_capture_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 2);
}

#[test]
fn transport_capture_requires_nonzero_attempt_and_fence() {
    let path = temp_db("invalid-binding");
    let mut ledger = TransportCaptureLedger::open(&path, &provider()).unwrap();
    let mut invalid = binding("release-e");
    invalid.fencing_token = 0;
    assert_eq!(
        ledger.capture_once(
            &invalid,
            &CapturedTransportResult::NotSentProven {
                evidence_ref: "local-proof".into(),
            },
            5_000,
        ),
        Err(TransportCaptureError::InvalidBinding)
    );
}
