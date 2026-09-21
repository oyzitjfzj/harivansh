use noerith_storage::{
    LocalStore, ParentInfluence, PublishFailPoint, SourceDraft, StorageError,
    model::{AllowedUseState, CopyPurgeState, InfluenceRole, PhysicalState},
};
use rusqlite::Connection;
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);
const DB_KEY: &str = "synthetic-q03-database-passphrase-not-a-user-secret";
const WRONG_DB_KEY: &str = "synthetic-q03-wrong-database-passphrase";
const BLOB_KEY: [u8; 32] = [0x42; 32];
const SNAPSHOT_KEY: [u8; 32] = [0x71; 32];

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("noerith-q03-{label}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn draft() -> SourceDraft {
    SourceDraft::synthetic()
}

fn marker(label: &str) -> String {
    format!("NOERITH_Q03_UNIQUE_MARKER_{label}_A9F4EEDC_0123456789ABCDEF")
}

fn contains_bytes(path: &Path, needle: &[u8]) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read artifact");
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn open_sqlcipher(path: &Path, passphrase: &str) -> Connection {
    let connection = Connection::open(path).expect("open SQLCipher database");
    connection
        .pragma_update(None, "key", passphrase)
        .expect("set SQLCipher key");
    let _: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .expect("decrypt SQLCipher schema");
    connection
}

fn backup_protected_and_blob(
    store: &LocalStore,
    root: &Path,
    source: &noerith_storage::model::SourceIdentity,
    label: &str,
) -> (PathBuf, PathBuf, String) {
    let record = store.source_record(source).expect("source record");
    let db_backup = root.join(format!("{label}-protected.backup"));
    let blob_backup = root.join(format!("{label}-blob.backup"));
    store
        .checkpoint_protected_database(&db_backup)
        .expect("checkpoint protected database");
    fs::copy(
        root.join("blobs")
            .join(format!("{}.blob", record.original_blob_ref)),
        &blob_backup,
    )
    .expect("backup encrypted blob");
    (db_backup, blob_backup, record.original_blob_ref)
}

#[test]
fn q03_01_02_03_cipher_plaintext_and_fts_posture() {
    let dir = TestDir::new("cipher-posture");
    let text = marker("CIPHER_FTS");
    let mut store = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("open encrypted store");
    let runtime = store.runtime_info().clone();
    assert!(!runtime.cipher_version.trim().is_empty());
    assert_eq!(runtime.journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(runtime.secure_delete, 1);
    assert_eq!(runtime.temp_store, 2);
    store
        .publish(
            "tenant-a",
            "source-cipher",
            &draft(),
            &text,
            text.as_bytes(),
            &[],
        )
        .expect("publish encrypted source");
    assert_eq!(store.search_count("tenant-a", &text).expect("search"), 1);

    for name in ["protected.db", "protected.db-wal", "protected.db-shm"] {
        let path = dir.0.join(name);
        if path.exists() {
            assert!(
                !contains_bytes(&path, text.as_bytes()),
                "plaintext marker leaked in {name}"
            );
        }
    }
    let inventory = store.artifact_inventory();
    assert!(inventory.contains_key("protected.db"));
    assert!(inventory.contains_key("lifecycle.db"));
    println!(
        "Q03-RUNTIME sqlite={} cipher={} provider={:?} status={:?} journal={} secure_delete={} temp_store={} schema={}",
        runtime.sqlite_version,
        runtime.cipher_version,
        runtime.cipher_provider,
        runtime.cipher_status,
        runtime.journal_mode,
        runtime.secure_delete,
        runtime.temp_store,
        runtime.schema_version
    );
    println!("Q03-ARTIFACTS {inventory:?}");

    store
        .delete_current("tenant-a", "source-cipher")
        .expect("delete");
    assert_eq!(
        store
            .search_count("tenant-a", &text)
            .expect("search after delete"),
        0
    );
    drop(store);

    let connection = open_sqlcipher(&dir.0.join("protected.db"), DB_KEY);
    let fts_secure_delete: i64 = connection
        .query_row(
            "SELECT v FROM source_fts_config WHERE k='secure-delete'",
            [],
            |row| row.get(0),
        )
        .expect("FTS5 secure-delete setting");
    assert_eq!(fts_secure_delete, 1);
    drop(connection);

    assert!(
        LocalStore::open(&dir.0, WRONG_DB_KEY, BLOB_KEY).is_err(),
        "wrong SQLCipher key must fail closed"
    );
    for name in ["protected.db", "protected.db-wal", "protected.db-shm"] {
        let path = dir.0.join(name);
        if path.exists() {
            assert!(!contains_bytes(&path, text.as_bytes()));
        }
    }
}

#[test]
fn q03_04_08_09_14_publication_crashes_are_hidden_and_recovery_converges() {
    for (label, failpoint) in [
        ("after-blob-stage", PublishFailPoint::AfterBlobStage),
        ("after-registration", PublishFailPoint::AfterRegistration),
        ("after-final-rename", PublishFailPoint::AfterFinalRename),
    ] {
        let dir = TestDir::new(label);
        let mut store = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("open");
        let source_id = format!("source-{label}");
        assert!(matches!(
            store.publish_with_failpoint(
                "tenant-a",
                &source_id,
                &draft(),
                label,
                b"synthetic private payload",
                &[],
                failpoint,
            ),
            Err(StorageError::SimulatedCrash(_))
        ));
        assert!(
            store.current_identity("tenant-a", &source_id).is_err(),
            "a partial publication must never become current"
        );
        let first = store.recover().expect("first recovery");
        let second = store.recover().expect("second recovery");
        let third = store.recover().expect("third recovery");
        assert!(store.current_identity("tenant-a", &source_id).is_err());
        assert_eq!(second.orphan_staging_removed, 0);
        assert_eq!(third.orphan_staging_removed, 0);
        assert_eq!(second.quarantined_registered_blobs, 0);
        assert_eq!(third.quarantined_registered_blobs, 0);
        if failpoint == PublishFailPoint::AfterBlobStage {
            assert_eq!(first.orphan_staging_removed, 1);
        } else {
            assert_eq!(first.quarantined_registered_blobs, 1);
        }
    }
}

#[test]
fn q03_05_two_prepared_reads_fail_after_delete() {
    let dir = TestDir::new("prepared-delete");
    let mut store = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("open");
    store
        .publish(
            "tenant-a",
            "source-prepared",
            &draft(),
            "prepared",
            b"private",
            &[],
        )
        .expect("publish");
    let read_a = store
        .prepare_read("tenant-a", "source-prepared")
        .expect("prepare read A");
    let read_b = store
        .prepare_read("tenant-a", "source-prepared")
        .expect("prepare read B");
    store
        .delete_current("tenant-a", "source-prepared")
        .expect("delete");
    assert!(store.finish_read(&read_a).is_err());
    assert!(store.finish_read(&read_b).is_err());
}

#[test]
fn q03_06_old_protected_backup_and_blob_cannot_resurrect_deleted_source() {
    let dir = TestDir::new("raw-restore-delete");
    let mut store = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("open");
    let source = store
        .publish(
            "tenant-a",
            "source-restore-delete",
            &draft(),
            "restore",
            b"must stay deleted",
            &[],
        )
        .expect("publish");
    let (db_backup, blob_backup, blob_id) =
        backup_protected_and_blob(&store, &dir.0, &source, "before-delete");
    store
        .delete_current("tenant-a", "source-restore-delete")
        .expect("delete");
    drop(store);

    LocalStore::replace_protected_database_from_backup(&dir.0, &db_backup)
        .expect("restore old protected database");
    fs::copy(
        &blob_backup,
        dir.0.join("blobs").join(format!("{blob_id}.blob")),
    )
    .expect("restore old encrypted blob");

    let mut restored = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("reopen");
    assert!(
        restored
            .read_current("tenant-a", "source-restore-delete")
            .is_err(),
        "independent lifecycle frontier must block restored deleted data"
    );
    restored
        .recover()
        .expect("reconcile restored protected database");
    assert!(
        restored
            .read_current("tenant-a", "source-restore-delete")
            .is_err()
    );
    assert!(
        !dir.0.join("blobs").join(format!("{blob_id}.blob")).exists(),
        "recovery must purge the resurrected physical copy"
    );
}

#[test]
fn q03_07_missing_lifecycle_frontier_fails_closed() {
    let source_dir = TestDir::new("missing-frontier-source");
    let mut store = LocalStore::open(&source_dir.0, DB_KEY, BLOB_KEY).expect("open");
    let source = store
        .publish(
            "tenant-a",
            "source-missing-frontier",
            &draft(),
            "frontier",
            b"private",
            &[],
        )
        .expect("publish");
    let (db_backup, blob_backup, blob_id) =
        backup_protected_and_blob(&store, &source_dir.0, &source, "source");
    drop(store);

    let restore_dir = TestDir::new("missing-frontier-restore");
    fs::create_dir_all(restore_dir.0.join("blobs")).expect("blob dir");
    fs::copy(&db_backup, restore_dir.0.join("protected.db")).expect("copy protected DB");
    fs::copy(
        &blob_backup,
        restore_dir.0.join("blobs").join(format!("{blob_id}.blob")),
    )
    .expect("copy encrypted blob");
    let restored = LocalStore::open(&restore_dir.0, DB_KEY, BLOB_KEY).expect("open restored");
    assert!(
        restored
            .read_current("tenant-a", "source-missing-frontier")
            .is_err(),
        "protected data without the current independent frontier must not be served"
    );
}

#[test]
fn q03_10_authenticated_blob_tamper_fails_closed() {
    let dir = TestDir::new("tamper");
    let mut store = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("open");
    let source = store
        .publish(
            "tenant-a",
            "source-tamper",
            &draft(),
            "tamper",
            b"authenticated secret",
            &[],
        )
        .expect("publish");
    let record = store.source_record(&source).expect("record");
    let path = dir
        .0
        .join("blobs")
        .join(format!("{}.blob", record.original_blob_ref));
    let mut encoded = fs::read(&path).expect("read ciphertext");
    let last = encoded.last_mut().expect("ciphertext byte");
    *last ^= 0x01;
    fs::write(&path, encoded).expect("tamper ciphertext");
    assert!(matches!(
        store.read_current("tenant-a", "source-tamper"),
        Err(StorageError::IntegrityMismatch) | Err(StorageError::Crypto)
    ));
}

#[test]
fn q03_11_copy_registry_preserves_residual_truth() {
    let dir = TestDir::new("copies");
    let mut store = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("open");
    let source = store
        .publish(
            "tenant-a",
            "source-copies",
            &draft(),
            "copies",
            b"private",
            &[],
        )
        .expect("publish");
    store
        .register_copy(
            &source,
            "offline-backup",
            "BACKUP",
            "offline-provider",
            "PROVIDER_DELETE",
        )
        .expect("register backup");
    store
        .delete_current("tenant-a", "source-copies")
        .expect("delete");
    store
        .set_copy_purge_state(
            "tenant-a",
            "offline-backup",
            CopyPurgeState::Unknown,
            None,
            Some("provider offline; deletion outcome unknown"),
        )
        .expect("record residual");
    let copies = store.copy_records(&source).expect("copy records");
    assert!(
        copies
            .iter()
            .any(|copy| copy.purge_state == CopyPurgeState::Confirmed)
    );
    assert!(copies.iter().any(|copy| {
        copy.copy_id == "offline-backup"
            && copy.purge_state == CopyPurgeState::Unknown
            && copy.residual_reason.as_deref() == Some("provider offline; deletion outcome unknown")
    }));
}

#[test]
fn q03_12_schema_upgrade_preserves_active_and_blocked_state_and_newer_schema_fails() {
    let dir = TestDir::new("migration");
    let mut store = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("open");
    store
        .publish(
            "tenant-a",
            "source-active",
            &draft(),
            "active",
            b"active payload",
            &[],
        )
        .expect("publish active");
    store
        .publish(
            "tenant-a",
            "source-blocked",
            &draft(),
            "blocked",
            b"blocked payload",
            &[],
        )
        .expect("publish blocked candidate");
    store
        .delete_current("tenant-a", "source-blocked")
        .expect("delete blocked candidate");
    drop(store);

    let connection = open_sqlcipher(&dir.0.join("protected.db"), DB_KEY);
    connection
        .execute("ALTER TABLE namespaces DROP COLUMN authority_epoch", [])
        .expect("simulate v1 namespace schema");
    connection
        .pragma_update(None, "user_version", 1_i64)
        .expect("mark v1");
    drop(connection);

    let migrated = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("migrate v1 to v2");
    assert_eq!(
        migrated
            .read_current("tenant-a", "source-active")
            .expect("active source survives migration"),
        b"active payload"
    );
    assert!(
        migrated.read_current("tenant-a", "source-blocked").is_err(),
        "blocked source must stay blocked through migration"
    );
    drop(migrated);

    let connection = open_sqlcipher(&dir.0.join("protected.db"), DB_KEY);
    connection
        .pragma_update(None, "user_version", 3_i64)
        .expect("simulate unsupported newer schema");
    drop(connection);
    assert!(matches!(
        LocalStore::open(&dir.0, DB_KEY, BLOB_KEY),
        Err(StorageError::UnsupportedSchemaVersion(3))
    ));
}

#[test]
fn q03_13_old_protected_authority_cannot_become_current_again() {
    let dir = TestDir::new("authority-rollback");
    let mut store = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("open");
    let source = store
        .publish(
            "tenant-a",
            "source-authority",
            &draft(),
            "authority",
            b"authority-bound private data",
            &[],
        )
        .expect("publish");
    let (db_backup, blob_backup, blob_id) =
        backup_protected_and_blob(&store, &dir.0, &source, "old-authority");
    store
        .set_authority_epoch("tenant-a", 1)
        .expect("advance authority frontier");
    assert!(store.read_current("tenant-a", "source-authority").is_err());
    drop(store);

    LocalStore::replace_protected_database_from_backup(&dir.0, &db_backup)
        .expect("restore old protected DB");
    fs::copy(
        &blob_backup,
        dir.0.join("blobs").join(format!("{blob_id}.blob")),
    )
    .expect("restore old blob");
    let restored = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("reopen");
    assert!(
        restored
            .read_current("tenant-a", "source-authority")
            .is_err(),
        "newer authority frontier must dominate restored old protected state"
    );
}

#[test]
fn q03_payload_bounds_correction_lineage_and_dependent_delete() {
    let dir = TestDir::new("bounds-lineage");
    let mut store = LocalStore::open(&dir.0, DB_KEY, BLOB_KEY).expect("open");
    for (index, size) in [0_usize, 1, 4096, 1_048_576].into_iter().enumerate() {
        let source_id = format!("source-size-{index}");
        let payload = vec![(index as u8).wrapping_add(11); size];
        store
            .publish(
                "tenant-a",
                &source_id,
                &draft(),
                &format!("size-{index}"),
                &payload,
                &[],
            )
            .expect("publish bounded payload");
        assert_eq!(
            store
                .read_current("tenant-a", &source_id)
                .expect("round trip"),
            payload
        );
    }

    let parent = store
        .publish(
            "tenant-a",
            "source-parent",
            &draft(),
            "parent-v1",
            b"parent v1",
            &[],
        )
        .expect("publish parent");
    let corrected = store
        .correct(
            "tenant-a",
            "source-parent",
            "correction-1",
            &draft(),
            "parent-v2",
            b"parent v2",
        )
        .expect("correct parent");
    assert_eq!(corrected.version, parent.version + 1);
    let old = store.source_record(&parent).expect("old record");
    assert_eq!(old.use_state, AllowedUseState::Superseded);
    assert!(
        store
            .lineage_for_child(&corrected)
            .expect("correction lineage")
            .iter()
            .any(|edge| edge.parent == parent && edge.role == InfluenceRole::Correction)
    );

    let child = store
        .publish(
            "tenant-a",
            "source-child",
            &draft(),
            "child",
            b"derived child",
            &[ParentInfluence {
                parent: corrected.clone(),
                role: InfluenceRole::DataInput,
            }],
        )
        .expect("publish child");
    assert_eq!(
        store
            .source_record(&child)
            .expect("child record")
            .erasure_state,
        PhysicalState::Present
    );
    store
        .delete_current("tenant-a", "source-parent")
        .expect("delete parent closure");
    assert!(store.read_current("tenant-a", "source-parent").is_err());
    assert!(store.read_current("tenant-a", "source-child").is_err());
}

#[test]
fn q03_snapshot_restore_is_quarantined_even_with_valid_ciphertext() {
    let source_dir = TestDir::new("snapshot-source");
    let mut source_store = LocalStore::open(&source_dir.0, DB_KEY, BLOB_KEY).expect("open");
    let source = source_store
        .publish(
            "tenant-a",
            "source-snapshot",
            &draft(),
            "snapshot",
            b"snapshot private data",
            &[],
        )
        .expect("publish");
    let snapshot = source_store
        .export_snapshot(&source, "snapshot", &SNAPSHOT_KEY, "backup-one")
        .expect("export snapshot");

    let restore_dir = TestDir::new("snapshot-restore");
    let copied = restore_dir.0.join("incoming.snapshot");
    fs::copy(snapshot, &copied).expect("copy snapshot");
    let mut restored = LocalStore::open(&restore_dir.0, DB_KEY, BLOB_KEY).expect("open restore");
    let result = restored
        .import_snapshot_quarantined(&copied, &SNAPSHOT_KEY)
        .expect("import quarantined");
    assert_eq!(result.use_state, AllowedUseState::Quarantined);
    assert!(
        restored
            .read_current("tenant-a", "source-snapshot")
            .is_err(),
        "snapshot import must not silently become current authority"
    );
}
