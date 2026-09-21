use noerith_storage::{
    KeyOpenError, KeyProviderError, LocalStore, SyntheticKeyProvider, work::DurableWorkStore,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn temp_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "noerith-key-provider-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp root");
    path
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_dir_all(path);
}

#[test]
fn s02_key_provider_debug_never_prints_synthetic_secrets() {
    let provider = SyntheticKeyProvider::uniform("DB_SUPER_SECRET", [0xA5; 32]);
    let rendered = format!("{provider:?}");
    assert!(!rendered.contains("DB_SUPER_SECRET"));
    assert!(!rendered.contains("165"));
    assert!(rendered.contains("REDACTED"));
}

#[test]
fn s02_local_store_opens_through_key_provider_boundary() {
    let root = temp_root("local-open");
    let provider = SyntheticKeyProvider::uniform("qualified-ci-key", [7_u8; 32]);
    let store =
        LocalStore::open_with_key_provider(&root, &provider).expect("open through provider");
    assert!(!store.runtime_info().cipher_version.trim().is_empty());
    drop(store);
    cleanup(&root);
}

#[test]
fn s02_wrong_provider_secret_fails_closed() {
    let root = temp_root("wrong-secret");
    let correct = SyntheticKeyProvider::uniform("correct-key", [9_u8; 32]);
    let store = LocalStore::open_with_key_provider(&root, &correct).expect("initial open");
    drop(store);

    let wrong = SyntheticKeyProvider::uniform("wrong-key", [9_u8; 32]);
    assert!(LocalStore::open_with_key_provider(&root, &wrong).is_err());
    cleanup(&root);
}

#[test]
fn s02_durable_work_store_opens_through_key_provider_boundary() {
    let root = temp_root("work-open");
    let provider = SyntheticKeyProvider::uniform("work-key", [11_u8; 32]);
    let database = root.join("work.db");
    let _store = DurableWorkStore::open_with_key_provider(&database, &provider)
        .expect("durable work store through provider");
    cleanup(&root);
}

#[test]
fn s02_distinct_lifecycle_and_protected_keys_fail_closed_until_split_constructor_exists() {
    let root = temp_root("split-key");
    let provider =
        SyntheticKeyProvider::split("lifecycle-key", "protected-key", "work-key", [13_u8; 32]);
    let error = match LocalStore::open_with_key_provider(&root, &provider) {
        Ok(_) => panic!("distinct database keys must not be silently collapsed"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        KeyOpenError::Provider(KeyProviderError::InvalidSecret)
    ));
    cleanup(&root);
}
