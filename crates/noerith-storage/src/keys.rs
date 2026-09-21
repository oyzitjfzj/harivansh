use crate::{
    LocalStore, StorageError,
    work::{DurableWorkStore, WorkError},
};
use std::{fmt, path::Path};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKeyPurpose {
    LifecycleFrontier,
    ProtectedStore,
    DurableWork,
    EffectLedger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKeyPurpose {
    ProtectedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyProviderError {
    Unavailable,
    InvalidSecret,
}

impl fmt::Display for KeyProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "key provider unavailable"),
            Self::InvalidSecret => write!(f, "key provider returned invalid secret"),
        }
    }
}

impl std::error::Error for KeyProviderError {}

#[derive(Debug)]
pub enum KeyOpenError {
    Provider(KeyProviderError),
    Storage(StorageError),
    Work(WorkError),
}

impl fmt::Display for KeyOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "key provider error: {error}"),
            Self::Storage(error) => write!(f, "storage open error: {error}"),
            Self::Work(error) => write!(f, "durable work open error: {error}"),
        }
    }
}

impl std::error::Error for KeyOpenError {}

impl From<KeyProviderError> for KeyOpenError {
    fn from(value: KeyProviderError) -> Self {
        Self::Provider(value)
    }
}

impl From<StorageError> for KeyOpenError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

impl From<WorkError> for KeyOpenError {
    fn from(value: WorkError) -> Self {
        Self::Work(value)
    }
}

/// Boundary for storage secrets. Platform implementations may obtain these
/// from OS-backed keystores or other qualified secret services. Callers receive
/// short-lived zeroizing material; secret values are never identities.
pub trait KeyProvider {
    fn database_passphrase(
        &self,
        purpose: DatabaseKeyPurpose,
    ) -> std::result::Result<Zeroizing<String>, KeyProviderError>;

    fn blob_key(
        &self,
        purpose: BlobKeyPurpose,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, KeyProviderError>;
}

impl LocalStore {
    pub fn open_with_key_provider(
        root: impl AsRef<Path>,
        provider: &impl KeyProvider,
    ) -> std::result::Result<Self, KeyOpenError> {
        let lifecycle_key = provider.database_passphrase(DatabaseKeyPurpose::LifecycleFrontier)?;
        let protected_key = provider.database_passphrase(DatabaseKeyPurpose::ProtectedStore)?;
        let blob_key = provider.blob_key(BlobKeyPurpose::ProtectedBlob)?;

        // The current Q03 LocalStore candidate still uses one SQLCipher passphrase
        // for both protected databases. Fail closed rather than silently discard
        // a provider's distinct lifecycle key until that storage-internal
        // constructor is split and requalified.
        if lifecycle_key.as_str() != protected_key.as_str() {
            return Err(KeyProviderError::InvalidSecret.into());
        }

        Ok(Self::open(root, protected_key.as_str(), *blob_key)?)
    }
}

impl DurableWorkStore {
    pub fn open_with_key_provider(
        path: impl AsRef<Path>,
        provider: &impl KeyProvider,
    ) -> std::result::Result<Self, KeyOpenError> {
        let key = provider.database_passphrase(DatabaseKeyPurpose::DurableWork)?;
        Ok(Self::open(path, key.as_str())?)
    }
}

/// Synthetic-only provider for CI and bounded qualification. It deliberately
/// avoids pretending to be a production OS keystore.
#[derive(Clone)]
pub struct SyntheticKeyProvider {
    lifecycle_database: String,
    protected_database: String,
    durable_work_database: String,
    effect_ledger_database: String,
    blob: [u8; 32],
}

impl SyntheticKeyProvider {
    pub fn uniform(database_passphrase: impl Into<String>, blob_key: [u8; 32]) -> Self {
        let database_passphrase = database_passphrase.into();
        Self {
            lifecycle_database: database_passphrase.clone(),
            protected_database: database_passphrase.clone(),
            durable_work_database: database_passphrase.clone(),
            effect_ledger_database: database_passphrase,
            blob: blob_key,
        }
    }

    pub fn split(
        lifecycle_database: impl Into<String>,
        protected_database: impl Into<String>,
        durable_work_database: impl Into<String>,
        blob_key: [u8; 32],
    ) -> Self {
        let durable_work_database = durable_work_database.into();
        Self {
            lifecycle_database: lifecycle_database.into(),
            protected_database: protected_database.into(),
            effect_ledger_database: durable_work_database.clone(),
            durable_work_database,
            blob: blob_key,
        }
    }

    pub fn with_effect_ledger_key(mut self, effect_ledger_database: impl Into<String>) -> Self {
        self.effect_ledger_database = effect_ledger_database.into();
        self
    }
}

impl fmt::Debug for SyntheticKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyntheticKeyProvider")
            .field("lifecycle_database", &"[REDACTED]")
            .field("protected_database", &"[REDACTED]")
            .field("durable_work_database", &"[REDACTED]")
            .field("effect_ledger_database", &"[REDACTED]")
            .field("blob", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SyntheticKeyProvider {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.lifecycle_database);
        zeroize::Zeroize::zeroize(&mut self.protected_database);
        zeroize::Zeroize::zeroize(&mut self.durable_work_database);
        zeroize::Zeroize::zeroize(&mut self.effect_ledger_database);
        zeroize::Zeroize::zeroize(&mut self.blob);
    }
}

impl KeyProvider for SyntheticKeyProvider {
    fn database_passphrase(
        &self,
        purpose: DatabaseKeyPurpose,
    ) -> std::result::Result<Zeroizing<String>, KeyProviderError> {
        let value = match purpose {
            DatabaseKeyPurpose::LifecycleFrontier => &self.lifecycle_database,
            DatabaseKeyPurpose::ProtectedStore => &self.protected_database,
            DatabaseKeyPurpose::DurableWork => &self.durable_work_database,
            DatabaseKeyPurpose::EffectLedger => &self.effect_ledger_database,
        };
        if value.is_empty() {
            return Err(KeyProviderError::InvalidSecret);
        }
        Ok(Zeroizing::new(value.clone()))
    }

    fn blob_key(
        &self,
        _purpose: BlobKeyPurpose,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, KeyProviderError> {
        Ok(Zeroizing::new(self.blob))
    }
}
