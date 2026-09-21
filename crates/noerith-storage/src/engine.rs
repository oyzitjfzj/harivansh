use crate::frontier::FrontierStore;
use crate::model::{
    AllowedUseState, CopyPurgeState, CopyRecord, DeleteJobState, InfluenceEdge, InfluenceRole,
    PhysicalState, PreparedRead, RecoveryReport, RestoreResult, RuntimeInfo, SnapshotPayload,
    SourceIdentity, SourceRecord,
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const CURRENT_SCHEMA_VERSION: i64 = 2;
const BLOB_MAGIC: &[u8; 4] = b"NRTB";
const SNAPSHOT_MAGIC: &[u8; 4] = b"NRTS";
const FORMAT_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const MAX_CLOSURE_NODES: usize = 4096;

#[derive(Debug)]
pub enum StorageError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    Json(serde_json::Error),
    Crypto,
    CipherInactive,
    UnsupportedSchemaVersion(i64),
    InvalidOpaqueId,
    InvalidMetadata(&'static str),
    NotFound,
    TenantMismatch,
    Blocked,
    Quarantined,
    StaleLifecycle,
    IntegrityMismatch,
    BlobUnavailable,
    LineageInvalid,
    ClosureTooLarge,
    SimulatedCrash(&'static str),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "sqlite error: {error}"),
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::Crypto => write!(f, "authenticated encryption or decryption failed"),
            Self::CipherInactive => write!(f, "SQLCipher connection is not encrypted"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported storage schema version {version}")
            }
            Self::InvalidOpaqueId => write!(f, "invalid opaque identifier"),
            Self::InvalidMetadata(field) => write!(f, "invalid source metadata field: {field}"),
            Self::NotFound => write!(f, "record not found"),
            Self::TenantMismatch => write!(f, "tenant namespace mismatch"),
            Self::Blocked => write!(f, "source use is blocked"),
            Self::Quarantined => write!(f, "source is quarantined"),
            Self::StaleLifecycle => write!(f, "prepared source use is stale"),
            Self::IntegrityMismatch => write!(f, "stored ciphertext integrity mismatch"),
            Self::BlobUnavailable => write!(f, "encrypted blob is unavailable"),
            Self::LineageInvalid => write!(f, "lineage is invalid for current source state"),
            Self::ClosureTooLarge => write!(f, "bounded lineage closure exceeded"),
            Self::SimulatedCrash(point) => write!(f, "simulated crash at {point}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<std::io::Error> for StorageError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDraft {
    pub source_kind: String,
    pub media_type: String,
    pub digest_profile: String,
    pub capture_actor: String,
    pub subject_refs: Vec<String>,
    pub owner_refs: Vec<String>,
    pub account_refs: Vec<String>,
    pub source_locator_ref: String,
    pub captured_at: String,
    pub source_time: Option<String>,
    pub exact_span_scheme: String,
    pub transcript_or_ocr_derivation_refs: Vec<String>,
    pub issuer_integrity_evidence: Vec<String>,
    pub truth_evidence_refs: Vec<String>,
    pub data_use_label_ref: String,
    pub trust_taint_label_ref: String,
    pub key_scope_ref: String,
    pub authority_ref: Option<String>,
    pub authority_epoch: u64,
}

impl SourceDraft {
    pub fn synthetic() -> Self {
        Self {
            source_kind: "synthetic".into(),
            media_type: "application/octet-stream".into(),
            digest_profile: "sha256-ciphertext-v1".into(),
            capture_actor: "synthetic-test".into(),
            subject_refs: Vec::new(),
            owner_refs: vec!["synthetic-owner".into()],
            account_refs: Vec::new(),
            source_locator_ref: "synthetic://local".into(),
            captured_at: "2026-09-07T00:00:00Z".into(),
            source_time: None,
            exact_span_scheme: "byte-offset-v1".into(),
            transcript_or_ocr_derivation_refs: Vec::new(),
            issuer_integrity_evidence: Vec::new(),
            truth_evidence_refs: Vec::new(),
            data_use_label_ref: "label:synthetic".into(),
            trust_taint_label_ref: "taint:synthetic".into(),
            key_scope_ref: "keyscope:synthetic".into(),
            authority_ref: None,
            authority_epoch: 0,
        }
    }

    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("source_kind", self.source_kind.as_str()),
            ("media_type", self.media_type.as_str()),
            ("digest_profile", self.digest_profile.as_str()),
            ("capture_actor", self.capture_actor.as_str()),
            ("source_locator_ref", self.source_locator_ref.as_str()),
            ("captured_at", self.captured_at.as_str()),
            ("exact_span_scheme", self.exact_span_scheme.as_str()),
            ("data_use_label_ref", self.data_use_label_ref.as_str()),
            ("trust_taint_label_ref", self.trust_taint_label_ref.as_str()),
            ("key_scope_ref", self.key_scope_ref.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(StorageError::InvalidMetadata(name));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentInfluence {
    pub parent: SourceIdentity,
    pub role: InfluenceRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishFailPoint {
    None,
    AfterBlobStage,
    AfterRegistration,
    AfterFinalRename,
}

pub struct LocalStore {
    root: PathBuf,
    connection: Connection,
    frontier: FrontierStore,
    blob_key: [u8; 32],
    runtime: RuntimeInfo,
}

impl Drop for LocalStore {
    fn drop(&mut self) {
        self.blob_key.fill(0);
    }
}

impl LocalStore {
    pub fn open(
        root: impl AsRef<Path>,
        database_passphrase: &str,
        blob_key: [u8; 32],
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("staging"))?;
        fs::create_dir_all(root.join("snapshots"))?;

        // The lifecycle frontier is deliberately independent from protected.db.
        // Restoring an older protected database therefore cannot restore old permission to use data.
        let frontier = FrontierStore::open(&root.join("lifecycle.db"), database_passphrase)?;
        let (mut connection, mut runtime) =
            open_cipher(&root.join("protected.db"), database_passphrase)?;
        initialize_schema(&mut connection)?;
        runtime.schema_version =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;

        Ok(Self {
            root,
            connection,
            frontier,
            blob_key,
            runtime,
        })
    }

    pub fn runtime_info(&self) -> &RuntimeInfo {
        &self.runtime
    }

    pub fn current_namespace_epoch(&self, tenant_namespace: &str) -> Result<u64> {
        validate_opaque_id(tenant_namespace)?;
        self.frontier.namespace_epoch(tenant_namespace)
    }

    pub fn set_authority_epoch(
        &mut self,
        tenant_namespace: &str,
        authority_epoch: u64,
    ) -> Result<()> {
        validate_opaque_id(tenant_namespace)?;
        // Advance the independent authority frontier first. If the protected mirror update fails,
        // the system becomes more restrictive rather than reviving stale authority.
        self.frontier
            .set_authority_epoch(tenant_namespace, authority_epoch)?;
        ensure_namespace(&self.connection, tenant_namespace)?;
        let changed = self.connection.execute(
            "UPDATE namespaces SET authority_epoch=?2 WHERE tenant_namespace=?1 AND authority_epoch<=?2",
            params![tenant_namespace, authority_epoch as i64],
        )?;
        if changed == 0 {
            return Err(StorageError::StaleLifecycle);
        }
        Ok(())
    }

    pub fn publish(
        &mut self,
        tenant_namespace: &str,
        source_id: &str,
        draft: &SourceDraft,
        search_text: &str,
        plaintext: &[u8],
        parents: &[ParentInfluence],
    ) -> Result<SourceIdentity> {
        self.publish_inner(
            tenant_namespace,
            source_id,
            draft,
            search_text,
            plaintext,
            parents,
            None,
            None,
            PublishFailPoint::None,
        )
    }

    pub fn correct(
        &mut self,
        tenant_namespace: &str,
        source_id: &str,
        correction_event_ref: &str,
        draft: &SourceDraft,
        search_text: &str,
        plaintext: &[u8],
    ) -> Result<SourceIdentity> {
        validate_opaque_id(correction_event_ref)?;
        let predecessor = self.current_identity(tenant_namespace, source_id)?;
        let parent = ParentInfluence {
            parent: predecessor.clone(),
            role: InfluenceRole::Correction,
        };
        self.publish_inner(
            tenant_namespace,
            source_id,
            draft,
            search_text,
            plaintext,
            &[parent],
            Some(predecessor),
            Some(correction_event_ref),
            PublishFailPoint::None,
        )
    }

    // Protected publication keeps authority, lifecycle, lineage, and payload inputs explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_with_failpoint(
        &mut self,
        tenant_namespace: &str,
        source_id: &str,
        draft: &SourceDraft,
        search_text: &str,
        plaintext: &[u8],
        parents: &[ParentInfluence],
        failpoint: PublishFailPoint,
    ) -> Result<SourceIdentity> {
        self.publish_inner(
            tenant_namespace,
            source_id,
            draft,
            search_text,
            plaintext,
            parents,
            None,
            None,
            failpoint,
        )
    }

    pub fn current_identity(
        &self,
        tenant_namespace: &str,
        source_id: &str,
    ) -> Result<SourceIdentity> {
        validate_opaque_id(tenant_namespace)?;
        validate_opaque_id(source_id)?;
        let version: Option<i64> = self
            .connection
            .query_row(
                "SELECT current_version FROM source_heads WHERE tenant_namespace=?1 AND source_id=?2",
                params![tenant_namespace, source_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let version = version.ok_or(StorageError::NotFound)?;
        Ok(SourceIdentity {
            tenant_namespace: tenant_namespace.to_owned(),
            source_id: source_id.to_owned(),
            version: version as u64,
        })
    }

    pub fn source_record(&self, source: &SourceIdentity) -> Result<SourceRecord> {
        validate_identity(source)?;
        self.connection
            .query_row(
                "SELECT source_kind,original_blob_ref,media_type,byte_length,digest_profile,content_digest, \
                        capture_actor,subject_refs_json,owner_refs_json,account_refs_json,source_locator_ref,captured_at,source_time, \
                        exact_span_scheme,transcript_refs_json,issuer_integrity_json,truth_evidence_json,data_use_label_ref, \
                        trust_taint_label_ref,lifecycle_head_ref,lifecycle_epoch,key_scope_ref,predecessor_source_id,predecessor_version, \
                        correction_event_ref,use_state,erasure_state,authority_ref,authority_epoch \
                 FROM source_versions WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    source.tenant_namespace,
                    source.source_id,
                    source.version as i64
                ],
                |row| {
                    let predecessor_id: Option<String> = row.get(22)?;
                    let predecessor_version: Option<i64> = row.get(23)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, String>(13)?,
                        row.get::<_, String>(14)?,
                        row.get::<_, String>(15)?,
                        row.get::<_, String>(16)?,
                        row.get::<_, String>(17)?,
                        row.get::<_, String>(18)?,
                        row.get::<_, String>(19)?,
                        row.get::<_, i64>(20)?,
                        row.get::<_, String>(21)?,
                        predecessor_id,
                        predecessor_version,
                        row.get::<_, Option<String>>(24)?,
                        row.get::<_, String>(25)?,
                        row.get::<_, String>(26)?,
                        row.get::<_, Option<String>>(27)?,
                        row.get::<_, i64>(28)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::NotFound)
            .and_then(|row| {
                let predecessor_ref = match (row.22, row.23) {
                    (Some(source_id), Some(version)) => Some(SourceIdentity {
                        tenant_namespace: source.tenant_namespace.clone(),
                        source_id,
                        version: version as u64,
                    }),
                    (None, None) => None,
                    _ => return Err(StorageError::IntegrityMismatch),
                };
                Ok(SourceRecord {
                    identity: source.clone(),
                    source_kind: row.0,
                    original_blob_ref: row.1,
                    media_type: row.2,
                    byte_length: row.3 as u64,
                    digest_profile: row.4,
                    digest: row.5,
                    capture_actor: row.6,
                    subject_refs: serde_json::from_str(&row.7)?,
                    owner_refs: serde_json::from_str(&row.8)?,
                    account_refs: serde_json::from_str(&row.9)?,
                    source_locator_ref: row.10,
                    captured_at: row.11,
                    source_time: row.12,
                    exact_span_scheme: row.13,
                    transcript_or_ocr_derivation_refs: serde_json::from_str(&row.14)?,
                    issuer_integrity_evidence: serde_json::from_str(&row.15)?,
                    truth_evidence_refs: serde_json::from_str(&row.16)?,
                    data_use_label_ref: row.17,
                    trust_taint_label_ref: row.18,
                    lifecycle_head_ref: row.19,
                    lifecycle_epoch: row.20 as u64,
                    key_scope_ref: row.21,
                    predecessor_ref,
                    correction_event_ref: row.24,
                    use_state: parse_use_state(&row.25)?,
                    erasure_state: parse_physical_state(&row.26)?,
                    authority_ref: row.27,
                    authority_epoch: row.28 as u64,
                })
            })
    }

    pub fn prepare_read(&self, tenant_namespace: &str, source_id: &str) -> Result<PreparedRead> {
        let identity = self.current_identity(tenant_namespace, source_id)?;
        let record = self.source_record(&identity)?;
        if record.use_state != AllowedUseState::Active {
            return state_error(record.use_state);
        }
        self.frontier
            .require_active(&identity, record.lifecycle_epoch, record.authority_epoch)?;
        let namespace_lifecycle_epoch = self.current_namespace_epoch(tenant_namespace)?;
        Ok(PreparedRead {
            source: identity,
            source_lifecycle_epoch: record.lifecycle_epoch,
            namespace_lifecycle_epoch,
        })
    }

    pub fn finish_read(&self, prepared: &PreparedRead) -> Result<Vec<u8>> {
        validate_identity(&prepared.source)?;
        let current_namespace_epoch =
            self.current_namespace_epoch(&prepared.source.tenant_namespace)?;
        let current_identity = self.current_identity(
            &prepared.source.tenant_namespace,
            &prepared.source.source_id,
        )?;
        if current_identity != prepared.source {
            return Err(StorageError::StaleLifecycle);
        }
        let record = self.source_record(&prepared.source)?;
        if record.use_state != AllowedUseState::Active {
            return state_error(record.use_state);
        }
        if record.lifecycle_epoch != prepared.source_lifecycle_epoch {
            return Err(StorageError::StaleLifecycle);
        }
        self.frontier.require_active(
            &prepared.source,
            record.lifecycle_epoch,
            record.authority_epoch,
        )?;
        if current_namespace_epoch != prepared.namespace_lifecycle_epoch {
            // Namespace changes conservatively stale the old permit. The exact source dependency
            // is rechecked above; unaffected current source versions remain eligible.
        }

        let (blob_state, expected_digest): (String, String) = self.connection.query_row(
            "SELECT state,ciphertext_digest FROM blob_registry \
             WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3 AND blob_id=?4",
            params![
                prepared.source.tenant_namespace,
                prepared.source.source_id,
                prepared.source.version as i64,
                record.original_blob_ref
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if blob_state != "READY" {
            return Err(StorageError::BlobUnavailable);
        }
        let path = self.final_blob_path(&record.original_blob_ref)?;
        let encoded = fs::read(path)?;
        if sha256_hex(&encoded) != expected_digest {
            return Err(StorageError::IntegrityMismatch);
        }
        decrypt_blob(
            &self.blob_key,
            &prepared.source,
            record.lifecycle_epoch,
            &encoded,
        )
    }

    pub fn read_current(&self, tenant_namespace: &str, source_id: &str) -> Result<Vec<u8>> {
        let prepared = self.prepare_read(tenant_namespace, source_id)?;
        self.finish_read(&prepared)
    }

    pub fn search_count(&self, tenant_namespace: &str, query: &str) -> Result<u64> {
        validate_opaque_id(tenant_namespace)?;
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM source_fts \
             WHERE source_fts MATCH ?1 AND tenant_namespace=?2",
            params![query, tenant_namespace],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    pub fn lineage_for_child(&self, child: &SourceIdentity) -> Result<Vec<InfluenceEdge>> {
        validate_identity(child)?;
        let mut statement = self.connection.prepare(
            "SELECT parent_source_id,parent_version,role FROM lineage_edges \
             WHERE tenant_namespace=?1 AND child_source_id=?2 AND child_version=?3 \
             ORDER BY parent_source_id,parent_version,role",
        )?;
        let rows = statement.query_map(
            params![
                child.tenant_namespace,
                child.source_id,
                child.version as i64
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        let mut result = Vec::new();
        for row in rows {
            let (source_id, version, role) = row?;
            result.push(InfluenceEdge {
                child: child.clone(),
                parent: SourceIdentity {
                    tenant_namespace: child.tenant_namespace.clone(),
                    source_id,
                    version: version as u64,
                },
                role: parse_influence_role(&role)?,
            });
        }
        Ok(result)
    }

    pub fn delete_current(&mut self, tenant_namespace: &str, source_id: &str) -> Result<String> {
        validate_opaque_id(tenant_namespace)?;
        validate_opaque_id(source_id)?;
        let root = self.current_identity(tenant_namespace, source_id)?;
        self.frontier.require_current_identity(&root)?;

        let closure = {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let closure = collect_dependent_closure(&tx, &root)?;
            tx.commit()?;
            closure
        };
        for source in &closure {
            self.frontier.require_current_identity(source)?;
        }

        let current_epoch = self.frontier.namespace_epoch(tenant_namespace)?;
        let next_epoch = current_epoch + 1;
        // Use is blocked in the independent anti-rollback frontier before any physical cleanup.
        self.frontier
            .block_sources(tenant_namespace, &closure, next_epoch)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE namespaces SET lifecycle_epoch=?2 WHERE tenant_namespace=?1 AND lifecycle_epoch<=?2",
            params![tenant_namespace, next_epoch as i64],
        )?;
        let job_id = format!("delete-{}-{}-{}", source_id, root.version, next_epoch);
        tx.execute(
            "INSERT INTO deletion_jobs(tenant_namespace,job_id,root_source_id,root_version,state,started_epoch,residual_count)             VALUES(?1,?2,?3,?4,?5,?6,0)",
            params![
                tenant_namespace,
                job_id,
                source_id,
                root.version as i64,
                DeleteJobState::UseBlocked.as_db(),
                next_epoch as i64
            ],
        )?;
        for source in &closure {
            tx.execute(
                "UPDATE source_versions SET use_state=?4,erasure_state=?5,lifecycle_epoch=?6                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    source.tenant_namespace,
                    source.source_id,
                    source.version as i64,
                    AllowedUseState::Blocked.as_db(),
                    PhysicalState::PurgePending.as_db(),
                    next_epoch as i64
                ],
            )?;
            tx.execute(
                "DELETE FROM source_fts WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    source.tenant_namespace,
                    source.source_id,
                    source.version as i64
                ],
            )?;
            tx.execute(
                "UPDATE blob_registry SET state='PURGE_PENDING',lifecycle_epoch=?4                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3 AND state!='PURGED'",
                params![
                    source.tenant_namespace,
                    source.source_id,
                    source.version as i64,
                    next_epoch as i64
                ],
            )?;
            tx.execute(
                "UPDATE copy_registry SET purge_state=CASE WHEN purge_state='CONFIRMED' THEN purge_state ELSE 'PENDING' END,                    lifecycle_epoch_seen=?4                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    source.tenant_namespace,
                    source.source_id,
                    source.version as i64,
                    next_epoch as i64
                ],
            )?;
        }
        tx.commit()?;

        self.finish_physical_purge(tenant_namespace, &closure, &job_id)?;
        Ok(job_id)
    }

    pub fn register_copy(
        &mut self,
        source: &SourceIdentity,
        copy_id: &str,
        copy_kind: &str,
        custodian: &str,
        purge_capability: &str,
    ) -> Result<()> {
        validate_identity(source)?;
        validate_opaque_id(copy_id)?;
        if copy_kind.trim().is_empty()
            || custodian.trim().is_empty()
            || purge_capability.trim().is_empty()
        {
            return Err(StorageError::InvalidMetadata("copy_record"));
        }
        let record = self.source_record(source)?;
        self.connection.execute(
            "INSERT INTO copy_registry(tenant_namespace,copy_id,source_id,version,copy_kind,custodian, \
                locator_or_provider_request_ref,encryption_key_scope,created_at,allowed_purpose,retention_contract_ref, \
                lifecycle_epoch_seen,purge_capability,purge_state,purge_receipt_ref,residual_reason) \
             VALUES(?1,?2,?3,?4,?5,?6,'local:registered',?7,?8,'current-purpose','default-retention',?9,?10,?11,NULL,NULL)",
            params![
                source.tenant_namespace,
                copy_id,
                source.source_id,
                source.version as i64,
                copy_kind,
                custodian,
                record.key_scope_ref,
                record.captured_at,
                record.lifecycle_epoch as i64,
                purge_capability,
                CopyPurgeState::NotRequested.as_db()
            ],
        )?;
        Ok(())
    }

    pub fn set_copy_purge_state(
        &mut self,
        tenant_namespace: &str,
        copy_id: &str,
        purge_state: CopyPurgeState,
        purge_receipt_ref: Option<&str>,
        residual_reason: Option<&str>,
    ) -> Result<()> {
        validate_opaque_id(tenant_namespace)?;
        validate_opaque_id(copy_id)?;
        let changed = self.connection.execute(
            "UPDATE copy_registry SET purge_state=?3,purge_receipt_ref=?4,residual_reason=?5 \
             WHERE tenant_namespace=?1 AND copy_id=?2",
            params![
                tenant_namespace,
                copy_id,
                purge_state.as_db(),
                purge_receipt_ref,
                residual_reason
            ],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn copy_records(&self, source: &SourceIdentity) -> Result<Vec<CopyRecord>> {
        validate_identity(source)?;
        let mut statement = self.connection.prepare(
            "SELECT copy_id,copy_kind,custodian,locator_or_provider_request_ref,encryption_key_scope,created_at, \
                    allowed_purpose,retention_contract_ref,lifecycle_epoch_seen,purge_capability,purge_state,purge_receipt_ref,residual_reason \
             FROM copy_registry WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3 ORDER BY copy_id",
        )?;
        let rows = statement.query_map(
            params![
                source.tenant_namespace,
                source.source_id,
                source.version as i64
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                ))
            },
        )?;
        let mut result = Vec::new();
        for row in rows {
            let row = row?;
            result.push(CopyRecord {
                copy_id: row.0,
                source: source.clone(),
                copy_kind: row.1,
                custodian: row.2,
                locator_or_provider_request_ref: row.3,
                encryption_key_scope: row.4,
                created_at: row.5,
                allowed_purpose: row.6,
                retention_contract_ref: row.7,
                lifecycle_epoch_seen: row.8 as u64,
                purge_capability: row.9,
                purge_state: parse_copy_purge_state(&row.10)?,
                purge_receipt_ref: row.11,
                residual_reason: row.12,
            });
        }
        Ok(result)
    }

    pub fn export_snapshot(
        &mut self,
        source: &SourceIdentity,
        search_text: &str,
        snapshot_key: &[u8; 32],
        snapshot_name: &str,
    ) -> Result<PathBuf> {
        validate_identity(source)?;
        validate_opaque_id(snapshot_name)?;
        let current = self.current_identity(&source.tenant_namespace, &source.source_id)?;
        if current != *source {
            return Err(StorageError::StaleLifecycle);
        }
        let prepared = self.prepare_read(&source.tenant_namespace, &source.source_id)?;
        let plaintext = self.finish_read(&prepared)?;
        let record = self.source_record(source)?;
        let payload = SnapshotPayload {
            format_version: 1,
            exported_namespace_epoch: self.current_namespace_epoch(&source.tenant_namespace)?,
            source: record,
            search_text: search_text.to_owned(),
            plaintext,
        };
        let serialized = serde_json::to_vec(&payload)?;
        let encoded = encrypt_snapshot(snapshot_key, &source.tenant_namespace, &serialized)?;
        let path = self
            .root
            .join("snapshots")
            .join(format!("{snapshot_name}.snapshot"));
        write_synced(&path, &encoded)?;
        sync_parent(&path)?;
        self.register_copy(
            source,
            snapshot_name,
            "BACKUP_SNAPSHOT",
            "local-snapshot",
            "IMPORT_RECONCILE",
        )?;
        Ok(path)
    }

    pub fn import_snapshot_quarantined(
        &mut self,
        snapshot_path: impl AsRef<Path>,
        snapshot_key: &[u8; 32],
    ) -> Result<RestoreResult> {
        let encoded = fs::read(snapshot_path)?;
        let (tenant_namespace, serialized) = decrypt_snapshot(snapshot_key, &encoded)?;
        let payload: SnapshotPayload = serde_json::from_slice(&serialized)?;
        if payload.format_version != 1
            || payload.source.identity.tenant_namespace != tenant_namespace
        {
            return Err(StorageError::IntegrityMismatch);
        }
        validate_identity(&payload.source.identity)?;
        ensure_namespace(&self.connection, &tenant_namespace)?;
        let current_epoch = self.current_namespace_epoch(&tenant_namespace)?;
        let imported = self.insert_snapshot_history(&payload, current_epoch)?;
        Ok(RestoreResult {
            imported_source: imported,
            use_state: AllowedUseState::Quarantined,
            reason: "historical snapshot imported without current activation authority".into(),
        })
    }

    pub fn checkpoint_protected_database(&self, backup_path: impl AsRef<Path>) -> Result<()> {
        let _: (i64, i64, i64) =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
        fs::copy(self.root.join("protected.db"), backup_path)?;
        Ok(())
    }

    pub fn replace_protected_database_from_backup(
        root: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
    ) -> Result<()> {
        let root = root.as_ref();
        for name in ["protected.db-wal", "protected.db-shm"] {
            let path = root.join(name);
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        fs::copy(backup_path, root.join("protected.db"))?;
        Ok(())
    }

    pub fn recover(&mut self) -> Result<RecoveryReport> {
        let mut report = RecoveryReport::default();

        for pending in self.frontier.pending_publications()? {
            let protected: Option<(Option<i64>, String, String)> = self
                .connection
                .query_row(
                    "SELECT h.current_version,v.use_state,b.state FROM source_heads h                     JOIN source_versions v ON v.tenant_namespace=h.tenant_namespace AND v.source_id=h.source_id AND v.version=h.current_version                     JOIN blob_registry b ON b.tenant_namespace=v.tenant_namespace AND b.source_id=v.source_id AND b.version=v.version                     WHERE h.tenant_namespace=?1 AND h.source_id=?2",
                    params![pending.tenant_namespace, pending.source_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if matches!(protected, Some((Some(version), ref use_state, ref blob_state))
                if version as u64 == pending.target_version && use_state == "ACTIVE" && blob_state == "READY")
            {
                self.frontier.commit_publication(
                    &pending.tenant_namespace,
                    &pending.source_id,
                    pending.target_version,
                    pending.lifecycle_epoch,
                    pending.authority_epoch,
                )?;
            } else {
                self.frontier.abort_publication(
                    &pending.tenant_namespace,
                    &pending.source_id,
                    pending.target_version,
                )?;
            }
        }

        // A restored protected.db is never allowed to overrule a newer independent block.
        for frontier in self.frontier.blocked_sources()? {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE source_versions SET use_state='BLOCKED',erasure_state='PURGE_PENDING',lifecycle_epoch=?4                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    frontier.source.tenant_namespace,
                    frontier.source.source_id,
                    frontier.source.version as i64,
                    frontier.lifecycle_epoch as i64
                ],
            )?;
            tx.execute(
                "DELETE FROM source_fts WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    frontier.source.tenant_namespace,
                    frontier.source.source_id,
                    frontier.source.version as i64
                ],
            )?;
            tx.execute(
                "UPDATE blob_registry SET state='PURGE_PENDING',lifecycle_epoch=?4                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3 AND state!='PURGED'",
                params![
                    frontier.source.tenant_namespace,
                    frontier.source.source_id,
                    frontier.source.version as i64,
                    frontier.lifecycle_epoch as i64
                ],
            )?;
            tx.commit()?;
        }

        let registered: BTreeSet<String> = {
            let mut statement = self
                .connection
                .prepare("SELECT blob_id FROM blob_registry")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<std::result::Result<BTreeSet<_>, _>>()?
        };
        for entry in fs::read_dir(self.root.join("staging"))? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|item| item.to_str()) else {
                continue;
            };
            let Some(blob_id) = name.strip_suffix(".stage") else {
                continue;
            };
            if !registered.contains(blob_id) {
                fs::remove_file(&path)?;
                report.orphan_staging_removed += 1;
            }
        }

        let staged: Vec<(String, String, String, i64)> = {
            let mut statement = self.connection.prepare(
                "SELECT tenant_namespace,blob_id,source_id,version FROM blob_registry WHERE state='STAGED'",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (tenant, blob_id, source_id, version) in staged {
            for path in [
                self.staging_blob_path(&blob_id)?,
                self.final_blob_path(&blob_id)?,
            ] {
                if path.exists() {
                    fs::remove_file(path)?;
                    report.purged_blob_files += 1;
                }
            }
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE blob_registry SET state='PURGED' WHERE tenant_namespace=?1 AND blob_id=?2",
                params![tenant, blob_id],
            )?;
            tx.execute(
                "UPDATE source_versions SET use_state=?4,erasure_state=?5 \
                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    tenant,
                    source_id,
                    version,
                    AllowedUseState::Quarantined.as_db(),
                    PhysicalState::Purged.as_db()
                ],
            )?;
            tx.execute(
                "UPDATE copy_registry SET purge_state='CONFIRMED',residual_reason=NULL \
                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3 AND copy_kind='LOCAL_BLOB'",
                params![tenant, source_id, version],
            )?;
            tx.commit()?;
            report.quarantined_registered_blobs += 1;
        }

        let pending: Vec<(String, String, String, i64)> = {
            let mut statement = self.connection.prepare(
                "SELECT tenant_namespace,blob_id,source_id,version FROM blob_registry WHERE state='PURGE_PENDING'",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (tenant, blob_id, source_id, version) in pending {
            let path = self.final_blob_path(&blob_id)?;
            if path.exists() {
                fs::remove_file(path)?;
                report.purged_blob_files += 1;
            }
            self.connection.execute(
                "UPDATE blob_registry SET state='PURGED' WHERE tenant_namespace=?1 AND blob_id=?2",
                params![tenant, blob_id],
            )?;
            self.connection.execute(
                "UPDATE source_versions SET erasure_state=?4 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![tenant, source_id, version, PhysicalState::Purged.as_db()],
            )?;
            self.connection.execute(
                "UPDATE copy_registry SET purge_state='CONFIRMED',residual_reason=NULL \
                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3 AND copy_kind='LOCAL_BLOB'",
                params![tenant, source_id, version],
            )?;
        }
        report.residual_copies = self.connection.query_row(
            "SELECT count(*) FROM copy_registry WHERE purge_state IN ('PENDING','UNSUPPORTED','FAILED','UNKNOWN')",
            [],
            |row| row.get::<_, i64>(0),
        )? as usize;
        Ok(report)
    }

    pub fn artifact_inventory(&self) -> BTreeMap<String, u64> {
        let mut result = BTreeMap::new();
        for name in [
            "protected.db",
            "protected.db-wal",
            "protected.db-shm",
            "lifecycle.db",
            "lifecycle.db-wal",
            "lifecycle.db-shm",
        ] {
            let path = self.root.join(name);
            if let Ok(metadata) = fs::metadata(path) {
                result.insert(name.to_owned(), metadata.len());
            }
        }
        result
    }

    // Internal protected commit path mirrors the explicit publication contract fields.
    #[allow(clippy::too_many_arguments)]
    fn publish_inner(
        &mut self,
        tenant_namespace: &str,
        source_id: &str,
        draft: &SourceDraft,
        search_text: &str,
        plaintext: &[u8],
        parents: &[ParentInfluence],
        predecessor: Option<SourceIdentity>,
        correction_event_ref: Option<&str>,
        failpoint: PublishFailPoint,
    ) -> Result<SourceIdentity> {
        validate_opaque_id(tenant_namespace)?;
        validate_opaque_id(source_id)?;
        draft.validate()?;
        ensure_namespace(&self.connection, tenant_namespace)?;
        let current_epoch = self.current_namespace_epoch(tenant_namespace)?;
        let target_epoch = current_epoch + 1;
        let version = self.next_version(tenant_namespace, source_id)?;
        let identity = SourceIdentity {
            tenant_namespace: tenant_namespace.to_owned(),
            source_id: source_id.to_owned(),
            version,
        };
        for parent in parents {
            validate_identity(&parent.parent)?;
            if parent.parent.tenant_namespace != tenant_namespace {
                return Err(StorageError::TenantMismatch);
            }
        }
        if predecessor
            .as_ref()
            .is_some_and(|item| item.tenant_namespace != tenant_namespace)
        {
            return Err(StorageError::TenantMismatch);
        }
        for parent in parents {
            self.frontier.require_current_identity(&parent.parent)?;
        }
        if let Some(predecessor) = predecessor.as_ref() {
            self.frontier.require_current_identity(predecessor)?;
        }
        self.frontier.begin_publication(
            tenant_namespace,
            source_id,
            predecessor.as_ref().map(|item| item.version),
            version,
            target_epoch,
            draft.authority_epoch,
        )?;

        let blob_id = blob_id_for(&identity, target_epoch);
        let stage_path = self.staging_blob_path(&blob_id)?;
        let final_path = self.final_blob_path(&blob_id)?;
        let encoded = encrypt_blob(&self.blob_key, &identity, target_epoch, plaintext)?;
        write_synced(&stage_path, &encoded)?;
        let ciphertext_digest = sha256_hex(&encoded);
        if failpoint == PublishFailPoint::AfterBlobStage {
            return Err(StorageError::SimulatedCrash("after_blob_stage"));
        }

        let content_digest = sha256_hex(plaintext);
        let subject_refs_json = serde_json::to_string(&draft.subject_refs)?;
        let owner_refs_json = serde_json::to_string(&draft.owner_refs)?;
        let account_refs_json = serde_json::to_string(&draft.account_refs)?;
        let transcript_refs_json = serde_json::to_string(&draft.transcript_or_ocr_derivation_refs)?;
        let issuer_integrity_json = serde_json::to_string(&draft.issuer_integrity_evidence)?;
        let truth_evidence_json = serde_json::to_string(&draft.truth_evidence_refs)?;
        {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            if namespace_epoch_tx(&tx, tenant_namespace)? > current_epoch {
                return Err(StorageError::StaleLifecycle);
            }
            validate_parent_state(&tx, tenant_namespace, parents)?;
            if let Some(predecessor) = predecessor.as_ref() {
                require_current_source(&tx, predecessor)?;
            }
            tx.execute(
                "INSERT INTO source_versions(tenant_namespace,source_id,version,source_kind,original_blob_ref,media_type,byte_length, \
                    digest_profile,content_digest,capture_actor,subject_refs_json,owner_refs_json,account_refs_json,source_locator_ref, \
                    captured_at,source_time,exact_span_scheme,transcript_refs_json,issuer_integrity_json,truth_evidence_json, \
                    data_use_label_ref,trust_taint_label_ref,lifecycle_head_ref,lifecycle_epoch,key_scope_ref,predecessor_source_id, \
                    predecessor_version,correction_event_ref,use_state,erasure_state,authority_ref,authority_epoch,search_text) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33)",
                params![
                    tenant_namespace,
                    source_id,
                    version as i64,
                    draft.source_kind,
                    blob_id,
                    draft.media_type,
                    plaintext.len() as i64,
                    draft.digest_profile,
                    content_digest,
                    draft.capture_actor,
                    subject_refs_json,
                    owner_refs_json,
                    account_refs_json,
                    draft.source_locator_ref,
                    draft.captured_at,
                    draft.source_time,
                    draft.exact_span_scheme,
                    transcript_refs_json,
                    issuer_integrity_json,
                    truth_evidence_json,
                    draft.data_use_label_ref,
                    draft.trust_taint_label_ref,
                    format!("lifecycle:{tenant_namespace}:{source_id}"),
                    target_epoch as i64,
                    draft.key_scope_ref,
                    predecessor.as_ref().map(|item| item.source_id.as_str()),
                    predecessor.as_ref().map(|item| item.version as i64),
                    correction_event_ref,
                    AllowedUseState::Quarantined.as_db(),
                    PhysicalState::HeldIsolated.as_db(),
                    draft.authority_ref,
                    draft.authority_epoch as i64,
                    search_text
                ],
            )?;
            tx.execute(
                "INSERT INTO blob_registry(tenant_namespace,blob_id,source_id,version,lifecycle_epoch,state,ciphertext_digest,ciphertext_len) \
                 VALUES(?1,?2,?3,?4,?5,'STAGED',?6,?7)",
                params![
                    tenant_namespace,
                    blob_id,
                    source_id,
                    version as i64,
                    target_epoch as i64,
                    ciphertext_digest,
                    encoded.len() as i64
                ],
            )?;
            tx.execute(
                "INSERT INTO copy_registry(tenant_namespace,copy_id,source_id,version,copy_kind,custodian, \
                    locator_or_provider_request_ref,encryption_key_scope,created_at,allowed_purpose,retention_contract_ref, \
                    lifecycle_epoch_seen,purge_capability,purge_state,purge_receipt_ref,residual_reason) \
                 VALUES(?1,?2,?3,?4,'LOCAL_BLOB','local-device',?5,?6,?7,'source-use','local-retention',?8,'LOCAL_DELETE',?9,NULL,NULL)",
                params![
                    tenant_namespace,
                    format!("local-{blob_id}"),
                    source_id,
                    version as i64,
                    blob_id,
                    draft.key_scope_ref,
                    draft.captured_at,
                    target_epoch as i64,
                    CopyPurgeState::NotRequested.as_db()
                ],
            )?;
            for parent in parents {
                tx.execute(
                    "INSERT INTO lineage_edges(tenant_namespace,child_source_id,child_version,parent_source_id,parent_version,role) \
                     VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        tenant_namespace,
                        source_id,
                        version as i64,
                        parent.parent.source_id,
                        parent.parent.version as i64,
                        parent.role.as_db()
                    ],
                )?;
            }
            tx.commit()?;
        }
        if failpoint == PublishFailPoint::AfterRegistration {
            return Err(StorageError::SimulatedCrash("after_registration"));
        }

        fs::rename(&stage_path, &final_path)?;
        sync_parent(&final_path)?;
        if failpoint == PublishFailPoint::AfterFinalRename {
            return Err(StorageError::SimulatedCrash("after_final_rename"));
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if namespace_epoch_tx(&tx, tenant_namespace)? > current_epoch {
            return Err(StorageError::StaleLifecycle);
        }
        validate_parent_state(&tx, tenant_namespace, parents)?;
        if let Some(predecessor) = predecessor.as_ref() {
            require_current_source(&tx, predecessor)?;
            tx.execute(
                "UPDATE source_versions SET use_state=?4,lifecycle_epoch=?5 \
                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    tenant_namespace,
                    predecessor.source_id,
                    predecessor.version as i64,
                    AllowedUseState::Superseded.as_db(),
                    target_epoch as i64
                ],
            )?;
            tx.execute(
                "DELETE FROM source_fts WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    tenant_namespace,
                    predecessor.source_id,
                    predecessor.version as i64
                ],
            )?;
        }
        tx.execute(
            "UPDATE namespaces SET lifecycle_epoch=?2 WHERE tenant_namespace=?1 AND lifecycle_epoch<=?2",
            params![tenant_namespace, target_epoch as i64],
        )?;
        tx.execute(
            "UPDATE source_versions SET use_state=?4,erasure_state=?5,lifecycle_epoch=?6 \
             WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
            params![
                tenant_namespace,
                source_id,
                version as i64,
                AllowedUseState::Active.as_db(),
                PhysicalState::Present.as_db(),
                target_epoch as i64
            ],
        )?;
        tx.execute(
            "UPDATE blob_registry SET state='READY',lifecycle_epoch=?5 \
             WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3 AND blob_id=?4",
            params![
                tenant_namespace,
                source_id,
                version as i64,
                blob_id,
                target_epoch as i64
            ],
        )?;
        tx.execute(
            "INSERT INTO source_heads(tenant_namespace,source_id,current_version,lifecycle_epoch) VALUES(?1,?2,?3,?4) \
             ON CONFLICT(tenant_namespace,source_id) DO UPDATE SET current_version=excluded.current_version,lifecycle_epoch=excluded.lifecycle_epoch",
            params![tenant_namespace, source_id, version as i64, target_epoch as i64],
        )?;
        tx.execute(
            "INSERT INTO source_fts(tenant_namespace,source_id,version,body) VALUES(?1,?2,?3,?4)",
            params![tenant_namespace, source_id, version as i64, search_text],
        )?;
        tx.commit()?;
        // protected.db may now contain a complete ACTIVE candidate, but it is not readable until
        // the independent frontier commits the exact version and lifecycle epoch.
        self.frontier.commit_publication(
            tenant_namespace,
            source_id,
            version,
            target_epoch,
            draft.authority_epoch,
        )?;
        Ok(identity)
    }

    fn next_version(&self, tenant_namespace: &str, source_id: &str) -> Result<u64> {
        let max_version: Option<i64> = self.connection.query_row(
            "SELECT max(version) FROM source_versions WHERE tenant_namespace=?1 AND source_id=?2",
            params![tenant_namespace, source_id],
            |row| row.get(0),
        )?;
        Ok(max_version.unwrap_or(0) as u64 + 1)
    }

    fn finish_physical_purge(
        &mut self,
        tenant_namespace: &str,
        closure: &[SourceIdentity],
        job_id: &str,
    ) -> Result<()> {
        let mut residuals = 0_i64;
        for source in closure {
            let blob_id: String = self.connection.query_row(
                "SELECT original_blob_ref FROM source_versions WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![tenant_namespace, source.source_id, source.version as i64],
                |row| row.get(0),
            )?;
            let path = self.final_blob_path(&blob_id)?;
            if path.exists() {
                fs::remove_file(&path)?;
                sync_parent(&path)?;
            }
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE blob_registry SET state='PURGED' WHERE tenant_namespace=?1 AND blob_id=?2",
                params![tenant_namespace, blob_id],
            )?;
            tx.execute(
                "UPDATE source_versions SET erasure_state=?4 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    tenant_namespace,
                    source.source_id,
                    source.version as i64,
                    PhysicalState::Purged.as_db()
                ],
            )?;
            tx.execute(
                "UPDATE copy_registry SET purge_state='CONFIRMED',purge_receipt_ref='local-delete',residual_reason=NULL \
                 WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3 AND copy_kind='LOCAL_BLOB'",
                params![tenant_namespace, source.source_id, source.version as i64],
            )?;
            tx.commit()?;
        }
        residuals += self.connection.query_row(
            "SELECT count(*) FROM copy_registry WHERE tenant_namespace=?1 AND purge_state IN ('PENDING','UNSUPPORTED','FAILED','UNKNOWN')",
            [tenant_namespace],
            |row| row.get::<_, i64>(0),
        )?;
        self.connection.execute(
            "UPDATE deletion_jobs SET state=?3,residual_count=?4 WHERE tenant_namespace=?1 AND job_id=?2",
            params![
                tenant_namespace,
                job_id,
                if residuals == 0 {
                    DeleteJobState::Complete.as_db()
                } else {
                    DeleteJobState::Residuals.as_db()
                },
                residuals
            ],
        )?;
        Ok(())
    }

    fn insert_snapshot_history(
        &mut self,
        payload: &SnapshotPayload,
        current_namespace_epoch: u64,
    ) -> Result<SourceIdentity> {
        let source = &payload.source;
        let next_version = self.next_version(
            &source.identity.tenant_namespace,
            &source.identity.source_id,
        )?;
        let imported = SourceIdentity {
            tenant_namespace: source.identity.tenant_namespace.clone(),
            source_id: source.identity.source_id.clone(),
            version: next_version,
        };
        let blob_id = blob_id_for(&imported, current_namespace_epoch);
        let final_path = self.final_blob_path(&blob_id)?;
        let encoded = encrypt_blob(
            &self.blob_key,
            &imported,
            current_namespace_epoch,
            &payload.plaintext,
        )?;
        write_synced(&final_path, &encoded)?;
        sync_parent(&final_path)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO source_versions(tenant_namespace,source_id,version,source_kind,original_blob_ref,media_type,byte_length, \
                digest_profile,content_digest,capture_actor,subject_refs_json,owner_refs_json,account_refs_json,source_locator_ref, \
                captured_at,source_time,exact_span_scheme,transcript_refs_json,issuer_integrity_json,truth_evidence_json, \
                data_use_label_ref,trust_taint_label_ref,lifecycle_head_ref,lifecycle_epoch,key_scope_ref,predecessor_source_id, \
                predecessor_version,correction_event_ref,use_state,erasure_state,authority_ref,authority_epoch,search_text) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33)",
            params![
                imported.tenant_namespace,
                imported.source_id,
                imported.version as i64,
                source.source_kind,
                blob_id,
                source.media_type,
                payload.plaintext.len() as i64,
                source.digest_profile,
                sha256_hex(&payload.plaintext),
                source.capture_actor,
                serde_json::to_string(&source.subject_refs)?,
                serde_json::to_string(&source.owner_refs)?,
                serde_json::to_string(&source.account_refs)?,
                source.source_locator_ref,
                source.captured_at,
                source.source_time,
                source.exact_span_scheme,
                serde_json::to_string(&source.transcript_or_ocr_derivation_refs)?,
                serde_json::to_string(&source.issuer_integrity_evidence)?,
                serde_json::to_string(&source.truth_evidence_refs)?,
                source.data_use_label_ref,
                source.trust_taint_label_ref,
                format!("lifecycle:{}:{}", imported.tenant_namespace, imported.source_id),
                current_namespace_epoch as i64,
                source.key_scope_ref,
                source.identity.source_id,
                source.identity.version as i64,
                source.correction_event_ref,
                AllowedUseState::Quarantined.as_db(),
                PhysicalState::HeldIsolated.as_db(),
                source.authority_ref,
                source.authority_epoch as i64,
                payload.search_text
            ],
        )?;
        tx.execute(
            "INSERT INTO blob_registry(tenant_namespace,blob_id,source_id,version,lifecycle_epoch,state,ciphertext_digest,ciphertext_len) \
             VALUES(?1,?2,?3,?4,?5,'READY',?6,?7)",
            params![
                imported.tenant_namespace,
                blob_id,
                imported.source_id,
                imported.version as i64,
                current_namespace_epoch as i64,
                sha256_hex(&encoded),
                encoded.len() as i64
            ],
        )?;
        tx.execute(
            "INSERT INTO copy_registry(tenant_namespace,copy_id,source_id,version,copy_kind,custodian, \
                locator_or_provider_request_ref,encryption_key_scope,created_at,allowed_purpose,retention_contract_ref, \
                lifecycle_epoch_seen,purge_capability,purge_state,purge_receipt_ref,residual_reason) \
             VALUES(?1,?2,?3,?4,'RESTORED_BLOB','local-device',?5,?6,?7,'restore-review','local-retention',?8,'LOCAL_DELETE',?9,NULL,'awaiting current activation authority')",
            params![
                imported.tenant_namespace,
                format!("restore-{blob_id}"),
                imported.source_id,
                imported.version as i64,
                blob_id,
                source.key_scope_ref,
                source.captured_at,
                current_namespace_epoch as i64,
                CopyPurgeState::NotRequested.as_db()
            ],
        )?;
        tx.commit()?;
        Ok(imported)
    }

    fn final_blob_path(&self, blob_id: &str) -> Result<PathBuf> {
        validate_opaque_id(blob_id)?;
        Ok(self.root.join("blobs").join(format!("{blob_id}.blob")))
    }

    fn staging_blob_path(&self, blob_id: &str) -> Result<PathBuf> {
        validate_opaque_id(blob_id)?;
        Ok(self.root.join("staging").join(format!("{blob_id}.stage")))
    }
}

fn open_cipher(path: &Path, passphrase: &str) -> Result<(Connection, RuntimeInfo)> {
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "key", passphrase)?;
    let cipher_version: String =
        connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    if cipher_version.trim().is_empty() {
        return Err(StorageError::CipherInactive);
    }
    let cipher_status = match connection.query_row("PRAGMA cipher_status", [], |row| {
        row.get::<_, rusqlite::types::Value>(0)
    }) {
        Ok(rusqlite::types::Value::Null) => None,
        Ok(rusqlite::types::Value::Integer(value)) => Some(value.to_string()),
        Ok(rusqlite::types::Value::Real(value)) => Some(value.to_string()),
        Ok(rusqlite::types::Value::Text(value)) => Some(value),
        Ok(rusqlite::types::Value::Blob(_)) => return Err(StorageError::CipherInactive),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(error) => return Err(error.into()),
    };
    if cipher_status.as_deref().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "disabled" | "inactive"
        )
    }) {
        return Err(StorageError::CipherInactive);
    }
    let cipher_provider =
        match connection.query_row("PRAGMA cipher_provider", [], |row| row.get::<_, String>(0)) {
            Ok(value) => Some(value),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(error) => return Err(error.into()),
        };
    let sqlite_version: String =
        connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    connection.pragma_update(None, "busy_timeout", 5000_i64)?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StorageError::Sqlite(rusqlite::Error::InvalidQuery));
    }
    let secure_delete: i64 = connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    let temp_store: i64 = connection.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    Ok((
        connection,
        RuntimeInfo {
            sqlite_version,
            cipher_version,
            cipher_provider,
            cipher_status,
            journal_mode,
            secure_delete,
            temp_store,
            schema_version: 0,
        },
    ))
}

fn initialize_schema(connection: &mut Connection) -> Result<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion(version));
    }
    create_schema_objects(connection)?;
    if version == 1 && !has_column(connection, "namespaces", "authority_epoch")? {
        connection.execute(
            "ALTER TABLE namespaces ADD COLUMN authority_epoch INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    connection.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    connection.execute(
        "INSERT INTO source_fts(source_fts,rank) VALUES('secure-delete',1)",
        [],
    )?;
    Ok(())
}

fn create_schema_objects(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS namespaces( \
            tenant_namespace TEXT PRIMARY KEY, \
            lifecycle_epoch INTEGER NOT NULL DEFAULT 0 CHECK(lifecycle_epoch>=0), \
            authority_epoch INTEGER NOT NULL DEFAULT 0 CHECK(authority_epoch>=0) \
         ); \
         CREATE TABLE IF NOT EXISTS source_versions( \
            tenant_namespace TEXT NOT NULL,source_id TEXT NOT NULL,version INTEGER NOT NULL CHECK(version>0), \
            source_kind TEXT NOT NULL,original_blob_ref TEXT NOT NULL,media_type TEXT NOT NULL,byte_length INTEGER NOT NULL CHECK(byte_length>=0), \
            digest_profile TEXT NOT NULL,content_digest TEXT NOT NULL,capture_actor TEXT NOT NULL,subject_refs_json TEXT NOT NULL, \
            owner_refs_json TEXT NOT NULL,account_refs_json TEXT NOT NULL,source_locator_ref TEXT NOT NULL,captured_at TEXT NOT NULL, \
            source_time TEXT,exact_span_scheme TEXT NOT NULL,transcript_refs_json TEXT NOT NULL,issuer_integrity_json TEXT NOT NULL, \
            truth_evidence_json TEXT NOT NULL,data_use_label_ref TEXT NOT NULL,trust_taint_label_ref TEXT NOT NULL,lifecycle_head_ref TEXT NOT NULL, \
            lifecycle_epoch INTEGER NOT NULL CHECK(lifecycle_epoch>=0),key_scope_ref TEXT NOT NULL,predecessor_source_id TEXT,predecessor_version INTEGER, \
            correction_event_ref TEXT,use_state TEXT NOT NULL CHECK(use_state IN ('ACTIVE','QUARANTINED','DISPUTED','SUPERSEDED','EXPIRED','BLOCKED')), \
            erasure_state TEXT NOT NULL CHECK(erasure_state IN ('PRESENT','PURGE_PENDING','PURGED','CRYPTO_ERASED','HELD_ISOLATED','UNKNOWN')), \
            authority_ref TEXT,authority_epoch INTEGER NOT NULL DEFAULT 0 CHECK(authority_epoch>=0),search_text TEXT NOT NULL, \
            PRIMARY KEY(tenant_namespace,source_id,version), \
            FOREIGN KEY(tenant_namespace) REFERENCES namespaces(tenant_namespace) \
         ); \
         CREATE TABLE IF NOT EXISTS source_heads( \
            tenant_namespace TEXT NOT NULL,source_id TEXT NOT NULL,current_version INTEGER,lifecycle_epoch INTEGER NOT NULL CHECK(lifecycle_epoch>=0), \
            PRIMARY KEY(tenant_namespace,source_id), \
            FOREIGN KEY(tenant_namespace) REFERENCES namespaces(tenant_namespace) \
         ); \
         CREATE TABLE IF NOT EXISTS blob_registry( \
            tenant_namespace TEXT NOT NULL,blob_id TEXT NOT NULL,source_id TEXT NOT NULL,version INTEGER NOT NULL, \
            lifecycle_epoch INTEGER NOT NULL CHECK(lifecycle_epoch>=0), \
            state TEXT NOT NULL CHECK(state IN ('STAGED','READY','PURGE_PENDING','PURGED')), \
            ciphertext_digest TEXT NOT NULL,ciphertext_len INTEGER NOT NULL CHECK(ciphertext_len>=0), \
            PRIMARY KEY(tenant_namespace,blob_id), \
            FOREIGN KEY(tenant_namespace,source_id,version) REFERENCES source_versions(tenant_namespace,source_id,version) ON DELETE CASCADE \
         ); \
         CREATE TABLE IF NOT EXISTS copy_registry( \
            tenant_namespace TEXT NOT NULL,copy_id TEXT NOT NULL,source_id TEXT NOT NULL,version INTEGER NOT NULL,copy_kind TEXT NOT NULL, \
            custodian TEXT NOT NULL,locator_or_provider_request_ref TEXT NOT NULL,encryption_key_scope TEXT NOT NULL,created_at TEXT NOT NULL, \
            allowed_purpose TEXT NOT NULL,retention_contract_ref TEXT NOT NULL,lifecycle_epoch_seen INTEGER NOT NULL CHECK(lifecycle_epoch_seen>=0), \
            purge_capability TEXT NOT NULL,purge_state TEXT NOT NULL CHECK(purge_state IN ('NOT_REQUESTED','PENDING','CONFIRMED','UNSUPPORTED','FAILED','UNKNOWN')), \
            purge_receipt_ref TEXT,residual_reason TEXT, \
            PRIMARY KEY(tenant_namespace,copy_id), \
            FOREIGN KEY(tenant_namespace,source_id,version) REFERENCES source_versions(tenant_namespace,source_id,version) ON DELETE CASCADE \
         ); \
         CREATE TABLE IF NOT EXISTS lineage_edges( \
            tenant_namespace TEXT NOT NULL,child_source_id TEXT NOT NULL,child_version INTEGER NOT NULL,parent_source_id TEXT NOT NULL,parent_version INTEGER NOT NULL, \
            role TEXT NOT NULL CHECK(role IN ('DATA_INPUT','CONTROL_INPUT','SUPPORT_EVIDENCE','CONTRADICTION_EVIDENCE','CORRECTION')), \
            PRIMARY KEY(tenant_namespace,child_source_id,child_version,parent_source_id,parent_version,role), \
            FOREIGN KEY(tenant_namespace,child_source_id,child_version) REFERENCES source_versions(tenant_namespace,source_id,version) ON DELETE CASCADE, \
            FOREIGN KEY(tenant_namespace,parent_source_id,parent_version) REFERENCES source_versions(tenant_namespace,source_id,version) \
         ); \
         CREATE TABLE IF NOT EXISTS deletion_jobs( \
            tenant_namespace TEXT NOT NULL,job_id TEXT NOT NULL,root_source_id TEXT NOT NULL,root_version INTEGER NOT NULL, \
            state TEXT NOT NULL CHECK(state IN ('ACCEPTED','USE_BLOCKED','ENUMERATING','PURGING','RESIDUALS','COMPLETE')), \
            started_epoch INTEGER NOT NULL CHECK(started_epoch>=0),residual_count INTEGER NOT NULL DEFAULT 0 CHECK(residual_count>=0), \
            PRIMARY KEY(tenant_namespace,job_id) \
         ); \
         CREATE VIRTUAL TABLE IF NOT EXISTS source_fts USING fts5(tenant_namespace UNINDEXED,source_id UNINDEXED,version UNINDEXED,body);",
    )?;
    Ok(())
}

fn has_column(connection: &Connection, table: &str, column: &str) -> Result<bool> {
    let sql = format!("PRAGMA table_info({table})");
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_namespace(connection: &Connection, tenant_namespace: &str) -> Result<()> {
    connection.execute(
        "INSERT INTO namespaces(tenant_namespace,lifecycle_epoch,authority_epoch) VALUES(?1,0,0) ON CONFLICT DO NOTHING",
        [tenant_namespace],
    )?;
    Ok(())
}

fn namespace_epoch_tx(tx: &Transaction<'_>, tenant_namespace: &str) -> Result<u64> {
    tx.query_row(
        "SELECT lifecycle_epoch FROM namespaces WHERE tenant_namespace=?1",
        [tenant_namespace],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value as u64)
    .map_err(StorageError::from)
}

fn require_current_source(tx: &Transaction<'_>, source: &SourceIdentity) -> Result<()> {
    let row: Option<(Option<i64>, String)> = tx
        .query_row(
            "SELECT h.current_version,v.use_state FROM source_heads h \
             JOIN source_versions v ON v.tenant_namespace=h.tenant_namespace AND v.source_id=h.source_id AND v.version=h.current_version \
             WHERE h.tenant_namespace=?1 AND h.source_id=?2",
            params![source.tenant_namespace, source.source_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((Some(version), state)) = row else {
        return Err(StorageError::NotFound);
    };
    if version as u64 != source.version || state != "ACTIVE" {
        return Err(StorageError::StaleLifecycle);
    }
    Ok(())
}

fn validate_parent_state(
    tx: &Transaction<'_>,
    tenant_namespace: &str,
    parents: &[ParentInfluence],
) -> Result<()> {
    for parent in parents {
        if parent.parent.tenant_namespace != tenant_namespace {
            return Err(StorageError::TenantMismatch);
        }
        let state: Option<String> = tx
            .query_row(
                "SELECT use_state FROM source_versions WHERE tenant_namespace=?1 AND source_id=?2 AND version=?3",
                params![
                    tenant_namespace,
                    parent.parent.source_id,
                    parent.parent.version as i64
                ],
                |row| row.get(0),
            )
            .optional()?;
        if state.as_deref() != Some("ACTIVE") {
            return Err(StorageError::LineageInvalid);
        }
    }
    Ok(())
}

fn collect_dependent_closure(
    tx: &Transaction<'_>,
    root: &SourceIdentity,
) -> Result<Vec<SourceIdentity>> {
    let mut queue = VecDeque::from([root.clone()]);
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    while let Some(current) = queue.pop_front() {
        if !seen.insert((current.source_id.clone(), current.version)) {
            continue;
        }
        if seen.len() > MAX_CLOSURE_NODES {
            return Err(StorageError::ClosureTooLarge);
        }
        output.push(current.clone());
        let mut statement = tx.prepare(
            "SELECT child_source_id,child_version FROM lineage_edges \
             WHERE tenant_namespace=?1 AND parent_source_id=?2 AND parent_version=?3",
        )?;
        let rows = statement.query_map(
            params![
                root.tenant_namespace,
                current.source_id,
                current.version as i64
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?;
        for row in rows {
            let (source_id, version) = row?;
            queue.push_back(SourceIdentity {
                tenant_namespace: root.tenant_namespace.clone(),
                source_id,
                version: version as u64,
            });
        }
    }
    Ok(output)
}

fn validate_identity(source: &SourceIdentity) -> Result<()> {
    validate_opaque_id(&source.tenant_namespace)?;
    validate_opaque_id(&source.source_id)?;
    if source.version == 0 {
        return Err(StorageError::InvalidOpaqueId);
    }
    Ok(())
}

fn validate_opaque_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(StorageError::InvalidOpaqueId);
    }
    Ok(())
}

fn parse_use_state(value: &str) -> Result<AllowedUseState> {
    match value {
        "ACTIVE" => Ok(AllowedUseState::Active),
        "QUARANTINED" => Ok(AllowedUseState::Quarantined),
        "DISPUTED" => Ok(AllowedUseState::Disputed),
        "SUPERSEDED" => Ok(AllowedUseState::Superseded),
        "EXPIRED" => Ok(AllowedUseState::Expired),
        "BLOCKED" => Ok(AllowedUseState::Blocked),
        _ => Err(StorageError::IntegrityMismatch),
    }
}

fn parse_physical_state(value: &str) -> Result<PhysicalState> {
    match value {
        "PRESENT" => Ok(PhysicalState::Present),
        "PURGE_PENDING" => Ok(PhysicalState::PurgePending),
        "PURGED" => Ok(PhysicalState::Purged),
        "CRYPTO_ERASED" => Ok(PhysicalState::CryptoErased),
        "HELD_ISOLATED" => Ok(PhysicalState::HeldIsolated),
        "UNKNOWN" => Ok(PhysicalState::Unknown),
        _ => Err(StorageError::IntegrityMismatch),
    }
}

fn parse_copy_purge_state(value: &str) -> Result<CopyPurgeState> {
    match value {
        "NOT_REQUESTED" => Ok(CopyPurgeState::NotRequested),
        "PENDING" => Ok(CopyPurgeState::Pending),
        "CONFIRMED" => Ok(CopyPurgeState::Confirmed),
        "UNSUPPORTED" => Ok(CopyPurgeState::Unsupported),
        "FAILED" => Ok(CopyPurgeState::Failed),
        "UNKNOWN" => Ok(CopyPurgeState::Unknown),
        _ => Err(StorageError::IntegrityMismatch),
    }
}

fn parse_influence_role(value: &str) -> Result<InfluenceRole> {
    match value {
        "DATA_INPUT" => Ok(InfluenceRole::DataInput),
        "CONTROL_INPUT" => Ok(InfluenceRole::ControlInput),
        "SUPPORT_EVIDENCE" => Ok(InfluenceRole::SupportEvidence),
        "CONTRADICTION_EVIDENCE" => Ok(InfluenceRole::ContradictionEvidence),
        "CORRECTION" => Ok(InfluenceRole::Correction),
        _ => Err(StorageError::IntegrityMismatch),
    }
}

fn state_error<T>(state: AllowedUseState) -> Result<T> {
    match state {
        AllowedUseState::Quarantined => Err(StorageError::Quarantined),
        AllowedUseState::Blocked
        | AllowedUseState::Disputed
        | AllowedUseState::Superseded
        | AllowedUseState::Expired => Err(StorageError::Blocked),
        AllowedUseState::Active => Err(StorageError::IntegrityMismatch),
    }
}

fn blob_id_for(source: &SourceIdentity, lifecycle_epoch: u64) -> String {
    let input = format!(
        "{}\0{}\0{}\0{}",
        source.tenant_namespace, source.source_id, source.version, lifecycle_epoch
    );
    format!("blob-{}", sha256_hex(input.as_bytes()))
}

fn blob_aad(source: &SourceIdentity, lifecycle_epoch: u64) -> Vec<u8> {
    format!(
        "NOERITH-BLOB-v1\0{}\0{}\0{}\0{}",
        source.tenant_namespace, source.source_id, source.version, lifecycle_epoch
    )
    .into_bytes()
}

fn encrypt_blob(
    key: &[u8; 32],
    source: &SourceIdentity,
    lifecycle_epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    encrypt_framed(
        BLOB_MAGIC,
        key,
        &blob_aad(source, lifecycle_epoch),
        plaintext,
    )
}

fn decrypt_blob(
    key: &[u8; 32],
    source: &SourceIdentity,
    lifecycle_epoch: u64,
    encoded: &[u8],
) -> Result<Vec<u8>> {
    decrypt_framed(BLOB_MAGIC, key, &blob_aad(source, lifecycle_epoch), encoded)
}

fn encrypt_snapshot(key: &[u8; 32], tenant_namespace: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let aad = format!("NOERITH-SNAPSHOT-v1\0{tenant_namespace}");
    let framed = encrypt_framed(SNAPSHOT_MAGIC, key, aad.as_bytes(), plaintext)?;
    let mut output = Vec::with_capacity(4 + tenant_namespace.len() + framed.len());
    let tenant_len: u32 = tenant_namespace
        .len()
        .try_into()
        .map_err(|_| StorageError::InvalidOpaqueId)?;
    output.extend_from_slice(&tenant_len.to_be_bytes());
    output.extend_from_slice(tenant_namespace.as_bytes());
    output.extend_from_slice(&framed);
    Ok(output)
}

fn decrypt_snapshot(key: &[u8; 32], encoded: &[u8]) -> Result<(String, Vec<u8>)> {
    if encoded.len() < 4 {
        return Err(StorageError::IntegrityMismatch);
    }
    let tenant_len = u32::from_be_bytes(
        encoded[..4]
            .try_into()
            .map_err(|_| StorageError::IntegrityMismatch)?,
    ) as usize;
    if encoded.len() < 4 + tenant_len {
        return Err(StorageError::IntegrityMismatch);
    }
    let tenant = std::str::from_utf8(&encoded[4..4 + tenant_len])
        .map_err(|_| StorageError::IntegrityMismatch)?
        .to_owned();
    validate_opaque_id(&tenant)?;
    let aad = format!("NOERITH-SNAPSHOT-v1\0{tenant}");
    let plaintext = decrypt_framed(
        SNAPSHOT_MAGIC,
        key,
        aad.as_bytes(),
        &encoded[4 + tenant_len..],
    )?;
    Ok((tenant, plaintext))
}

fn encrypt_framed(
    magic: &[u8; 4],
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| StorageError::Crypto)?;
    let nonce = XNonce::generate();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| StorageError::Crypto)?;
    let mut output = Vec::with_capacity(magic.len() + 1 + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(magic);
    output.push(FORMAT_VERSION);
    output.extend_from_slice(nonce.as_ref());
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt_framed(magic: &[u8; 4], key: &[u8; 32], aad: &[u8], encoded: &[u8]) -> Result<Vec<u8>> {
    if encoded.len() < 5 + NONCE_LEN + 16 || &encoded[..4] != magic || encoded[4] != FORMAT_VERSION
    {
        return Err(StorageError::IntegrityMismatch);
    }
    let nonce_bytes: [u8; NONCE_LEN] = encoded[5..5 + NONCE_LEN]
        .try_into()
        .map_err(|_| StorageError::IntegrityMismatch)?;
    let nonce = XNonce::from(nonce_bytes);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| StorageError::Crypto)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &encoded[5 + NONCE_LEN..],
                aad,
            },
        )
        .map_err(|_| StorageError::Crypto)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing into String cannot fail");
    }
    output
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(StorageError::InvalidOpaqueId)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framed_crypto_binds_associated_data() {
        let key = [7_u8; 32];
        let source = SourceIdentity {
            tenant_namespace: "tenant-a".into(),
            source_id: "source-1".into(),
            version: 1,
        };
        let encoded = encrypt_blob(&key, &source, 1, b"private").expect("encrypt");
        assert_eq!(
            decrypt_blob(&key, &source, 1, &encoded).expect("decrypt"),
            b"private"
        );
        let wrong = SourceIdentity {
            tenant_namespace: "tenant-b".into(),
            ..source
        };
        assert!(decrypt_blob(&key, &wrong, 1, &encoded).is_err());
    }
}
