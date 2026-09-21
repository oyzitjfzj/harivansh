use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub tenant_namespace: String,
    pub source_id: String,
    pub version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AllowedUseState {
    Active,
    Quarantined,
    Disputed,
    Superseded,
    Expired,
    Blocked,
}

impl AllowedUseState {
    pub const fn as_db(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Quarantined => "QUARANTINED",
            Self::Disputed => "DISPUTED",
            Self::Superseded => "SUPERSEDED",
            Self::Expired => "EXPIRED",
            Self::Blocked => "BLOCKED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PhysicalState {
    Present,
    PurgePending,
    Purged,
    CryptoErased,
    HeldIsolated,
    Unknown,
}

impl PhysicalState {
    pub const fn as_db(self) -> &'static str {
        match self {
            Self::Present => "PRESENT",
            Self::PurgePending => "PURGE_PENDING",
            Self::Purged => "PURGED",
            Self::CryptoErased => "CRYPTO_ERASED",
            Self::HeldIsolated => "HELD_ISOLATED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CopyPurgeState {
    NotRequested,
    Pending,
    Confirmed,
    Unsupported,
    Failed,
    Unknown,
}

impl CopyPurgeState {
    pub const fn as_db(self) -> &'static str {
        match self {
            Self::NotRequested => "NOT_REQUESTED",
            Self::Pending => "PENDING",
            Self::Confirmed => "CONFIRMED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeleteJobState {
    Accepted,
    UseBlocked,
    Enumerating,
    Purging,
    Residuals,
    Complete,
}

impl DeleteJobState {
    pub const fn as_db(self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::UseBlocked => "USE_BLOCKED",
            Self::Enumerating => "ENUMERATING",
            Self::Purging => "PURGING",
            Self::Residuals => "RESIDUALS",
            Self::Complete => "COMPLETE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceRole {
    DataInput,
    ControlInput,
    SupportEvidence,
    ContradictionEvidence,
    Correction,
}

impl InfluenceRole {
    pub const fn as_db(self) -> &'static str {
        match self {
            Self::DataInput => "DATA_INPUT",
            Self::ControlInput => "CONTROL_INPUT",
            Self::SupportEvidence => "SUPPORT_EVIDENCE",
            Self::ContradictionEvidence => "CONTRADICTION_EVIDENCE",
            Self::Correction => "CORRECTION",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecord {
    pub identity: SourceIdentity,
    pub source_kind: String,
    pub original_blob_ref: String,
    pub media_type: String,
    pub byte_length: u64,
    pub digest_profile: String,
    pub digest: String,
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
    pub lifecycle_head_ref: String,
    pub lifecycle_epoch: u64,
    pub key_scope_ref: String,
    pub predecessor_ref: Option<SourceIdentity>,
    pub correction_event_ref: Option<String>,
    pub use_state: AllowedUseState,
    pub erasure_state: PhysicalState,
    pub authority_ref: Option<String>,
    pub authority_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfluenceEdge {
    pub child: SourceIdentity,
    pub parent: SourceIdentity,
    pub role: InfluenceRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyRecord {
    pub copy_id: String,
    pub source: SourceIdentity,
    pub copy_kind: String,
    pub custodian: String,
    pub locator_or_provider_request_ref: String,
    pub encryption_key_scope: String,
    pub created_at: String,
    pub allowed_purpose: String,
    pub retention_contract_ref: String,
    pub lifecycle_epoch_seen: u64,
    pub purge_capability: String,
    pub purge_state: CopyPurgeState,
    pub purge_receipt_ref: Option<String>,
    pub residual_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRead {
    pub source: SourceIdentity,
    pub source_lifecycle_epoch: u64,
    pub namespace_lifecycle_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub sqlite_version: String,
    pub cipher_version: String,
    pub cipher_provider: Option<String>,
    pub cipher_status: Option<String>,
    pub journal_mode: String,
    pub secure_delete: i64,
    pub temp_store: i64,
    pub schema_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryReport {
    pub orphan_staging_removed: usize,
    pub quarantined_registered_blobs: usize,
    pub purged_blob_files: usize,
    pub residual_copies: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPayload {
    pub format_version: u32,
    pub exported_namespace_epoch: u64,
    pub source: SourceRecord,
    pub search_text: String,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreResult {
    pub imported_source: SourceIdentity,
    pub use_state: AllowedUseState,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_enums_have_stable_external_names() {
        assert_eq!(AllowedUseState::Blocked.as_db(), "BLOCKED");
        assert_eq!(PhysicalState::PurgePending.as_db(), "PURGE_PENDING");
        assert_eq!(CopyPurgeState::Unknown.as_db(), "UNKNOWN");
        assert_eq!(DeleteJobState::UseBlocked.as_db(), "USE_BLOCKED");
        assert_eq!(InfluenceRole::Correction.as_db(), "CORRECTION");
    }

    #[test]
    fn source_identity_serialization_preserves_namespace_and_version() {
        let source = SourceIdentity {
            tenant_namespace: "tenant-a".into(),
            source_id: "source-1".into(),
            version: 7,
        };
        let encoded = serde_json::to_string(&source).expect("serialize identity");
        let decoded: SourceIdentity = serde_json::from_str(&encoded).expect("deserialize identity");
        assert_eq!(decoded, source);
    }
}
