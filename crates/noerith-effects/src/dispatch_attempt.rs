use crate::{DigestRef, EffectError, IdempotencyBinding, VersionedRef};
use noerith_storage::{DatabaseKeyPurpose, KeyProvider};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, path::Path};

const ATTEMPT_SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonotonicDeadline {
    pub clock_ref: String,
    pub deadline_tick: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartedAt {
    pub utc_timestamp: String,
    pub uncertainty_before: String,
    pub uncertainty_after: String,
    pub clock_source: String,
    pub synchronization_state: SynchronizationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynchronizationState {
    Synced,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderIdempotencyKey {
    Supported(String),
    Unsupported,
}

impl ProviderIdempotencyKey {
    pub fn from_binding(binding: &IdempotencyBinding) -> Self {
        match binding {
            IdempotencyBinding::Supported { key, .. } => Self::Supported(key.clone()),
            IdempotencyBinding::Unsupported => Self::Unsupported,
        }
    }

    fn validate(&self) -> Result<(), DispatchAttemptError> {
        if let Self::Supported(key) = self
            && key.trim().is_empty()
        {
            return Err(DispatchAttemptError::InvalidField(
                "provider_idempotency_key",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptTransportResult {
    NotSentProven,
    ResponseReceived,
    ResponseLost,
    ConnectionFailedAmbiguous,
    LocalAbort,
}

impl AttemptTransportResult {
    const fn as_db(self) -> &'static str {
        match self {
            Self::NotSentProven => "not-sent-proven",
            Self::ResponseReceived => "response-received",
            Self::ResponseLost => "response-lost",
            Self::ConnectionFailedAmbiguous => "connection-failed-ambiguous",
            Self::LocalAbort => "local-abort",
        }
    }

    fn parse(value: &str) -> Result<Self, DispatchAttemptError> {
        match value {
            "not-sent-proven" => Ok(Self::NotSentProven),
            "response-received" => Ok(Self::ResponseReceived),
            "response-lost" => Ok(Self::ResponseLost),
            "connection-failed-ambiguous" => Ok(Self::ConnectionFailedAmbiguous),
            "local-abort" => Ok(Self::LocalAbort),
            _ => Err(DispatchAttemptError::CorruptRecord),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptNextAction {
    None,
    RetrySameIntent,
    Reconcile,
    ManualReview,
}

impl AttemptNextAction {
    const fn as_db(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::RetrySameIntent => "retry-same-intent",
            Self::Reconcile => "reconcile",
            Self::ManualReview => "manual-review",
        }
    }

    fn parse(value: &str) -> Result<Self, DispatchAttemptError> {
        match value {
            "none" => Ok(Self::None),
            "retry-same-intent" => Ok(Self::RetrySameIntent),
            "reconcile" => Ok(Self::Reconcile),
            "manual-review" => Ok(Self::ManualReview),
            _ => Err(DispatchAttemptError::CorruptRecord),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchAttemptBinding {
    pub attempt_id: String,
    pub effect_intent_id: String,
    pub decision_snapshot: DigestRef,
    pub dispatch_claim_revision: u64,
    pub fencing_token: u64,
    pub adapter: VersionedRef,
    pub capability: VersionedRef,
    pub environment: VersionedRef,
    pub credential_handle_ref: String,
    pub provider_idempotency_key: ProviderIdempotencyKey,
    pub request_digest: String,
    pub started_at: StartedAt,
    pub monotonic_deadline: MonotonicDeadline,
}

impl DispatchAttemptBinding {
    pub fn validate(&self) -> Result<(), DispatchAttemptError> {
        for (name, value) in [
            ("attempt_id", self.attempt_id.as_str()),
            ("effect_intent_id", self.effect_intent_id.as_str()),
            (
                "decision_snapshot.ref_id",
                self.decision_snapshot.ref_id.as_str(),
            ),
            (
                "decision_snapshot.digest",
                self.decision_snapshot.digest.as_str(),
            ),
            ("adapter.ref_id", self.adapter.ref_id.as_str()),
            ("capability.ref_id", self.capability.ref_id.as_str()),
            ("environment.ref_id", self.environment.ref_id.as_str()),
            ("credential_handle_ref", self.credential_handle_ref.as_str()),
            ("request_digest", self.request_digest.as_str()),
            (
                "started_at.utc_timestamp",
                self.started_at.utc_timestamp.as_str(),
            ),
            (
                "started_at.uncertainty_before",
                self.started_at.uncertainty_before.as_str(),
            ),
            (
                "started_at.uncertainty_after",
                self.started_at.uncertainty_after.as_str(),
            ),
            (
                "started_at.clock_source",
                self.started_at.clock_source.as_str(),
            ),
            (
                "monotonic_deadline.clock_ref",
                self.monotonic_deadline.clock_ref.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(DispatchAttemptError::InvalidField(name));
            }
        }
        if self.dispatch_claim_revision == 0 || self.fencing_token == 0 {
            return Err(DispatchAttemptError::InvalidClaim);
        }
        self.provider_idempotency_key.validate()?;
        Ok(())
    }

    fn digest(&self) -> Result<String, DispatchAttemptError> {
        let bytes = serde_json::to_vec(self)?;
        Ok(sha256_hex(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedDispatchAttempt {
    pub binding: DispatchAttemptBinding,
    pub transport_result: AttemptTransportResult,
    pub provider_status_receipt_refs: Vec<String>,
    pub next_action: AttemptNextAction,
    pub finalized_at_ms: u64,
}

#[derive(Debug)]
pub enum DispatchAttemptError {
    InvalidField(&'static str),
    InvalidClaim,
    MissingEvidence,
    DuplicateAttemptConflict,
    AlreadyFinalized,
    NotFound,
    CorruptRecord,
    KeyProvider(String),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    ClockRange,
}

impl PartialEq for DispatchAttemptError {
    fn eq(&self, other: &Self) -> bool {
        use DispatchAttemptError::{
            AlreadyFinalized, ClockRange, CorruptRecord, DuplicateAttemptConflict, InvalidClaim,
            MissingEvidence, NotFound,
        };
        matches!(
            (self, other),
            (InvalidClaim, InvalidClaim)
                | (MissingEvidence, MissingEvidence)
                | (DuplicateAttemptConflict, DuplicateAttemptConflict)
                | (AlreadyFinalized, AlreadyFinalized)
                | (NotFound, NotFound)
                | (CorruptRecord, CorruptRecord)
                | (ClockRange, ClockRange)
        ) || matches!((self, other), (Self::InvalidField(a), Self::InvalidField(b)) if a == b)
    }
}

impl Eq for DispatchAttemptError {}

impl fmt::Display for DispatchAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DispatchAttemptError {}

impl From<rusqlite::Error> for DispatchAttemptError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<serde_json::Error> for DispatchAttemptError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<EffectError> for DispatchAttemptError {
    fn from(value: EffectError) -> Self {
        Self::KeyProvider(value.to_string())
    }
}

pub struct DispatchAttemptLedger {
    connection: Connection,
}

impl DispatchAttemptLedger {
    pub fn open(
        path: impl AsRef<Path>,
        provider: &impl KeyProvider,
    ) -> Result<Self, DispatchAttemptError> {
        let key = provider
            .database_passphrase(DatabaseKeyPurpose::EffectLedger)
            .map_err(|error| DispatchAttemptError::KeyProvider(error.to_string()))?;
        if key.trim().is_empty() {
            return Err(DispatchAttemptError::KeyProvider(
                "empty effect-ledger key".into(),
            ));
        }
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "key", key.as_str())?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if cipher_version.trim().is_empty() {
            return Err(DispatchAttemptError::KeyProvider(
                "SQLCipher unavailable".into(),
            ));
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.pragma_update(None, "busy_timeout", 5000_i64)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(DispatchAttemptError::KeyProvider("WAL unavailable".into()));
        }
        initialize_schema(&mut connection)?;
        Ok(Self { connection })
    }

    pub fn start_attempt(
        &mut self,
        tenant_namespace: &str,
        binding: &DispatchAttemptBinding,
        created_at_ms: u64,
    ) -> Result<bool, DispatchAttemptError> {
        require_text(tenant_namespace, "tenant_namespace")?;
        binding.validate()?;
        let binding_json = serde_json::to_string(binding)?;
        let binding_digest = binding.digest()?;
        let created_at = as_i64(created_at_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT binding_digest,binding_json FROM dispatch_attempt_v01 WHERE tenant_namespace=?1 AND attempt_id=?2",
                params![tenant_namespace, binding.attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((digest, json)) = existing {
            if digest == binding_digest && json == binding_json {
                tx.commit()?;
                return Ok(false);
            }
            return Err(DispatchAttemptError::DuplicateAttemptConflict);
        }
        tx.execute(
            "INSERT INTO dispatch_attempt_v01(tenant_namespace,attempt_id,effect_intent_id,binding_json,binding_digest,transport_result,next_action,finalized_at,created_at) \
             VALUES(?1,?2,?3,?4,?5,NULL,NULL,NULL,?6)",
            params![
                tenant_namespace,
                binding.attempt_id,
                binding.effect_intent_id,
                binding_json,
                binding_digest,
                created_at
            ],
        )?;
        tx.execute(
            "INSERT INTO dispatch_attempt_events(tenant_namespace,attempt_id,event_type,evidence_ref,recorded_at) VALUES(?1,?2,'ATTEMPT_BOUND',?3,?4)",
            params![tenant_namespace, binding.attempt_id, binding.request_digest, created_at],
        )?;
        tx.commit()?;
        Ok(true)
    }

    // Finalization is one atomic evidence write; keeping each bound field explicit avoids
    // hiding authority/evidence semantics inside an opaque bag solely to satisfy a lint.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_once(
        &mut self,
        tenant_namespace: &str,
        attempt_id: &str,
        transport_result: AttemptTransportResult,
        provider_status_receipt_refs: &[String],
        next_action: AttemptNextAction,
        evidence_ref: &str,
        finalized_at_ms: u64,
    ) -> Result<bool, DispatchAttemptError> {
        require_text(tenant_namespace, "tenant_namespace")?;
        require_text(attempt_id, "attempt_id")?;
        require_text(evidence_ref, "evidence_ref")?;
        if provider_status_receipt_refs
            .iter()
            .any(|item| item.trim().is_empty())
        {
            return Err(DispatchAttemptError::MissingEvidence);
        }
        validate_result_action(transport_result, next_action)?;
        let finalized_at = as_i64(finalized_at_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(Option<String>, Option<String>, Option<i64>)> = tx
            .query_row(
                "SELECT transport_result,next_action,finalized_at FROM dispatch_attempt_v01 WHERE tenant_namespace=?1 AND attempt_id=?2",
                params![tenant_namespace, attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((current_result, current_action, current_finalized_at)) = current else {
            return Err(DispatchAttemptError::NotFound);
        };
        if let (Some(existing_result), Some(existing_action), Some(existing_time)) =
            (current_result, current_action, current_finalized_at)
        {
            if existing_result == transport_result.as_db()
                && existing_action == next_action.as_db()
                && existing_time == finalized_at
            {
                tx.commit()?;
                return Ok(false);
            }
            return Err(DispatchAttemptError::AlreadyFinalized);
        }
        tx.execute(
            "UPDATE dispatch_attempt_v01 SET transport_result=?3,next_action=?4,finalized_at=?5 \
             WHERE tenant_namespace=?1 AND attempt_id=?2 AND transport_result IS NULL",
            params![
                tenant_namespace,
                attempt_id,
                transport_result.as_db(),
                next_action.as_db(),
                finalized_at
            ],
        )?;
        for reference in provider_status_receipt_refs {
            tx.execute(
                "INSERT OR IGNORE INTO dispatch_attempt_evidence(tenant_namespace,attempt_id,evidence_ref) VALUES(?1,?2,?3)",
                params![tenant_namespace, attempt_id, reference],
            )?;
        }
        tx.execute(
            "INSERT INTO dispatch_attempt_events(tenant_namespace,attempt_id,event_type,evidence_ref,recorded_at) VALUES(?1,?2,'TRANSPORT_FINALIZED',?3,?4)",
            params![tenant_namespace, attempt_id, evidence_ref, finalized_at],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn finalized_attempt(
        &self,
        tenant_namespace: &str,
        attempt_id: &str,
    ) -> Result<FinalizedDispatchAttempt, DispatchAttemptError> {
        let row: Option<(String, String, String, i64)> = self
            .connection
            .query_row(
                "SELECT binding_json,transport_result,next_action,finalized_at FROM dispatch_attempt_v01 \
                 WHERE tenant_namespace=?1 AND attempt_id=?2 AND transport_result IS NOT NULL",
                params![tenant_namespace, attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((binding_json, transport_result, next_action, finalized_at)) = row else {
            return Err(DispatchAttemptError::NotFound);
        };
        let binding: DispatchAttemptBinding = serde_json::from_str(&binding_json)?;
        binding.validate()?;
        let provider_status_receipt_refs = self.evidence_refs(tenant_namespace, attempt_id)?;
        Ok(FinalizedDispatchAttempt {
            binding,
            transport_result: AttemptTransportResult::parse(&transport_result)?,
            provider_status_receipt_refs,
            next_action: AttemptNextAction::parse(&next_action)?,
            finalized_at_ms: u64::try_from(finalized_at)
                .map_err(|_| DispatchAttemptError::CorruptRecord)?,
        })
    }

    pub fn verify_binding(
        &self,
        tenant_namespace: &str,
        attempt_id: &str,
    ) -> Result<(), DispatchAttemptError> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT binding_json,binding_digest FROM dispatch_attempt_v01 WHERE tenant_namespace=?1 AND attempt_id=?2",
                params![tenant_namespace, attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((binding_json, stored_digest)) = row else {
            return Err(DispatchAttemptError::NotFound);
        };
        let binding: DispatchAttemptBinding = serde_json::from_str(&binding_json)?;
        binding.validate()?;
        let actual = binding.digest()?;
        if actual != stored_digest {
            return Err(DispatchAttemptError::CorruptRecord);
        }
        Ok(())
    }

    fn evidence_refs(
        &self,
        tenant_namespace: &str,
        attempt_id: &str,
    ) -> Result<Vec<String>, DispatchAttemptError> {
        let mut statement = self.connection.prepare(
            "SELECT evidence_ref FROM dispatch_attempt_evidence WHERE tenant_namespace=?1 AND attempt_id=?2 ORDER BY evidence_ref",
        )?;
        let rows = statement.query_map(params![tenant_namespace, attempt_id], |row| {
            row.get::<_, String>(0)
        })?;
        let mut refs = Vec::new();
        for row in rows {
            refs.push(row?);
        }
        Ok(refs)
    }
}

fn validate_result_action(
    result: AttemptTransportResult,
    action: AttemptNextAction,
) -> Result<(), DispatchAttemptError> {
    let valid = match result {
        AttemptTransportResult::NotSentProven | AttemptTransportResult::LocalAbort => {
            matches!(
                action,
                AttemptNextAction::None | AttemptNextAction::RetrySameIntent
            )
        }
        AttemptTransportResult::ResponseReceived => matches!(action, AttemptNextAction::None),
        AttemptTransportResult::ResponseLost
        | AttemptTransportResult::ConnectionFailedAmbiguous => {
            matches!(
                action,
                AttemptNextAction::RetrySameIntent
                    | AttemptNextAction::Reconcile
                    | AttemptNextAction::ManualReview
            )
        }
    };
    if valid {
        Ok(())
    } else {
        Err(DispatchAttemptError::InvalidField("next_action"))
    }
}

fn initialize_schema(connection: &mut Connection) -> Result<(), DispatchAttemptError> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS dispatch_attempt_schema_meta(schema_version INTEGER NOT NULL);\
         CREATE TABLE IF NOT EXISTS dispatch_attempt_v01(\
           tenant_namespace TEXT NOT NULL,attempt_id TEXT NOT NULL,effect_intent_id TEXT NOT NULL,\
           binding_json TEXT NOT NULL,binding_digest TEXT NOT NULL,transport_result TEXT NULL,next_action TEXT NULL,\
           finalized_at INTEGER NULL,created_at INTEGER NOT NULL,\
           PRIMARY KEY(tenant_namespace,attempt_id));\
         CREATE TABLE IF NOT EXISTS dispatch_attempt_evidence(\
           tenant_namespace TEXT NOT NULL,attempt_id TEXT NOT NULL,evidence_ref TEXT NOT NULL,\
           PRIMARY KEY(tenant_namespace,attempt_id,evidence_ref),\
           FOREIGN KEY(tenant_namespace,attempt_id) REFERENCES dispatch_attempt_v01(tenant_namespace,attempt_id));\
         CREATE TABLE IF NOT EXISTS dispatch_attempt_events(\
           event_id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_namespace TEXT NOT NULL,attempt_id TEXT NOT NULL,\
           event_type TEXT NOT NULL,evidence_ref TEXT NOT NULL,recorded_at INTEGER NOT NULL,\
           FOREIGN KEY(tenant_namespace,attempt_id) REFERENCES dispatch_attempt_v01(tenant_namespace,attempt_id));",
    )?;
    let current: Option<i64> = tx
        .query_row(
            "SELECT schema_version FROM dispatch_attempt_schema_meta LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match current {
        Some(version) if version == ATTEMPT_SCHEMA_VERSION => {}
        Some(_) => return Err(DispatchAttemptError::CorruptRecord),
        None => {
            tx.execute(
                "INSERT INTO dispatch_attempt_schema_meta(schema_version) VALUES(?1)",
                [ATTEMPT_SCHEMA_VERSION],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn require_text(value: &str, name: &'static str) -> Result<(), DispatchAttemptError> {
    if value.trim().is_empty() {
        Err(DispatchAttemptError::InvalidField(name))
    } else {
        Ok(())
    }
}

fn as_i64(value: u64) -> Result<i64, DispatchAttemptError> {
    i64::try_from(value).map_err(|_| DispatchAttemptError::ClockRange)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
