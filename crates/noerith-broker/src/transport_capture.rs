use noerith_effects::{DigestRef, SynchronizationState};
use noerith_storage::{DatabaseKeyPurpose, KeyProvider};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, path::Path};

const CAPTURE_SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCaptureBinding {
    pub tenant_namespace: String,
    pub release_id: String,
    pub effect_intent_id: String,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub decision_snapshot: DigestRef,
    pub fencing_token: u64,
    pub request_digest: String,
    pub adapter_ref: String,
    /// Opaque exact version token. No numeric/semver meaning is inferred here.
    pub adapter_version: String,
}

impl TransportCaptureBinding {
    pub fn validate(&self) -> Result<(), TransportCaptureError> {
        for (name, value) in [
            ("tenant_namespace", self.tenant_namespace.as_str()),
            ("release_id", self.release_id.as_str()),
            ("effect_intent_id", self.effect_intent_id.as_str()),
            ("attempt_id", self.attempt_id.as_str()),
            (
                "decision_snapshot.ref_id",
                self.decision_snapshot.ref_id.as_str(),
            ),
            (
                "decision_snapshot.digest",
                self.decision_snapshot.digest.as_str(),
            ),
            ("request_digest", self.request_digest.as_str()),
            ("adapter_ref", self.adapter_ref.as_str()),
            ("adapter_version", self.adapter_version.as_str()),
        ] {
            require_text(value, name)?;
        }
        if self.attempt_number == 0 || self.fencing_token == 0 {
            return Err(TransportCaptureError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapturedTransportResult {
    NotSentProven { evidence_ref: String },
    Accepted { receipt_ref: String },
    RejectedNoEffect { evidence_ref: String },
    ResponseLost { evidence_ref: String },
    ConnectionFailedAmbiguous { evidence_ref: String },
}

impl CapturedTransportResult {
    pub fn evidence_ref(&self) -> &str {
        match self {
            Self::NotSentProven { evidence_ref }
            | Self::RejectedNoEffect { evidence_ref }
            | Self::ResponseLost { evidence_ref }
            | Self::ConnectionFailedAmbiguous { evidence_ref } => evidence_ref,
            Self::Accepted { receipt_ref } => receipt_ref,
        }
    }

    fn validate(&self) -> Result<(), TransportCaptureError> {
        require_text(self.evidence_ref(), "transport_result.evidence_ref")
    }
}

/// Physical-time evidence attached to the returned provider result.
///
/// This is deliberately separate from local durable ordering. A returned result
/// remains evidence even when a trustworthy physical clock is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "time_kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureTimeEvidence {
    Observed {
        unix_time_ms: u64,
        uncertainty_before_ms: u64,
        uncertainty_after_ms: u64,
        clock_source: String,
        synchronization_state: SynchronizationState,
    },
    Unavailable {
        reason: String,
        evidence_ref: String,
    },
    /// Loaded only from a pre-v2 row. It must never be presented as qualified
    /// synchronized physical time and cannot be written through the typed API.
    LegacyScalar { captured_at_ms: u64 },
}

impl CaptureTimeEvidence {
    fn validate_for_new_capture(&self) -> Result<(), TransportCaptureError> {
        match self {
            Self::Observed { clock_source, .. } => {
                require_text(clock_source, "capture_time.clock_source")
            }
            Self::Unavailable {
                reason,
                evidence_ref,
            } => {
                require_text(reason, "capture_time.reason")?;
                require_text(evidence_ref, "capture_time.evidence_ref")
            }
            Self::LegacyScalar { .. } => Err(TransportCaptureError::LegacyTimeWriteRejected),
        }
    }

    fn validate_loaded(&self) -> Result<(), TransportCaptureError> {
        match self {
            Self::Observed { clock_source, .. } => {
                require_text(clock_source, "capture_time.clock_source")
            }
            Self::Unavailable {
                reason,
                evidence_ref,
            } => {
                require_text(reason, "capture_time.reason")?;
                require_text(evidence_ref, "capture_time.evidence_ref")
            }
            Self::LegacyScalar { .. } => Ok(()),
        }
    }
}

/// Compatibility view for v1 callers. Typed v2 rows are intentionally not
/// projected into this shape because doing so could turn unavailable/degraded
/// time into a fake scalar wall-clock claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedTransportRecord {
    pub binding: TransportCaptureBinding,
    pub result: CapturedTransportResult,
    pub captured_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedCapturedTransportRecord {
    pub binding: TransportCaptureBinding,
    pub result: CapturedTransportResult,
    pub time_evidence: CaptureTimeEvidence,
    /// Ledger-local durable order token. `None` means a pre-v2 record for which
    /// no independent local-order fact was stored.
    pub local_order: Option<u64>,
}

#[derive(Debug)]
pub enum TransportCaptureError {
    InvalidField(&'static str),
    InvalidBinding,
    DuplicateCaptureConflict,
    NotFound,
    CorruptRecord,
    ClockRange,
    LocalOrderRange,
    LegacyTimeWriteRejected,
    TypedEvidenceRequired,
    KeyProvider(String),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

impl PartialEq for TransportCaptureError {
    fn eq(&self, other: &Self) -> bool {
        use TransportCaptureError::{
            ClockRange, CorruptRecord, DuplicateCaptureConflict, InvalidBinding,
            LegacyTimeWriteRejected, LocalOrderRange, NotFound, TypedEvidenceRequired,
        };
        matches!(
            (self, other),
            (InvalidBinding, InvalidBinding)
                | (DuplicateCaptureConflict, DuplicateCaptureConflict)
                | (NotFound, NotFound)
                | (CorruptRecord, CorruptRecord)
                | (ClockRange, ClockRange)
                | (LocalOrderRange, LocalOrderRange)
                | (LegacyTimeWriteRejected, LegacyTimeWriteRejected)
                | (TypedEvidenceRequired, TypedEvidenceRequired)
        ) || matches!((self, other), (Self::InvalidField(a), Self::InvalidField(b)) if a == b)
    }
}

impl Eq for TransportCaptureError {}

impl fmt::Display for TransportCaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(name) => write!(f, "invalid transport-capture field: {name}"),
            Self::InvalidBinding => f.write_str("invalid transport-capture binding"),
            Self::DuplicateCaptureConflict => f.write_str("conflicting transport result capture"),
            Self::NotFound => f.write_str("transport result capture not found"),
            Self::CorruptRecord => f.write_str("transport result capture corrupt"),
            Self::ClockRange => f.write_str("transport result capture clock out of range"),
            Self::LocalOrderRange => {
                f.write_str("transport result capture local order out of range")
            }
            Self::LegacyTimeWriteRejected => {
                f.write_str("legacy scalar time cannot be written as new typed evidence")
            }
            Self::TypedEvidenceRequired => {
                f.write_str("typed transport-capture evidence requires typed load API")
            }
            Self::KeyProvider(_) => f.write_str("transport result capture key-provider error"),
            Self::Sqlite(_) => f.write_str("transport result capture storage error"),
            Self::Json(_) => f.write_str("transport result capture serialization error"),
        }
    }
}

impl std::error::Error for TransportCaptureError {}

impl From<rusqlite::Error> for TransportCaptureError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<serde_json::Error> for TransportCaptureError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub struct TransportCaptureLedger {
    connection: Connection,
}

#[derive(Debug)]
struct RawCaptureRow {
    effect_intent_id: String,
    attempt_id: String,
    attempt_number: i64,
    binding_json: String,
    binding_digest: String,
    result_json: String,
    result_digest: String,
    captured_at: i64,
    time_evidence_json: Option<String>,
    time_evidence_digest: Option<String>,
    local_order: Option<i64>,
}

impl TransportCaptureLedger {
    pub fn open(
        path: impl AsRef<Path>,
        provider: &impl KeyProvider,
    ) -> Result<Self, TransportCaptureError> {
        let key = provider
            .database_passphrase(DatabaseKeyPurpose::EffectLedger)
            .map_err(|error| TransportCaptureError::KeyProvider(error.to_string()))?;
        if key.trim().is_empty() {
            return Err(TransportCaptureError::KeyProvider("empty key".into()));
        }
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "key", key.as_str())?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if cipher_version.trim().is_empty() {
            return Err(TransportCaptureError::KeyProvider(
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
            return Err(TransportCaptureError::CorruptRecord);
        }
        initialize_schema(&mut connection)?;
        Ok(Self { connection })
    }

    /// Transitional v1-compatible capture. The scalar is preserved exactly and
    /// later typed loads classify it as legacy rather than inventing clock quality.
    pub fn capture_once(
        &mut self,
        binding: &TransportCaptureBinding,
        result: &CapturedTransportResult,
        captured_at_ms: u64,
    ) -> Result<bool, TransportCaptureError> {
        binding.validate()?;
        result.validate()?;
        let binding_json = serde_json::to_string(binding)?;
        let result_json = serde_json::to_string(result)?;
        let binding_digest = sha256_hex(binding_json.as_bytes());
        let result_digest = sha256_hex(result_json.as_bytes());
        let captured_at = as_i64(captured_at_ms)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            load_raw_row_tx(&tx, &binding.tenant_namespace, &binding.release_id)?
        {
            validate_raw_row(&existing, &binding.tenant_namespace, &binding.release_id)?;
            if existing.binding_json == binding_json
                && existing.binding_digest == binding_digest
                && existing.result_json == result_json
                && existing.result_digest == result_digest
                && existing.captured_at == captured_at
                && existing.time_evidence_json.is_none()
                && existing.time_evidence_digest.is_none()
                && existing.local_order.is_none()
            {
                tx.commit()?;
                return Ok(false);
            }
            return Err(TransportCaptureError::DuplicateCaptureConflict);
        }

        tx.execute(
            "INSERT INTO broker_transport_capture_v01(\
                tenant_namespace,release_id,effect_intent_id,attempt_id,attempt_number,\
                binding_json,binding_digest,result_json,result_digest,captured_at,\
                time_evidence_json,time_evidence_digest,local_order) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL,NULL)",
            params![
                binding.tenant_namespace,
                binding.release_id,
                binding.effect_intent_id,
                binding.attempt_id,
                i64::from(binding.attempt_number),
                binding_json,
                binding_digest,
                result_json,
                result_digest,
                captured_at,
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Final typed capture path. `time_evidence` describes post-return physical
    /// time confidence. The local order token is allocated inside the same
    /// immediate transaction, so callers cannot forge or reuse ordering values.
    pub fn capture_once_with_evidence(
        &mut self,
        binding: &TransportCaptureBinding,
        result: &CapturedTransportResult,
        time_evidence: &CaptureTimeEvidence,
    ) -> Result<bool, TransportCaptureError> {
        binding.validate()?;
        result.validate()?;
        time_evidence.validate_for_new_capture()?;

        let binding_json = serde_json::to_string(binding)?;
        let result_json = serde_json::to_string(result)?;
        let time_json = serde_json::to_string(time_evidence)?;
        let binding_digest = sha256_hex(binding_json.as_bytes());
        let result_digest = sha256_hex(result_json.as_bytes());
        let time_digest = sha256_hex(time_json.as_bytes());
        let legacy_placeholder = match time_evidence {
            CaptureTimeEvidence::Observed { unix_time_ms, .. } => as_i64(*unix_time_ms)?,
            CaptureTimeEvidence::Unavailable { .. } => 0,
            CaptureTimeEvidence::LegacyScalar { .. } => {
                return Err(TransportCaptureError::LegacyTimeWriteRejected);
            }
        };

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            load_raw_row_tx(&tx, &binding.tenant_namespace, &binding.release_id)?
        {
            validate_raw_row(&existing, &binding.tenant_namespace, &binding.release_id)?;
            if existing.binding_json == binding_json
                && existing.binding_digest == binding_digest
                && existing.result_json == result_json
                && existing.result_digest == result_digest
                && existing.time_evidence_json.as_deref() == Some(time_json.as_str())
                && existing.time_evidence_digest.as_deref() == Some(time_digest.as_str())
            {
                tx.commit()?;
                return Ok(false);
            }
            return Err(TransportCaptureError::DuplicateCaptureConflict);
        }

        let local_order = allocate_local_order(&tx)?;
        tx.execute(
            "INSERT INTO broker_transport_capture_v01(\
                tenant_namespace,release_id,effect_intent_id,attempt_id,attempt_number,\
                binding_json,binding_digest,result_json,result_digest,captured_at,\
                time_evidence_json,time_evidence_digest,local_order) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                binding.tenant_namespace,
                binding.release_id,
                binding.effect_intent_id,
                binding.attempt_id,
                i64::from(binding.attempt_number),
                binding_json,
                binding_digest,
                result_json,
                result_digest,
                legacy_placeholder,
                time_json,
                time_digest,
                local_order,
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Compatibility loader for pre-v2 callers. Typed rows are rejected rather
    /// than being flattened into a misleading scalar timestamp.
    pub fn load(
        &self,
        tenant_namespace: &str,
        release_id: &str,
    ) -> Result<CapturedTransportRecord, TransportCaptureError> {
        let raw = self.load_checked_raw(tenant_namespace, release_id)?;
        if raw.time_evidence_json.is_some()
            || raw.time_evidence_digest.is_some()
            || raw.local_order.is_some()
        {
            return Err(TransportCaptureError::TypedEvidenceRequired);
        }
        Ok(CapturedTransportRecord {
            binding: serde_json::from_str(&raw.binding_json)?,
            result: serde_json::from_str(&raw.result_json)?,
            captured_at_ms: u64::try_from(raw.captured_at)
                .map_err(|_| TransportCaptureError::ClockRange)?,
        })
    }

    /// Typed loader. Existing v1 rows remain explicit `LegacyScalar` evidence;
    /// mixed/partial v2 rows are corruption rather than guessed defaults.
    pub fn load_with_evidence(
        &self,
        tenant_namespace: &str,
        release_id: &str,
    ) -> Result<TypedCapturedTransportRecord, TransportCaptureError> {
        let raw = self.load_checked_raw(tenant_namespace, release_id)?;
        let binding: TransportCaptureBinding = serde_json::from_str(&raw.binding_json)?;
        let result: CapturedTransportResult = serde_json::from_str(&raw.result_json)?;

        match (
            raw.time_evidence_json,
            raw.time_evidence_digest,
            raw.local_order,
        ) {
            (None, None, None) => Ok(TypedCapturedTransportRecord {
                binding,
                result,
                time_evidence: CaptureTimeEvidence::LegacyScalar {
                    captured_at_ms: u64::try_from(raw.captured_at)
                        .map_err(|_| TransportCaptureError::ClockRange)?,
                },
                local_order: None,
            }),
            (Some(time_json), Some(_), Some(local_order)) => {
                let time_evidence: CaptureTimeEvidence = serde_json::from_str(&time_json)?;
                Ok(TypedCapturedTransportRecord {
                    binding,
                    result,
                    time_evidence,
                    local_order: Some(
                        u64::try_from(local_order)
                            .map_err(|_| TransportCaptureError::LocalOrderRange)?,
                    ),
                })
            }
            _ => Err(TransportCaptureError::CorruptRecord),
        }
    }

    fn load_checked_raw(
        &self,
        tenant_namespace: &str,
        release_id: &str,
    ) -> Result<RawCaptureRow, TransportCaptureError> {
        require_text(tenant_namespace, "tenant_namespace")?;
        require_text(release_id, "release_id")?;
        let raw = load_raw_row_connection(&self.connection, tenant_namespace, release_id)?
            .ok_or(TransportCaptureError::NotFound)?;
        validate_raw_row(&raw, tenant_namespace, release_id)?;
        Ok(raw)
    }
}

fn load_raw_row_connection(
    connection: &Connection,
    tenant_namespace: &str,
    release_id: &str,
) -> Result<Option<RawCaptureRow>, TransportCaptureError> {
    connection
        .query_row(
            "SELECT effect_intent_id,attempt_id,attempt_number,binding_json,binding_digest,\
                    result_json,result_digest,captured_at,time_evidence_json,time_evidence_digest,local_order \
             FROM broker_transport_capture_v01 \
             WHERE tenant_namespace=?1 AND release_id=?2",
            params![tenant_namespace, release_id],
            raw_row,
        )
        .optional()
        .map_err(Into::into)
}

fn load_raw_row_tx(
    tx: &Transaction<'_>,
    tenant_namespace: &str,
    release_id: &str,
) -> Result<Option<RawCaptureRow>, TransportCaptureError> {
    tx.query_row(
        "SELECT effect_intent_id,attempt_id,attempt_number,binding_json,binding_digest,\
                result_json,result_digest,captured_at,time_evidence_json,time_evidence_digest,local_order \
         FROM broker_transport_capture_v01 \
         WHERE tenant_namespace=?1 AND release_id=?2",
        params![tenant_namespace, release_id],
        raw_row,
    )
    .optional()
    .map_err(Into::into)
}

fn raw_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawCaptureRow> {
    Ok(RawCaptureRow {
        effect_intent_id: row.get(0)?,
        attempt_id: row.get(1)?,
        attempt_number: row.get(2)?,
        binding_json: row.get(3)?,
        binding_digest: row.get(4)?,
        result_json: row.get(5)?,
        result_digest: row.get(6)?,
        captured_at: row.get(7)?,
        time_evidence_json: row.get(8)?,
        time_evidence_digest: row.get(9)?,
        local_order: row.get(10)?,
    })
}

fn validate_raw_row(
    raw: &RawCaptureRow,
    tenant_namespace: &str,
    release_id: &str,
) -> Result<(), TransportCaptureError> {
    if sha256_hex(raw.binding_json.as_bytes()) != raw.binding_digest
        || sha256_hex(raw.result_json.as_bytes()) != raw.result_digest
    {
        return Err(TransportCaptureError::CorruptRecord);
    }
    let binding: TransportCaptureBinding = serde_json::from_str(&raw.binding_json)?;
    let result: CapturedTransportResult = serde_json::from_str(&raw.result_json)?;
    binding.validate()?;
    result.validate()?;
    if binding.tenant_namespace != tenant_namespace
        || binding.release_id != release_id
        || binding.effect_intent_id != raw.effect_intent_id
        || binding.attempt_id != raw.attempt_id
        || i64::from(binding.attempt_number) != raw.attempt_number
    {
        return Err(TransportCaptureError::CorruptRecord);
    }

    match (
        raw.time_evidence_json.as_deref(),
        raw.time_evidence_digest.as_deref(),
        raw.local_order,
    ) {
        (None, None, None) => {
            u64::try_from(raw.captured_at).map_err(|_| TransportCaptureError::ClockRange)?;
        }
        (Some(time_json), Some(time_digest), Some(local_order)) => {
            if sha256_hex(time_json.as_bytes()) != time_digest {
                return Err(TransportCaptureError::CorruptRecord);
            }
            let time_evidence: CaptureTimeEvidence = serde_json::from_str(time_json)?;
            time_evidence.validate_loaded()?;
            if matches!(time_evidence, CaptureTimeEvidence::LegacyScalar { .. }) {
                return Err(TransportCaptureError::CorruptRecord);
            }
            if local_order <= 0 {
                return Err(TransportCaptureError::LocalOrderRange);
            }
            match time_evidence {
                CaptureTimeEvidence::Observed { unix_time_ms, .. } => {
                    if raw.captured_at != as_i64(unix_time_ms)? {
                        return Err(TransportCaptureError::CorruptRecord);
                    }
                }
                CaptureTimeEvidence::Unavailable { .. } => {
                    if raw.captured_at != 0 {
                        return Err(TransportCaptureError::CorruptRecord);
                    }
                }
                CaptureTimeEvidence::LegacyScalar { .. } => unreachable!(),
            }
        }
        _ => return Err(TransportCaptureError::CorruptRecord),
    }
    Ok(())
}

fn allocate_local_order(tx: &Transaction<'_>) -> Result<i64, TransportCaptureError> {
    let current: i64 = tx.query_row(
        "SELECT next_order FROM broker_transport_capture_sequence WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if current <= 0 || current == i64::MAX {
        return Err(TransportCaptureError::LocalOrderRange);
    }
    let changed = tx.execute(
        "UPDATE broker_transport_capture_sequence SET next_order=?1 WHERE singleton=1 AND next_order=?2",
        params![current + 1, current],
    )?;
    if changed != 1 {
        return Err(TransportCaptureError::CorruptRecord);
    }
    Ok(current)
}

fn initialize_schema(connection: &mut Connection) -> Result<(), TransportCaptureError> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS broker_transport_capture_meta(\
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),\
            schema_version INTEGER NOT NULL);\
         CREATE TABLE IF NOT EXISTS broker_transport_capture_v01(\
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
            time_evidence_json TEXT,\
            time_evidence_digest TEXT,\
            local_order INTEGER,\
            PRIMARY KEY(tenant_namespace,release_id));\
         CREATE TABLE IF NOT EXISTS broker_transport_capture_sequence(\
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),\
            next_order INTEGER NOT NULL CHECK(next_order>0));",
    )?;

    let current: Option<i64> = tx
        .query_row(
            "SELECT schema_version FROM broker_transport_capture_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;

    match current {
        None => {
            ensure_v2_columns(&tx)?;
            tx.execute(
                "INSERT INTO broker_transport_capture_meta(singleton,schema_version) VALUES(1,?1)",
                [CAPTURE_SCHEMA_VERSION],
            )?;
        }
        Some(1) => {
            ensure_v2_columns(&tx)?;
            tx.execute(
                "UPDATE broker_transport_capture_meta SET schema_version=?1 WHERE singleton=1",
                [CAPTURE_SCHEMA_VERSION],
            )?;
        }
        Some(version) if version == CAPTURE_SCHEMA_VERSION => {
            if !has_v2_columns(&tx)? {
                return Err(TransportCaptureError::CorruptRecord);
            }
        }
        Some(_) => return Err(TransportCaptureError::CorruptRecord),
    }

    tx.execute(
        "INSERT OR IGNORE INTO broker_transport_capture_sequence(singleton,next_order) VALUES(1,1)",
        [],
    )?;
    let next_order: i64 = tx.query_row(
        "SELECT next_order FROM broker_transport_capture_sequence WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if next_order <= 0 {
        return Err(TransportCaptureError::LocalOrderRange);
    }

    tx.commit()?;
    Ok(())
}

fn ensure_v2_columns(tx: &Transaction<'_>) -> Result<(), TransportCaptureError> {
    if !column_exists(tx, "time_evidence_json")? {
        tx.execute(
            "ALTER TABLE broker_transport_capture_v01 ADD COLUMN time_evidence_json TEXT",
            [],
        )?;
    }
    if !column_exists(tx, "time_evidence_digest")? {
        tx.execute(
            "ALTER TABLE broker_transport_capture_v01 ADD COLUMN time_evidence_digest TEXT",
            [],
        )?;
    }
    if !column_exists(tx, "local_order")? {
        tx.execute(
            "ALTER TABLE broker_transport_capture_v01 ADD COLUMN local_order INTEGER",
            [],
        )?;
    }
    Ok(())
}

fn has_v2_columns(tx: &Transaction<'_>) -> Result<bool, TransportCaptureError> {
    Ok(column_exists(tx, "time_evidence_json")?
        && column_exists(tx, "time_evidence_digest")?
        && column_exists(tx, "local_order")?)
}

fn column_exists(tx: &Transaction<'_>, name: &str) -> Result<bool, TransportCaptureError> {
    let mut statement = tx.prepare("PRAGMA table_info(broker_transport_capture_v01)")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let column: String = row.get(1)?;
        if column == name {
            return Ok(true);
        }
    }
    Ok(false)
}

fn require_text(value: &str, name: &'static str) -> Result<(), TransportCaptureError> {
    if value.trim().is_empty() {
        return Err(TransportCaptureError::InvalidField(name));
    }
    Ok(())
}

fn as_i64(value: u64) -> Result<i64, TransportCaptureError> {
    i64::try_from(value).map_err(|_| TransportCaptureError::ClockRange)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write to String cannot fail");
    }
    out
}
