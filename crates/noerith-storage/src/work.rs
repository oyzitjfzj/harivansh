use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{fmt, path::Path};

const WORK_SCHEMA_VERSION: i64 = 1;
const DEFAULT_RETRY_BASE_MS: u64 = 250;
const DEFAULT_RETRY_MAX_MS: u64 = 30_000;

pub type WorkResult<T> = std::result::Result<T, WorkError>;

#[derive(Debug)]
pub enum WorkError {
    Sqlite(rusqlite::Error),
    InvalidId,
    NotFound,
    DuplicateIntentConflict,
    InvalidTransition,
    StaleFence,
    LeaseBusy,
    ExecutionUnhealthy,
    UnsafeRetry,
    RetryBudgetExhausted,
    MissingIdempotencyKey,
    IdempotencyExpired,
    ControlDeadlineExceeded,
}

impl fmt::Display for WorkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for WorkError {}

impl From<rusqlite::Error> for WorkError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkState {
    Planned,
    Running,
    Waiting,
    Completed,
    Failed,
    Cancelled,
}

impl WorkState {
    fn parse(value: &str) -> WorkResult<Self> {
        match value {
            "PLANNED" => Ok(Self::Planned),
            "RUNNING" => Ok(Self::Running),
            "WAITING" => Ok(Self::Waiting),
            "COMPLETED" => Ok(Self::Completed),
            "FAILED" => Ok(Self::Failed),
            "CANCELLED" => Ok(Self::Cancelled),
            _ => Err(WorkError::InvalidTransition),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectState {
    Proposed,
    Prepared,
    Authorized,
    CommitReady,
    Dispatching,
    RejectedNoEffect,
    Accepted,
    AcceptanceUnknown,
    Reconciling,
    Unresolved,
    OutcomePending,
    Succeeded,
    FailedAfterAccept,
    OutcomeUnknown,
    CancelledPrecommit,
    Stale,
    Abandoned,
}

impl EffectState {
    fn as_db(self) -> &'static str {
        match self {
            Self::Proposed => "PROPOSED",
            Self::Prepared => "PREPARED",
            Self::Authorized => "AUTHORIZED",
            Self::CommitReady => "COMMIT_READY",
            Self::Dispatching => "DISPATCHING",
            Self::RejectedNoEffect => "REJECTED_NO_EFFECT",
            Self::Accepted => "ACCEPTED",
            Self::AcceptanceUnknown => "ACCEPTANCE_UNKNOWN",
            Self::Reconciling => "RECONCILING",
            Self::Unresolved => "UNRESOLVED",
            Self::OutcomePending => "OUTCOME_PENDING",
            Self::Succeeded => "SUCCEEDED",
            Self::FailedAfterAccept => "FAILED_AFTER_ACCEPT",
            Self::OutcomeUnknown => "OUTCOME_UNKNOWN",
            Self::CancelledPrecommit => "CANCELLED_PRECOMMIT",
            Self::Stale => "STALE",
            Self::Abandoned => "ABANDONED",
        }
    }

    fn parse(value: &str) -> WorkResult<Self> {
        match value {
            "PROPOSED" => Ok(Self::Proposed),
            "PREPARED" => Ok(Self::Prepared),
            "AUTHORIZED" => Ok(Self::Authorized),
            "COMMIT_READY" => Ok(Self::CommitReady),
            "DISPATCHING" => Ok(Self::Dispatching),
            "REJECTED_NO_EFFECT" => Ok(Self::RejectedNoEffect),
            "ACCEPTED" => Ok(Self::Accepted),
            "ACCEPTANCE_UNKNOWN" => Ok(Self::AcceptanceUnknown),
            "RECONCILING" => Ok(Self::Reconciling),
            "UNRESOLVED" => Ok(Self::Unresolved),
            "OUTCOME_PENDING" => Ok(Self::OutcomePending),
            "SUCCEEDED" => Ok(Self::Succeeded),
            "FAILED_AFTER_ACCEPT" => Ok(Self::FailedAfterAccept),
            "OUTCOME_UNKNOWN" => Ok(Self::OutcomeUnknown),
            "CANCELLED_PRECOMMIT" => Ok(Self::CancelledPrecommit),
            "STALE" => Ok(Self::Stale),
            "ABANDONED" => Ok(Self::Abandoned),
            _ => Err(WorkError::InvalidTransition),
        }
    }

    fn pre_dispatch(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Prepared | Self::Authorized | Self::CommitReady
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterClass {
    E0ReadOnly,
    E1OpaqueWrite,
    E2DedupWrite,
    E3ObservableWrite,
    E4CompensatableWrite,
    E5SharedAtomic,
}

impl AdapterClass {
    fn as_db(self) -> &'static str {
        match self {
            Self::E0ReadOnly => "E0_READ_ONLY",
            Self::E1OpaqueWrite => "E1_OPAQUE_WRITE",
            Self::E2DedupWrite => "E2_DEDUP_WRITE",
            Self::E3ObservableWrite => "E3_OBSERVABLE_WRITE",
            Self::E4CompensatableWrite => "E4_COMPENSATABLE_WRITE",
            Self::E5SharedAtomic => "E5_SHARED_ATOMIC",
        }
    }

    fn parse(value: &str) -> WorkResult<Self> {
        match value {
            "E0_READ_ONLY" => Ok(Self::E0ReadOnly),
            "E1_OPAQUE_WRITE" => Ok(Self::E1OpaqueWrite),
            "E2_DEDUP_WRITE" => Ok(Self::E2DedupWrite),
            "E3_OBSERVABLE_WRITE" => Ok(Self::E3ObservableWrite),
            "E4_COMPENSATABLE_WRITE" => Ok(Self::E4CompensatableWrite),
            "E5_SHARED_ATOMIC" => Ok(Self::E5SharedAtomic),
            _ => Err(WorkError::InvalidTransition),
        }
    }

    fn requires_idempotency(self) -> bool {
        matches!(
            self,
            Self::E2DedupWrite
                | Self::E3ObservableWrite
                | Self::E4CompensatableWrite
                | Self::E5SharedAtomic
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelState {
    None,
    Requested,
    Confirmed,
    TooLate,
    Unknown,
}

impl CancelState {
    fn as_db(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Requested => "REQUESTED",
            Self::Confirmed => "CONFIRMED",
            Self::TooLate => "TOO_LATE",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn parse(value: &str) -> WorkResult<Self> {
        match value {
            "NONE" => Ok(Self::None),
            "REQUESTED" => Ok(Self::Requested),
            "CONFIRMED" => Ok(Self::Confirmed),
            "TOO_LATE" => Ok(Self::TooLate),
            "UNKNOWN" => Ok(Self::Unknown),
            _ => Err(WorkError::InvalidTransition),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompensationState {
    NotApplicable,
    Available,
    Planned,
    Authorized,
    Running,
    Compensated,
    Failed,
    Unavailable,
}

impl CompensationState {
    fn as_db(self) -> &'static str {
        match self {
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::Available => "AVAILABLE",
            Self::Planned => "PLANNED",
            Self::Authorized => "AUTHORIZED",
            Self::Running => "RUNNING",
            Self::Compensated => "COMPENSATED",
            Self::Failed => "FAILED",
            Self::Unavailable => "UNAVAILABLE",
        }
    }

    fn parse(value: &str) -> WorkResult<Self> {
        match value {
            "NOT_APPLICABLE" => Ok(Self::NotApplicable),
            "AVAILABLE" => Ok(Self::Available),
            "PLANNED" => Ok(Self::Planned),
            "AUTHORIZED" => Ok(Self::Authorized),
            "RUNNING" => Ok(Self::Running),
            "COMPENSATED" => Ok(Self::Compensated),
            "FAILED" => Ok(Self::Failed),
            "UNAVAILABLE" => Ok(Self::Unavailable),
            _ => Err(WorkError::InvalidTransition),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
    Quarantined,
}

impl HealthState {
    fn as_db(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Degraded => "DEGRADED",
            Self::Unhealthy => "UNHEALTHY",
            Self::Quarantined => "QUARANTINED",
        }
    }

    fn parse(value: &str) -> WorkResult<Self> {
        match value {
            "HEALTHY" => Ok(Self::Healthy),
            "DEGRADED" => Ok(Self::Degraded),
            "UNHEALTHY" => Ok(Self::Unhealthy),
            "QUARANTINED" => Ok(Self::Quarantined),
            _ => Err(WorkError::InvalidTransition),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectSpec {
    pub tenant_namespace: String,
    pub intent_id: String,
    pub work_id: String,
    pub operation_type: String,
    pub target_account: String,
    pub payload_digest: String,
    pub adapter_class: AdapterClass,
    pub idempotency_key: Option<String>,
    pub idempotency_valid_until: Option<u64>,
    pub retry_budget: u32,
    pub expected_evidence_plan_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchLease {
    pub tenant_namespace: String,
    pub owner: String,
    pub fence: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkClaim {
    pub tenant_namespace: String,
    pub work_id: String,
    pub owner: String,
    pub fence: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchTicket {
    pub tenant_namespace: String,
    pub intent_id: String,
    pub owner: String,
    pub fence: u64,
    pub idempotency_key: Option<String>,
    pub attempt: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectView {
    pub state: EffectState,
    pub cancel_state: CancelState,
    pub compensation_state: CompensationState,
    pub adapter_class: AdapterClass,
    pub attempt_count: u32,
    pub retry_budget: u32,
    pub idempotency_key: Option<String>,
    pub parent_intent_id: Option<String>,
    pub receipt_ref: Option<String>,
    pub observation_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    NoAutomaticRetry,
    RetrySameIntent { after_ms: u64 },
    Reconcile,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    NotAccepted { evidence_ref: String },
    Accepted { receipt_ref: String },
    Unresolved { evidence_ref: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationOutcome {
    Pending { evidence_ref: String },
    Succeeded { evidence_ref: String },
    Failed { evidence_ref: String },
    Unknown { evidence_ref: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    Confirmed,
    TooLate,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackInput {
    pub callback_id: String,
    pub callback_digest: String,
    pub accepted: bool,
    pub evidence_ref: String,
}

#[derive(Debug)]
struct EffectViewRow {
    state: String,
    cancel_state: String,
    compensation_state: String,
    adapter_class: String,
    attempt_count: i64,
    retry_budget: i64,
    idempotency_key: Option<String>,
    parent_intent_id: Option<String>,
    receipt_ref: Option<String>,
    observation_ref: Option<String>,
}

pub struct DurableWorkStore {
    connection: Connection,
}

impl DurableWorkStore {
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> WorkResult<Self> {
        if passphrase.is_empty() {
            return Err(WorkError::InvalidId);
        }
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "key", passphrase)?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if cipher_version.trim().is_empty() {
            return Err(WorkError::ExecutionUnhealthy);
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.pragma_update(None, "busy_timeout", 5000_i64)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(WorkError::ExecutionUnhealthy);
        }
        initialize_schema(&mut connection)?;
        Ok(Self { connection })
    }

    pub fn create_work(
        &mut self,
        tenant_namespace: &str,
        work_id: &str,
        payload_digest: &str,
        now: u64,
    ) -> WorkResult<()> {
        validate_id(tenant_namespace)?;
        validate_id(work_id)?;
        validate_id(payload_digest)?;
        let now = as_i64(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_tenant(&tx, tenant_namespace)?;
        tx.execute(
            "INSERT INTO work_items(tenant_namespace,work_id,revision,state,payload_digest,created_at,updated_at) \
             VALUES(?1,?2,1,'PLANNED',?3,?4,?4)",
            params![tenant_namespace, work_id, payload_digest, now],
        )?;
        tx.execute(
            "INSERT INTO work_queue(tenant_namespace,work_id,state,priority,available_at,claim_fence) VALUES(?1,?2,'READY',0,?3,0)",
            params![tenant_namespace, work_id, now],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            None,
            "WORK_CREATED",
            now,
            Some(work_id),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn claim_next_work(
        &mut self,
        tenant_namespace: &str,
        owner: &str,
        now: u64,
        ttl: u64,
    ) -> WorkResult<Option<WorkClaim>> {
        validate_id(tenant_namespace)?;
        validate_id(owner)?;
        if ttl == 0 {
            return Err(WorkError::InvalidId);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_healthy(&tx, tenant_namespace)?;
        let candidate: Option<(String, i64)> = tx
            .query_row(
                "SELECT work_id,claim_fence FROM work_queue WHERE tenant_namespace=?1 AND state='READY' AND available_at<=?2 \
                 ORDER BY priority DESC,available_at ASC,work_id ASC LIMIT 1",
                params![tenant_namespace, as_i64(now)?],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((work_id, old_fence)) = candidate else {
            tx.commit()?;
            return Ok(None);
        };
        let next_fence = old_fence.checked_add(1).ok_or(WorkError::StaleFence)?;
        let expires_at = as_i64(now.saturating_add(ttl))?;
        let changed = tx.execute(
            "UPDATE work_queue SET state='CLAIMED',claim_owner=?3,claim_fence=?4,claim_expires_at=?5 \
             WHERE tenant_namespace=?1 AND work_id=?2 AND state='READY' AND claim_fence=?6",
            params![tenant_namespace, work_id, owner, next_fence, expires_at, old_fence],
        )?;
        if changed != 1 {
            return Err(WorkError::LeaseBusy);
        }
        tx.execute(
            "UPDATE work_items SET state='RUNNING',revision=revision+1,updated_at=?3 WHERE tenant_namespace=?1 AND work_id=?2",
            params![tenant_namespace, work_id, as_i64(now)?],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            None,
            "WORK_CLAIMED",
            as_i64(now)?,
            Some(&work_id),
        )?;
        tx.commit()?;
        Ok(Some(WorkClaim {
            tenant_namespace: tenant_namespace.to_owned(),
            work_id,
            owner: owner.to_owned(),
            fence: u64::try_from(next_fence).map_err(|_| WorkError::StaleFence)?,
            expires_at: now.saturating_add(ttl),
        }))
    }

    pub fn wait_work(&mut self, claim: &WorkClaim, available_at: u64, now: u64) -> WorkResult<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_work_claim(&tx, claim, now)?;
        tx.execute(
            "UPDATE work_items SET state='WAITING',revision=revision+1,updated_at=?3 WHERE tenant_namespace=?1 AND work_id=?2",
            params![claim.tenant_namespace, claim.work_id, as_i64(now)?],
        )?;
        tx.execute(
            "UPDATE work_queue SET state='READY',available_at=?3,claim_owner=NULL,claim_expires_at=NULL \
             WHERE tenant_namespace=?1 AND work_id=?2",
            params![claim.tenant_namespace, claim.work_id, as_i64(available_at)?],
        )?;
        append_event(
            &tx,
            &claim.tenant_namespace,
            None,
            "WORK_WAITING",
            as_i64(now)?,
            Some(&claim.work_id),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn recover_expired_work_claims(
        &mut self,
        tenant_namespace: &str,
        now: u64,
    ) -> WorkResult<usize> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement = tx.prepare(
            "SELECT work_id FROM work_queue WHERE tenant_namespace=?1 AND state='CLAIMED' AND claim_expires_at<=?2",
        )?;
        let rows = statement.query_map(params![tenant_namespace, as_i64(now)?], |row| {
            row.get::<_, String>(0)
        })?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        drop(statement);
        for work_id in &ids {
            tx.execute(
                "UPDATE work_queue SET state='READY',claim_owner=NULL,claim_expires_at=NULL WHERE tenant_namespace=?1 AND work_id=?2",
                params![tenant_namespace, work_id],
            )?;
            tx.execute(
                "UPDATE work_items SET state='WAITING',revision=revision+1,updated_at=?3 WHERE tenant_namespace=?1 AND work_id=?2 AND state='RUNNING'",
                params![tenant_namespace, work_id, as_i64(now)?],
            )?;
        }
        if !ids.is_empty() {
            append_event(
                &tx,
                tenant_namespace,
                None,
                "WORK_CLAIMS_RECOVERED",
                as_i64(now)?,
                None,
            )?;
        }
        tx.commit()?;
        Ok(ids.len())
    }

    pub fn create_effect(&mut self, spec: &EffectSpec, now: u64) -> WorkResult<()> {
        validate_effect_spec(spec)?;
        if spec.adapter_class.requires_idempotency() && spec.idempotency_key.is_none() {
            return Err(WorkError::MissingIdempotencyKey);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_tenant(&tx, &spec.tenant_namespace)?;
        insert_effect_tx(&tx, spec, now, None)?;
        tx.commit()?;
        Ok(())
    }

    pub fn prepare_effect(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        now: u64,
    ) -> WorkResult<()> {
        self.transition_exact(
            tenant_namespace,
            intent_id,
            EffectState::Proposed,
            EffectState::Prepared,
            "EFFECT_PREPARED",
            now,
        )
    }

    pub fn authorize_effect(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        decision_snapshot_digest: &str,
        now: u64,
    ) -> WorkResult<()> {
        validate_id(decision_snapshot_digest)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_effect_state(&tx, tenant_namespace, intent_id, EffectState::Prepared)?;
        tx.execute(
            "UPDATE effect_intents SET state='AUTHORIZED',decision_snapshot_digest=?3,updated_at=?4 \
             WHERE tenant_namespace=?1 AND intent_id=?2",
            params![
                tenant_namespace,
                intent_id,
                decision_snapshot_digest,
                as_i64(now)?
            ],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            "EFFECT_AUTHORIZED",
            as_i64(now)?,
            Some(decision_snapshot_digest),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn acquire_dispatch_lease(
        &mut self,
        tenant_namespace: &str,
        owner: &str,
        now: u64,
        ttl: u64,
    ) -> WorkResult<DispatchLease> {
        validate_id(tenant_namespace)?;
        validate_id(owner)?;
        if ttl == 0 {
            return Err(WorkError::InvalidId);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_tenant(&tx, tenant_namespace)?;
        let current: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT owner,fence,expires_at FROM dispatch_leases WHERE tenant_namespace=?1",
                [tenant_namespace],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let now_i = as_i64(now)?;
        let expires_at = as_i64(now.saturating_add(ttl))?;
        let fence = match current {
            Some((current_owner, _current_fence, current_expiry))
                if current_expiry > now_i && current_owner != owner =>
            {
                return Err(WorkError::LeaseBusy);
            }
            Some((current_owner, current_fence, current_expiry))
                if current_expiry > now_i && current_owner == owner =>
            {
                tx.execute(
                    "UPDATE dispatch_leases SET expires_at=?3 WHERE tenant_namespace=?1 AND owner=?2",
                    params![tenant_namespace, owner, expires_at],
                )?;
                u64::try_from(current_fence).map_err(|_| WorkError::StaleFence)?
            }
            Some((_, current_fence, _)) => {
                let next = current_fence.checked_add(1).ok_or(WorkError::StaleFence)?;
                tx.execute(
                    "UPDATE dispatch_leases SET owner=?2,fence=?3,expires_at=?4 WHERE tenant_namespace=?1",
                    params![tenant_namespace, owner, next, expires_at],
                )?;
                u64::try_from(next).map_err(|_| WorkError::StaleFence)?
            }
            None => {
                tx.execute(
                    "INSERT INTO dispatch_leases(tenant_namespace,owner,fence,expires_at) VALUES(?1,?2,1,?3)",
                    params![tenant_namespace, owner, expires_at],
                )?;
                1
            }
        };
        tx.commit()?;
        Ok(DispatchLease {
            tenant_namespace: tenant_namespace.to_owned(),
            owner: owner.to_owned(),
            fence,
            expires_at: now.saturating_add(ttl),
        })
    }

    pub fn commit_ready(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        lease: &DispatchLease,
        now: u64,
    ) -> WorkResult<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_healthy(&tx, tenant_namespace)?;
        validate_lease(&tx, tenant_namespace, lease, now)?;
        require_effect_state(&tx, tenant_namespace, intent_id, EffectState::Authorized)?;
        require_not_cancelled(&tx, tenant_namespace, intent_id)?;
        tx.execute(
            "UPDATE effect_intents SET state='COMMIT_READY',current_fence=?3,updated_at=?4 \
             WHERE tenant_namespace=?1 AND intent_id=?2",
            params![
                tenant_namespace,
                intent_id,
                as_i64(lease.fence)?,
                as_i64(now)?
            ],
        )?;
        tx.execute(
            "INSERT INTO outbox(tenant_namespace,intent_id,state,available_at) VALUES(?1,?2,'READY',?3) \
             ON CONFLICT(tenant_namespace,intent_id) DO UPDATE SET state='READY',available_at=excluded.available_at, \
                claim_owner=NULL,claim_fence=NULL",
            params![tenant_namespace, intent_id, as_i64(now)?],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            "COMMIT_READY",
            as_i64(now)?,
            None,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn claim_outbox(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        lease: &DispatchLease,
        now: u64,
    ) -> WorkResult<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&tx, tenant_namespace, lease, now)?;
        require_healthy(&tx, tenant_namespace)?;
        require_effect_state(&tx, tenant_namespace, intent_id, EffectState::CommitReady)?;
        require_not_cancelled(&tx, tenant_namespace, intent_id)?;
        let changed = tx.execute(
            "UPDATE outbox SET state='CLAIMED',claim_owner=?3,claim_fence=?4 \
             WHERE tenant_namespace=?1 AND intent_id=?2 AND state='READY' AND available_at<=?5",
            params![
                tenant_namespace,
                intent_id,
                lease.owner,
                as_i64(lease.fence)?,
                as_i64(now)?
            ],
        )?;
        if changed != 1 {
            return Err(WorkError::InvalidTransition);
        }
        tx.commit()?;
        Ok(())
    }

    pub fn begin_dispatch(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        lease: &DispatchLease,
        now: u64,
    ) -> WorkResult<DispatchTicket> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&tx, tenant_namespace, lease, now)?;
        require_healthy(&tx, tenant_namespace)?;
        require_effect_state(&tx, tenant_namespace, intent_id, EffectState::CommitReady)?;
        require_not_cancelled(&tx, tenant_namespace, intent_id)?;
        let claim: Option<(String, i64)> = tx
            .query_row(
                "SELECT claim_owner,claim_fence FROM outbox WHERE tenant_namespace=?1 AND intent_id=?2 AND state='CLAIMED'",
                params![tenant_namespace, intent_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if claim
            .as_ref()
            .map(|(owner, fence)| (owner.as_str(), *fence))
            != Some((lease.owner.as_str(), as_i64(lease.fence)?))
        {
            return Err(WorkError::StaleFence);
        }
        let (attempt_count, idempotency_key): (i64, Option<String>) = tx.query_row(
            "SELECT attempt_count,idempotency_key FROM effect_intents WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let next_attempt = attempt_count
            .checked_add(1)
            .ok_or(WorkError::RetryBudgetExhausted)?;
        tx.execute(
            "UPDATE effect_intents SET state='DISPATCHING',attempt_count=?3,current_fence=?4,dispatch_started_at=?5,updated_at=?5 \
             WHERE tenant_namespace=?1 AND intent_id=?2",
            params![
                tenant_namespace,
                intent_id,
                next_attempt,
                as_i64(lease.fence)?,
                as_i64(now)?
            ],
        )?;
        tx.execute(
            "UPDATE outbox SET state='DISPATCHING' WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id],
        )?;
        tx.execute(
            "INSERT INTO dispatch_attempts(tenant_namespace,intent_id,attempt_number,owner,fence,state,started_at) \
             VALUES(?1,?2,?3,?4,?5,'STARTED',?6)",
            params![
                tenant_namespace,
                intent_id,
                next_attempt,
                lease.owner,
                as_i64(lease.fence)?,
                as_i64(now)?
            ],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            "DISPATCH_BOUNDARY_CROSSED",
            as_i64(now)?,
            None,
        )?;
        tx.commit()?;
        Ok(DispatchTicket {
            tenant_namespace: tenant_namespace.to_owned(),
            intent_id: intent_id.to_owned(),
            owner: lease.owner.clone(),
            fence: lease.fence,
            idempotency_key,
            attempt: u32::try_from(next_attempt).map_err(|_| WorkError::RetryBudgetExhausted)?,
        })
    }

    pub fn record_dispatch_accepted(
        &mut self,
        ticket: &DispatchTicket,
        receipt_ref: &str,
        now: u64,
    ) -> WorkResult<()> {
        validate_id(receipt_ref)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_attempt_open(&tx, ticket)?;
        finish_attempt(&tx, ticket, "ACCEPTED", receipt_ref, now)?;
        let current = effect_state_tx(&tx, &ticket.tenant_namespace, &ticket.intent_id)?;
        if matches!(
            current,
            EffectState::Dispatching
                | EffectState::AcceptanceUnknown
                | EffectState::Reconciling
                | EffectState::Unresolved
                | EffectState::RejectedNoEffect
        ) {
            tx.execute(
                "UPDATE effect_intents SET state='ACCEPTED',receipt_ref=?3,updated_at=?4 WHERE tenant_namespace=?1 AND intent_id=?2",
                params![
                    ticket.tenant_namespace,
                    ticket.intent_id,
                    receipt_ref,
                    as_i64(now)?
                ],
            )?;
        }
        mark_outbox_done(&tx, &ticket.tenant_namespace, &ticket.intent_id)?;
        append_event(
            &tx,
            &ticket.tenant_namespace,
            Some(&ticket.intent_id),
            "PROVIDER_ACCEPTED",
            as_i64(now)?,
            Some(receipt_ref),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_dispatch_rejected(
        &mut self,
        ticket: &DispatchTicket,
        evidence_ref: &str,
        now: u64,
    ) -> WorkResult<()> {
        validate_id(evidence_ref)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_attempt_open(&tx, ticket)?;
        finish_attempt(&tx, ticket, "REJECTED_NO_EFFECT", evidence_ref, now)?;
        let current = effect_state_tx(&tx, &ticket.tenant_namespace, &ticket.intent_id)?;
        if matches!(
            current,
            EffectState::Dispatching
                | EffectState::AcceptanceUnknown
                | EffectState::Reconciling
                | EffectState::Unresolved
        ) {
            tx.execute(
                "UPDATE effect_intents SET state='REJECTED_NO_EFFECT',last_error=?3,updated_at=?4 WHERE tenant_namespace=?1 AND intent_id=?2",
                params![
                    ticket.tenant_namespace,
                    ticket.intent_id,
                    evidence_ref,
                    as_i64(now)?
                ],
            )?;
            mark_outbox_done(&tx, &ticket.tenant_namespace, &ticket.intent_id)?;
        }
        append_event(
            &tx,
            &ticket.tenant_namespace,
            Some(&ticket.intent_id),
            "PROVIDER_REJECTED_NO_EFFECT",
            as_i64(now)?,
            Some(evidence_ref),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_dispatch_ambiguous(
        &mut self,
        ticket: &DispatchTicket,
        evidence_ref: &str,
        now: u64,
    ) -> WorkResult<()> {
        validate_id(evidence_ref)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_attempt_open(&tx, ticket)?;
        finish_attempt(&tx, ticket, "UNKNOWN", evidence_ref, now)?;
        if effect_state_tx(&tx, &ticket.tenant_namespace, &ticket.intent_id)?
            == EffectState::Dispatching
        {
            tx.execute(
                "UPDATE effect_intents SET state='ACCEPTANCE_UNKNOWN',last_error=?3,updated_at=?4 WHERE tenant_namespace=?1 AND intent_id=?2",
                params![
                    ticket.tenant_namespace,
                    ticket.intent_id,
                    evidence_ref,
                    as_i64(now)?
                ],
            )?;
            tx.execute(
                "UPDATE outbox SET state='BLOCKED' WHERE tenant_namespace=?1 AND intent_id=?2",
                params![ticket.tenant_namespace, ticket.intent_id],
            )?;
        }
        append_event(
            &tx,
            &ticket.tenant_namespace,
            Some(&ticket.intent_id),
            "ACCEPTANCE_UNKNOWN",
            as_i64(now)?,
            Some(evidence_ref),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn recover_inflight(&mut self, tenant_namespace: &str, now: u64) -> WorkResult<usize> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count = tx.execute(
            "UPDATE effect_intents SET state='ACCEPTANCE_UNKNOWN',last_error='recovered-after-dispatch-crash',updated_at=?2 \
             WHERE tenant_namespace=?1 AND state='DISPATCHING'",
            params![tenant_namespace, as_i64(now)?],
        )?;
        tx.execute(
            "UPDATE outbox SET state='BLOCKED' WHERE tenant_namespace=?1 AND state='DISPATCHING'",
            [tenant_namespace],
        )?;
        tx.execute(
            "UPDATE dispatch_attempts SET state='UNKNOWN',finished_at=?2,evidence_ref='recovered-after-dispatch-crash' \
             WHERE tenant_namespace=?1 AND state='STARTED'",
            params![tenant_namespace, as_i64(now)?],
        )?;
        if count > 0 {
            append_event(
                &tx,
                tenant_namespace,
                None,
                "RECOVERED_AMBIGUOUS_DISPATCHES",
                as_i64(now)?,
                None,
            )?;
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn retry_decision(
        &self,
        tenant_namespace: &str,
        intent_id: &str,
        now: u64,
    ) -> WorkResult<RetryDecision> {
        let row: (String, String, i64, i64, Option<String>, Option<i64>, String) = self
            .connection
            .query_row(
                "SELECT state,adapter_class,attempt_count,retry_budget,idempotency_key,idempotency_valid_until,cancel_state \
                 FROM effect_intents WHERE tenant_namespace=?1 AND intent_id=?2",
                params![tenant_namespace, intent_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )?;
        let state = EffectState::parse(&row.0)?;
        if !matches!(
            state,
            EffectState::AcceptanceUnknown | EffectState::Unresolved
        ) {
            return Ok(RetryDecision::Terminal);
        }
        if CancelState::parse(&row.6)? != CancelState::None {
            return Ok(RetryDecision::NoAutomaticRetry);
        }
        let adapter = AdapterClass::parse(&row.1)?;
        match adapter {
            AdapterClass::E0ReadOnly => Ok(RetryDecision::Terminal),
            AdapterClass::E1OpaqueWrite => Ok(RetryDecision::NoAutomaticRetry),
            AdapterClass::E2DedupWrite => {
                let Some(key) = row.4 else {
                    return Err(WorkError::MissingIdempotencyKey);
                };
                let Some(valid_until) = row.5 else {
                    return Err(WorkError::IdempotencyExpired);
                };
                if valid_until < as_i64(now)? {
                    return Err(WorkError::IdempotencyExpired);
                }
                if row.2 >= row.3 {
                    return Err(WorkError::RetryBudgetExhausted);
                }
                Ok(RetryDecision::RetrySameIntent {
                    after_ms: retry_delay_ms(
                        DEFAULT_RETRY_BASE_MS,
                        DEFAULT_RETRY_MAX_MS,
                        u32::try_from(row.2).map_err(|_| WorkError::RetryBudgetExhausted)?,
                        &key,
                    ),
                })
            }
            AdapterClass::E3ObservableWrite
            | AdapterClass::E4CompensatableWrite
            | AdapterClass::E5SharedAtomic => Ok(RetryDecision::Reconcile),
        }
    }

    pub fn prepare_same_intent_retry(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        lease: &DispatchLease,
        fresh_decision_snapshot_digest: &str,
        now: u64,
    ) -> WorkResult<()> {
        validate_id(fresh_decision_snapshot_digest)?;
        match self.retry_decision(tenant_namespace, intent_id, now)? {
            RetryDecision::RetrySameIntent { after_ms } => {
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                validate_lease(&tx, tenant_namespace, lease, now)?;
                require_healthy(&tx, tenant_namespace)?;
                tx.execute(
                    "UPDATE effect_intents SET state='COMMIT_READY',current_fence=?3,decision_snapshot_digest=?4,updated_at=?5 \
                     WHERE tenant_namespace=?1 AND intent_id=?2 AND state IN ('ACCEPTANCE_UNKNOWN','UNRESOLVED')",
                    params![
                        tenant_namespace,
                        intent_id,
                        as_i64(lease.fence)?,
                        fresh_decision_snapshot_digest,
                        as_i64(now)?
                    ],
                )?;
                tx.execute(
                    "UPDATE outbox SET state='READY',available_at=?3,claim_owner=NULL,claim_fence=NULL \
                     WHERE tenant_namespace=?1 AND intent_id=?2",
                    params![
                        tenant_namespace,
                        intent_id,
                        as_i64(now.saturating_add(after_ms))?
                    ],
                )?;
                append_event(
                    &tx,
                    tenant_namespace,
                    Some(intent_id),
                    "SAFE_SAME_INTENT_RETRY_SCHEDULED",
                    as_i64(now)?,
                    None,
                )?;
                tx.commit()?;
                Ok(())
            }
            RetryDecision::NoAutomaticRetry => Err(WorkError::UnsafeRetry),
            RetryDecision::Reconcile => Err(WorkError::UnsafeRetry),
            RetryDecision::Terminal => Err(WorkError::InvalidTransition),
        }
    }

    pub fn start_reconciliation(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        now: u64,
    ) -> WorkResult<()> {
        let current = self.effect_view(tenant_namespace, intent_id)?.state;
        if !matches!(
            current,
            EffectState::AcceptanceUnknown | EffectState::Unresolved | EffectState::OutcomeUnknown
        ) {
            return Err(WorkError::InvalidTransition);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE effect_intents SET state='RECONCILING',updated_at=?3 WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id, as_i64(now)?],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            "RECONCILIATION_STARTED",
            as_i64(now)?,
            None,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn resolve_reconciliation(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        outcome: ReconcileOutcome,
        now: u64,
    ) -> WorkResult<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_effect_state(&tx, tenant_namespace, intent_id, EffectState::Reconciling)?;
        let (state, evidence, receipt): (&str, &str, Option<&str>) = match &outcome {
            ReconcileOutcome::NotAccepted { evidence_ref } => {
                (EffectState::RejectedNoEffect.as_db(), evidence_ref, None)
            }
            ReconcileOutcome::Accepted { receipt_ref } => (
                EffectState::Accepted.as_db(),
                receipt_ref,
                Some(receipt_ref),
            ),
            ReconcileOutcome::Unresolved { evidence_ref } => {
                (EffectState::Unresolved.as_db(), evidence_ref, None)
            }
        };
        validate_id(evidence)?;
        tx.execute(
            "UPDATE effect_intents SET state=?3,receipt_ref=COALESCE(?4,receipt_ref),last_error=?5,updated_at=?6 \
             WHERE tenant_namespace=?1 AND intent_id=?2",
            params![
                tenant_namespace,
                intent_id,
                state,
                receipt,
                evidence,
                as_i64(now)?
            ],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            "RECONCILIATION_RESULT",
            as_i64(now)?,
            Some(evidence),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn observe(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        outcome: ObservationOutcome,
        now: u64,
    ) -> WorkResult<()> {
        let current = self.effect_view(tenant_namespace, intent_id)?.state;
        if !matches!(
            current,
            EffectState::Accepted
                | EffectState::OutcomePending
                | EffectState::OutcomeUnknown
                | EffectState::FailedAfterAccept
        ) {
            return Err(WorkError::InvalidTransition);
        }
        let (next, evidence) = match &outcome {
            ObservationOutcome::Pending { evidence_ref } => {
                (EffectState::OutcomePending, evidence_ref)
            }
            ObservationOutcome::Succeeded { evidence_ref } => {
                (EffectState::Succeeded, evidence_ref)
            }
            ObservationOutcome::Failed { evidence_ref } => {
                (EffectState::FailedAfterAccept, evidence_ref)
            }
            ObservationOutcome::Unknown { evidence_ref } => {
                (EffectState::OutcomeUnknown, evidence_ref)
            }
        };
        validate_id(evidence)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE effect_intents SET state=?3,observation_ref=?4,updated_at=?5 \
             WHERE tenant_namespace=?1 AND intent_id=?2",
            params![
                tenant_namespace,
                intent_id,
                next.as_db(),
                evidence,
                as_i64(now)?
            ],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            "OBSERVATION_RECORDED",
            as_i64(now)?,
            Some(evidence),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn request_cancel(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        now: u64,
    ) -> WorkResult<CancelState> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = effect_state_tx(&tx, tenant_namespace, intent_id)?;
        let cancel_state = if state.pre_dispatch() {
            tx.execute(
                "UPDATE effect_intents SET state='CANCELLED_PRECOMMIT',cancel_state='CONFIRMED',updated_at=?3 \
                 WHERE tenant_namespace=?1 AND intent_id=?2",
                params![tenant_namespace, intent_id, as_i64(now)?],
            )?;
            tx.execute(
                "UPDATE outbox SET state='BLOCKED' WHERE tenant_namespace=?1 AND intent_id=?2",
                params![tenant_namespace, intent_id],
            )?;
            CancelState::Confirmed
        } else {
            match state {
                EffectState::Succeeded => CancelState::TooLate,
                EffectState::RejectedNoEffect | EffectState::CancelledPrecommit => {
                    CancelState::Confirmed
                }
                _ => CancelState::Requested,
            }
        };
        tx.execute(
            "UPDATE effect_intents SET cancel_state=?3,updated_at=?4 WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id, cancel_state.as_db(), as_i64(now)?],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            "CANCEL_STATE_CHANGED",
            as_i64(now)?,
            Some(cancel_state.as_db()),
        )?;
        tx.commit()?;
        Ok(cancel_state)
    }

    pub fn record_cancel_outcome(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        outcome: CancelOutcome,
        evidence_ref: &str,
        now: u64,
    ) -> WorkResult<CancelState> {
        validate_id(evidence_ref)?;
        let current = self.effect_view(tenant_namespace, intent_id)?.cancel_state;
        if current != CancelState::Requested {
            return Err(WorkError::InvalidTransition);
        }
        let next = match outcome {
            CancelOutcome::Confirmed => CancelState::Confirmed,
            CancelOutcome::TooLate => CancelState::TooLate,
            CancelOutcome::Unknown => CancelState::Unknown,
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE effect_intents SET cancel_state=?3,cancel_evidence_ref=?4,updated_at=?5 WHERE tenant_namespace=?1 AND intent_id=?2",
            params![
                tenant_namespace,
                intent_id,
                next.as_db(),
                evidence_ref,
                as_i64(now)?
            ],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            "CANCEL_RESULT",
            as_i64(now)?,
            Some(evidence_ref),
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn apply_callback(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        callback: &CallbackInput,
        now: u64,
    ) -> WorkResult<bool> {
        validate_id(&callback.callback_id)?;
        validate_id(&callback.callback_digest)?;
        validate_id(&callback.evidence_ref)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT intent_id,callback_digest FROM callbacks WHERE tenant_namespace=?1 AND callback_id=?2",
                params![tenant_namespace, callback.callback_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_intent, existing_digest)) = existing {
            if existing_intent == intent_id && existing_digest == callback.callback_digest {
                tx.commit()?;
                return Ok(false);
            }
            return Err(WorkError::DuplicateIntentConflict);
        }
        let current = effect_state_tx(&tx, tenant_namespace, intent_id)?;
        let may_change_primary = matches!(
            current,
            EffectState::Dispatching
                | EffectState::AcceptanceUnknown
                | EffectState::Reconciling
                | EffectState::Unresolved
        );
        let may_record_only = matches!(
            current,
            EffectState::Accepted
                | EffectState::OutcomePending
                | EffectState::Succeeded
                | EffectState::FailedAfterAccept
                | EffectState::OutcomeUnknown
        );
        if !may_change_primary && !may_record_only {
            return Err(WorkError::InvalidTransition);
        }
        tx.execute(
            "INSERT INTO callbacks(tenant_namespace,callback_id,intent_id,callback_digest,recorded_at) VALUES(?1,?2,?3,?4,?5)",
            params![
                tenant_namespace,
                callback.callback_id,
                intent_id,
                callback.callback_digest,
                as_i64(now)?
            ],
        )?;
        if may_change_primary {
            let next = if callback.accepted {
                EffectState::Accepted
            } else {
                EffectState::RejectedNoEffect
            };
            tx.execute(
                "UPDATE effect_intents SET state=?3,receipt_ref=CASE WHEN ?4 THEN ?5 ELSE receipt_ref END,last_error=?5,updated_at=?6 \
                 WHERE tenant_namespace=?1 AND intent_id=?2",
                params![
                    tenant_namespace,
                    intent_id,
                    next.as_db(),
                    callback.accepted,
                    callback.evidence_ref,
                    as_i64(now)?
                ],
            )?;
        }
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            "CALLBACK_APPLIED",
            as_i64(now)?,
            Some(&callback.evidence_ref),
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn set_health(
        &mut self,
        tenant_namespace: &str,
        state: HealthState,
        now: u64,
    ) -> WorkResult<()> {
        validate_id(tenant_namespace)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_tenant(&tx, tenant_namespace)?;
        tx.execute(
            "UPDATE execution_health SET state=?2,epoch=epoch+1,updated_at=?3 WHERE tenant_namespace=?1",
            params![tenant_namespace, state.as_db(), as_i64(now)?],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            None,
            "EXECUTION_HEALTH_CHANGED",
            as_i64(now)?,
            Some(state.as_db()),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn health(&self, tenant_namespace: &str) -> WorkResult<HealthState> {
        let value: String = self.connection.query_row(
            "SELECT state FROM execution_health WHERE tenant_namespace=?1",
            [tenant_namespace],
            |row| row.get(0),
        )?;
        HealthState::parse(&value)
    }

    pub fn create_compensation(
        &mut self,
        original_tenant: &str,
        original_intent: &str,
        compensation: &EffectSpec,
        now: u64,
    ) -> WorkResult<()> {
        validate_effect_spec(compensation)?;
        if compensation.adapter_class.requires_idempotency()
            && compensation.idempotency_key.is_none()
        {
            return Err(WorkError::MissingIdempotencyKey);
        }
        if compensation.tenant_namespace != original_tenant
            || compensation.intent_id == original_intent
        {
            return Err(WorkError::InvalidTransition);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (adapter, state): (String, String) = tx.query_row(
            "SELECT adapter_class,state FROM effect_intents WHERE tenant_namespace=?1 AND intent_id=?2",
            params![original_tenant, original_intent],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if AdapterClass::parse(&adapter)? != AdapterClass::E4CompensatableWrite
            || !matches!(
                EffectState::parse(&state)?,
                EffectState::Accepted
                    | EffectState::OutcomePending
                    | EffectState::FailedAfterAccept
                    | EffectState::OutcomeUnknown
                    | EffectState::Succeeded
            )
        {
            return Err(WorkError::InvalidTransition);
        }
        insert_effect_tx(&tx, compensation, now, Some(original_intent))?;
        tx.execute(
            "UPDATE effect_intents SET compensation_state='PLANNED',updated_at=?3 WHERE tenant_namespace=?1 AND intent_id=?2",
            params![original_tenant, original_intent, as_i64(now)?],
        )?;
        append_event(
            &tx,
            original_tenant,
            Some(original_intent),
            "COMPENSATION_PLANNED",
            as_i64(now)?,
            Some(&compensation.intent_id),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn try_complete_work(
        &mut self,
        tenant_namespace: &str,
        work_id: &str,
        now: u64,
    ) -> WorkResult<bool> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (total, succeeded): (i64, i64) = tx.query_row(
            "SELECT count(*),COALESCE(sum(CASE WHEN state='SUCCEEDED' THEN 1 ELSE 0 END),0) FROM effect_intents WHERE tenant_namespace=?1 AND work_id=?2",
            params![tenant_namespace, work_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if total == 0 || succeeded != total {
            tx.commit()?;
            return Ok(false);
        }
        let changed = tx.execute(
            "UPDATE work_items SET state='COMPLETED',revision=revision+1,updated_at=?3 WHERE tenant_namespace=?1 AND work_id=?2 AND state!='COMPLETED'",
            params![tenant_namespace, work_id, as_i64(now)?],
        )?;
        tx.execute(
            "UPDATE work_queue SET state='BLOCKED',claim_owner=NULL,claim_expires_at=NULL WHERE tenant_namespace=?1 AND work_id=?2",
            params![tenant_namespace, work_id],
        )?;
        if changed == 1 {
            append_event(
                &tx,
                tenant_namespace,
                None,
                "WORK_COMPLETED",
                as_i64(now)?,
                Some(work_id),
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn work_state(&self, tenant_namespace: &str, work_id: &str) -> WorkResult<WorkState> {
        let value: String = self.connection.query_row(
            "SELECT state FROM work_items WHERE tenant_namespace=?1 AND work_id=?2",
            params![tenant_namespace, work_id],
            |row| row.get(0),
        )?;
        WorkState::parse(&value)
    }

    pub fn effect_view(&self, tenant_namespace: &str, intent_id: &str) -> WorkResult<EffectView> {
        let row = self.connection.query_row(
            "SELECT state,cancel_state,compensation_state,adapter_class,attempt_count,retry_budget,idempotency_key,parent_intent_id,receipt_ref,observation_ref \
             FROM effect_intents WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id],
            |row| {
                Ok(EffectViewRow {
                    state: row.get(0)?,
                    cancel_state: row.get(1)?,
                    compensation_state: row.get(2)?,
                    adapter_class: row.get(3)?,
                    attempt_count: row.get(4)?,
                    retry_budget: row.get(5)?,
                    idempotency_key: row.get(6)?,
                    parent_intent_id: row.get(7)?,
                    receipt_ref: row.get(8)?,
                    observation_ref: row.get(9)?,
                })
            },
        )?;
        Ok(EffectView {
            state: EffectState::parse(&row.state)?,
            cancel_state: CancelState::parse(&row.cancel_state)?,
            compensation_state: CompensationState::parse(&row.compensation_state)?,
            adapter_class: AdapterClass::parse(&row.adapter_class)?,
            attempt_count: u32::try_from(row.attempt_count)
                .map_err(|_| WorkError::InvalidTransition)?,
            retry_budget: u32::try_from(row.retry_budget)
                .map_err(|_| WorkError::InvalidTransition)?,
            idempotency_key: row.idempotency_key,
            parent_intent_id: row.parent_intent_id,
            receipt_ref: row.receipt_ref,
            observation_ref: row.observation_ref,
        })
    }

    pub fn event_count(&self, tenant_namespace: &str, intent_id: &str) -> WorkResult<u64> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM effect_events WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| WorkError::InvalidTransition)
    }

    fn transition_exact(
        &mut self,
        tenant_namespace: &str,
        intent_id: &str,
        from: EffectState,
        to: EffectState,
        event: &str,
        now: u64,
    ) -> WorkResult<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_effect_state(&tx, tenant_namespace, intent_id, from)?;
        tx.execute(
            "UPDATE effect_intents SET state=?3,updated_at=?4 WHERE tenant_namespace=?1 AND intent_id=?2",
            params![tenant_namespace, intent_id, to.as_db(), as_i64(now)?],
        )?;
        append_event(
            &tx,
            tenant_namespace,
            Some(intent_id),
            event,
            as_i64(now)?,
            None,
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn initialize_schema(connection: &mut Connection) -> WorkResult<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > WORK_SCHEMA_VERSION {
        return Err(WorkError::InvalidTransition);
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS work_namespaces( \
            tenant_namespace TEXT PRIMARY KEY \
         ); \
         CREATE TABLE IF NOT EXISTS work_items( \
            tenant_namespace TEXT NOT NULL,work_id TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0), \
            state TEXT NOT NULL CHECK(state IN ('PLANNED','RUNNING','WAITING','COMPLETED','FAILED','CANCELLED')), \
            payload_digest TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL, \
            PRIMARY KEY(tenant_namespace,work_id), \
            FOREIGN KEY(tenant_namespace) REFERENCES work_namespaces(tenant_namespace) \
         ); \
         CREATE TABLE IF NOT EXISTS work_queue( \
            tenant_namespace TEXT NOT NULL,work_id TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('READY','CLAIMED','BLOCKED')), \
            priority INTEGER NOT NULL,available_at INTEGER NOT NULL,claim_owner TEXT,claim_fence INTEGER NOT NULL CHECK(claim_fence>=0),claim_expires_at INTEGER, \
            PRIMARY KEY(tenant_namespace,work_id), \
            FOREIGN KEY(tenant_namespace,work_id) REFERENCES work_items(tenant_namespace,work_id) ON DELETE CASCADE \
         ); \
         CREATE TABLE IF NOT EXISTS effect_intents( \
            tenant_namespace TEXT NOT NULL,intent_id TEXT NOT NULL,work_id TEXT NOT NULL,operation_type TEXT NOT NULL, \
            target_account TEXT NOT NULL,payload_digest TEXT NOT NULL,adapter_class TEXT NOT NULL, \
            idempotency_key TEXT,idempotency_valid_until INTEGER,state TEXT NOT NULL,cancel_state TEXT NOT NULL, \
            compensation_state TEXT NOT NULL,attempt_count INTEGER NOT NULL CHECK(attempt_count>=0),retry_budget INTEGER NOT NULL CHECK(retry_budget>=0), \
            expected_evidence_plan_ref TEXT NOT NULL,decision_snapshot_digest TEXT,current_fence INTEGER,dispatch_started_at INTEGER, \
            receipt_ref TEXT,observation_ref TEXT,cancel_evidence_ref TEXT,last_error TEXT,parent_intent_id TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL, \
            PRIMARY KEY(tenant_namespace,intent_id), \
            FOREIGN KEY(tenant_namespace,work_id) REFERENCES work_items(tenant_namespace,work_id) \
         ); \
         CREATE TABLE IF NOT EXISTS outbox( \
            tenant_namespace TEXT NOT NULL,intent_id TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('READY','CLAIMED','DISPATCHING','DONE','BLOCKED')), \
            available_at INTEGER NOT NULL,claim_owner TEXT,claim_fence INTEGER,PRIMARY KEY(tenant_namespace,intent_id), \
            FOREIGN KEY(tenant_namespace,intent_id) REFERENCES effect_intents(tenant_namespace,intent_id) ON DELETE CASCADE \
         ); \
         CREATE TABLE IF NOT EXISTS dispatch_attempts( \
            tenant_namespace TEXT NOT NULL,intent_id TEXT NOT NULL,attempt_number INTEGER NOT NULL CHECK(attempt_number>0), \
            owner TEXT NOT NULL,fence INTEGER NOT NULL CHECK(fence>0),state TEXT NOT NULL CHECK(state IN ('STARTED','ACCEPTED','REJECTED_NO_EFFECT','UNKNOWN')), \
            started_at INTEGER NOT NULL,finished_at INTEGER,evidence_ref TEXT, \
            PRIMARY KEY(tenant_namespace,intent_id,attempt_number), \
            FOREIGN KEY(tenant_namespace,intent_id) REFERENCES effect_intents(tenant_namespace,intent_id) ON DELETE CASCADE \
         ); \
         CREATE TABLE IF NOT EXISTS dispatch_leases( \
            tenant_namespace TEXT PRIMARY KEY,owner TEXT NOT NULL,fence INTEGER NOT NULL CHECK(fence>0),expires_at INTEGER NOT NULL, \
            FOREIGN KEY(tenant_namespace) REFERENCES work_namespaces(tenant_namespace) \
         ); \
         CREATE TABLE IF NOT EXISTS callbacks( \
            tenant_namespace TEXT NOT NULL,callback_id TEXT NOT NULL,intent_id TEXT NOT NULL,callback_digest TEXT NOT NULL,recorded_at INTEGER NOT NULL, \
            PRIMARY KEY(tenant_namespace,callback_id), \
            FOREIGN KEY(tenant_namespace,intent_id) REFERENCES effect_intents(tenant_namespace,intent_id) \
         ); \
         CREATE TABLE IF NOT EXISTS execution_health( \
            tenant_namespace TEXT PRIMARY KEY,state TEXT NOT NULL CHECK(state IN ('HEALTHY','DEGRADED','UNHEALTHY','QUARANTINED')), \
            epoch INTEGER NOT NULL CHECK(epoch>=0),updated_at INTEGER NOT NULL, \
            FOREIGN KEY(tenant_namespace) REFERENCES work_namespaces(tenant_namespace) \
         ); \
         CREATE TABLE IF NOT EXISTS effect_events( \
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,tenant_namespace TEXT NOT NULL,intent_id TEXT,event_type TEXT NOT NULL, \
            recorded_at INTEGER NOT NULL,evidence_ref TEXT \
         ); \
         CREATE INDEX IF NOT EXISTS idx_work_queue_ready ON work_queue(tenant_namespace,state,available_at,priority DESC); \
         CREATE INDEX IF NOT EXISTS idx_outbox_ready ON outbox(tenant_namespace,state,available_at); \
         CREATE INDEX IF NOT EXISTS idx_effect_work ON effect_intents(tenant_namespace,work_id);",
    )?;
    connection.pragma_update(None, "user_version", WORK_SCHEMA_VERSION)?;
    Ok(())
}

fn ensure_tenant(tx: &Transaction<'_>, tenant_namespace: &str) -> WorkResult<()> {
    tx.execute(
        "INSERT OR IGNORE INTO work_namespaces(tenant_namespace) VALUES(?1)",
        [tenant_namespace],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO execution_health(tenant_namespace,state,epoch,updated_at) VALUES(?1,'HEALTHY',0,0)",
        [tenant_namespace],
    )?;
    Ok(())
}

fn validate_work_claim(tx: &Transaction<'_>, claim: &WorkClaim, now: u64) -> WorkResult<()> {
    let row: Option<(String, i64, Option<i64>)> = tx
        .query_row(
            "SELECT claim_owner,claim_fence,claim_expires_at FROM work_queue WHERE tenant_namespace=?1 AND work_id=?2 AND state='CLAIMED'",
            params![claim.tenant_namespace, claim.work_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((owner, fence, expires_at)) = row else {
        return Err(WorkError::StaleFence);
    };
    let now_i = as_i64(now)?;
    if owner != claim.owner
        || fence != as_i64(claim.fence)?
        || expires_at.map(|value| value <= now_i).unwrap_or(true)
    {
        return Err(WorkError::StaleFence);
    }
    Ok(())
}

fn insert_effect_tx(
    tx: &Transaction<'_>,
    spec: &EffectSpec,
    now: u64,
    parent_intent_id: Option<&str>,
) -> WorkResult<()> {
    let work_state: Option<String> = tx
        .query_row(
            "SELECT state FROM work_items WHERE tenant_namespace=?1 AND work_id=?2",
            params![spec.tenant_namespace, spec.work_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(work_state) = work_state else {
        return Err(WorkError::NotFound);
    };
    if matches!(
        WorkState::parse(&work_state)?,
        WorkState::Completed | WorkState::Failed | WorkState::Cancelled
    ) {
        return Err(WorkError::InvalidTransition);
    }
    let existing: Option<(String, String, String, String, String, Option<String>)> = tx
        .query_row(
            "SELECT work_id,payload_digest,target_account,operation_type,adapter_class,idempotency_key FROM effect_intents \
             WHERE tenant_namespace=?1 AND intent_id=?2",
            params![spec.tenant_namespace, spec.intent_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    if let Some((work, payload, target, operation, adapter, key)) = existing {
        if work == spec.work_id
            && payload == spec.payload_digest
            && target == spec.target_account
            && operation == spec.operation_type
            && adapter == spec.adapter_class.as_db()
            && key == spec.idempotency_key
        {
            return Ok(());
        }
        return Err(WorkError::DuplicateIntentConflict);
    }
    tx.execute(
        "INSERT INTO effect_intents(tenant_namespace,intent_id,work_id,operation_type,target_account,payload_digest, \
            adapter_class,idempotency_key,idempotency_valid_until,state,cancel_state,compensation_state,attempt_count, \
            retry_budget,expected_evidence_plan_ref,parent_intent_id,created_at,updated_at) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'PROPOSED','NONE',?10,0,?11,?12,?13,?14,?14)",
        params![
            spec.tenant_namespace,
            spec.intent_id,
            spec.work_id,
            spec.operation_type,
            spec.target_account,
            spec.payload_digest,
            spec.adapter_class.as_db(),
            spec.idempotency_key,
            spec.idempotency_valid_until.map(as_i64).transpose()?,
            if spec.adapter_class == AdapterClass::E4CompensatableWrite {
                CompensationState::Available.as_db()
            } else {
                CompensationState::NotApplicable.as_db()
            },
            i64::from(spec.retry_budget),
            spec.expected_evidence_plan_ref,
            parent_intent_id,
            as_i64(now)?
        ],
    )?;
    append_event(
        tx,
        &spec.tenant_namespace,
        Some(&spec.intent_id),
        "EFFECT_PROPOSED",
        as_i64(now)?,
        parent_intent_id,
    )?;
    Ok(())
}

fn validate_effect_spec(spec: &EffectSpec) -> WorkResult<()> {
    validate_id(&spec.tenant_namespace)?;
    validate_id(&spec.intent_id)?;
    validate_id(&spec.work_id)?;
    validate_id(&spec.operation_type)?;
    validate_id(&spec.target_account)?;
    validate_id(&spec.payload_digest)?;
    validate_id(&spec.expected_evidence_plan_ref)?;
    if let Some(value) = &spec.idempotency_key {
        validate_id(value)?;
    }
    Ok(())
}

fn validate_id(value: &str) -> WorkResult<()> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(WorkError::InvalidId);
    }
    Ok(())
}

fn as_i64(value: u64) -> WorkResult<i64> {
    i64::try_from(value).map_err(|_| WorkError::InvalidId)
}

fn effect_state_tx(
    tx: &Transaction<'_>,
    tenant_namespace: &str,
    intent_id: &str,
) -> WorkResult<EffectState> {
    let value: String = tx.query_row(
        "SELECT state FROM effect_intents WHERE tenant_namespace=?1 AND intent_id=?2",
        params![tenant_namespace, intent_id],
        |row| row.get(0),
    )?;
    EffectState::parse(&value)
}

fn require_effect_state(
    tx: &Transaction<'_>,
    tenant_namespace: &str,
    intent_id: &str,
    expected: EffectState,
) -> WorkResult<()> {
    if effect_state_tx(tx, tenant_namespace, intent_id)? != expected {
        return Err(WorkError::InvalidTransition);
    }
    Ok(())
}

fn require_not_cancelled(
    tx: &Transaction<'_>,
    tenant_namespace: &str,
    intent_id: &str,
) -> WorkResult<()> {
    let state: String = tx.query_row(
        "SELECT cancel_state FROM effect_intents WHERE tenant_namespace=?1 AND intent_id=?2",
        params![tenant_namespace, intent_id],
        |row| row.get(0),
    )?;
    if CancelState::parse(&state)? != CancelState::None {
        return Err(WorkError::InvalidTransition);
    }
    Ok(())
}

fn require_healthy(tx: &Transaction<'_>, tenant_namespace: &str) -> WorkResult<()> {
    let value: String = tx.query_row(
        "SELECT state FROM execution_health WHERE tenant_namespace=?1",
        [tenant_namespace],
        |row| row.get(0),
    )?;
    if HealthState::parse(&value)? != HealthState::Healthy {
        return Err(WorkError::ExecutionUnhealthy);
    }
    Ok(())
}

fn validate_lease(
    tx: &Transaction<'_>,
    tenant_namespace: &str,
    lease: &DispatchLease,
    now: u64,
) -> WorkResult<()> {
    if lease.tenant_namespace != tenant_namespace {
        return Err(WorkError::StaleFence);
    }
    let row: Option<(String, i64, i64)> = tx
        .query_row(
            "SELECT owner,fence,expires_at FROM dispatch_leases WHERE tenant_namespace=?1",
            [tenant_namespace],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((owner, fence, expires_at)) = row else {
        return Err(WorkError::StaleFence);
    };
    if owner != lease.owner || fence != as_i64(lease.fence)? || expires_at <= as_i64(now)? {
        return Err(WorkError::StaleFence);
    }
    Ok(())
}

fn require_attempt_open(tx: &Transaction<'_>, ticket: &DispatchTicket) -> WorkResult<()> {
    let row: Option<(String, i64, String)> = tx
        .query_row(
            "SELECT owner,fence,state FROM dispatch_attempts WHERE tenant_namespace=?1 AND intent_id=?2 AND attempt_number=?3",
            params![
                ticket.tenant_namespace,
                ticket.intent_id,
                i64::from(ticket.attempt)
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((owner, fence, state)) = row else {
        return Err(WorkError::NotFound);
    };
    if owner != ticket.owner
        || fence != as_i64(ticket.fence)?
        || !matches!(state.as_str(), "STARTED" | "UNKNOWN")
    {
        return Err(WorkError::StaleFence);
    }
    Ok(())
}

fn finish_attempt(
    tx: &Transaction<'_>,
    ticket: &DispatchTicket,
    state: &str,
    evidence_ref: &str,
    now: u64,
) -> WorkResult<()> {
    let changed = tx.execute(
        "UPDATE dispatch_attempts SET state=?4,finished_at=?5,evidence_ref=?6 \
         WHERE tenant_namespace=?1 AND intent_id=?2 AND attempt_number=?3 AND state IN ('STARTED','UNKNOWN')",
        params![
            ticket.tenant_namespace,
            ticket.intent_id,
            i64::from(ticket.attempt),
            state,
            as_i64(now)?,
            evidence_ref
        ],
    )?;
    if changed != 1 {
        return Err(WorkError::InvalidTransition);
    }
    Ok(())
}

fn mark_outbox_done(
    tx: &Transaction<'_>,
    tenant_namespace: &str,
    intent_id: &str,
) -> WorkResult<()> {
    tx.execute(
        "UPDATE outbox SET state='DONE' WHERE tenant_namespace=?1 AND intent_id=?2",
        params![tenant_namespace, intent_id],
    )?;
    Ok(())
}

fn append_event(
    tx: &Transaction<'_>,
    tenant_namespace: &str,
    intent_id: Option<&str>,
    event_type: &str,
    recorded_at: i64,
    evidence_ref: Option<&str>,
) -> WorkResult<()> {
    tx.execute(
        "INSERT INTO effect_events(tenant_namespace,intent_id,event_type,recorded_at,evidence_ref) VALUES(?1,?2,?3,?4,?5)",
        params![
            tenant_namespace,
            intent_id,
            event_type,
            recorded_at,
            evidence_ref
        ],
    )?;
    Ok(())
}

fn retry_delay_ms(base_ms: u64, max_ms: u64, attempt: u32, seed: &str) -> u64 {
    let shift = attempt.min(16);
    let exponential = base_ms.saturating_mul(1_u64 << shift).min(max_ms);
    let lower = exponential.saturating_mul(3) / 4;
    let span = exponential.saturating_sub(lower).max(1);
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in seed.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    lower.saturating_add(hash % span).min(max_ms)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn retry_delay_is_bounded() {
        for attempt in 0..64 {
            let delay = retry_delay_ms(250, 30_000, attempt, "intent-key");
            assert!(delay <= 30_000);
            assert!(delay >= 187);
        }
    }
}
