use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectError {
    Sqlite(String),
    Json(String),
    KeyProvider(String),
    InvalidField(&'static str),
    MissingTarget,
    InvalidTransition,
    DuplicateIntentConflict,
    NotFound,
    LeaseBusy,
    StaleFence,
    UnqualifiedAdapter,
    QualificationAdapterMismatch,
    SharedAtomicBoundaryUnproved,
    ExternalMutationMismatch,
    MissingIdempotencyKey,
    InvalidRetryPolicy,
    RetryNotAllowed,
    RetryBudgetExhausted,
    IdempotencyExpired,
    MissingEvidence,
    ExecutionUnhealthy,
}

impl std::fmt::Display for EffectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EffectError {}

impl From<rusqlite::Error> for EffectError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value.to_string())
    }
}

impl From<serde_json::Error> for EffectError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestRef {
    pub ref_id: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedRef {
    pub ref_id: String,
    pub version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectClass {
    Read,
    LocalWrite,
    ExternalReversible,
    ExternalConsequential,
    IrreversibleHighImpact,
}

impl EffectClass {
    pub const fn mutates_external_state(self) -> bool {
        matches!(
            self,
            Self::ExternalReversible | Self::ExternalConsequential | Self::IrreversibleHighImpact
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reversibility {
    Reversible,
    Compensatable,
    CancellableBeforeAccept,
    Irreversible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "knowledge",
    content = "milliseconds",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum DurationKnowledge {
    Known(u64),
    Unknown,
}

impl DurationKnowledge {
    pub const fn known_nonzero(self) -> Option<u64> {
        match self {
            Self::Known(value) if value > 0 => Some(value),
            Self::Known(_) | Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AcceptanceReceipt {
    None,
    Opaque,
    Verifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatusQuery {
    None,
    ByIntent,
    ByProviderId,
    ObservableState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallbackSemantics {
    None,
    Signed,
    ReplayProtected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CancelBeforeAcceptance {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CancelAfterAcceptance {
    Supported,
    BestEffort,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompensationCapability {
    None,
    SemanticUndo,
    CompensatingAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionBoundary {
    None,
    ProviderLocal,
    SharedAtomic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterAssuranceProfile {
    pub mutates_external_state: bool,
    pub accepts_stable_idempotency_key: bool,
    pub dedup_retention: DurationKnowledge,
    pub returns_acceptance_receipt: AcceptanceReceipt,
    pub status_query: StatusQuery,
    pub callback_semantics: CallbackSemantics,
    pub cancel_before_acceptance: CancelBeforeAcceptance,
    pub cancel_after_acceptance: CancelAfterAcceptance,
    pub compensation: CompensationCapability,
    pub transaction_boundary: TransactionBoundary,
    pub maximum_request_age: DurationKnowledge,
    pub replay_controls: BTreeSet<String>,
    pub known_ambiguity_failure_modes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterQualificationEvidence {
    pub adapter_ref: String,
    pub adapter_version: String,
    pub evidence_refs: BTreeSet<String>,
    pub exact_shared_atomic_boundary_ref: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperatingClass {
    E0ReadOnly,
    E1OpaqueWrite,
    E2DedupWrite,
    E3ObservableWrite,
    E4CompensatableWrite,
    E5SharedAtomic,
}

impl OperatingClass {
    pub const fn as_db(self) -> &'static str {
        match self {
            Self::E0ReadOnly => "E0_READ_ONLY",
            Self::E1OpaqueWrite => "E1_OPAQUE_WRITE",
            Self::E2DedupWrite => "E2_DEDUP_WRITE",
            Self::E3ObservableWrite => "E3_OBSERVABLE_WRITE",
            Self::E4CompensatableWrite => "E4_COMPENSATABLE_WRITE",
            Self::E5SharedAtomic => "E5_SHARED_ATOMIC",
        }
    }

    pub fn parse(value: &str) -> Result<Self, EffectError> {
        match value {
            "E0_READ_ONLY" => Ok(Self::E0ReadOnly),
            "E1_OPAQUE_WRITE" => Ok(Self::E1OpaqueWrite),
            "E2_DEDUP_WRITE" => Ok(Self::E2DedupWrite),
            "E3_OBSERVABLE_WRITE" => Ok(Self::E3ObservableWrite),
            "E4_COMPENSATABLE_WRITE" => Ok(Self::E4CompensatableWrite),
            "E5_SHARED_ATOMIC" => Ok(Self::E5SharedAtomic),
            _ => Err(EffectError::InvalidField("operating_class")),
        }
    }
}

pub fn derive_operating_class(
    profile: &AdapterAssuranceProfile,
    qualification: &AdapterQualificationEvidence,
) -> Result<OperatingClass, EffectError> {
    if !qualification.verified || qualification.evidence_refs.is_empty() {
        return Err(EffectError::UnqualifiedAdapter);
    }

    if profile.transaction_boundary == TransactionBoundary::SharedAtomic {
        if !profile.mutates_external_state {
            return Err(EffectError::ExternalMutationMismatch);
        }
        if qualification
            .exact_shared_atomic_boundary_ref
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Ok(OperatingClass::E5SharedAtomic);
        }
        return Err(EffectError::SharedAtomicBoundaryUnproved);
    }

    if !profile.mutates_external_state {
        return Ok(OperatingClass::E0ReadOnly);
    }

    if !profile.accepts_stable_idempotency_key || profile.dedup_retention.known_nonzero().is_none()
    {
        return Ok(OperatingClass::E1OpaqueWrite);
    }

    let observable = profile.returns_acceptance_receipt != AcceptanceReceipt::None
        || profile.status_query != StatusQuery::None;
    if !observable {
        return Ok(OperatingClass::E2DedupWrite);
    }

    if profile.compensation != CompensationCapability::None {
        return Ok(OperatingClass::E4CompensatableWrite);
    }

    Ok(OperatingClass::E3ObservableWrite)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdempotencyBinding {
    Supported { key: String, valid_until_ms: u64 },
    Unsupported,
}

impl IdempotencyBinding {
    pub fn key(&self) -> Option<&str> {
        match self {
            Self::Supported { key, .. } => Some(key),
            Self::Unsupported => None,
        }
    }

    pub const fn valid_until_ms(&self) -> Option<u64> {
        match self {
            Self::Supported { valid_until_ms, .. } => Some(*valid_until_ms),
            Self::Unsupported => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    Proposed,
    Prepared,
    Authorized,
    CommitReady,
    Dispatching,
    RejectedNoEffect,
    Accepted,
    AcceptanceUnknown,
    Reconciling,
    OutcomePending,
    Succeeded,
    FailedAfterAccept,
    OutcomeUnknown,
    Unresolved,
    Abandoned,
    Stale,
    CancelledPrecommit,
}

impl LifecycleState {
    pub const fn as_db(self) -> &'static str {
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
            Self::OutcomePending => "OUTCOME_PENDING",
            Self::Succeeded => "SUCCEEDED",
            Self::FailedAfterAccept => "FAILED_AFTER_ACCEPT",
            Self::OutcomeUnknown => "OUTCOME_UNKNOWN",
            Self::Unresolved => "UNRESOLVED",
            Self::Abandoned => "ABANDONED",
            Self::Stale => "STALE",
            Self::CancelledPrecommit => "CANCELLED_PRECOMMIT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CancelState {
    None,
    Requested,
    BlockedBeforeCommit,
    ForwardedToProvider,
    ConfirmedCancelled,
    TooLate,
    CancelUnknown,
}

impl CancelState {
    pub const fn as_db(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Requested => "REQUESTED",
            Self::BlockedBeforeCommit => "BLOCKED_BEFORE_COMMIT",
            Self::ForwardedToProvider => "FORWARDED_TO_PROVIDER",
            Self::ConfirmedCancelled => "CONFIRMED_CANCELLED",
            Self::TooLate => "TOO_LATE",
            Self::CancelUnknown => "CANCEL_UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationRecord {
    pub state: CancelState,
    pub evidence_refs: Vec<String>,
}

impl Default for CancellationRecord {
    fn default() -> Self {
        Self {
            state: CancelState::None,
            evidence_refs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompensationRecord {
    pub state: CompensationState,
    pub linked_effect_intent_ref: Option<String>,
    pub evidence_refs: Vec<String>,
}

impl Default for CompensationRecord {
    fn default() -> Self {
        Self {
            state: CompensationState::NotApplicable,
            linked_effect_intent_ref: None,
            evidence_refs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectIntent {
    pub effect_intent_id: String,
    pub operation_type: String,
    pub principal_context: DigestRef,
    pub goal: VersionedRef,
    pub work: VersionedRef,
    pub target_resources: Vec<String>,
    pub target_accounts: Vec<String>,
    pub target_principals: Vec<String>,
    pub payload_schema: String,
    pub payload_canonical_digest: String,
    pub payload_ref: String,
    pub purpose: String,
    pub data_classes: BTreeSet<String>,
    pub disclosure_classes: BTreeSet<String>,
    pub effect_class: EffectClass,
    pub reversibility: Reversibility,
    pub adapter_ref: String,
    pub adapter_version: String,
    pub assurance_profile: AdapterAssuranceProfile,
    pub idempotency: IdempotencyBinding,
    pub expected_evidence_plan_ref: String,
    pub created_by_message_ref: String,
    pub lifecycle_state: LifecycleState,
    pub decision_snapshot_refs: Vec<DigestRef>,
    pub dispatch_attempt_refs: Vec<String>,
    pub provider_receipt_refs: Vec<String>,
    pub observation_refs: Vec<String>,
    pub cancellation: CancellationRecord,
    pub compensation: CompensationRecord,
    pub current_fence: Option<u64>,
}

impl EffectIntent {
    pub fn validate_static(
        &self,
        qualification: &AdapterQualificationEvidence,
    ) -> Result<OperatingClass, EffectError> {
        for (name, value) in [
            ("effect_intent_id", self.effect_intent_id.as_str()),
            ("operation_type", self.operation_type.as_str()),
            (
                "principal_context.ref_id",
                self.principal_context.ref_id.as_str(),
            ),
            (
                "principal_context.digest",
                self.principal_context.digest.as_str(),
            ),
            ("goal.ref_id", self.goal.ref_id.as_str()),
            ("work.ref_id", self.work.ref_id.as_str()),
            ("payload_schema", self.payload_schema.as_str()),
            (
                "payload_canonical_digest",
                self.payload_canonical_digest.as_str(),
            ),
            ("payload_ref", self.payload_ref.as_str()),
            ("purpose", self.purpose.as_str()),
            ("adapter_ref", self.adapter_ref.as_str()),
            ("adapter_version", self.adapter_version.as_str()),
            (
                "expected_evidence_plan_ref",
                self.expected_evidence_plan_ref.as_str(),
            ),
            (
                "created_by_message_ref",
                self.created_by_message_ref.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(EffectError::InvalidField(name));
            }
        }

        if self.target_resources.is_empty()
            && self.target_accounts.is_empty()
            && self.target_principals.is_empty()
        {
            return Err(EffectError::MissingTarget);
        }

        if qualification.adapter_ref != self.adapter_ref
            || qualification.adapter_version != self.adapter_version
        {
            return Err(EffectError::QualificationAdapterMismatch);
        }

        if self.effect_class.mutates_external_state()
            != self.assurance_profile.mutates_external_state
        {
            return Err(EffectError::ExternalMutationMismatch);
        }

        let operating_class = derive_operating_class(&self.assurance_profile, qualification)?;
        if matches!(
            operating_class,
            OperatingClass::E2DedupWrite
                | OperatingClass::E3ObservableWrite
                | OperatingClass::E4CompensatableWrite
        ) {
            match &self.idempotency {
                IdempotencyBinding::Supported {
                    key,
                    valid_until_ms,
                } if !key.trim().is_empty() && *valid_until_ms > 0 => {}
                _ => return Err(EffectError::MissingIdempotencyKey),
            }
        }

        if let IdempotencyBinding::Supported { key, .. } = &self.idempotency
            && key.trim().is_empty()
        {
            return Err(EffectError::MissingIdempotencyKey);
        }

        Ok(operating_class)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetryStrategy {
    Fixed,
    Exponential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub strategy: RetryStrategy,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub max_attempts: u32,
    pub qualification_ref: String,
}

impl RetryPolicy {
    pub fn validate_for(
        &self,
        operating_class: OperatingClass,
        intent: &EffectIntent,
    ) -> Result<(), EffectError> {
        if self.qualification_ref.trim().is_empty()
            || self.max_attempts == 0
            || self.base_delay_ms == 0
            || self.max_delay_ms < self.base_delay_ms
        {
            return Err(EffectError::InvalidRetryPolicy);
        }

        if operating_class == OperatingClass::E1OpaqueWrite && self.max_attempts > 1 {
            return Err(EffectError::InvalidRetryPolicy);
        }

        if matches!(
            operating_class,
            OperatingClass::E2DedupWrite
                | OperatingClass::E3ObservableWrite
                | OperatingClass::E4CompensatableWrite
        ) && self.max_attempts > 1
            && !matches!(intent.idempotency, IdempotencyBinding::Supported { .. })
        {
            return Err(EffectError::InvalidRetryPolicy);
        }
        Ok(())
    }

    pub fn delay_after_attempt(&self, attempt_count: u32) -> Result<u64, EffectError> {
        if attempt_count == 0 {
            return Err(EffectError::InvalidRetryPolicy);
        }
        let delay = match self.strategy {
            RetryStrategy::Fixed => self.base_delay_ms,
            RetryStrategy::Exponential => {
                let exponent = attempt_count.saturating_sub(1).min(63);
                self.base_delay_ms
                    .saturating_mul(1_u64.checked_shl(exponent).unwrap_or(u64::MAX))
            }
        };
        Ok(delay.min(self.max_delay_ms))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchLease {
    pub tenant_namespace: String,
    pub owner: String,
    pub fence: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchTicket {
    pub tenant_namespace: String,
    pub effect_intent_id: String,
    pub attempt_number: u32,
    pub fence: u64,
    pub request_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportResult {
    NotSentProven { evidence_ref: String },
    ResponseAccepted { receipt_ref: String },
    ResponseRejectedNoEffect { evidence_ref: String },
    ResponseLost { evidence_ref: String },
    ConnectionFailedAmbiguous { evidence_ref: String },
    LocalAbortNotSentProven { evidence_ref: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    Terminal,
    NoAutomaticRetry,
    RetrySameIntent { after_ms: u64 },
    Reconcile,
    ManualReview,
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
pub enum CancelResolution {
    ConfirmedCancelled,
    TooLate,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectView {
    pub intent: EffectIntent,
    pub operating_class: OperatingClass,
    pub retry_policy: RetryPolicy,
    pub attempt_count: u32,
    pub record_digest: String,
}
