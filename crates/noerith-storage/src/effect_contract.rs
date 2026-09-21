use std::{collections::BTreeSet, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EffectClass {
    Read,
    LocalWrite,
    ExternalReversible,
    ExternalConsequential,
    IrreversibleHighImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reversibility {
    Reversible,
    Compensatable,
    CancellableBeforeAccept,
    Irreversible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationKnowledge {
    Known(Duration),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceReceipt {
    None,
    Opaque,
    Verifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusQuery {
    None,
    ByIntent,
    ByProviderId,
    ObservableState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackSemantics {
    None,
    Signed,
    ReplayProtected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelBeforeAcceptance {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelAfterAcceptance {
    Supported,
    BestEffort,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompensationCapability {
    None,
    SemanticUndo,
    CompensatingAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionBoundary {
    None,
    ProviderLocal,
    SharedAtomic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterQualificationEvidence {
    pub adapter_ref: String,
    pub adapter_version: String,
    pub evidence_refs: BTreeSet<String>,
    pub exact_shared_atomic_boundary_ref: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperatingClass {
    E0ReadOnly,
    E1OpaqueWrite,
    E2DedupWrite,
    E3ObservableWrite,
    E4CompensatableWrite,
    E5SharedAtomic,
}

impl OperatingClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::E0ReadOnly => "E0_READ_ONLY",
            Self::E1OpaqueWrite => "E1_OPAQUE_WRITE",
            Self::E2DedupWrite => "E2_DEDUP_WRITE",
            Self::E3ObservableWrite => "E3_OBSERVABLE_WRITE",
            Self::E4CompensatableWrite => "E4_COMPENSATABLE_WRITE",
            Self::E5SharedAtomic => "E5_SHARED_ATOMIC",
        }
    }

    /// Adapter capability can only be reduced by user/risk/policy limits.
    /// A limit is never expanded merely because an adapter qualified higher.
    pub fn restricted_to(self, external_ceiling: Self) -> Self {
        std::cmp::min(self, external_ceiling)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectContractError {
    EmptyField(&'static str),
    MissingTarget,
    UnqualifiedAssurance,
    QualificationAdapterMismatch,
    SharedAtomicBoundaryUnproved,
    ExternalMutationMismatch,
    MissingIdempotencyKey,
}

pub fn derive_operating_class(
    profile: &AdapterAssuranceProfile,
    qualification: &AdapterQualificationEvidence,
) -> Result<OperatingClass, EffectContractError> {
    if !qualification.verified || qualification.evidence_refs.is_empty() {
        return Err(EffectContractError::UnqualifiedAssurance);
    }

    if profile.transaction_boundary == TransactionBoundary::SharedAtomic {
        if !profile.mutates_external_state {
            return Err(EffectContractError::ExternalMutationMismatch);
        }
        match qualification.exact_shared_atomic_boundary_ref.as_deref() {
            Some(boundary) if !boundary.trim().is_empty() => {
                return Ok(OperatingClass::E5SharedAtomic);
            }
            _ => return Err(EffectContractError::SharedAtomicBoundaryUnproved),
        }
    }

    if !profile.mutates_external_state {
        return Ok(OperatingClass::E0ReadOnly);
    }

    let dedup_qualified = profile.accepts_stable_idempotency_key
        && matches!(profile.dedup_retention, DurationKnowledge::Known(duration) if !duration.is_zero());
    if !dedup_qualified {
        return Ok(OperatingClass::E1OpaqueWrite);
    }

    let observable_acceptance = profile.returns_acceptance_receipt != AcceptanceReceipt::None
        || profile.status_query != StatusQuery::None;
    if !observable_acceptance {
        return Ok(OperatingClass::E2DedupWrite);
    }

    if profile.compensation != CompensationCapability::None {
        return Ok(OperatingClass::E4CompensatableWrite);
    }

    Ok(OperatingClass::E3ObservableWrite)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectIntent {
    pub effect_intent_id: String,
    pub operation_type: String,
    pub principal_context_ref: String,
    pub principal_context_digest: String,
    pub goal_ref: String,
    pub goal_version: u64,
    pub work_ref: String,
    pub work_revision: u64,
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
    pub idempotency_key: Option<String>,
    pub expected_evidence_plan_ref: String,
    pub created_by_message_ref: String,
    pub lifecycle_state: String,
    pub decision_snapshot_refs: Vec<String>,
    pub dispatch_attempt_refs: Vec<String>,
    pub provider_receipt_refs: Vec<String>,
    pub observation_refs: Vec<String>,
    pub cancellation_record_ref: Option<String>,
    pub compensation_record_ref: Option<String>,
    pub current_fence: Option<u64>,
}

impl EffectIntent {
    pub fn validate(
        &self,
        qualification: &AdapterQualificationEvidence,
    ) -> Result<OperatingClass, EffectContractError> {
        for (name, value) in [
            ("effect_intent_id", self.effect_intent_id.as_str()),
            ("operation_type", self.operation_type.as_str()),
            ("principal_context_ref", self.principal_context_ref.as_str()),
            (
                "principal_context_digest",
                self.principal_context_digest.as_str(),
            ),
            ("goal_ref", self.goal_ref.as_str()),
            ("work_ref", self.work_ref.as_str()),
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
            ("lifecycle_state", self.lifecycle_state.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(EffectContractError::EmptyField(name));
            }
        }

        if self.target_resources.is_empty()
            && self.target_accounts.is_empty()
            && self.target_principals.is_empty()
        {
            return Err(EffectContractError::MissingTarget);
        }

        if qualification.adapter_ref != self.adapter_ref
            || qualification.adapter_version != self.adapter_version
        {
            return Err(EffectContractError::QualificationAdapterMismatch);
        }

        let external_effect = matches!(
            self.effect_class,
            EffectClass::ExternalReversible
                | EffectClass::ExternalConsequential
                | EffectClass::IrreversibleHighImpact
        );
        if external_effect != self.assurance_profile.mutates_external_state {
            return Err(EffectContractError::ExternalMutationMismatch);
        }

        let operating_class = derive_operating_class(&self.assurance_profile, qualification)?;
        if matches!(
            operating_class,
            OperatingClass::E2DedupWrite
                | OperatingClass::E3ObservableWrite
                | OperatingClass::E4CompensatableWrite
        ) && self
            .idempotency_key
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(EffectContractError::MissingIdempotencyKey);
        }

        Ok(operating_class)
    }

    /// A retry of one real user intention keeps the same stable intent identity
    /// and, where supported, the same idempotency key. Payload equality alone
    /// never makes two intentions the same.
    pub fn is_same_retry_identity_as(&self, other: &Self) -> bool {
        self.effect_intent_id == other.effect_intent_id
            && self.idempotency_key == other.idempotency_key
    }
}
