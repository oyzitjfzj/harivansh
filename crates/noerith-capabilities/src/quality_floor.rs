extern crate alloc;

use crate::{
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    regime::SpecialistRegime,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const QUALITY_FLOOR_PLAN_CANONICAL_PROFILE: &str =
    "NOERITH/QUALITY-FLOOR-PLAN/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0QUALITY-FLOOR-PLAN\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QualityGateId {
    Q06MemoryContext,
    Q07ModelsExperts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QualityCriterionKind {
    Recall,
    Fidelity,
    Privacy,
    NoSilentLostConstraint,
    Quality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QualityProfileMetricRole {
    Cost,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityFloorCriterion {
    pub kind: QualityCriterionKind,
    pub criterion_ref: Reference,
    pub measurement_target_ref: Reference,
    pub threshold_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityProfileMetric {
    pub role: QualityProfileMetricRole,
    pub metric_ref: Reference,
    pub measurement_target_ref: Reference,
    pub reporting_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q06CoverageContract {
    pub long_history_memory_corpus_ref: Reference,
    pub multi_session_reasoning_corpus_ref: Reference,
    pub correction_case_corpus_ref: Reference,
    pub poisoning_case_corpus_ref: Reference,
    pub lifecycle_case_corpus_ref: Reference,
    pub abstention_unknown_case_corpus_ref: Reference,
    pub protected_constraint_evidence_ref: Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Q07ComparisonAxis {
    CandidateModel,
    WorkerTopology,
    ReasoningEffort,
    ContextStrategy,
    RetrievalStrategy,
}

impl Q07ComparisonAxis {
    pub const ALL: [Self; 5] = [
        Self::CandidateModel,
        Self::WorkerTopology,
        Self::ReasoningEffort,
        Self::ContextStrategy,
        Self::RetrievalStrategy,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q07CoverageContract {
    pub heldout_regime_corpus_refs: BTreeMap<SpecialistRegime, Reference>,
    pub comparison_axis_refs: BTreeMap<Q07ComparisonAxis, Reference>,
    pub repeated_trial_protocol_ref: Reference,
    pub candidate_configuration_manifest_ref: Reference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityGateCoverage {
    Q06(Q06CoverageContract),
    Q07(Q07CoverageContract),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityFloorPlan {
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub gate: QualityGateId,
    pub source_contract_refs: BTreeSet<Reference>,
    pub floor_criteria: Vec<QualityFloorCriterion>,
    pub profile_metrics: Vec<QualityProfileMetric>,
    pub coverage: QualityGateCoverage,
    pub evaluation_corpus_refs: BTreeSet<Reference>,
    pub grader_plan_refs: BTreeSet<Reference>,
    pub environment_qualification_plan_refs: BTreeSet<Reference>,
    pub trial_protocol_ref: Reference,
    pub statistical_model_ref: Reference,
    pub uncertainty_policy_ref: Reference,
    pub seed_manifest_ref: Reference,
    pub hardware_manifest_ref: Reference,
    pub confidence_target_ref: Reference,
    pub analysis_plan_ref: Reference,
    pub preregistration_evidence_ref: Reference,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQualityFloorPlan {
    plan_ref: Reference,
    plan_version: OpaqueVersion,
    content_digest: ContentDigest,
    gate: QualityGateId,
    hard_criterion_refs: BTreeSet<Reference>,
    profile_metric_refs: BTreeSet<Reference>,
    canonical_profile_ref: &'static str,
}

impl VerifiedQualityFloorPlan {
    pub fn plan_ref(&self) -> &Reference {
        &self.plan_ref
    }

    pub fn plan_version(&self) -> &OpaqueVersion {
        &self.plan_version
    }

    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    pub fn gate(&self) -> QualityGateId {
        self.gate
    }

    pub fn hard_criterion_refs(&self) -> &BTreeSet<Reference> {
        &self.hard_criterion_refs
    }

    pub fn profile_metric_refs(&self) -> &BTreeSet<Reference> {
        &self.profile_metric_refs
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityFloorError {
    MissingSourceContracts,
    WrongCoverageForGate,
    DuplicateCriterion(String),
    DuplicateCriterionKind(QualityCriterionKind),
    DuplicateProfileMetric(String),
    CriterionProfileCollision(String),
    MissingCriterionEvidence(String),
    MissingMetricEvidence(String),
    MissingQ06Criterion(QualityCriterionKind),
    MissingQ07Criterion(QualityCriterionKind),
    MissingQ07CostProfile,
    MissingQ07Regime(SpecialistRegime),
    UnexpectedQ07RegimeCount,
    MissingQ07ComparisonAxis(Q07ComparisonAxis),
    MissingCommonEvidence,
    UnsupportedDigestAlgorithm(String),
    DigestMismatch,
    EncodingFailure,
}

impl fmt::Display for QualityFloorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "quality-floor plan rejected: {self:?}")
    }
}

pub fn compute_quality_floor_plan_digest(
    plan: &QualityFloorPlan,
) -> Result<ContentDigest, QualityFloorError> {
    validate_plan_shape(plan)?;
    let transcript = canonical_quality_floor_plan_transcript(plan)?;
    let digest = Sha256::digest(&transcript);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| QualityFloorError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| QualityFloorError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| QualityFloorError::EncodingFailure)?,
    })
}

pub fn verify_quality_floor_plan(
    plan: &QualityFloorPlan,
) -> Result<VerifiedQualityFloorPlan, QualityFloorError> {
    if plan.content_digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(QualityFloorError::UnsupportedDigestAlgorithm(
            plan.content_digest.algorithm_ref.to_string(),
        ));
    }
    let computed = compute_quality_floor_plan_digest(plan)?;
    if computed != plan.content_digest {
        return Err(QualityFloorError::DigestMismatch);
    }
    Ok(VerifiedQualityFloorPlan {
        plan_ref: plan.plan_ref.clone(),
        plan_version: plan.plan_version.clone(),
        content_digest: computed,
        gate: plan.gate,
        hard_criterion_refs: plan
            .floor_criteria
            .iter()
            .map(|criterion| criterion.criterion_ref.clone())
            .collect(),
        profile_metric_refs: plan
            .profile_metrics
            .iter()
            .map(|metric| metric.metric_ref.clone())
            .collect(),
        canonical_profile_ref: QUALITY_FLOOR_PLAN_CANONICAL_PROFILE,
    })
}

pub fn canonical_quality_floor_plan_transcript(
    plan: &QualityFloorPlan,
) -> Result<Vec<u8>, QualityFloorError> {
    validate_plan_shape(plan)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&plan.plan_ref)?;
    encoder.version(&plan.plan_version)?;
    encoder.gate(plan.gate)?;
    encoder.ref_set(&plan.source_contract_refs)?;

    let mut criteria: Vec<&QualityFloorCriterion> = plan.floor_criteria.iter().collect();
    criteria.sort_by(|left, right| left.criterion_ref.cmp(&right.criterion_ref));
    encoder.count(criteria.len())?;
    for criterion in criteria {
        encoder.criterion(criterion)?;
    }

    let mut metrics: Vec<&QualityProfileMetric> = plan.profile_metrics.iter().collect();
    metrics.sort_by(|left, right| left.metric_ref.cmp(&right.metric_ref));
    encoder.count(metrics.len())?;
    for metric in metrics {
        encoder.metric(metric)?;
    }

    encoder.coverage(&plan.coverage)?;
    encoder.ref_set(&plan.evaluation_corpus_refs)?;
    encoder.ref_set(&plan.grader_plan_refs)?;
    encoder.ref_set(&plan.environment_qualification_plan_refs)?;
    encoder.reference(&plan.trial_protocol_ref)?;
    encoder.reference(&plan.statistical_model_ref)?;
    encoder.reference(&plan.uncertainty_policy_ref)?;
    encoder.reference(&plan.seed_manifest_ref)?;
    encoder.reference(&plan.hardware_manifest_ref)?;
    encoder.reference(&plan.confidence_target_ref)?;
    encoder.reference(&plan.analysis_plan_ref)?;
    encoder.reference(&plan.preregistration_evidence_ref)?;
    encoder.ref_set(&plan.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

fn validate_plan_shape(plan: &QualityFloorPlan) -> Result<(), QualityFloorError> {
    if plan.source_contract_refs.is_empty() {
        return Err(QualityFloorError::MissingSourceContracts);
    }
    if plan.evaluation_corpus_refs.is_empty()
        || plan.grader_plan_refs.is_empty()
        || plan.environment_qualification_plan_refs.is_empty()
        || plan.invalidation_dependency_refs.is_empty()
    {
        return Err(QualityFloorError::MissingCommonEvidence);
    }

    let mut criterion_refs = BTreeSet::new();
    let mut criterion_kinds = BTreeSet::new();
    for criterion in &plan.floor_criteria {
        if !criterion_refs.insert(criterion.criterion_ref.clone()) {
            return Err(QualityFloorError::DuplicateCriterion(
                criterion.criterion_ref.to_string(),
            ));
        }
        if !criterion_kinds.insert(criterion.kind) {
            return Err(QualityFloorError::DuplicateCriterionKind(criterion.kind));
        }
        if criterion.evidence_requirement_refs.is_empty() {
            return Err(QualityFloorError::MissingCriterionEvidence(
                criterion.criterion_ref.to_string(),
            ));
        }
    }

    let mut metric_refs = BTreeSet::new();
    for metric in &plan.profile_metrics {
        if !metric_refs.insert(metric.metric_ref.clone()) {
            return Err(QualityFloorError::DuplicateProfileMetric(
                metric.metric_ref.to_string(),
            ));
        }
        if criterion_refs.contains(&metric.metric_ref) {
            return Err(QualityFloorError::CriterionProfileCollision(
                metric.metric_ref.to_string(),
            ));
        }
        if metric.evidence_requirement_refs.is_empty() {
            return Err(QualityFloorError::MissingMetricEvidence(
                metric.metric_ref.to_string(),
            ));
        }
    }

    match (&plan.gate, &plan.coverage) {
        (QualityGateId::Q06MemoryContext, QualityGateCoverage::Q06(_)) => {
            for kind in [
                QualityCriterionKind::Recall,
                QualityCriterionKind::Fidelity,
                QualityCriterionKind::Privacy,
                QualityCriterionKind::NoSilentLostConstraint,
            ] {
                if !criterion_kinds.contains(&kind) {
                    return Err(QualityFloorError::MissingQ06Criterion(kind));
                }
            }
        }
        (QualityGateId::Q07ModelsExperts, QualityGateCoverage::Q07(coverage)) => {
            for kind in [QualityCriterionKind::Quality, QualityCriterionKind::Privacy] {
                if !criterion_kinds.contains(&kind) {
                    return Err(QualityFloorError::MissingQ07Criterion(kind));
                }
            }
            if !plan
                .profile_metrics
                .iter()
                .any(|metric| metric.role == QualityProfileMetricRole::Cost)
            {
                return Err(QualityFloorError::MissingQ07CostProfile);
            }
            if coverage.heldout_regime_corpus_refs.len() != SpecialistRegime::ALL.len() {
                return Err(QualityFloorError::UnexpectedQ07RegimeCount);
            }
            for regime in SpecialistRegime::ALL {
                if !coverage.heldout_regime_corpus_refs.contains_key(&regime) {
                    return Err(QualityFloorError::MissingQ07Regime(regime));
                }
            }
            for axis in Q07ComparisonAxis::ALL {
                if !coverage.comparison_axis_refs.contains_key(&axis) {
                    return Err(QualityFloorError::MissingQ07ComparisonAxis(axis));
                }
            }
        }
        _ => return Err(QualityFloorError::WrongCoverageForGate),
    }
    Ok(())
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn count(&mut self, value: usize) -> Result<(), QualityFloorError> {
        let value = u64::try_from(value).map_err(|_| QualityFloorError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), QualityFloorError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), QualityFloorError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), QualityFloorError> {
        self.scalar(value.as_str())
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), QualityFloorError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn gate(&mut self, gate: QualityGateId) -> Result<(), QualityFloorError> {
        self.scalar(match gate {
            QualityGateId::Q06MemoryContext => "Q06-memory-context",
            QualityGateId::Q07ModelsExperts => "Q07-models-experts",
        })
    }

    fn criterion(&mut self, value: &QualityFloorCriterion) -> Result<(), QualityFloorError> {
        self.scalar(match value.kind {
            QualityCriterionKind::Recall => "recall",
            QualityCriterionKind::Fidelity => "fidelity",
            QualityCriterionKind::Privacy => "privacy",
            QualityCriterionKind::NoSilentLostConstraint => "no-silent-lost-constraint",
            QualityCriterionKind::Quality => "quality",
        })?;
        self.reference(&value.criterion_ref)?;
        self.reference(&value.measurement_target_ref)?;
        self.reference(&value.threshold_policy_ref)?;
        self.ref_set(&value.evidence_requirement_refs)
    }

    fn metric(&mut self, value: &QualityProfileMetric) -> Result<(), QualityFloorError> {
        self.scalar(match value.role {
            QualityProfileMetricRole::Cost => "cost",
            QualityProfileMetricRole::Other => "other",
        })?;
        self.reference(&value.metric_ref)?;
        self.reference(&value.measurement_target_ref)?;
        self.reference(&value.reporting_policy_ref)?;
        self.ref_set(&value.evidence_requirement_refs)
    }

    fn coverage(&mut self, value: &QualityGateCoverage) -> Result<(), QualityFloorError> {
        match value {
            QualityGateCoverage::Q06(coverage) => {
                self.scalar("q06")?;
                self.reference(&coverage.long_history_memory_corpus_ref)?;
                self.reference(&coverage.multi_session_reasoning_corpus_ref)?;
                self.reference(&coverage.correction_case_corpus_ref)?;
                self.reference(&coverage.poisoning_case_corpus_ref)?;
                self.reference(&coverage.lifecycle_case_corpus_ref)?;
                self.reference(&coverage.abstention_unknown_case_corpus_ref)?;
                self.reference(&coverage.protected_constraint_evidence_ref)
            }
            QualityGateCoverage::Q07(coverage) => {
                self.scalar("q07")?;
                self.count(coverage.heldout_regime_corpus_refs.len())?;
                for (regime, reference) in &coverage.heldout_regime_corpus_refs {
                    self.scalar(match regime {
                        SpecialistRegime::ConversationPersonalAssistant => {
                            "conversation-personal-assistant"
                        }
                        SpecialistRegime::ResearchDeepResearch => "research-deep-research",
                        SpecialistRegime::SoftwareEngineering => "software-engineering",
                        SpecialistRegime::ActionAutomation => "action-automation",
                        SpecialistRegime::CreationArtifact => "creation-artifact",
                        SpecialistRegime::MonitoringLongRunningWork => {
                            "monitoring-long-running-work"
                        }
                    })?;
                    self.reference(reference)?;
                }
                self.count(coverage.comparison_axis_refs.len())?;
                for (axis, reference) in &coverage.comparison_axis_refs {
                    self.scalar(match axis {
                        Q07ComparisonAxis::CandidateModel => "candidate-model",
                        Q07ComparisonAxis::WorkerTopology => "worker-topology",
                        Q07ComparisonAxis::ReasoningEffort => "reasoning-effort",
                        Q07ComparisonAxis::ContextStrategy => "context-strategy",
                        Q07ComparisonAxis::RetrievalStrategy => "retrieval-strategy",
                    })?;
                    self.reference(reference)?;
                }
                self.reference(&coverage.repeated_trial_protocol_ref)?;
                self.reference(&coverage.candidate_configuration_manifest_ref)
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
