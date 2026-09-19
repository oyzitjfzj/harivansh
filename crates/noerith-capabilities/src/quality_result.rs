extern crate alloc;

use crate::{
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    qualification::EvidenceStatus,
    quality_floor::{
        Q07ComparisonAxis, QualityCriterionKind, QualityFloorError, QualityFloorPlan,
        QualityGateCoverage, QualityGateId, QualityProfileMetricRole, VerifiedQualityFloorPlan,
        verify_quality_floor_plan,
    },
    regime::SpecialistRegime,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const QUALITY_FLOOR_RESULT_CANONICAL_PROFILE: &str =
    "NOERITH/QUALITY-FLOOR-RESULT/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0QUALITY-FLOOR-RESULT\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityExperimentBinding {
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityCriterionResult {
    pub result_ref: Reference,
    pub criterion_ref: Reference,
    pub kind: QualityCriterionKind,
    pub status: EvidenceStatus,
    pub measurement_target_ref: Reference,
    pub threshold_policy_ref: Reference,
    pub satisfied_evidence_requirement_refs: BTreeSet<Reference>,
    pub analysis_result_ref: Reference,
    pub trial_evidence_refs: BTreeSet<Reference>,
    pub grader_result_refs: BTreeSet<Reference>,
    pub environment_evidence_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityProfileResult {
    pub result_ref: Reference,
    pub metric_ref: Reference,
    pub role: QualityProfileMetricRole,
    pub measurement_target_ref: Reference,
    pub reporting_policy_ref: Reference,
    pub satisfied_evidence_requirement_refs: BTreeSet<Reference>,
    pub measured_result_ref: Reference,
    pub evidence_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QualityCoverageItem {
    Q06LongHistoryMemory,
    Q06MultiSessionReasoning,
    Q06Corrections,
    Q06Poisoning,
    Q06Lifecycle,
    Q06AbstentionUnknown,
    Q06ProtectedConstraint,
    Q07Regime(SpecialistRegime),
    Q07ComparisonAxis(Q07ComparisonAxis),
    Q07RepeatedTrials,
    Q07CandidateConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityCoverageResult {
    pub item: QualityCoverageItem,
    pub requirement_ref: Reference,
    pub evidence_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityFloorResultSet {
    pub result_set_ref: Reference,
    pub result_set_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub plan_digest: ContentDigest,
    pub gate: QualityGateId,
    pub experiment: QualityExperimentBinding,
    pub criterion_results: Vec<QualityCriterionResult>,
    pub profile_results: Vec<QualityProfileResult>,
    pub coverage_results: Vec<QualityCoverageResult>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQualityFloorResult {
    result_set_ref: Reference,
    result_set_version: OpaqueVersion,
    content_digest: ContentDigest,
    plan_ref: Reference,
    plan_version: OpaqueVersion,
    plan_digest: ContentDigest,
    gate: QualityGateId,
    criterion_result_refs: BTreeSet<Reference>,
    profile_result_refs: BTreeSet<Reference>,
    coverage_evidence_refs: BTreeSet<Reference>,
    canonical_profile_ref: &'static str,
}

impl VerifiedQualityFloorResult {
    pub fn result_set_ref(&self) -> &Reference {
        &self.result_set_ref
    }

    pub fn result_set_version(&self) -> &OpaqueVersion {
        &self.result_set_version
    }

    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    pub fn plan_ref(&self) -> &Reference {
        &self.plan_ref
    }

    pub fn plan_version(&self) -> &OpaqueVersion {
        &self.plan_version
    }

    pub fn plan_digest(&self) -> &ContentDigest {
        &self.plan_digest
    }

    pub fn gate(&self) -> QualityGateId {
        self.gate
    }

    pub fn criterion_result_refs(&self) -> &BTreeSet<Reference> {
        &self.criterion_result_refs
    }

    pub fn profile_result_refs(&self) -> &BTreeSet<Reference> {
        &self.profile_result_refs
    }

    pub fn coverage_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.coverage_evidence_refs
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityResultError {
    FloorPlan(QualityFloorError),
    VerifiedPlanMismatch,
    PlanBindingMismatch,
    ExperimentBindingMismatch,
    DuplicateCriterionResult(String),
    DuplicateCriterionResultRef(String),
    CriterionSetMismatch,
    CriterionBindingMismatch(String),
    CriterionEvidenceMissing(String),
    HardCriterionFailed(String),
    HardCriterionIndeterminate(String),
    DuplicateProfileResult(String),
    DuplicateProfileResultRef(String),
    ResultRefCollision(String),
    ProfileSetMismatch,
    ProfileBindingMismatch(String),
    ProfileEvidenceMissing(String),
    DuplicateCoverageItem(QualityCoverageItem),
    CoverageSetMismatch,
    CoverageBindingMismatch(QualityCoverageItem),
    CoverageEvidenceMissing(QualityCoverageItem),
    MissingProvenance,
    MissingInvalidationDependencies,
    UnsupportedDigestAlgorithm(String),
    DigestMismatch,
    EncodingFailure,
}

impl fmt::Display for QualityResultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "quality-floor result rejected: {self:?}")
    }
}

pub fn compute_quality_floor_result_digest(
    result: &QualityFloorResultSet,
) -> Result<ContentDigest, QualityResultError> {
    validate_result_shape(result)?;
    let transcript = canonical_quality_floor_result_transcript(result)?;
    let digest = Sha256::digest(&transcript);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| QualityResultError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| QualityResultError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| QualityResultError::EncodingFailure)?,
    })
}

pub fn verify_quality_floor_result(
    plan: &QualityFloorPlan,
    verified_plan: &VerifiedQualityFloorPlan,
    result: &QualityFloorResultSet,
) -> Result<VerifiedQualityFloorResult, QualityResultError> {
    let current_plan = verify_quality_floor_plan(plan).map_err(QualityResultError::FloorPlan)?;
    if &current_plan != verified_plan {
        return Err(QualityResultError::VerifiedPlanMismatch);
    }
    if result.content_digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(QualityResultError::UnsupportedDigestAlgorithm(
            result.content_digest.algorithm_ref.to_string(),
        ));
    }
    let current_digest = compute_quality_floor_result_digest(result)?;
    if current_digest != result.content_digest {
        return Err(QualityResultError::DigestMismatch);
    }
    if result.plan_ref != plan.plan_ref
        || result.plan_version != plan.plan_version
        || result.plan_digest != plan.content_digest
        || result.gate != plan.gate
    {
        return Err(QualityResultError::PlanBindingMismatch);
    }
    if !experiment_matches_plan(&result.experiment, plan) {
        return Err(QualityResultError::ExperimentBindingMismatch);
    }
    if !plan
        .invalidation_dependency_refs
        .is_subset(&result.invalidation_dependency_refs)
    {
        return Err(QualityResultError::MissingInvalidationDependencies);
    }

    let criterion_result_refs = verify_criteria(plan, &result.criterion_results)?;
    let profile_result_refs = verify_profiles(plan, &result.profile_results)?;
    let coverage_evidence_refs = verify_coverage(plan, &result.coverage_results)?;

    Ok(VerifiedQualityFloorResult {
        result_set_ref: result.result_set_ref.clone(),
        result_set_version: result.result_set_version.clone(),
        content_digest: current_digest,
        plan_ref: result.plan_ref.clone(),
        plan_version: result.plan_version.clone(),
        plan_digest: result.plan_digest.clone(),
        gate: result.gate,
        criterion_result_refs,
        profile_result_refs,
        coverage_evidence_refs,
        canonical_profile_ref: QUALITY_FLOOR_RESULT_CANONICAL_PROFILE,
    })
}

pub fn canonical_quality_floor_result_transcript(
    result: &QualityFloorResultSet,
) -> Result<Vec<u8>, QualityResultError> {
    validate_result_shape(result)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&result.result_set_ref)?;
    encoder.version(&result.result_set_version)?;
    encoder.reference(&result.plan_ref)?;
    encoder.version(&result.plan_version)?;
    encoder.digest(&result.plan_digest)?;
    encoder.gate(result.gate)?;
    encoder.experiment(&result.experiment)?;

    let mut criteria: Vec<&QualityCriterionResult> = result.criterion_results.iter().collect();
    criteria.sort_by(|left, right| left.criterion_ref.cmp(&right.criterion_ref));
    encoder.count(criteria.len())?;
    for criterion in criteria {
        encoder.criterion_result(criterion)?;
    }

    let mut profiles: Vec<&QualityProfileResult> = result.profile_results.iter().collect();
    profiles.sort_by(|left, right| left.metric_ref.cmp(&right.metric_ref));
    encoder.count(profiles.len())?;
    for profile in profiles {
        encoder.profile_result(profile)?;
    }

    let mut coverage: Vec<&QualityCoverageResult> = result.coverage_results.iter().collect();
    coverage.sort_by_key(|entry| entry.item);
    encoder.count(coverage.len())?;
    for entry in coverage {
        encoder.coverage_result(entry)?;
    }
    encoder.ref_set(&result.provenance_refs)?;
    encoder.ref_set(&result.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

fn validate_result_shape(result: &QualityFloorResultSet) -> Result<(), QualityResultError> {
    if result.provenance_refs.is_empty() {
        return Err(QualityResultError::MissingProvenance);
    }
    if result.invalidation_dependency_refs.is_empty() {
        return Err(QualityResultError::MissingInvalidationDependencies);
    }
    if result.experiment.evaluation_corpus_refs.is_empty()
        || result.experiment.grader_plan_refs.is_empty()
        || result
            .experiment
            .environment_qualification_plan_refs
            .is_empty()
    {
        return Err(QualityResultError::ExperimentBindingMismatch);
    }

    let mut criterion_refs = BTreeSet::new();
    let mut result_refs = BTreeSet::new();
    for item in &result.criterion_results {
        if !criterion_refs.insert(item.criterion_ref.clone()) {
            return Err(QualityResultError::DuplicateCriterionResult(
                item.criterion_ref.to_string(),
            ));
        }
        if !result_refs.insert(item.result_ref.clone()) {
            return Err(QualityResultError::DuplicateCriterionResultRef(
                item.result_ref.to_string(),
            ));
        }
        if item.satisfied_evidence_requirement_refs.is_empty()
            || item.trial_evidence_refs.is_empty()
            || item.grader_result_refs.is_empty()
            || item.environment_evidence_refs.is_empty()
            || item.provenance_refs.is_empty()
            || item.invalidation_dependency_refs.is_empty()
        {
            return Err(QualityResultError::CriterionEvidenceMissing(
                item.criterion_ref.to_string(),
            ));
        }
    }

    let mut metric_refs = BTreeSet::new();
    let mut profile_result_refs = BTreeSet::new();
    for item in &result.profile_results {
        if !metric_refs.insert(item.metric_ref.clone()) {
            return Err(QualityResultError::DuplicateProfileResult(
                item.metric_ref.to_string(),
            ));
        }
        if !profile_result_refs.insert(item.result_ref.clone()) {
            return Err(QualityResultError::DuplicateProfileResultRef(
                item.result_ref.to_string(),
            ));
        }
        if result_refs.contains(&item.result_ref) {
            return Err(QualityResultError::ResultRefCollision(
                item.result_ref.to_string(),
            ));
        }
        if item.satisfied_evidence_requirement_refs.is_empty()
            || item.evidence_refs.is_empty()
            || item.provenance_refs.is_empty()
            || item.invalidation_dependency_refs.is_empty()
        {
            return Err(QualityResultError::ProfileEvidenceMissing(
                item.metric_ref.to_string(),
            ));
        }
    }

    let mut coverage_items = BTreeSet::new();
    for item in &result.coverage_results {
        if !coverage_items.insert(item.item) {
            return Err(QualityResultError::DuplicateCoverageItem(item.item));
        }
        if item.evidence_refs.is_empty() {
            return Err(QualityResultError::CoverageEvidenceMissing(item.item));
        }
    }
    Ok(())
}

fn experiment_matches_plan(experiment: &QualityExperimentBinding, plan: &QualityFloorPlan) -> bool {
    experiment.evaluation_corpus_refs == plan.evaluation_corpus_refs
        && experiment.grader_plan_refs == plan.grader_plan_refs
        && experiment.environment_qualification_plan_refs
            == plan.environment_qualification_plan_refs
        && experiment.trial_protocol_ref == plan.trial_protocol_ref
        && experiment.statistical_model_ref == plan.statistical_model_ref
        && experiment.uncertainty_policy_ref == plan.uncertainty_policy_ref
        && experiment.seed_manifest_ref == plan.seed_manifest_ref
        && experiment.hardware_manifest_ref == plan.hardware_manifest_ref
        && experiment.confidence_target_ref == plan.confidence_target_ref
        && experiment.analysis_plan_ref == plan.analysis_plan_ref
        && experiment.preregistration_evidence_ref == plan.preregistration_evidence_ref
}

fn verify_criteria(
    plan: &QualityFloorPlan,
    results: &[QualityCriterionResult],
) -> Result<BTreeSet<Reference>, QualityResultError> {
    let expected: BTreeMap<&Reference, _> = plan
        .floor_criteria
        .iter()
        .map(|criterion| (&criterion.criterion_ref, criterion))
        .collect();
    let actual: BTreeMap<&Reference, _> = results
        .iter()
        .map(|result| (&result.criterion_ref, result))
        .collect();
    if expected.len() != actual.len() || expected.keys().ne(actual.keys()) {
        return Err(QualityResultError::CriterionSetMismatch);
    }

    let mut result_refs = BTreeSet::new();
    for (reference, criterion) in expected {
        let result = actual
            .get(reference)
            .expect("criterion key set equality already verified");
        if result.kind != criterion.kind
            || result.measurement_target_ref != criterion.measurement_target_ref
            || result.threshold_policy_ref != criterion.threshold_policy_ref
            || result.satisfied_evidence_requirement_refs != criterion.evidence_requirement_refs
        {
            return Err(QualityResultError::CriterionBindingMismatch(
                reference.to_string(),
            ));
        }
        match result.status {
            EvidenceStatus::Pass => {}
            EvidenceStatus::Fail => {
                return Err(QualityResultError::HardCriterionFailed(
                    reference.to_string(),
                ));
            }
            EvidenceStatus::Indeterminate => {
                return Err(QualityResultError::HardCriterionIndeterminate(
                    reference.to_string(),
                ));
            }
        }
        result_refs.insert(result.result_ref.clone());
    }
    Ok(result_refs)
}

fn verify_profiles(
    plan: &QualityFloorPlan,
    results: &[QualityProfileResult],
) -> Result<BTreeSet<Reference>, QualityResultError> {
    let expected: BTreeMap<&Reference, _> = plan
        .profile_metrics
        .iter()
        .map(|metric| (&metric.metric_ref, metric))
        .collect();
    let actual: BTreeMap<&Reference, _> = results
        .iter()
        .map(|result| (&result.metric_ref, result))
        .collect();
    if expected.len() != actual.len() || expected.keys().ne(actual.keys()) {
        return Err(QualityResultError::ProfileSetMismatch);
    }

    let mut result_refs = BTreeSet::new();
    for (reference, metric) in expected {
        let result = actual
            .get(reference)
            .expect("profile key set equality already verified");
        if result.role != metric.role
            || result.measurement_target_ref != metric.measurement_target_ref
            || result.reporting_policy_ref != metric.reporting_policy_ref
            || result.satisfied_evidence_requirement_refs != metric.evidence_requirement_refs
        {
            return Err(QualityResultError::ProfileBindingMismatch(
                reference.to_string(),
            ));
        }
        result_refs.insert(result.result_ref.clone());
    }
    Ok(result_refs)
}

fn verify_coverage(
    plan: &QualityFloorPlan,
    results: &[QualityCoverageResult],
) -> Result<BTreeSet<Reference>, QualityResultError> {
    let expected = expected_coverage(plan);
    let actual: BTreeMap<QualityCoverageItem, &QualityCoverageResult> =
        results.iter().map(|result| (result.item, result)).collect();
    if expected.len() != actual.len() || expected.keys().ne(actual.keys()) {
        return Err(QualityResultError::CoverageSetMismatch);
    }

    let mut evidence_refs = BTreeSet::new();
    for (item, requirement_ref) in expected {
        let result = actual
            .get(&item)
            .expect("coverage key set equality already verified");
        if &result.requirement_ref != requirement_ref {
            return Err(QualityResultError::CoverageBindingMismatch(item));
        }
        evidence_refs.extend(result.evidence_refs.iter().cloned());
    }
    Ok(evidence_refs)
}

fn expected_coverage(plan: &QualityFloorPlan) -> BTreeMap<QualityCoverageItem, &Reference> {
    let mut expected = BTreeMap::new();
    match &plan.coverage {
        QualityGateCoverage::Q06(coverage) => {
            expected.insert(
                QualityCoverageItem::Q06LongHistoryMemory,
                &coverage.long_history_memory_corpus_ref,
            );
            expected.insert(
                QualityCoverageItem::Q06MultiSessionReasoning,
                &coverage.multi_session_reasoning_corpus_ref,
            );
            expected.insert(
                QualityCoverageItem::Q06Corrections,
                &coverage.correction_case_corpus_ref,
            );
            expected.insert(
                QualityCoverageItem::Q06Poisoning,
                &coverage.poisoning_case_corpus_ref,
            );
            expected.insert(
                QualityCoverageItem::Q06Lifecycle,
                &coverage.lifecycle_case_corpus_ref,
            );
            expected.insert(
                QualityCoverageItem::Q06AbstentionUnknown,
                &coverage.abstention_unknown_case_corpus_ref,
            );
            expected.insert(
                QualityCoverageItem::Q06ProtectedConstraint,
                &coverage.protected_constraint_evidence_ref,
            );
        }
        QualityGateCoverage::Q07(coverage) => {
            for (regime, reference) in &coverage.heldout_regime_corpus_refs {
                expected.insert(QualityCoverageItem::Q07Regime(*regime), reference);
            }
            for (axis, reference) in &coverage.comparison_axis_refs {
                expected.insert(QualityCoverageItem::Q07ComparisonAxis(*axis), reference);
            }
            expected.insert(
                QualityCoverageItem::Q07RepeatedTrials,
                &coverage.repeated_trial_protocol_ref,
            );
            expected.insert(
                QualityCoverageItem::Q07CandidateConfiguration,
                &coverage.candidate_configuration_manifest_ref,
            );
        }
    }
    expected
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

    fn count(&mut self, value: usize) -> Result<(), QualityResultError> {
        let value = u64::try_from(value).map_err(|_| QualityResultError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), QualityResultError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), QualityResultError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), QualityResultError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), QualityResultError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), QualityResultError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn status(&mut self, status: EvidenceStatus) -> Result<(), QualityResultError> {
        self.scalar(match status {
            EvidenceStatus::Pass => "pass",
            EvidenceStatus::Fail => "fail",
            EvidenceStatus::Indeterminate => "indeterminate",
        })
    }

    fn gate(&mut self, gate: QualityGateId) -> Result<(), QualityResultError> {
        self.scalar(match gate {
            QualityGateId::Q06MemoryContext => "Q06-memory-context",
            QualityGateId::Q07ModelsExperts => "Q07-models-experts",
        })
    }

    fn criterion_kind(&mut self, kind: QualityCriterionKind) -> Result<(), QualityResultError> {
        self.scalar(match kind {
            QualityCriterionKind::Recall => "recall",
            QualityCriterionKind::Fidelity => "fidelity",
            QualityCriterionKind::Privacy => "privacy",
            QualityCriterionKind::NoSilentLostConstraint => "no-silent-lost-constraint",
            QualityCriterionKind::Quality => "quality",
        })
    }

    fn profile_role(&mut self, role: QualityProfileMetricRole) -> Result<(), QualityResultError> {
        self.scalar(match role {
            QualityProfileMetricRole::Cost => "cost",
            QualityProfileMetricRole::Other => "other",
        })
    }

    fn experiment(&mut self, value: &QualityExperimentBinding) -> Result<(), QualityResultError> {
        self.ref_set(&value.evaluation_corpus_refs)?;
        self.ref_set(&value.grader_plan_refs)?;
        self.ref_set(&value.environment_qualification_plan_refs)?;
        self.reference(&value.trial_protocol_ref)?;
        self.reference(&value.statistical_model_ref)?;
        self.reference(&value.uncertainty_policy_ref)?;
        self.reference(&value.seed_manifest_ref)?;
        self.reference(&value.hardware_manifest_ref)?;
        self.reference(&value.confidence_target_ref)?;
        self.reference(&value.analysis_plan_ref)?;
        self.reference(&value.preregistration_evidence_ref)
    }

    fn criterion_result(
        &mut self,
        value: &QualityCriterionResult,
    ) -> Result<(), QualityResultError> {
        self.reference(&value.result_ref)?;
        self.reference(&value.criterion_ref)?;
        self.criterion_kind(value.kind)?;
        self.status(value.status)?;
        self.reference(&value.measurement_target_ref)?;
        self.reference(&value.threshold_policy_ref)?;
        self.ref_set(&value.satisfied_evidence_requirement_refs)?;
        self.reference(&value.analysis_result_ref)?;
        self.ref_set(&value.trial_evidence_refs)?;
        self.ref_set(&value.grader_result_refs)?;
        self.ref_set(&value.environment_evidence_refs)?;
        self.ref_set(&value.provenance_refs)?;
        self.ref_set(&value.invalidation_dependency_refs)
    }

    fn profile_result(&mut self, value: &QualityProfileResult) -> Result<(), QualityResultError> {
        self.reference(&value.result_ref)?;
        self.reference(&value.metric_ref)?;
        self.profile_role(value.role)?;
        self.reference(&value.measurement_target_ref)?;
        self.reference(&value.reporting_policy_ref)?;
        self.ref_set(&value.satisfied_evidence_requirement_refs)?;
        self.reference(&value.measured_result_ref)?;
        self.ref_set(&value.evidence_refs)?;
        self.ref_set(&value.provenance_refs)?;
        self.ref_set(&value.invalidation_dependency_refs)
    }

    fn coverage_result(&mut self, value: &QualityCoverageResult) -> Result<(), QualityResultError> {
        self.coverage_item(value.item)?;
        self.reference(&value.requirement_ref)?;
        self.ref_set(&value.evidence_refs)
    }

    fn coverage_item(&mut self, item: QualityCoverageItem) -> Result<(), QualityResultError> {
        match item {
            QualityCoverageItem::Q06LongHistoryMemory => self.scalar("q06:long-history-memory"),
            QualityCoverageItem::Q06MultiSessionReasoning => {
                self.scalar("q06:multi-session-reasoning")
            }
            QualityCoverageItem::Q06Corrections => self.scalar("q06:corrections"),
            QualityCoverageItem::Q06Poisoning => self.scalar("q06:poisoning"),
            QualityCoverageItem::Q06Lifecycle => self.scalar("q06:lifecycle"),
            QualityCoverageItem::Q06AbstentionUnknown => self.scalar("q06:abstention-unknown"),
            QualityCoverageItem::Q06ProtectedConstraint => self.scalar("q06:protected-constraint"),
            QualityCoverageItem::Q07Regime(regime) => {
                self.scalar("q07:regime")?;
                self.scalar(match regime {
                    SpecialistRegime::ConversationPersonalAssistant => {
                        "conversation-personal-assistant"
                    }
                    SpecialistRegime::ResearchDeepResearch => "research-deep-research",
                    SpecialistRegime::SoftwareEngineering => "software-engineering",
                    SpecialistRegime::ActionAutomation => "action-automation",
                    SpecialistRegime::CreationArtifact => "creation-artifact",
                    SpecialistRegime::MonitoringLongRunningWork => "monitoring-long-running-work",
                })
            }
            QualityCoverageItem::Q07ComparisonAxis(axis) => {
                self.scalar("q07:axis")?;
                self.scalar(match axis {
                    Q07ComparisonAxis::CandidateModel => "candidate-model",
                    Q07ComparisonAxis::WorkerTopology => "worker-topology",
                    Q07ComparisonAxis::ReasoningEffort => "reasoning-effort",
                    Q07ComparisonAxis::ContextStrategy => "context-strategy",
                    Q07ComparisonAxis::RetrievalStrategy => "retrieval-strategy",
                })
            }
            QualityCoverageItem::Q07RepeatedTrials => self.scalar("q07:repeated-trials"),
            QualityCoverageItem::Q07CandidateConfiguration => {
                self.scalar("q07:candidate-configuration")
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
