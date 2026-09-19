extern crate alloc;

use crate::{
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    qualification::EvidenceStatus,
    quality_floor::{
        QualityCriterionKind, QualityFloorError, QualityFloorPlan, QualityGateId,
        QualityProfileMetricRole, VerifiedQualityFloorPlan, verify_quality_floor_plan,
    },
    quality_result::{
        QualityFloorResultSet, QualityResultError, VerifiedQualityFloorResult,
        verify_quality_floor_result,
    },
    quality_trial::VerifiedQualityTrialSet,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const QUALITY_ANALYSIS_CANONICAL_PROFILE: &str = "NOERITH/QUALITY-ANALYSIS/CANONICAL-2026-09";
pub const QUALITY_PROFILE_MEASUREMENT_CANONICAL_PROFILE: &str =
    "NOERITH/QUALITY-PROFILE-MEASUREMENT/CANONICAL-2026-09";

const ANALYSIS_DOMAIN: &[u8] = b"NOERITH\0QUALITY-ANALYSIS\0CANONICAL-2026-09\0";
const PROFILE_DOMAIN: &[u8] = b"NOERITH\0QUALITY-PROFILE-MEASUREMENT\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityCriterionAnalysisRecord {
    pub analysis_ref: Reference,
    pub analysis_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub plan_digest: ContentDigest,
    pub gate: QualityGateId,
    pub criterion_ref: Reference,
    pub kind: QualityCriterionKind,
    pub status: EvidenceStatus,
    pub measurement_target_ref: Reference,
    pub threshold_policy_ref: Reference,
    pub analysis_plan_ref: Reference,
    pub statistical_model_ref: Reference,
    pub uncertainty_policy_ref: Reference,
    pub confidence_target_ref: Reference,
    pub trial_evidence_refs: BTreeSet<Reference>,
    pub analysis_output_ref: Reference,
    pub assumption_evidence_refs: BTreeSet<Reference>,
    pub diagnostic_evidence_refs: BTreeSet<Reference>,
    pub decision_evidence_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityProfileMeasurementRecord {
    pub measurement_ref: Reference,
    pub measurement_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub plan_digest: ContentDigest,
    pub gate: QualityGateId,
    pub metric_ref: Reference,
    pub role: QualityProfileMetricRole,
    pub measurement_target_ref: Reference,
    pub reporting_policy_ref: Reference,
    pub analysis_plan_ref: Reference,
    pub statistical_model_ref: Reference,
    pub uncertainty_policy_ref: Reference,
    pub confidence_target_ref: Reference,
    pub trial_evidence_refs: BTreeSet<Reference>,
    pub measured_output_ref: Reference,
    pub supporting_evidence_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityAnalysisEvidenceBundle {
    pub criterion_analyses: Vec<QualityCriterionAnalysisRecord>,
    pub profile_measurements: Vec<QualityProfileMeasurementRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQualityAnalysisEvidence {
    result: VerifiedQualityFloorResult,
    criterion_analysis_evidence_refs: BTreeSet<Reference>,
    profile_measurement_evidence_refs: BTreeSet<Reference>,
    trial_evidence_refs: BTreeSet<Reference>,
    canonical_profile_ref: &'static str,
}

impl VerifiedQualityAnalysisEvidence {
    pub fn result(&self) -> &VerifiedQualityFloorResult {
        &self.result
    }

    pub fn criterion_analysis_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.criterion_analysis_evidence_refs
    }

    pub fn profile_measurement_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.profile_measurement_evidence_refs
    }

    pub fn trial_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.trial_evidence_refs
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityAnalysisError {
    FloorPlan(QualityFloorError),
    VerifiedPlanMismatch,
    Result(QualityResultError),
    MissingTrialEvidence,
    DuplicateTrialEvidence(String),
    TrialPlanMismatch(String),
    MissingCriterionAnalysis(String),
    ExtraCriterionAnalysis(String),
    DuplicateCriterionAnalysis(String),
    DuplicateCriterionAnalysisEvidence(String),
    CriterionAnalysisBindingMismatch(String),
    CriterionAnalysisTrialMismatch(String),
    UnknownCriterionTrialEvidence(String),
    CriterionAnalysisEvidenceMissing(String),
    MissingProfileMeasurement(String),
    ExtraProfileMeasurement(String),
    DuplicateProfileMeasurement(String),
    DuplicateProfileMeasurementEvidence(String),
    ProfileMeasurementBindingMismatch(String),
    ProfileMeasurementTrialMismatch(String),
    UnknownProfileTrialEvidence(String),
    ProfileMeasurementEvidenceMissing(String),
    MissingProvenance(String),
    MissingInvalidationDependencies(String),
    UnsupportedDigestAlgorithm(String),
    DigestMismatch(String),
    EncodingFailure,
}

impl fmt::Display for QualityAnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "quality analysis evidence rejected: {self:?}")
    }
}

pub fn compute_quality_criterion_analysis_digest(
    record: &QualityCriterionAnalysisRecord,
) -> Result<ContentDigest, QualityAnalysisError> {
    validate_criterion_analysis_shape(record)?;
    sha256_digest(&canonical_quality_criterion_analysis_transcript(record)?)
}

pub fn compute_quality_profile_measurement_digest(
    record: &QualityProfileMeasurementRecord,
) -> Result<ContentDigest, QualityAnalysisError> {
    validate_profile_measurement_shape(record)?;
    sha256_digest(&canonical_quality_profile_measurement_transcript(record)?)
}

pub fn canonical_quality_criterion_analysis_transcript(
    record: &QualityCriterionAnalysisRecord,
) -> Result<Vec<u8>, QualityAnalysisError> {
    validate_criterion_analysis_shape(record)?;
    let mut encoder = Encoder::new();
    encoder.raw(ANALYSIS_DOMAIN);
    encoder.reference(&record.analysis_ref)?;
    encoder.version(&record.analysis_version)?;
    encode_common_plan_binding(
        &mut encoder,
        &record.plan_ref,
        &record.plan_version,
        &record.plan_digest,
        record.gate,
    )?;
    encoder.reference(&record.criterion_ref)?;
    encoder.criterion_kind(record.kind)?;
    encoder.status(record.status)?;
    encoder.reference(&record.measurement_target_ref)?;
    encoder.reference(&record.threshold_policy_ref)?;
    encoder.reference(&record.analysis_plan_ref)?;
    encoder.reference(&record.statistical_model_ref)?;
    encoder.reference(&record.uncertainty_policy_ref)?;
    encoder.reference(&record.confidence_target_ref)?;
    encoder.ref_set(&record.trial_evidence_refs)?;
    encoder.reference(&record.analysis_output_ref)?;
    encoder.ref_set(&record.assumption_evidence_refs)?;
    encoder.ref_set(&record.diagnostic_evidence_refs)?;
    encoder.ref_set(&record.decision_evidence_refs)?;
    encoder.ref_set(&record.provenance_refs)?;
    encoder.ref_set(&record.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

pub fn canonical_quality_profile_measurement_transcript(
    record: &QualityProfileMeasurementRecord,
) -> Result<Vec<u8>, QualityAnalysisError> {
    validate_profile_measurement_shape(record)?;
    let mut encoder = Encoder::new();
    encoder.raw(PROFILE_DOMAIN);
    encoder.reference(&record.measurement_ref)?;
    encoder.version(&record.measurement_version)?;
    encode_common_plan_binding(
        &mut encoder,
        &record.plan_ref,
        &record.plan_version,
        &record.plan_digest,
        record.gate,
    )?;
    encoder.reference(&record.metric_ref)?;
    encoder.profile_role(record.role)?;
    encoder.reference(&record.measurement_target_ref)?;
    encoder.reference(&record.reporting_policy_ref)?;
    encoder.reference(&record.analysis_plan_ref)?;
    encoder.reference(&record.statistical_model_ref)?;
    encoder.reference(&record.uncertainty_policy_ref)?;
    encoder.reference(&record.confidence_target_ref)?;
    encoder.ref_set(&record.trial_evidence_refs)?;
    encoder.reference(&record.measured_output_ref)?;
    encoder.ref_set(&record.supporting_evidence_refs)?;
    encoder.ref_set(&record.provenance_refs)?;
    encoder.ref_set(&record.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

/// Stronger Q06/Q07 evidence composition. This does not implement statistics;
/// it proves that every asserted hard-floor status and every profile
/// measurement resolves to exact content-bound analysis evidence tied to the
/// preregistered plan and the exact verified repeated-trial population.
pub fn verify_quality_analysis_evidence(
    plan: &QualityFloorPlan,
    verified_plan: &VerifiedQualityFloorPlan,
    result: &QualityFloorResultSet,
    trial_sets: &[VerifiedQualityTrialSet],
    bundle: &QualityAnalysisEvidenceBundle,
) -> Result<VerifiedQualityAnalysisEvidence, QualityAnalysisError> {
    let current_plan = verify_quality_floor_plan(plan).map_err(QualityAnalysisError::FloorPlan)?;
    if &current_plan != verified_plan {
        return Err(QualityAnalysisError::VerifiedPlanMismatch);
    }
    let verified_result = verify_quality_floor_result(plan, verified_plan, result)
        .map_err(QualityAnalysisError::Result)?;

    let trial_evidence_refs = verified_trial_evidence_refs(plan, trial_sets)?;
    let result_trial_evidence_refs: BTreeSet<Reference> = result
        .criterion_results
        .iter()
        .flat_map(|criterion| criterion.trial_evidence_refs.iter().cloned())
        .collect();
    if result_trial_evidence_refs.is_empty() || result_trial_evidence_refs != trial_evidence_refs {
        return Err(QualityAnalysisError::MissingTrialEvidence);
    }

    let criterion_results: BTreeMap<&Reference, _> = result
        .criterion_results
        .iter()
        .map(|criterion| (&criterion.criterion_ref, criterion))
        .collect();
    let plan_criteria: BTreeMap<&Reference, _> = plan
        .floor_criteria
        .iter()
        .map(|criterion| (&criterion.criterion_ref, criterion))
        .collect();

    let mut analyses = BTreeMap::<Reference, &QualityCriterionAnalysisRecord>::new();
    let mut criterion_analysis_evidence_refs = BTreeSet::new();
    for analysis in &bundle.criterion_analyses {
        verify_criterion_analysis_integrity(analysis)?;
        if analyses
            .insert(analysis.criterion_ref.clone(), analysis)
            .is_some()
        {
            return Err(QualityAnalysisError::DuplicateCriterionAnalysis(
                analysis.criterion_ref.to_string(),
            ));
        }
        if !criterion_analysis_evidence_refs.insert(analysis.content_digest.value.clone()) {
            return Err(QualityAnalysisError::DuplicateCriterionAnalysisEvidence(
                analysis.content_digest.value.to_string(),
            ));
        }
    }

    for (criterion_ref, result_entry) in &criterion_results {
        let analysis = analyses.get(*criterion_ref).ok_or_else(|| {
            QualityAnalysisError::MissingCriterionAnalysis(criterion_ref.to_string())
        })?;
        let criterion = plan_criteria.get(*criterion_ref).ok_or_else(|| {
            QualityAnalysisError::CriterionAnalysisBindingMismatch(criterion_ref.to_string())
        })?;
        verify_criterion_analysis_binding(
            plan,
            criterion,
            result_entry,
            analysis,
            &trial_evidence_refs,
        )?;
    }
    for criterion_ref in analyses.keys() {
        if !criterion_results.contains_key(criterion_ref) {
            return Err(QualityAnalysisError::ExtraCriterionAnalysis(
                criterion_ref.to_string(),
            ));
        }
    }

    let profile_results: BTreeMap<&Reference, _> = result
        .profile_results
        .iter()
        .map(|profile| (&profile.metric_ref, profile))
        .collect();
    let plan_profiles: BTreeMap<&Reference, _> = plan
        .profile_metrics
        .iter()
        .map(|profile| (&profile.metric_ref, profile))
        .collect();

    let mut measurements = BTreeMap::<Reference, &QualityProfileMeasurementRecord>::new();
    let mut profile_measurement_evidence_refs = BTreeSet::new();
    for measurement in &bundle.profile_measurements {
        verify_profile_measurement_integrity(measurement)?;
        if measurements
            .insert(measurement.metric_ref.clone(), measurement)
            .is_some()
        {
            return Err(QualityAnalysisError::DuplicateProfileMeasurement(
                measurement.metric_ref.to_string(),
            ));
        }
        if !profile_measurement_evidence_refs.insert(measurement.content_digest.value.clone()) {
            return Err(QualityAnalysisError::DuplicateProfileMeasurementEvidence(
                measurement.content_digest.value.to_string(),
            ));
        }
    }

    for (metric_ref, result_entry) in &profile_results {
        let measurement = measurements.get(*metric_ref).ok_or_else(|| {
            QualityAnalysisError::MissingProfileMeasurement(metric_ref.to_string())
        })?;
        let metric = plan_profiles.get(*metric_ref).ok_or_else(|| {
            QualityAnalysisError::ProfileMeasurementBindingMismatch(metric_ref.to_string())
        })?;
        verify_profile_measurement_binding(
            plan,
            metric,
            result_entry,
            measurement,
            &trial_evidence_refs,
        )?;
    }
    for metric_ref in measurements.keys() {
        if !profile_results.contains_key(metric_ref) {
            return Err(QualityAnalysisError::ExtraProfileMeasurement(
                metric_ref.to_string(),
            ));
        }
    }

    Ok(VerifiedQualityAnalysisEvidence {
        result: verified_result,
        criterion_analysis_evidence_refs,
        profile_measurement_evidence_refs,
        trial_evidence_refs,
        canonical_profile_ref: QUALITY_ANALYSIS_CANONICAL_PROFILE,
    })
}

fn verified_trial_evidence_refs(
    plan: &QualityFloorPlan,
    trial_sets: &[VerifiedQualityTrialSet],
) -> Result<BTreeSet<Reference>, QualityAnalysisError> {
    if trial_sets.is_empty() {
        return Err(QualityAnalysisError::MissingTrialEvidence);
    }
    let mut refs = BTreeSet::new();
    for trial_set in trial_sets {
        if trial_set.plan_ref() != &plan.plan_ref
            || trial_set.plan_version() != &plan.plan_version
            || trial_set.plan_digest() != &plan.content_digest
            || trial_set.gate() != plan.gate
        {
            return Err(QualityAnalysisError::TrialPlanMismatch(
                trial_set.trial_set_ref().to_string(),
            ));
        }
        let evidence_ref = trial_set.verification_digest().value.clone();
        if !refs.insert(evidence_ref.clone()) {
            return Err(QualityAnalysisError::DuplicateTrialEvidence(
                evidence_ref.to_string(),
            ));
        }
    }
    Ok(refs)
}

fn verify_criterion_analysis_integrity(
    record: &QualityCriterionAnalysisRecord,
) -> Result<(), QualityAnalysisError> {
    require_sha256(&record.content_digest)?;
    let current = compute_quality_criterion_analysis_digest(record)?;
    if current != record.content_digest {
        return Err(QualityAnalysisError::DigestMismatch(
            record.analysis_ref.to_string(),
        ));
    }
    Ok(())
}

fn verify_profile_measurement_integrity(
    record: &QualityProfileMeasurementRecord,
) -> Result<(), QualityAnalysisError> {
    require_sha256(&record.content_digest)?;
    let current = compute_quality_profile_measurement_digest(record)?;
    if current != record.content_digest {
        return Err(QualityAnalysisError::DigestMismatch(
            record.measurement_ref.to_string(),
        ));
    }
    Ok(())
}

fn verify_criterion_analysis_binding(
    plan: &QualityFloorPlan,
    criterion: &crate::quality_floor::QualityFloorCriterion,
    result: &crate::quality_result::QualityCriterionResult,
    analysis: &QualityCriterionAnalysisRecord,
    known_trial_refs: &BTreeSet<Reference>,
) -> Result<(), QualityAnalysisError> {
    let reference = criterion.criterion_ref.to_string();
    if analysis.plan_ref != plan.plan_ref
        || analysis.plan_version != plan.plan_version
        || analysis.plan_digest != plan.content_digest
        || analysis.gate != plan.gate
        || analysis.criterion_ref != criterion.criterion_ref
        || analysis.kind != criterion.kind
        || analysis.status != result.status
        || analysis.measurement_target_ref != criterion.measurement_target_ref
        || analysis.threshold_policy_ref != criterion.threshold_policy_ref
        || analysis.analysis_plan_ref != plan.analysis_plan_ref
        || analysis.statistical_model_ref != plan.statistical_model_ref
        || analysis.uncertainty_policy_ref != plan.uncertainty_policy_ref
        || analysis.confidence_target_ref != plan.confidence_target_ref
        || result.analysis_result_ref != analysis.content_digest.value
    {
        return Err(QualityAnalysisError::CriterionAnalysisBindingMismatch(
            reference,
        ));
    }
    if analysis.trial_evidence_refs != result.trial_evidence_refs {
        return Err(QualityAnalysisError::CriterionAnalysisTrialMismatch(
            reference,
        ));
    }
    if !analysis.trial_evidence_refs.is_subset(known_trial_refs) {
        return Err(QualityAnalysisError::UnknownCriterionTrialEvidence(
            reference,
        ));
    }
    if !plan
        .invalidation_dependency_refs
        .is_subset(&analysis.invalidation_dependency_refs)
    {
        return Err(QualityAnalysisError::MissingInvalidationDependencies(
            reference,
        ));
    }
    Ok(())
}

fn verify_profile_measurement_binding(
    plan: &QualityFloorPlan,
    metric: &crate::quality_floor::QualityProfileMetric,
    result: &crate::quality_result::QualityProfileResult,
    measurement: &QualityProfileMeasurementRecord,
    known_trial_refs: &BTreeSet<Reference>,
) -> Result<(), QualityAnalysisError> {
    let reference = metric.metric_ref.to_string();
    if measurement.plan_ref != plan.plan_ref
        || measurement.plan_version != plan.plan_version
        || measurement.plan_digest != plan.content_digest
        || measurement.gate != plan.gate
        || measurement.metric_ref != metric.metric_ref
        || measurement.role != metric.role
        || measurement.measurement_target_ref != metric.measurement_target_ref
        || measurement.reporting_policy_ref != metric.reporting_policy_ref
        || measurement.analysis_plan_ref != plan.analysis_plan_ref
        || measurement.statistical_model_ref != plan.statistical_model_ref
        || measurement.uncertainty_policy_ref != plan.uncertainty_policy_ref
        || measurement.confidence_target_ref != plan.confidence_target_ref
        || result.measured_result_ref != measurement.content_digest.value
        || result.evidence_refs != measurement.supporting_evidence_refs
    {
        return Err(QualityAnalysisError::ProfileMeasurementBindingMismatch(
            reference,
        ));
    }
    if &measurement.trial_evidence_refs != known_trial_refs {
        return Err(QualityAnalysisError::ProfileMeasurementTrialMismatch(
            reference,
        ));
    }
    if !measurement.trial_evidence_refs.is_subset(known_trial_refs) {
        return Err(QualityAnalysisError::UnknownProfileTrialEvidence(reference));
    }
    if !plan
        .invalidation_dependency_refs
        .is_subset(&measurement.invalidation_dependency_refs)
    {
        return Err(QualityAnalysisError::MissingInvalidationDependencies(
            reference,
        ));
    }
    Ok(())
}

fn validate_criterion_analysis_shape(
    record: &QualityCriterionAnalysisRecord,
) -> Result<(), QualityAnalysisError> {
    let reference = record.analysis_ref.to_string();
    if record.trial_evidence_refs.is_empty()
        || record.assumption_evidence_refs.is_empty()
        || record.diagnostic_evidence_refs.is_empty()
        || record.decision_evidence_refs.is_empty()
    {
        return Err(QualityAnalysisError::CriterionAnalysisEvidenceMissing(
            reference,
        ));
    }
    if record.provenance_refs.is_empty() {
        return Err(QualityAnalysisError::MissingProvenance(reference));
    }
    if record.invalidation_dependency_refs.is_empty() {
        return Err(QualityAnalysisError::MissingInvalidationDependencies(
            reference,
        ));
    }
    Ok(())
}

fn validate_profile_measurement_shape(
    record: &QualityProfileMeasurementRecord,
) -> Result<(), QualityAnalysisError> {
    let reference = record.measurement_ref.to_string();
    if record.trial_evidence_refs.is_empty() || record.supporting_evidence_refs.is_empty() {
        return Err(QualityAnalysisError::ProfileMeasurementEvidenceMissing(
            reference,
        ));
    }
    if record.provenance_refs.is_empty() {
        return Err(QualityAnalysisError::MissingProvenance(reference));
    }
    if record.invalidation_dependency_refs.is_empty() {
        return Err(QualityAnalysisError::MissingInvalidationDependencies(
            reference,
        ));
    }
    Ok(())
}

fn require_sha256(digest: &ContentDigest) -> Result<(), QualityAnalysisError> {
    if digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(QualityAnalysisError::UnsupportedDigestAlgorithm(
            digest.algorithm_ref.to_string(),
        ));
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> Result<ContentDigest, QualityAnalysisError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| QualityAnalysisError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| QualityAnalysisError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| QualityAnalysisError::EncodingFailure)?,
    })
}

fn encode_common_plan_binding(
    encoder: &mut Encoder,
    plan_ref: &Reference,
    plan_version: &OpaqueVersion,
    plan_digest: &ContentDigest,
    gate: QualityGateId,
) -> Result<(), QualityAnalysisError> {
    encoder.reference(plan_ref)?;
    encoder.version(plan_version)?;
    encoder.digest(plan_digest)?;
    encoder.gate(gate)
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

    fn count(&mut self, value: usize) -> Result<(), QualityAnalysisError> {
        let value = u64::try_from(value).map_err(|_| QualityAnalysisError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), QualityAnalysisError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), QualityAnalysisError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), QualityAnalysisError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), QualityAnalysisError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), QualityAnalysisError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn gate(&mut self, gate: QualityGateId) -> Result<(), QualityAnalysisError> {
        self.scalar(match gate {
            QualityGateId::Q06MemoryContext => "q06-memory-context",
            QualityGateId::Q07ModelsExperts => "q07-models-experts",
        })
    }

    fn criterion_kind(&mut self, kind: QualityCriterionKind) -> Result<(), QualityAnalysisError> {
        self.scalar(match kind {
            QualityCriterionKind::Recall => "recall",
            QualityCriterionKind::Fidelity => "fidelity",
            QualityCriterionKind::Privacy => "privacy",
            QualityCriterionKind::NoSilentLostConstraint => "no-silent-lost-constraint",
            QualityCriterionKind::Quality => "quality",
        })
    }

    fn profile_role(&mut self, role: QualityProfileMetricRole) -> Result<(), QualityAnalysisError> {
        self.scalar(match role {
            QualityProfileMetricRole::Cost => "cost",
            QualityProfileMetricRole::Other => "other",
        })
    }

    fn status(&mut self, status: EvidenceStatus) -> Result<(), QualityAnalysisError> {
        self.scalar(match status {
            EvidenceStatus::Pass => "pass",
            EvidenceStatus::Fail => "fail",
            EvidenceStatus::Indeterminate => "indeterminate",
        })
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
