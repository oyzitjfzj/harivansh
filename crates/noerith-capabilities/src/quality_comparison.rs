extern crate alloc;

use crate::{
    candidate_configuration::{
        CandidateConfigurationError, CandidateConfigurationManifest,
        VerifiedCandidateConfigurationManifest, verify_candidate_configuration_manifest,
    },
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    quality_evidence::VerifiedQualityEvidenceWithTrials,
    quality_floor::{
        Q07ComparisonAxis, QualityFloorError, QualityFloorPlan, QualityGateCoverage, QualityGateId,
        VerifiedQualityFloorPlan, verify_quality_floor_plan,
    },
    quality_result::{
        QualityCoverageItem, QualityFloorResultSet, QualityResultError, verify_quality_floor_result,
    },
    quality_trial::VerifiedQualityTrialSet,
    quality_trial_configuration::VerifiedQualityTrialConfigurationBinding,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const Q07_COMPARISON_ANALYSIS_CANONICAL_PROFILE: &str =
    "NOERITH/Q07-COMPARISON-ANALYSIS/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0Q07-COMPARISON-ANALYSIS\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q07ComparisonAnalysisRecord {
    pub analysis_ref: Reference,
    pub analysis_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub axis: Q07ComparisonAxis,
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub plan_digest: ContentDigest,
    pub comparison_requirement_ref: Reference,
    pub candidate_manifest_ref: Reference,
    pub candidate_manifest_version: OpaqueVersion,
    pub candidate_manifest_digest: ContentDigest,
    pub experiment_design_ref: Reference,
    pub randomization_policy_ref: Reference,
    pub blocking_policy_ref: Reference,
    pub trial_evidence_refs: BTreeSet<Reference>,
    pub comparison_estimand_ref: Reference,
    pub analysis_plan_ref: Reference,
    pub statistical_model_ref: Reference,
    pub uncertainty_policy_ref: Reference,
    pub confidence_target_ref: Reference,
    pub analysis_output_ref: Reference,
    pub assumption_evidence_refs: BTreeSet<Reference>,
    pub diagnostic_evidence_refs: BTreeSet<Reference>,
    pub interaction_confounding_evidence_refs: BTreeSet<Reference>,
    pub decision_evidence_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQ07ComparisonAnalysisEvidence {
    result_digest: ContentDigest,
    plan_ref: Reference,
    plan_version: OpaqueVersion,
    plan_digest: ContentDigest,
    candidate_manifest_ref: Reference,
    candidate_manifest_version: OpaqueVersion,
    candidate_manifest_digest: ContentDigest,
    trial_evidence_refs: BTreeSet<Reference>,
    axis_evidence_refs: BTreeMap<Q07ComparisonAxis, Reference>,
    canonical_profile_ref: &'static str,
}

impl VerifiedQ07ComparisonAnalysisEvidence {
    pub fn result_digest(&self) -> &ContentDigest {
        &self.result_digest
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

    pub fn candidate_manifest_ref(&self) -> &Reference {
        &self.candidate_manifest_ref
    }

    pub fn candidate_manifest_version(&self) -> &OpaqueVersion {
        &self.candidate_manifest_version
    }

    pub fn candidate_manifest_digest(&self) -> &ContentDigest {
        &self.candidate_manifest_digest
    }

    pub fn trial_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.trial_evidence_refs
    }

    pub fn axis_evidence_ref(&self, axis: Q07ComparisonAxis) -> Option<&Reference> {
        self.axis_evidence_refs.get(&axis)
    }

    pub fn axis_evidence_refs(&self) -> &BTreeMap<Q07ComparisonAxis, Reference> {
        &self.axis_evidence_refs
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Q07ComparisonAnalysisError {
    FloorPlan(QualityFloorError),
    VerifiedFloorPlanMismatch,
    WrongGate,
    Result(QualityResultError),
    QualityEvidenceResultMismatch,
    QualityEvidenceTrialPopulationMismatch,
    CandidateManifest(CandidateConfigurationError),
    CandidateManifestWrapperMismatch,
    FloorCandidateManifestMismatch,
    MissingTrialEvidence,
    TrialSetPlanMismatch(String),
    DuplicateTrialEvidence(String),
    MissingConfigurationBindings,
    DuplicateConfigurationBinding(String),
    ConfigurationBindingTrialPopulationMismatch,
    ConfigurationBindingManifestMismatch(String),
    MissingAxis(Q07ComparisonAxis),
    DuplicateAxis(Q07ComparisonAxis),
    AxisRequirementMismatch(Q07ComparisonAxis),
    AxisCoverageEvidenceMismatch(Q07ComparisonAxis),
    AnalysisPlanBindingMismatch(Q07ComparisonAxis),
    CandidateManifestBindingMismatch(Q07ComparisonAxis),
    ExperimentDesignBindingMismatch(Q07ComparisonAxis),
    ComparisonEstimandBindingMismatch(Q07ComparisonAxis),
    TrialPopulationMismatch(Q07ComparisonAxis),
    MissingMethodologicalEvidence(Q07ComparisonAxis),
    MissingInvalidationDependency {
        axis: Q07ComparisonAxis,
        dependency_ref: String,
    },
    UnsupportedDigestAlgorithm(String),
    DigestMismatch(Q07ComparisonAxis),
    DuplicateAnalysisEvidence(String),
    EncodingFailure,
}

impl fmt::Display for Q07ComparisonAnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Q07 comparison analysis rejected: {self:?}")
    }
}

pub fn compute_q07_comparison_analysis_digest(
    record: &Q07ComparisonAnalysisRecord,
) -> Result<ContentDigest, Q07ComparisonAnalysisError> {
    validate_record_shape(record)?;
    let transcript = canonical_q07_comparison_analysis_transcript(record)?;
    sha256_digest(&transcript)
}

pub fn canonical_q07_comparison_analysis_transcript(
    record: &Q07ComparisonAnalysisRecord,
) -> Result<Vec<u8>, Q07ComparisonAnalysisError> {
    validate_record_shape(record)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&record.analysis_ref)?;
    encoder.version(&record.analysis_version)?;
    encoder.axis(record.axis)?;
    encoder.reference(&record.plan_ref)?;
    encoder.version(&record.plan_version)?;
    encoder.digest(&record.plan_digest)?;
    encoder.reference(&record.comparison_requirement_ref)?;
    encoder.reference(&record.candidate_manifest_ref)?;
    encoder.version(&record.candidate_manifest_version)?;
    encoder.digest(&record.candidate_manifest_digest)?;
    encoder.reference(&record.experiment_design_ref)?;
    encoder.reference(&record.randomization_policy_ref)?;
    encoder.reference(&record.blocking_policy_ref)?;
    encoder.ref_set(&record.trial_evidence_refs)?;
    encoder.reference(&record.comparison_estimand_ref)?;
    encoder.reference(&record.analysis_plan_ref)?;
    encoder.reference(&record.statistical_model_ref)?;
    encoder.reference(&record.uncertainty_policy_ref)?;
    encoder.reference(&record.confidence_target_ref)?;
    encoder.reference(&record.analysis_output_ref)?;
    encoder.ref_set(&record.assumption_evidence_refs)?;
    encoder.ref_set(&record.diagnostic_evidence_refs)?;
    encoder.ref_set(&record.interaction_confounding_evidence_refs)?;
    encoder.ref_set(&record.decision_evidence_refs)?;
    encoder.ref_set(&record.provenance_refs)?;
    encoder.ref_set(&record.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_q07_comparison_analysis_evidence(
    plan: &QualityFloorPlan,
    verified_plan: &VerifiedQualityFloorPlan,
    result: &QualityFloorResultSet,
    quality_evidence: &VerifiedQualityEvidenceWithTrials,
    manifest: &CandidateConfigurationManifest,
    verified_manifest: &VerifiedCandidateConfigurationManifest,
    trial_sets: &[VerifiedQualityTrialSet],
    configuration_bindings: &[VerifiedQualityTrialConfigurationBinding],
    records: &[Q07ComparisonAnalysisRecord],
) -> Result<VerifiedQ07ComparisonAnalysisEvidence, Q07ComparisonAnalysisError> {
    let current_plan =
        verify_quality_floor_plan(plan).map_err(Q07ComparisonAnalysisError::FloorPlan)?;
    if &current_plan != verified_plan {
        return Err(Q07ComparisonAnalysisError::VerifiedFloorPlanMismatch);
    }
    if plan.gate != QualityGateId::Q07ModelsExperts {
        return Err(Q07ComparisonAnalysisError::WrongGate);
    }
    let QualityGateCoverage::Q07(coverage) = &plan.coverage else {
        return Err(Q07ComparisonAnalysisError::WrongGate);
    };

    let verified_result = verify_quality_floor_result(plan, verified_plan, result)
        .map_err(Q07ComparisonAnalysisError::Result)?;
    if quality_evidence.result() != &verified_result {
        return Err(Q07ComparisonAnalysisError::QualityEvidenceResultMismatch);
    }

    let current_manifest = verify_candidate_configuration_manifest(manifest)
        .map_err(Q07ComparisonAnalysisError::CandidateManifest)?;
    if &current_manifest != verified_manifest {
        return Err(Q07ComparisonAnalysisError::CandidateManifestWrapperMismatch);
    }
    if coverage.candidate_configuration_manifest_ref != manifest.content_digest.value {
        return Err(Q07ComparisonAnalysisError::FloorCandidateManifestMismatch);
    }

    let trial_evidence_refs = verify_trial_population(plan, trial_sets)?;
    if quality_evidence.trial_evidence_refs() != &trial_evidence_refs {
        return Err(Q07ComparisonAnalysisError::QualityEvidenceTrialPopulationMismatch);
    }
    verify_configuration_binding_population(
        manifest,
        &trial_evidence_refs,
        configuration_bindings,
    )?;

    let mut by_axis = BTreeMap::<Q07ComparisonAxis, Reference>::new();
    let mut analysis_evidence_refs = BTreeSet::new();
    for record in records {
        verify_record_integrity(record)?;
        let expected_requirement = coverage
            .comparison_axis_refs
            .get(&record.axis)
            .ok_or(Q07ComparisonAnalysisError::MissingAxis(record.axis))?;
        if &record.comparison_requirement_ref != expected_requirement {
            return Err(Q07ComparisonAnalysisError::AxisRequirementMismatch(
                record.axis,
            ));
        }
        verify_record_bindings(plan, manifest, &trial_evidence_refs, record)?;
        if by_axis
            .insert(record.axis, record.content_digest.value.clone())
            .is_some()
        {
            return Err(Q07ComparisonAnalysisError::DuplicateAxis(record.axis));
        }
        if !analysis_evidence_refs.insert(record.content_digest.value.clone()) {
            return Err(Q07ComparisonAnalysisError::DuplicateAnalysisEvidence(
                record.content_digest.value.to_string(),
            ));
        }
    }

    for axis in Q07ComparisonAxis::ALL {
        let evidence_ref = by_axis
            .get(&axis)
            .ok_or(Q07ComparisonAnalysisError::MissingAxis(axis))?;
        let observed = result
            .coverage_results
            .iter()
            .find(|entry| entry.item == QualityCoverageItem::Q07ComparisonAxis(axis))
            .ok_or(Q07ComparisonAnalysisError::MissingAxis(axis))?;
        let expected = BTreeSet::from([evidence_ref.clone()]);
        if observed.evidence_refs != expected {
            return Err(Q07ComparisonAnalysisError::AxisCoverageEvidenceMismatch(
                axis,
            ));
        }
    }

    Ok(VerifiedQ07ComparisonAnalysisEvidence {
        result_digest: verified_result.content_digest().clone(),
        plan_ref: plan.plan_ref.clone(),
        plan_version: plan.plan_version.clone(),
        plan_digest: plan.content_digest.clone(),
        candidate_manifest_ref: manifest.manifest_ref.clone(),
        candidate_manifest_version: manifest.manifest_version.clone(),
        candidate_manifest_digest: manifest.content_digest.clone(),
        trial_evidence_refs,
        axis_evidence_refs: by_axis,
        canonical_profile_ref: Q07_COMPARISON_ANALYSIS_CANONICAL_PROFILE,
    })
}

fn verify_trial_population(
    plan: &QualityFloorPlan,
    trial_sets: &[VerifiedQualityTrialSet],
) -> Result<BTreeSet<Reference>, Q07ComparisonAnalysisError> {
    if trial_sets.is_empty() {
        return Err(Q07ComparisonAnalysisError::MissingTrialEvidence);
    }
    let mut refs = BTreeSet::new();
    for trial_set in trial_sets {
        if trial_set.plan_ref() != &plan.plan_ref
            || trial_set.plan_version() != &plan.plan_version
            || trial_set.plan_digest() != &plan.content_digest
            || trial_set.gate() != QualityGateId::Q07ModelsExperts
        {
            return Err(Q07ComparisonAnalysisError::TrialSetPlanMismatch(
                trial_set.trial_set_ref().to_string(),
            ));
        }
        let evidence_ref = trial_set.verification_digest().value.clone();
        if !refs.insert(evidence_ref.clone()) {
            return Err(Q07ComparisonAnalysisError::DuplicateTrialEvidence(
                evidence_ref.to_string(),
            ));
        }
    }
    Ok(refs)
}

fn verify_configuration_binding_population(
    manifest: &CandidateConfigurationManifest,
    trial_evidence_refs: &BTreeSet<Reference>,
    bindings: &[VerifiedQualityTrialConfigurationBinding],
) -> Result<(), Q07ComparisonAnalysisError> {
    if bindings.is_empty() {
        return Err(Q07ComparisonAnalysisError::MissingConfigurationBindings);
    }
    let mut raw_trial_identities = BTreeSet::new();
    let mut bound_trial_evidence_refs = BTreeSet::new();
    for binding in bindings {
        let raw_identity = (
            binding.trial_set_ref().clone(),
            binding.trial_set_digest().algorithm_ref.clone(),
            binding.trial_set_digest().value.clone(),
        );
        if !raw_trial_identities.insert(raw_identity) {
            return Err(Q07ComparisonAnalysisError::DuplicateConfigurationBinding(
                binding.trial_set_ref().to_string(),
            ));
        }

        let trial_evidence_ref = binding.trial_evidence_digest().value.clone();
        if !bound_trial_evidence_refs.insert(trial_evidence_ref.clone()) {
            return Err(Q07ComparisonAnalysisError::DuplicateConfigurationBinding(
                trial_evidence_ref.to_string(),
            ));
        }
        if binding.configuration_manifest_ref() != &manifest.manifest_ref
            || binding.configuration_manifest_digest() != &manifest.content_digest
        {
            return Err(
                Q07ComparisonAnalysisError::ConfigurationBindingManifestMismatch(
                    binding.trial_set_ref().to_string(),
                ),
            );
        }
    }
    if &bound_trial_evidence_refs != trial_evidence_refs {
        return Err(Q07ComparisonAnalysisError::ConfigurationBindingTrialPopulationMismatch);
    }
    Ok(())
}

fn verify_record_bindings(
    plan: &QualityFloorPlan,
    manifest: &CandidateConfigurationManifest,
    trial_evidence_refs: &BTreeSet<Reference>,
    record: &Q07ComparisonAnalysisRecord,
) -> Result<(), Q07ComparisonAnalysisError> {
    if record.plan_ref != plan.plan_ref
        || record.plan_version != plan.plan_version
        || record.plan_digest != plan.content_digest
        || record.analysis_plan_ref != plan.analysis_plan_ref
        || record.statistical_model_ref != plan.statistical_model_ref
        || record.uncertainty_policy_ref != plan.uncertainty_policy_ref
        || record.confidence_target_ref != plan.confidence_target_ref
    {
        return Err(Q07ComparisonAnalysisError::AnalysisPlanBindingMismatch(
            record.axis,
        ));
    }
    if record.candidate_manifest_ref != manifest.manifest_ref
        || record.candidate_manifest_version != manifest.manifest_version
        || record.candidate_manifest_digest != manifest.content_digest
    {
        return Err(Q07ComparisonAnalysisError::CandidateManifestBindingMismatch(record.axis));
    }
    if record.experiment_design_ref != manifest.experiment_design_ref
        || record.randomization_policy_ref != manifest.randomization_policy_ref
        || record.blocking_policy_ref != manifest.blocking_policy_ref
    {
        return Err(Q07ComparisonAnalysisError::ExperimentDesignBindingMismatch(
            record.axis,
        ));
    }
    let expected_estimand = manifest
        .comparison_estimand_refs
        .get(&record.axis)
        .ok_or(Q07ComparisonAnalysisError::CandidateManifestBindingMismatch(record.axis))?;
    if &record.comparison_estimand_ref != expected_estimand {
        return Err(Q07ComparisonAnalysisError::ComparisonEstimandBindingMismatch(record.axis));
    }
    if &record.trial_evidence_refs != trial_evidence_refs {
        return Err(Q07ComparisonAnalysisError::TrialPopulationMismatch(
            record.axis,
        ));
    }
    for dependency in plan
        .invalidation_dependency_refs
        .iter()
        .chain(manifest.invalidation_dependency_refs.iter())
    {
        if !record.invalidation_dependency_refs.contains(dependency) {
            return Err(Q07ComparisonAnalysisError::MissingInvalidationDependency {
                axis: record.axis,
                dependency_ref: dependency.to_string(),
            });
        }
    }
    Ok(())
}

fn verify_record_integrity(
    record: &Q07ComparisonAnalysisRecord,
) -> Result<(), Q07ComparisonAnalysisError> {
    require_sha256(&record.content_digest)?;
    let current = compute_q07_comparison_analysis_digest(record)?;
    if current != record.content_digest {
        return Err(Q07ComparisonAnalysisError::DigestMismatch(record.axis));
    }
    Ok(())
}

fn validate_record_shape(
    record: &Q07ComparisonAnalysisRecord,
) -> Result<(), Q07ComparisonAnalysisError> {
    if record.trial_evidence_refs.is_empty()
        || record.assumption_evidence_refs.is_empty()
        || record.diagnostic_evidence_refs.is_empty()
        || record.interaction_confounding_evidence_refs.is_empty()
        || record.decision_evidence_refs.is_empty()
        || record.provenance_refs.is_empty()
        || record.invalidation_dependency_refs.is_empty()
    {
        return Err(Q07ComparisonAnalysisError::MissingMethodologicalEvidence(
            record.axis,
        ));
    }
    Ok(())
}

fn require_sha256(digest: &ContentDigest) -> Result<(), Q07ComparisonAnalysisError> {
    if digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(Q07ComparisonAnalysisError::UnsupportedDigestAlgorithm(
            digest.algorithm_ref.to_string(),
        ));
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> Result<ContentDigest, Q07ComparisonAnalysisError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| Q07ComparisonAnalysisError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| Q07ComparisonAnalysisError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| Q07ComparisonAnalysisError::EncodingFailure)?,
    })
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

    fn count(&mut self, value: usize) -> Result<(), Q07ComparisonAnalysisError> {
        let value =
            u64::try_from(value).map_err(|_| Q07ComparisonAnalysisError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), Q07ComparisonAnalysisError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), Q07ComparisonAnalysisError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), Q07ComparisonAnalysisError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), Q07ComparisonAnalysisError> {
        require_sha256(value)?;
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), Q07ComparisonAnalysisError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn axis(&mut self, axis: Q07ComparisonAxis) -> Result<(), Q07ComparisonAnalysisError> {
        self.scalar(match axis {
            Q07ComparisonAxis::CandidateModel => "candidate-model",
            Q07ComparisonAxis::WorkerTopology => "worker-topology",
            Q07ComparisonAxis::ReasoningEffort => "reasoning-effort",
            Q07ComparisonAxis::ContextStrategy => "context-strategy",
            Q07ComparisonAxis::RetrievalStrategy => "retrieval-strategy",
        })
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
