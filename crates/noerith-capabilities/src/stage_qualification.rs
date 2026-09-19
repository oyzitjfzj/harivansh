extern crate alloc;

use crate::{
    catalog::VerifiedCapabilityCatalog,
    grader::VerifiedEvidenceGrader,
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    qualification::{QualificationPlanIdentity, QualificationSubject},
    qualification_population::{
        QualificationPlanPopulationIdentity, QualificationPlanPopulationPurpose,
        VerifiedQualificationPlanPopulation,
    },
    quality_analysis::VerifiedQualityAnalysisEvidence,
    quality_comparison::VerifiedQ07ComparisonAnalysisEvidence,
    quality_evidence::VerifiedQualityEvidenceWithTrials,
    quality_floor::{Q07ComparisonAxis, QualityGateId},
    quality_trial_configuration::VerifiedQualityTrialConfigurationBinding,
    regime::{SixRegimeQualificationPlan, SpecialistRegime},
    regime_capability::VerifiedRegimeCapabilityConformance,
    regime_evidence::VerifiedRegimeExecutionEvidence,
    regime_verification::{
        VerifiedSixRegimeQualificationPlan, verify_six_regime_qualification_plan,
    },
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const S05_STAGE_QUALIFICATION_CANONICAL_PROFILE: &str =
    "NOERITH/S05-STAGE-QUALIFICATION/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0S05-STAGE-QUALIFICATION\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S05StageQualificationRequest {
    pub stage_ref: Reference,
    pub stage_version: OpaqueVersion,
    pub source_contract_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedS05DomainCapabilities {
    stage_ref: Reference,
    stage_version: OpaqueVersion,
    composition_digest: ContentDigest,
    six_regime_plan_ref: Reference,
    six_regime_plan_version: OpaqueVersion,
    six_regime_plan_digest: ContentDigest,
    sandbox_qualification_population: QualificationPlanPopulationIdentity,
    evidence_grader_qualification_population: QualificationPlanPopulationIdentity,
    catalog_ref: Reference,
    catalog_state_revision: u64,
    catalog_state_epoch_ref: Reference,
    catalog_integrity_ref: Reference,
    catalog_freshness_ref: Reference,
    q06_result_digest: ContentDigest,
    q07_result_digest: ContentDigest,
    regime_execution_evidence_refs: BTreeMap<SpecialistRegime, BTreeSet<Reference>>,
    regime_capability_evidence_refs: BTreeMap<SpecialistRegime, BTreeSet<Reference>>,
    qualified_grader_plan_evidence_refs: BTreeSet<Reference>,
    q07_candidate_configuration_manifest_ref: Reference,
    q07_candidate_configuration_manifest_digest: ContentDigest,
    q07_trial_evidence_refs: BTreeSet<Reference>,
    q07_comparison_axis_evidence_refs: BTreeMap<Q07ComparisonAxis, Reference>,
    canonical_profile_ref: &'static str,
}

impl VerifiedS05DomainCapabilities {
    pub fn stage_ref(&self) -> &Reference {
        &self.stage_ref
    }
    pub fn stage_version(&self) -> &OpaqueVersion {
        &self.stage_version
    }
    pub fn composition_digest(&self) -> &ContentDigest {
        &self.composition_digest
    }
    pub fn six_regime_plan_ref(&self) -> &Reference {
        &self.six_regime_plan_ref
    }
    pub fn six_regime_plan_version(&self) -> &OpaqueVersion {
        &self.six_regime_plan_version
    }
    pub fn six_regime_plan_digest(&self) -> &ContentDigest {
        &self.six_regime_plan_digest
    }
    pub fn sandbox_qualification_population(&self) -> &QualificationPlanPopulationIdentity {
        &self.sandbox_qualification_population
    }
    pub fn evidence_grader_qualification_population(&self) -> &QualificationPlanPopulationIdentity {
        &self.evidence_grader_qualification_population
    }
    pub fn catalog_ref(&self) -> &Reference {
        &self.catalog_ref
    }
    pub fn catalog_state_revision(&self) -> u64 {
        self.catalog_state_revision
    }
    pub fn catalog_state_epoch_ref(&self) -> &Reference {
        &self.catalog_state_epoch_ref
    }
    pub fn catalog_integrity_ref(&self) -> &Reference {
        &self.catalog_integrity_ref
    }
    pub fn catalog_freshness_ref(&self) -> &Reference {
        &self.catalog_freshness_ref
    }
    pub fn q06_result_digest(&self) -> &ContentDigest {
        &self.q06_result_digest
    }
    pub fn q07_result_digest(&self) -> &ContentDigest {
        &self.q07_result_digest
    }
    pub fn regime_execution_evidence_refs(
        &self,
        regime: SpecialistRegime,
    ) -> Option<&BTreeSet<Reference>> {
        self.regime_execution_evidence_refs.get(&regime)
    }
    pub fn regime_capability_evidence_refs(
        &self,
        regime: SpecialistRegime,
    ) -> Option<&BTreeSet<Reference>> {
        self.regime_capability_evidence_refs.get(&regime)
    }
    pub fn qualified_grader_plan_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.qualified_grader_plan_evidence_refs
    }
    pub fn q07_candidate_configuration_manifest_ref(&self) -> &Reference {
        &self.q07_candidate_configuration_manifest_ref
    }
    pub fn q07_candidate_configuration_manifest_digest(&self) -> &ContentDigest {
        &self.q07_candidate_configuration_manifest_digest
    }
    pub fn q07_trial_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.q07_trial_evidence_refs
    }
    pub fn q07_comparison_axis_evidence_refs(&self) -> &BTreeMap<Q07ComparisonAxis, Reference> {
        &self.q07_comparison_axis_evidence_refs
    }
    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S05StageQualificationError {
    EmptySourceContracts,
    EmptyProvenance,
    EmptyInvalidationDependencies,
    Plan(crate::regime::RegimePlanError),
    VerifiedPlanMismatch,
    SandboxPopulationPurposeMismatch,
    SandboxPopulationIdentityMismatch,
    GraderPopulationPurposeMismatch,
    GraderPopulationIdentityMismatch,
    MissingRegimeExecutionEvidence(SpecialistRegime),
    DuplicateRegimeExecutionEvidence(SpecialistRegime),
    RegimeExecutionPipelineMismatch(SpecialistRegime),
    MissingRegimeCapabilityConformance(SpecialistRegime),
    DuplicateRegimeCapabilityConformance(SpecialistRegime),
    RegimeCapabilityPipelineMismatch(SpecialistRegime),
    MissingRequiredGrader(String),
    ExtraUnrequiredGrader(String),
    DuplicateQualifiedGrader(String),
    GraderPlanNotPreregistered(String),
    Q06GateMismatch,
    Q07GateMismatch,
    Q06FloorBindingMismatch,
    Q07FloorBindingMismatch,
    Q06AnalysisResultMismatch,
    Q07AnalysisResultMismatch,
    Q06TrialPopulationMismatch,
    Q07TrialPopulationMismatch,
    MissingQ07ConfigurationBindings,
    DuplicateQ07TrialBinding(String),
    Q07TrialBindingCoverageMismatch,
    Q07CandidateManifestMismatch,
    Q07ComparisonResultDigestMismatch,
    Q07ComparisonFloorIdentityMismatch,
    Q07ComparisonTrialPopulationMismatch,
    Q07ComparisonCandidateManifestMismatch,
    MissingQ07ComparisonAxisEvidence(Q07ComparisonAxis),
    MissingCatalogCapability(String),
    CatalogCapabilityUnqualified(String),
    CatalogQualificationSubjectMismatch(String),
    CatalogQualificationAmbiguous(String),
    CatalogQualificationMissingOperation {
        requirement_ref: String,
        operation_ref: String,
    },
    UnsupportedDigestAlgorithm(String),
    EncodingFailure,
}

impl fmt::Display for S05StageQualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "S05 stage qualification rejected: {self:?}")
    }
}

#[derive(Clone)]
struct CurrentCatalogQualification {
    regime: SpecialistRegime,
    requirement_ref: Reference,
    subject: QualificationSubject,
    plan_identity: QualificationPlanIdentity,
    operation_refs: BTreeSet<Reference>,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_s05_stage_qualification(
    request: &S05StageQualificationRequest,
    plan: &SixRegimeQualificationPlan,
    verified_plan: &VerifiedSixRegimeQualificationPlan,
    sandbox_population: &VerifiedQualificationPlanPopulation,
    grader_population: &VerifiedQualificationPlanPopulation,
    regime_execution: &[VerifiedRegimeExecutionEvidence],
    regime_capabilities: &[VerifiedRegimeCapabilityConformance],
    catalog: &VerifiedCapabilityCatalog,
    graders: &[VerifiedEvidenceGrader],
    q06_evidence: &VerifiedQualityEvidenceWithTrials,
    q06_analysis: &VerifiedQualityAnalysisEvidence,
    q07_evidence: &VerifiedQualityEvidenceWithTrials,
    q07_analysis: &VerifiedQualityAnalysisEvidence,
    q07_comparison_analysis: &VerifiedQ07ComparisonAnalysisEvidence,
    q07_configuration_bindings: &[VerifiedQualityTrialConfigurationBinding],
) -> Result<VerifiedS05DomainCapabilities, S05StageQualificationError> {
    validate_request(request)?;
    let current_plan =
        verify_six_regime_qualification_plan(plan).map_err(S05StageQualificationError::Plan)?;
    if &current_plan != verified_plan {
        return Err(S05StageQualificationError::VerifiedPlanMismatch);
    }
    verify_population_bindings(plan, sandbox_population, grader_population)?;

    let execution_by_regime = verify_regime_execution_population(verified_plan, regime_execution)?;
    let capabilities_by_regime =
        verify_regime_capability_population(verified_plan, regime_capabilities)?;
    let qualified_grader_plan_evidence_refs = verify_graders(plan, grader_population, graders)?;

    verify_quality_gate(
        QualityGateId::Q06MemoryContext,
        &plan.q06_floor_ref,
        &plan.q06_floor_version,
        &plan.q06_floor_digest,
        q06_evidence,
        q06_analysis,
    )?;
    verify_quality_gate(
        QualityGateId::Q07ModelsExperts,
        &plan.q07_floor_ref,
        &plan.q07_floor_version,
        &plan.q07_floor_digest,
        q07_evidence,
        q07_analysis,
    )?;

    let (q07_manifest_ref, q07_manifest_digest, q07_trial_evidence_refs) =
        verify_q07_configuration_binding_population(q07_evidence, q07_configuration_bindings)?;
    let q07_comparison_axis_evidence_refs = verify_q07_comparison_stage_binding(
        verified_plan,
        q07_evidence,
        q07_comparison_analysis,
        &q07_manifest_ref,
        &q07_manifest_digest,
        &q07_trial_evidence_refs,
    )?;
    let current_catalog_qualifications =
        verify_catalog_capability_population(plan, &capabilities_by_regime, catalog)?;

    let regime_execution_evidence_refs = execution_by_regime
        .iter()
        .map(|(regime, evidence)| {
            let mut refs = evidence.integration_evidence_refs().clone();
            refs.extend(evidence.completion_evidence_refs().iter().cloned());
            (*regime, refs)
        })
        .collect::<BTreeMap<_, _>>();
    let regime_capability_evidence_refs = capabilities_by_regime
        .iter()
        .map(|(regime, evidence)| (*regime, evidence.binding_evidence_refs().clone()))
        .collect::<BTreeMap<_, _>>();

    let composition_digest = compute_composition_digest(
        request,
        verified_plan,
        sandbox_population,
        grader_population,
        &execution_by_regime,
        &capabilities_by_regime,
        catalog,
        graders,
        q06_evidence,
        q06_analysis,
        q07_evidence,
        q07_analysis,
        q07_comparison_analysis,
        &q07_comparison_axis_evidence_refs,
        q07_configuration_bindings,
        &current_catalog_qualifications,
    )?;

    let snapshot = catalog.snapshot();
    Ok(VerifiedS05DomainCapabilities {
        stage_ref: request.stage_ref.clone(),
        stage_version: request.stage_version.clone(),
        composition_digest,
        six_regime_plan_ref: verified_plan.plan_ref().clone(),
        six_regime_plan_version: verified_plan.plan_version().clone(),
        six_regime_plan_digest: verified_plan.content_digest().clone(),
        sandbox_qualification_population: sandbox_population.identity().clone(),
        evidence_grader_qualification_population: grader_population.identity().clone(),
        catalog_ref: snapshot.catalog_ref.clone(),
        catalog_state_revision: snapshot.state_revision,
        catalog_state_epoch_ref: snapshot.state_epoch_ref.clone(),
        catalog_integrity_ref: snapshot.integrity_ref.clone(),
        catalog_freshness_ref: snapshot.freshness_ref.clone(),
        q06_result_digest: q06_evidence.result().content_digest().clone(),
        q07_result_digest: q07_evidence.result().content_digest().clone(),
        regime_execution_evidence_refs,
        regime_capability_evidence_refs,
        qualified_grader_plan_evidence_refs,
        q07_candidate_configuration_manifest_ref: q07_manifest_ref,
        q07_candidate_configuration_manifest_digest: q07_manifest_digest,
        q07_trial_evidence_refs,
        q07_comparison_axis_evidence_refs,
        canonical_profile_ref: S05_STAGE_QUALIFICATION_CANONICAL_PROFILE,
    })
}

fn validate_request(
    request: &S05StageQualificationRequest,
) -> Result<(), S05StageQualificationError> {
    if request.source_contract_refs.is_empty() {
        return Err(S05StageQualificationError::EmptySourceContracts);
    }
    if request.provenance_refs.is_empty() {
        return Err(S05StageQualificationError::EmptyProvenance);
    }
    if request.invalidation_dependency_refs.is_empty() {
        return Err(S05StageQualificationError::EmptyInvalidationDependencies);
    }
    Ok(())
}

fn verify_population_bindings(
    plan: &SixRegimeQualificationPlan,
    sandbox_population: &VerifiedQualificationPlanPopulation,
    grader_population: &VerifiedQualificationPlanPopulation,
) -> Result<(), S05StageQualificationError> {
    if sandbox_population.purpose() != QualificationPlanPopulationPurpose::ExecutionEnvironment {
        return Err(S05StageQualificationError::SandboxPopulationPurposeMismatch);
    }
    if sandbox_population.identity() != &plan.sandbox_qualification_population {
        return Err(S05StageQualificationError::SandboxPopulationIdentityMismatch);
    }
    if grader_population.purpose() != QualificationPlanPopulationPurpose::EvidenceGrader {
        return Err(S05StageQualificationError::GraderPopulationPurposeMismatch);
    }
    if grader_population.identity() != &plan.evidence_grader_qualification_population {
        return Err(S05StageQualificationError::GraderPopulationIdentityMismatch);
    }
    Ok(())
}

fn verify_regime_execution_population<'a>(
    plan: &VerifiedSixRegimeQualificationPlan,
    evidence: &'a [VerifiedRegimeExecutionEvidence],
) -> Result<
    BTreeMap<SpecialistRegime, &'a VerifiedRegimeExecutionEvidence>,
    S05StageQualificationError,
> {
    let mut by_regime = BTreeMap::new();
    for item in evidence {
        if by_regime.insert(item.regime(), item).is_some() {
            return Err(
                S05StageQualificationError::DuplicateRegimeExecutionEvidence(item.regime()),
            );
        }
    }
    for regime in SpecialistRegime::ALL {
        let item = by_regime.get(&regime).ok_or(
            S05StageQualificationError::MissingRegimeExecutionEvidence(regime),
        )?;
        let pipeline = plan.pipeline(regime).ok_or(
            S05StageQualificationError::RegimeExecutionPipelineMismatch(regime),
        )?;
        if item.pipeline_ref() != pipeline.pipeline_ref()
            || item.pipeline_version() != pipeline.pipeline_version()
            || item.pipeline_digest() != pipeline.content_digest()
        {
            return Err(S05StageQualificationError::RegimeExecutionPipelineMismatch(
                regime,
            ));
        }
    }
    Ok(by_regime)
}

fn verify_regime_capability_population<'a>(
    plan: &VerifiedSixRegimeQualificationPlan,
    evidence: &'a [VerifiedRegimeCapabilityConformance],
) -> Result<
    BTreeMap<SpecialistRegime, &'a VerifiedRegimeCapabilityConformance>,
    S05StageQualificationError,
> {
    let mut by_regime = BTreeMap::new();
    for item in evidence {
        if by_regime.insert(item.regime(), item).is_some() {
            return Err(
                S05StageQualificationError::DuplicateRegimeCapabilityConformance(item.regime()),
            );
        }
    }
    for regime in SpecialistRegime::ALL {
        let item = by_regime
            .get(&regime)
            .ok_or(S05StageQualificationError::MissingRegimeCapabilityConformance(regime))?;
        let pipeline = plan
            .pipeline(regime)
            .ok_or(S05StageQualificationError::RegimeCapabilityPipelineMismatch(regime))?;
        if item.pipeline_ref() != pipeline.pipeline_ref()
            || item.pipeline_version() != pipeline.pipeline_version()
            || item.pipeline_digest() != pipeline.content_digest()
        {
            return Err(S05StageQualificationError::RegimeCapabilityPipelineMismatch(regime));
        }
    }
    Ok(by_regime)
}

fn verify_graders(
    plan: &SixRegimeQualificationPlan,
    grader_population: &VerifiedQualificationPlanPopulation,
    graders: &[VerifiedEvidenceGrader],
) -> Result<BTreeSet<Reference>, S05StageQualificationError> {
    let required: BTreeSet<Reference> = plan
        .pipelines
        .iter()
        .flat_map(|pipeline| pipeline.grading.grader_refs.iter().cloned())
        .collect();
    let mut covered = BTreeSet::new();
    let mut exact_identities = BTreeSet::<String>::new();
    let mut plan_evidence_refs = BTreeSet::new();

    for grader in graders {
        let grader_ref = &grader.grader().grader_ref;
        if !required.contains(grader_ref) {
            return Err(S05StageQualificationError::ExtraUnrequiredGrader(
                grader_ref.to_string(),
            ));
        }
        let plan_identity = grader.identity();
        if !grader_population.contains_exact(
            &plan_identity.plan_ref,
            &plan_identity.plan_version,
            &plan_identity.plan_digest,
        ) {
            return Err(S05StageQualificationError::GraderPlanNotPreregistered(
                grader_ref.to_string(),
            ));
        }
        let exact = alloc::format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            grader_ref,
            grader.grader().grader_version.as_str(),
            plan_identity.plan_ref,
            plan_identity.plan_version.as_str(),
            plan_identity.plan_digest.algorithm_ref,
            plan_identity.plan_digest.value,
        );
        if !exact_identities.insert(exact) {
            return Err(S05StageQualificationError::DuplicateQualifiedGrader(
                grader_ref.to_string(),
            ));
        }
        covered.insert(grader_ref.clone());
        plan_evidence_refs.insert(plan_identity.plan_digest.value.clone());
    }

    for required_ref in required {
        if !covered.contains(&required_ref) {
            return Err(S05StageQualificationError::MissingRequiredGrader(
                required_ref.to_string(),
            ));
        }
    }
    Ok(plan_evidence_refs)
}

fn verify_quality_gate(
    gate: QualityGateId,
    expected_plan_ref: &Reference,
    expected_plan_version: &OpaqueVersion,
    expected_plan_digest: &ContentDigest,
    evidence: &VerifiedQualityEvidenceWithTrials,
    analysis: &VerifiedQualityAnalysisEvidence,
) -> Result<(), S05StageQualificationError> {
    let result = evidence.result();
    let analysis_result = analysis.result();
    match gate {
        QualityGateId::Q06MemoryContext => {
            if result.gate() != gate || analysis_result.gate() != gate {
                return Err(S05StageQualificationError::Q06GateMismatch);
            }
            if result.plan_ref() != expected_plan_ref
                || result.plan_version() != expected_plan_version
                || result.plan_digest() != expected_plan_digest
            {
                return Err(S05StageQualificationError::Q06FloorBindingMismatch);
            }
            if result != analysis_result {
                return Err(S05StageQualificationError::Q06AnalysisResultMismatch);
            }
            if evidence.trial_evidence_refs() != analysis.trial_evidence_refs() {
                return Err(S05StageQualificationError::Q06TrialPopulationMismatch);
            }
        }
        QualityGateId::Q07ModelsExperts => {
            if result.gate() != gate || analysis_result.gate() != gate {
                return Err(S05StageQualificationError::Q07GateMismatch);
            }
            if result.plan_ref() != expected_plan_ref
                || result.plan_version() != expected_plan_version
                || result.plan_digest() != expected_plan_digest
            {
                return Err(S05StageQualificationError::Q07FloorBindingMismatch);
            }
            if result != analysis_result {
                return Err(S05StageQualificationError::Q07AnalysisResultMismatch);
            }
            if evidence.trial_evidence_refs() != analysis.trial_evidence_refs() {
                return Err(S05StageQualificationError::Q07TrialPopulationMismatch);
            }
        }
    }
    Ok(())
}

fn verify_q07_configuration_binding_population(
    q07_evidence: &VerifiedQualityEvidenceWithTrials,
    bindings: &[VerifiedQualityTrialConfigurationBinding],
) -> Result<(Reference, ContentDigest, BTreeSet<Reference>), S05StageQualificationError> {
    let first = bindings
        .first()
        .ok_or(S05StageQualificationError::MissingQ07ConfigurationBindings)?;
    let manifest_ref = first.configuration_manifest_ref().clone();
    let manifest_digest = first.configuration_manifest_digest().clone();
    let mut raw_trial_identities = BTreeSet::new();
    let mut trial_evidence_refs = BTreeSet::new();

    for binding in bindings {
        let raw_identity = (
            binding.trial_set_ref().clone(),
            binding.trial_set_digest().algorithm_ref.clone(),
            binding.trial_set_digest().value.clone(),
        );
        if !raw_trial_identities.insert(raw_identity) {
            return Err(S05StageQualificationError::DuplicateQ07TrialBinding(
                binding.trial_set_ref().to_string(),
            ));
        }

        let trial_evidence_ref = binding.trial_evidence_digest().value.clone();
        if !trial_evidence_refs.insert(trial_evidence_ref.clone()) {
            return Err(S05StageQualificationError::DuplicateQ07TrialBinding(
                trial_evidence_ref.to_string(),
            ));
        }
        if binding.configuration_manifest_ref() != &manifest_ref
            || binding.configuration_manifest_digest() != &manifest_digest
        {
            return Err(S05StageQualificationError::Q07CandidateManifestMismatch);
        }
    }
    if &trial_evidence_refs != q07_evidence.trial_evidence_refs() {
        return Err(S05StageQualificationError::Q07TrialBindingCoverageMismatch);
    }
    Ok((manifest_ref, manifest_digest, trial_evidence_refs))
}

fn verify_q07_comparison_stage_binding(
    plan: &VerifiedSixRegimeQualificationPlan,
    q07_evidence: &VerifiedQualityEvidenceWithTrials,
    comparison: &VerifiedQ07ComparisonAnalysisEvidence,
    q07_manifest_ref: &Reference,
    q07_manifest_digest: &ContentDigest,
    q07_trial_evidence_refs: &BTreeSet<Reference>,
) -> Result<BTreeMap<Q07ComparisonAxis, Reference>, S05StageQualificationError> {
    if comparison.result_digest() != q07_evidence.result().content_digest() {
        return Err(S05StageQualificationError::Q07ComparisonResultDigestMismatch);
    }
    if comparison.plan_ref() != plan.q07_floor_ref()
        || comparison.plan_version() != plan.q07_floor_version()
        || comparison.plan_digest() != plan.q07_floor_digest()
    {
        return Err(S05StageQualificationError::Q07ComparisonFloorIdentityMismatch);
    }
    if comparison.trial_evidence_refs() != q07_trial_evidence_refs {
        return Err(S05StageQualificationError::Q07ComparisonTrialPopulationMismatch);
    }
    if comparison.candidate_manifest_ref() != q07_manifest_ref
        || comparison.candidate_manifest_digest() != q07_manifest_digest
    {
        return Err(S05StageQualificationError::Q07ComparisonCandidateManifestMismatch);
    }

    let mut axis_evidence_refs = BTreeMap::new();
    for axis in Q07ComparisonAxis::ALL {
        let evidence_ref = comparison
            .axis_evidence_ref(axis)
            .ok_or(S05StageQualificationError::MissingQ07ComparisonAxisEvidence(axis))?;
        axis_evidence_refs.insert(axis, evidence_ref.clone());
    }
    Ok(axis_evidence_refs)
}

fn verify_catalog_capability_population(
    plan: &SixRegimeQualificationPlan,
    conformance: &BTreeMap<SpecialistRegime, &VerifiedRegimeCapabilityConformance>,
    catalog: &VerifiedCapabilityCatalog,
) -> Result<Vec<CurrentCatalogQualification>, S05StageQualificationError> {
    let mut current = Vec::new();
    for regime in SpecialistRegime::ALL {
        let pipeline = plan
            .pipelines
            .iter()
            .find(|pipeline| pipeline.regime == regime)
            .ok_or(S05StageQualificationError::MissingRegimeCapabilityConformance(regime))?;
        let verified = conformance
            .get(&regime)
            .ok_or(S05StageQualificationError::MissingRegimeCapabilityConformance(regime))?;

        for requirement in &pipeline.required_capabilities {
            let subjects = verified
                .subjects_for(&requirement.requirement_ref)
                .ok_or_else(|| {
                    S05StageQualificationError::MissingCatalogCapability(
                        requirement.requirement_ref.to_string(),
                    )
                })?;
            for subject in subjects {
                let entry = catalog
                    .lookup_exact(
                        &subject.capability_ref,
                        &subject.capability_version,
                        &subject.manifest_digest,
                    )
                    .ok_or_else(|| {
                        S05StageQualificationError::MissingCatalogCapability(
                            subject.capability_ref.to_string(),
                        )
                    })?;
                if entry.qualifications.is_empty() {
                    return Err(S05StageQualificationError::CatalogCapabilityUnqualified(
                        subject.capability_ref.to_string(),
                    ));
                }
                let mut matching = entry
                    .qualifications
                    .iter()
                    .filter(|qualification| qualification.subject() == subject);
                let qualification = matching.next().ok_or_else(|| {
                    S05StageQualificationError::CatalogQualificationSubjectMismatch(
                        subject.capability_ref.to_string(),
                    )
                })?;
                if matching.next().is_some() {
                    return Err(S05StageQualificationError::CatalogQualificationAmbiguous(
                        subject.capability_ref.to_string(),
                    ));
                }
                for operation_ref in &requirement.required_operation_refs {
                    if !qualification.operation_refs().contains(operation_ref) {
                        return Err(
                            S05StageQualificationError::CatalogQualificationMissingOperation {
                                requirement_ref: requirement.requirement_ref.to_string(),
                                operation_ref: operation_ref.to_string(),
                            },
                        );
                    }
                }
                current.push(CurrentCatalogQualification {
                    regime,
                    requirement_ref: requirement.requirement_ref.clone(),
                    subject: subject.clone(),
                    plan_identity: qualification.plan_identity().clone(),
                    operation_refs: qualification.operation_refs().clone(),
                });
            }
        }
    }
    Ok(current)
}

#[allow(clippy::too_many_arguments)]
fn compute_composition_digest(
    request: &S05StageQualificationRequest,
    plan: &VerifiedSixRegimeQualificationPlan,
    sandbox_population: &VerifiedQualificationPlanPopulation,
    grader_population: &VerifiedQualificationPlanPopulation,
    execution: &BTreeMap<SpecialistRegime, &VerifiedRegimeExecutionEvidence>,
    capabilities: &BTreeMap<SpecialistRegime, &VerifiedRegimeCapabilityConformance>,
    catalog: &VerifiedCapabilityCatalog,
    graders: &[VerifiedEvidenceGrader],
    q06_evidence: &VerifiedQualityEvidenceWithTrials,
    q06_analysis: &VerifiedQualityAnalysisEvidence,
    q07_evidence: &VerifiedQualityEvidenceWithTrials,
    q07_analysis: &VerifiedQualityAnalysisEvidence,
    q07_comparison_analysis: &VerifiedQ07ComparisonAnalysisEvidence,
    q07_comparison_axis_evidence_refs: &BTreeMap<Q07ComparisonAxis, Reference>,
    q07_configuration_bindings: &[VerifiedQualityTrialConfigurationBinding],
    current_catalog_qualifications: &[CurrentCatalogQualification],
) -> Result<ContentDigest, S05StageQualificationError> {
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&request.stage_ref)?;
    encoder.version(&request.stage_version)?;
    encoder.ref_set(&request.source_contract_refs)?;
    encoder.ref_set(&request.provenance_refs)?;
    encoder.ref_set(&request.invalidation_dependency_refs)?;
    encoder.reference(plan.plan_ref())?;
    encoder.version(plan.plan_version())?;
    encoder.digest(plan.content_digest())?;
    encoder.population_identity(sandbox_population.identity())?;
    encoder.population_identity(grader_population.identity())?;

    let snapshot = catalog.snapshot();
    encoder.reference(&snapshot.catalog_ref)?;
    encoder.u64_value(snapshot.state_revision);
    encoder.reference(&snapshot.state_epoch_ref)?;
    encoder.reference(&snapshot.integrity_ref)?;
    encoder.reference(&snapshot.freshness_ref)?;
    encoder.ref_set(&snapshot.provenance_refs)?;

    for regime in SpecialistRegime::ALL {
        encoder.regime(regime)?;
        let pipeline = plan.pipeline(regime).ok_or(
            S05StageQualificationError::RegimeExecutionPipelineMismatch(regime),
        )?;
        encoder.reference(pipeline.pipeline_ref())?;
        encoder.version(pipeline.pipeline_version())?;
        encoder.digest(pipeline.content_digest())?;

        let execution_item = execution.get(&regime).ok_or(
            S05StageQualificationError::MissingRegimeExecutionEvidence(regime),
        )?;
        encoder.ref_set(execution_item.integration_evidence_refs())?;
        encoder.ref_set(execution_item.completion_evidence_refs())?;
        let mut environments = execution_item.environments().iter().collect::<Vec<_>>();
        environments.sort_by(|left, right| {
            (
                left.environment_ref.as_str(),
                left.environment_version.as_str(),
                left.content_digest.value.as_str(),
            )
                .cmp(&(
                    right.environment_ref.as_str(),
                    right.environment_version.as_str(),
                    right.content_digest.value.as_str(),
                ))
        });
        encoder.count(environments.len())?;
        for environment in environments {
            encoder.reference(&environment.environment_ref)?;
            encoder.version(&environment.environment_version)?;
            encoder.digest(&environment.content_digest)?;
        }

        let capability_item = capabilities
            .get(&regime)
            .ok_or(S05StageQualificationError::MissingRegimeCapabilityConformance(regime))?;
        encoder.ref_set(capability_item.binding_evidence_refs())?;
    }

    let mut current_qualifications = current_catalog_qualifications.to_vec();
    current_qualifications.sort_by(|left, right| {
        (
            left.regime,
            left.requirement_ref.as_str(),
            left.subject.capability_ref.as_str(),
            left.subject.capability_version.as_str(),
            left.subject.manifest_digest.value.as_str(),
        )
            .cmp(&(
                right.regime,
                right.requirement_ref.as_str(),
                right.subject.capability_ref.as_str(),
                right.subject.capability_version.as_str(),
                right.subject.manifest_digest.value.as_str(),
            ))
    });
    encoder.count(current_qualifications.len())?;
    for qualification in &current_qualifications {
        encoder.regime(qualification.regime)?;
        encoder.reference(&qualification.requirement_ref)?;
        encoder.qualification_subject(&qualification.subject)?;
        encoder.qualification_plan_identity(&qualification.plan_identity)?;
        encoder.ref_set(&qualification.operation_refs)?;
    }

    let mut sorted_graders = graders.iter().collect::<Vec<_>>();
    sorted_graders.sort_by(|left, right| {
        (
            left.grader().grader_ref.as_str(),
            left.grader().grader_version.as_str(),
            left.identity().plan_ref.as_str(),
            left.identity().plan_version.as_str(),
            left.identity().plan_digest.value.as_str(),
        )
            .cmp(&(
                right.grader().grader_ref.as_str(),
                right.grader().grader_version.as_str(),
                right.identity().plan_ref.as_str(),
                right.identity().plan_version.as_str(),
                right.identity().plan_digest.value.as_str(),
            ))
    });
    encoder.count(sorted_graders.len())?;
    for grader in sorted_graders {
        encoder.reference(&grader.grader().grader_ref)?;
        encoder.version(&grader.grader().grader_version)?;
        encoder.reference(&grader.identity().plan_ref)?;
        encoder.version(&grader.identity().plan_version)?;
        encoder.digest(&grader.identity().plan_digest)?;
        encoder.ref_set(grader.qualification_evidence_refs())?;
    }

    encode_quality_package(&mut encoder, q06_evidence, q06_analysis)?;
    encode_quality_package(&mut encoder, q07_evidence, q07_analysis)?;
    encode_q07_comparison_package(
        &mut encoder,
        q07_comparison_analysis,
        q07_comparison_axis_evidence_refs,
    )?;

    let mut bindings = q07_configuration_bindings.iter().collect::<Vec<_>>();
    bindings.sort_by(|left, right| {
        (
            left.trial_set_ref().as_str(),
            left.trial_set_digest().value.as_str(),
            left.trial_evidence_digest().value.as_str(),
        )
            .cmp(&(
                right.trial_set_ref().as_str(),
                right.trial_set_digest().value.as_str(),
                right.trial_evidence_digest().value.as_str(),
            ))
    });
    encoder.count(bindings.len())?;
    for binding in bindings {
        encoder.reference(binding.trial_set_ref())?;
        encoder.digest(binding.trial_set_digest())?;
        encoder.digest(binding.trial_evidence_digest())?;
        encoder.reference(binding.configuration_manifest_ref())?;
        encoder.digest(binding.configuration_manifest_digest())?;
    }

    sha256_digest(&encoder.finish())
}

fn encode_quality_package(
    encoder: &mut Encoder,
    evidence: &VerifiedQualityEvidenceWithTrials,
    analysis: &VerifiedQualityAnalysisEvidence,
) -> Result<(), S05StageQualificationError> {
    let result = evidence.result();
    encoder.quality_gate(result.gate())?;
    encoder.reference(result.result_set_ref())?;
    encoder.version(result.result_set_version())?;
    encoder.digest(result.content_digest())?;
    encoder.reference(result.plan_ref())?;
    encoder.version(result.plan_version())?;
    encoder.digest(result.plan_digest())?;
    encoder.ref_set(evidence.trial_evidence_refs())?;
    encoder.ref_set(analysis.criterion_analysis_evidence_refs())?;
    encoder.ref_set(analysis.profile_measurement_evidence_refs())?;
    encoder.ref_set(analysis.trial_evidence_refs())?;
    Ok(())
}

fn encode_q07_comparison_package(
    encoder: &mut Encoder,
    comparison: &VerifiedQ07ComparisonAnalysisEvidence,
    axis_evidence_refs: &BTreeMap<Q07ComparisonAxis, Reference>,
) -> Result<(), S05StageQualificationError> {
    encoder.scalar(comparison.canonical_profile_ref())?;
    encoder.digest(comparison.result_digest())?;
    encoder.reference(comparison.plan_ref())?;
    encoder.version(comparison.plan_version())?;
    encoder.digest(comparison.plan_digest())?;
    encoder.reference(comparison.candidate_manifest_ref())?;
    encoder.digest(comparison.candidate_manifest_digest())?;
    encoder.ref_set(comparison.trial_evidence_refs())?;
    encode_q07_comparison_axis_evidence(encoder, axis_evidence_refs)
}

fn encode_q07_comparison_axis_evidence(
    encoder: &mut Encoder,
    axis_evidence_refs: &BTreeMap<Q07ComparisonAxis, Reference>,
) -> Result<(), S05StageQualificationError> {
    encoder.count(Q07ComparisonAxis::ALL.len())?;
    for axis in Q07ComparisonAxis::ALL {
        encoder.q07_comparison_axis(axis)?;
        let evidence_ref = axis_evidence_refs
            .get(&axis)
            .ok_or(S05StageQualificationError::MissingQ07ComparisonAxisEvidence(axis))?;
        encoder.reference(evidence_ref)?;
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> Result<ContentDigest, S05StageQualificationError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| S05StageQualificationError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| S05StageQualificationError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| S05StageQualificationError::EncodingFailure)?,
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
    fn count(&mut self, value: usize) -> Result<(), S05StageQualificationError> {
        let value =
            u64::try_from(value).map_err(|_| S05StageQualificationError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }
    fn u64_value(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn scalar(&mut self, value: &str) -> Result<(), S05StageQualificationError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }
    fn reference(&mut self, value: &Reference) -> Result<(), S05StageQualificationError> {
        self.scalar(value.as_str())
    }
    fn version(&mut self, value: &OpaqueVersion) -> Result<(), S05StageQualificationError> {
        self.scalar(value.as_str())
    }
    fn digest(&mut self, value: &ContentDigest) -> Result<(), S05StageQualificationError> {
        if value.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
            return Err(S05StageQualificationError::UnsupportedDigestAlgorithm(
                value.algorithm_ref.to_string(),
            ));
        }
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }
    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), S05StageQualificationError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }
    fn population_identity(
        &mut self,
        value: &QualificationPlanPopulationIdentity,
    ) -> Result<(), S05StageQualificationError> {
        self.reference(&value.population_ref)?;
        self.version(&value.population_version)?;
        self.digest(&value.population_digest)
    }
    fn qualification_subject(
        &mut self,
        value: &QualificationSubject,
    ) -> Result<(), S05StageQualificationError> {
        self.reference(&value.capability_ref)?;
        self.version(&value.capability_version)?;
        self.digest(&value.manifest_digest)?;
        self.reference(&value.artifact_ref)?;
        self.reference(&value.adapter_ref)?;
        self.version(&value.adapter_version)?;
        self.reference(&value.environment_ref)?;
        self.version(&value.environment_version)
    }
    fn qualification_plan_identity(
        &mut self,
        value: &QualificationPlanIdentity,
    ) -> Result<(), S05StageQualificationError> {
        self.reference(&value.plan_ref)?;
        self.version(&value.plan_version)?;
        self.digest(&value.plan_digest)
    }
    fn regime(&mut self, regime: SpecialistRegime) -> Result<(), S05StageQualificationError> {
        self.scalar(match regime {
            SpecialistRegime::ConversationPersonalAssistant => "conversation-personal-assistant",
            SpecialistRegime::ResearchDeepResearch => "research-deep-research",
            SpecialistRegime::SoftwareEngineering => "software-engineering",
            SpecialistRegime::ActionAutomation => "action-automation",
            SpecialistRegime::CreationArtifact => "creation-artifact",
            SpecialistRegime::MonitoringLongRunningWork => "monitoring-long-running-work",
        })
    }
    fn quality_gate(&mut self, gate: QualityGateId) -> Result<(), S05StageQualificationError> {
        self.scalar(match gate {
            QualityGateId::Q06MemoryContext => "Q06-memory-context",
            QualityGateId::Q07ModelsExperts => "Q07-models-experts",
        })
    }
    fn q07_comparison_axis(
        &mut self,
        axis: Q07ComparisonAxis,
    ) -> Result<(), S05StageQualificationError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(value: &str) -> Reference {
        Reference::new(value).expect("valid test reference")
    }

    fn complete_axis_map() -> BTreeMap<Q07ComparisonAxis, Reference> {
        Q07ComparisonAxis::ALL
            .into_iter()
            .map(|axis| {
                let suffix = match axis {
                    Q07ComparisonAxis::CandidateModel => "candidate-model",
                    Q07ComparisonAxis::WorkerTopology => "worker-topology",
                    Q07ComparisonAxis::ReasoningEffort => "reasoning-effort",
                    Q07ComparisonAxis::ContextStrategy => "context-strategy",
                    Q07ComparisonAxis::RetrievalStrategy => "retrieval-strategy",
                };
                (axis, reference(&alloc::format!("sha256:analysis-{suffix}")))
            })
            .collect()
    }

    fn encoded_axis_map(
        values: &BTreeMap<Q07ComparisonAxis, Reference>,
    ) -> Result<Vec<u8>, S05StageQualificationError> {
        let mut encoder = Encoder::new();
        encode_q07_comparison_axis_evidence(&mut encoder, values)?;
        Ok(encoder.finish())
    }

    #[test]
    fn q07_axis_encoding_binds_axis_to_analysis_digest() {
        let original = complete_axis_map();
        let mut swapped = original.clone();
        let model = swapped
            .get(&Q07ComparisonAxis::CandidateModel)
            .expect("candidate-model axis")
            .clone();
        let topology = swapped
            .get(&Q07ComparisonAxis::WorkerTopology)
            .expect("worker-topology axis")
            .clone();
        swapped.insert(Q07ComparisonAxis::CandidateModel, topology);
        swapped.insert(Q07ComparisonAxis::WorkerTopology, model);

        assert_ne!(
            encoded_axis_map(&original).expect("original encodes"),
            encoded_axis_map(&swapped).expect("swapped encodes")
        );
    }

    #[test]
    fn q07_axis_encoding_is_independent_of_map_insertion_order() {
        let original = complete_axis_map();
        let mut reversed = BTreeMap::new();
        for axis in Q07ComparisonAxis::ALL.into_iter().rev() {
            reversed.insert(axis, original.get(&axis).expect("axis exists").clone());
        }

        assert_eq!(
            encoded_axis_map(&original).expect("original encodes"),
            encoded_axis_map(&reversed).expect("reversed encodes")
        );
    }

    #[test]
    fn q07_axis_encoding_fails_closed_when_required_axis_is_missing() {
        let mut incomplete = complete_axis_map();
        incomplete.remove(&Q07ComparisonAxis::RetrievalStrategy);

        assert_eq!(
            encoded_axis_map(&incomplete),
            Err(
                S05StageQualificationError::MissingQ07ComparisonAxisEvidence(
                    Q07ComparisonAxis::RetrievalStrategy,
                )
            )
        );
    }
}
