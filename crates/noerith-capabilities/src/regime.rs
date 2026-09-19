extern crate alloc;

use crate::{
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    qualification_population::QualificationPlanPopulationIdentity,
};
use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const REGIME_PIPELINE_CANONICAL_PROFILE: &str =
    "NOERITH/REGIME-PIPELINE/CANONICAL-2026-09-CAPABILITY-REQUIREMENTS";
pub const SIX_REGIME_PLAN_CANONICAL_PROFILE: &str =
    "NOERITH/SIX-REGIME-PLAN/CANONICAL-2026-09-CAPABILITY-REQUIREMENTS";

const PIPELINE_DOMAIN: &[u8] =
    b"NOERITH\0REGIME-PIPELINE\0CANONICAL-2026-09-CAPABILITY-REQUIREMENTS\0";
const PLAN_DOMAIN: &[u8] = b"NOERITH\0SIX-REGIME-PLAN\0CANONICAL-2026-09-CAPABILITY-REQUIREMENTS\0";

/// The six specialist quality domains frozen by the NOERITH logical
/// architecture. These are evaluation/coordination domains, not fixed agent
/// recipes and not phrase-triggered modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpecialistRegime {
    ConversationPersonalAssistant,
    ResearchDeepResearch,
    SoftwareEngineering,
    ActionAutomation,
    CreationArtifact,
    MonitoringLongRunningWork,
}

impl SpecialistRegime {
    pub const ALL: [Self; 6] = [
        Self::ConversationPersonalAssistant,
        Self::ResearchDeepResearch,
        Self::SoftwareEngineering,
        Self::ActionAutomation,
        Self::CreationArtifact,
        Self::MonitoringLongRunningWork,
    ];
}

/// Preregistered evaluation population and partitions for one regime. Public
/// development material is intentionally distinct from held-out and
/// adversarial qualification material so a passing score cannot be obtained by
/// simply optimizing on the qualification cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegimeEvaluationCorpus {
    pub task_distribution_ref: Reference,
    pub development_partition_ref: Reference,
    pub heldout_partition_ref: Reference,
    pub adversarial_partition_ref: Reference,
    pub contamination_control_ref: Reference,
    pub coverage_model_ref: Reference,
    pub anti_gaming_review_ref: Reference,
}

/// Grader identities and the evidence needed to interpret their outputs. A
/// grader is itself a qualified measurement component; its verdict is not
/// self-authenticating evidence of capability quality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegimeGradingContract {
    pub grader_refs: BTreeSet<Reference>,
    pub grader_calibration_ref: Reference,
    pub grader_disagreement_policy_ref: Reference,
    pub evidence_schema_refs: BTreeSet<Reference>,
}

/// Reliability interpretation remains external and versioned instead of
/// embedding one universal number of trials or one score formula in code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegimeReliabilityProtocol {
    pub trial_protocol_ref: Reference,
    pub statistical_model_ref: Reference,
    pub uncertainty_reporting_ref: Reference,
    pub regression_policy_ref: Reference,
}

/// One preregistered functional capability requirement. The requirement is not
/// a provider/tool identity. A later conformance verifier must prove that at
/// least one exact qualified capability subject covers every operation listed
/// here. The containing pipeline digest freezes this exact requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegimeCapabilityRequirement {
    pub requirement_ref: Reference,
    pub required_operation_refs: BTreeSet<Reference>,
}

/// Predeclared obligations for one specialist regime. Content identity freezes
/// the exact preregistered measurement contract; it does not claim the regime
/// passed and carries no provider credential or execution permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegimePipelinePlan {
    pub regime: SpecialistRegime,
    pub pipeline_ref: Reference,
    pub pipeline_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub source_contract_refs: BTreeSet<Reference>,
    pub algorithm_policy_ref: Reference,
    pub corpus: RegimeEvaluationCorpus,
    pub grading: RegimeGradingContract,
    pub reliability: RegimeReliabilityProtocol,
    pub required_capabilities: Vec<RegimeCapabilityRequirement>,
    pub required_integration_contract_refs: BTreeSet<Reference>,
    pub quality_floor_refs: BTreeSet<Reference>,
    pub completion_evidence_requirement_refs: BTreeSet<Reference>,
}

/// Stage-level preregistration. Structural/content validity means only that
/// every S05 measurement obligation was frozen coherently. Q06/Q07 bind exact
/// floor identities. Execution-environment and grader dependencies bind exact
/// population-manifest identities so multiple subject-specific plans can be
/// preregistered without post-hoc substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SixRegimeQualificationPlan {
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub source_contract_refs: BTreeSet<Reference>,
    pub q06_floor_ref: Reference,
    pub q06_floor_version: OpaqueVersion,
    pub q06_floor_digest: ContentDigest,
    pub q07_floor_ref: Reference,
    pub q07_floor_version: OpaqueVersion,
    pub q07_floor_digest: ContentDigest,
    pub sandbox_qualification_population: QualificationPlanPopulationIdentity,
    pub evidence_grader_qualification_population: QualificationPlanPopulationIdentity,
    pub pipelines: Vec<RegimePipelinePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegimePlanError {
    MissingSourceContracts,
    MissingRegime(SpecialistRegime),
    DuplicateRegime(SpecialistRegime),
    DuplicatePipeline(String),
    MissingPipelineSourceContracts(SpecialistRegime),
    PartitionIdentityCollision(SpecialistRegime),
    MissingGraders(SpecialistRegime),
    MissingGraderEvidenceSchemas(SpecialistRegime),
    MissingCapabilities(SpecialistRegime),
    DuplicateCapabilityRequirement(String),
    EmptyCapabilityRequirementOperations(String),
    MissingIntegrationContracts(SpecialistRegime),
    MissingQualityFloors(SpecialistRegime),
    MissingCompletionEvidenceRequirements(SpecialistRegime),
    UnsupportedDigestAlgorithm(String),
    PipelineDigestMismatch(SpecialistRegime),
    PlanDigestMismatch,
    EncodingFailure,
}

impl fmt::Display for RegimePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "six-regime qualification plan rejected: {self:?}"
        )
    }
}

/// Compute the exact content identity of one regime pipeline. The digest field
/// itself is excluded from its transcript so callers can construct the record,
/// compute the digest, then freeze it.
pub fn compute_regime_pipeline_digest(
    pipeline: &RegimePipelinePlan,
) -> Result<ContentDigest, RegimePlanError> {
    let transcript = canonical_regime_pipeline_transcript(pipeline)?;
    sha256_digest(&transcript)
}

pub fn canonical_regime_pipeline_transcript(
    pipeline: &RegimePipelinePlan,
) -> Result<Vec<u8>, RegimePlanError> {
    validate_pipeline_shape(pipeline)?;
    let mut encoder = Encoder::new();
    encoder.raw(PIPELINE_DOMAIN);
    encoder.regime(pipeline.regime)?;
    encoder.reference(&pipeline.pipeline_ref)?;
    encoder.version(&pipeline.pipeline_version)?;
    encoder.ref_set(&pipeline.source_contract_refs)?;
    encoder.reference(&pipeline.algorithm_policy_ref)?;
    encoder.reference(&pipeline.corpus.task_distribution_ref)?;
    encoder.reference(&pipeline.corpus.development_partition_ref)?;
    encoder.reference(&pipeline.corpus.heldout_partition_ref)?;
    encoder.reference(&pipeline.corpus.adversarial_partition_ref)?;
    encoder.reference(&pipeline.corpus.contamination_control_ref)?;
    encoder.reference(&pipeline.corpus.coverage_model_ref)?;
    encoder.reference(&pipeline.corpus.anti_gaming_review_ref)?;
    encoder.ref_set(&pipeline.grading.grader_refs)?;
    encoder.reference(&pipeline.grading.grader_calibration_ref)?;
    encoder.reference(&pipeline.grading.grader_disagreement_policy_ref)?;
    encoder.ref_set(&pipeline.grading.evidence_schema_refs)?;
    encoder.reference(&pipeline.reliability.trial_protocol_ref)?;
    encoder.reference(&pipeline.reliability.statistical_model_ref)?;
    encoder.reference(&pipeline.reliability.uncertainty_reporting_ref)?;
    encoder.reference(&pipeline.reliability.regression_policy_ref)?;

    let mut requirements: Vec<&RegimeCapabilityRequirement> =
        pipeline.required_capabilities.iter().collect();
    requirements.sort_by(|left, right| left.requirement_ref.cmp(&right.requirement_ref));
    encoder.count(requirements.len())?;
    for requirement in requirements {
        encoder.reference(&requirement.requirement_ref)?;
        encoder.ref_set(&requirement.required_operation_refs)?;
    }

    encoder.ref_set(&pipeline.required_integration_contract_refs)?;
    encoder.ref_set(&pipeline.quality_floor_refs)?;
    encoder.ref_set(&pipeline.completion_evidence_requirement_refs)?;
    Ok(encoder.finish())
}

/// Compute the order-independent identity of the complete six-regime
/// preregistration. Every nested pipeline digest is recomputed first, so a
/// mutated nested plan cannot be hidden behind a stale digest string.
pub fn compute_six_regime_qualification_plan_digest(
    plan: &SixRegimeQualificationPlan,
) -> Result<ContentDigest, RegimePlanError> {
    let transcript = canonical_six_regime_qualification_plan_transcript(plan)?;
    sha256_digest(&transcript)
}

pub fn canonical_six_regime_qualification_plan_transcript(
    plan: &SixRegimeQualificationPlan,
) -> Result<Vec<u8>, RegimePlanError> {
    validate_plan_shape(plan)?;
    for pipeline in &plan.pipelines {
        verify_pipeline_digest(pipeline)?;
    }

    let mut encoder = Encoder::new();
    encoder.raw(PLAN_DOMAIN);
    encoder.reference(&plan.plan_ref)?;
    encoder.version(&plan.plan_version)?;
    encoder.ref_set(&plan.source_contract_refs)?;
    encoder.reference(&plan.q06_floor_ref)?;
    encoder.version(&plan.q06_floor_version)?;
    encoder.digest(&plan.q06_floor_digest)?;
    encoder.reference(&plan.q07_floor_ref)?;
    encoder.version(&plan.q07_floor_version)?;
    encoder.digest(&plan.q07_floor_digest)?;
    encoder.reference(&plan.sandbox_qualification_population.population_ref)?;
    encoder.version(&plan.sandbox_qualification_population.population_version)?;
    encoder.digest(&plan.sandbox_qualification_population.population_digest)?;
    encoder.reference(&plan.evidence_grader_qualification_population.population_ref)?;
    encoder.version(
        &plan
            .evidence_grader_qualification_population
            .population_version,
    )?;
    encoder.digest(
        &plan
            .evidence_grader_qualification_population
            .population_digest,
    )?;

    let mut pipelines: Vec<&RegimePipelinePlan> = plan.pipelines.iter().collect();
    pipelines.sort_by_key(|pipeline| pipeline.regime);
    encoder.count(pipelines.len())?;
    for pipeline in pipelines {
        encoder.regime(pipeline.regime)?;
        encoder.reference(&pipeline.pipeline_ref)?;
        encoder.version(&pipeline.pipeline_version)?;
        encoder.digest(&pipeline.content_digest)?;
    }
    Ok(encoder.finish())
}

/// Validate only preregistration structure and exact content identity. This
/// function never evaluates task outputs or turns a digest/reference into a
/// quality/capability pass.
pub fn validate_six_regime_qualification_plan(
    plan: &SixRegimeQualificationPlan,
) -> Result<(), RegimePlanError> {
    validate_plan_shape(plan)?;
    for pipeline in &plan.pipelines {
        verify_pipeline_digest(pipeline)?;
    }
    require_sha256(&plan.content_digest)?;
    let computed = compute_six_regime_qualification_plan_digest(plan)?;
    if computed != plan.content_digest {
        return Err(RegimePlanError::PlanDigestMismatch);
    }
    Ok(())
}

fn validate_plan_shape(plan: &SixRegimeQualificationPlan) -> Result<(), RegimePlanError> {
    if plan.source_contract_refs.is_empty() {
        return Err(RegimePlanError::MissingSourceContracts);
    }
    require_sha256(&plan.q06_floor_digest)?;
    require_sha256(&plan.q07_floor_digest)?;
    require_sha256(&plan.sandbox_qualification_population.population_digest)?;
    require_sha256(
        &plan
            .evidence_grader_qualification_population
            .population_digest,
    )?;

    let mut regimes = BTreeSet::new();
    let mut pipeline_refs = BTreeSet::new();
    for pipeline in &plan.pipelines {
        if !regimes.insert(pipeline.regime) {
            return Err(RegimePlanError::DuplicateRegime(pipeline.regime));
        }
        if !pipeline_refs.insert(pipeline.pipeline_ref.clone()) {
            return Err(RegimePlanError::DuplicatePipeline(
                pipeline.pipeline_ref.to_string(),
            ));
        }
        validate_pipeline_shape(pipeline)?;
    }
    for regime in SpecialistRegime::ALL {
        if !regimes.contains(&regime) {
            return Err(RegimePlanError::MissingRegime(regime));
        }
    }
    Ok(())
}

fn validate_pipeline_shape(pipeline: &RegimePipelinePlan) -> Result<(), RegimePlanError> {
    if pipeline.source_contract_refs.is_empty() {
        return Err(RegimePlanError::MissingPipelineSourceContracts(
            pipeline.regime,
        ));
    }

    let corpus = &pipeline.corpus;
    if corpus.development_partition_ref == corpus.heldout_partition_ref
        || corpus.development_partition_ref == corpus.adversarial_partition_ref
        || corpus.heldout_partition_ref == corpus.adversarial_partition_ref
    {
        return Err(RegimePlanError::PartitionIdentityCollision(pipeline.regime));
    }
    if pipeline.grading.grader_refs.is_empty() {
        return Err(RegimePlanError::MissingGraders(pipeline.regime));
    }
    if pipeline.grading.evidence_schema_refs.is_empty() {
        return Err(RegimePlanError::MissingGraderEvidenceSchemas(
            pipeline.regime,
        ));
    }
    if pipeline.required_capabilities.is_empty() {
        return Err(RegimePlanError::MissingCapabilities(pipeline.regime));
    }
    let mut requirement_refs = BTreeSet::new();
    for requirement in &pipeline.required_capabilities {
        if !requirement_refs.insert(requirement.requirement_ref.clone()) {
            return Err(RegimePlanError::DuplicateCapabilityRequirement(
                requirement.requirement_ref.to_string(),
            ));
        }
        if requirement.required_operation_refs.is_empty() {
            return Err(RegimePlanError::EmptyCapabilityRequirementOperations(
                requirement.requirement_ref.to_string(),
            ));
        }
    }
    if pipeline.required_integration_contract_refs.is_empty() {
        return Err(RegimePlanError::MissingIntegrationContracts(
            pipeline.regime,
        ));
    }
    if pipeline.quality_floor_refs.is_empty() {
        return Err(RegimePlanError::MissingQualityFloors(pipeline.regime));
    }
    if pipeline.completion_evidence_requirement_refs.is_empty() {
        return Err(RegimePlanError::MissingCompletionEvidenceRequirements(
            pipeline.regime,
        ));
    }
    Ok(())
}

fn verify_pipeline_digest(pipeline: &RegimePipelinePlan) -> Result<(), RegimePlanError> {
    require_sha256(&pipeline.content_digest)?;
    let computed = compute_regime_pipeline_digest(pipeline)?;
    if computed != pipeline.content_digest {
        return Err(RegimePlanError::PipelineDigestMismatch(pipeline.regime));
    }
    Ok(())
}

fn require_sha256(digest: &ContentDigest) -> Result<(), RegimePlanError> {
    if digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(RegimePlanError::UnsupportedDigestAlgorithm(
            digest.algorithm_ref.to_string(),
        ));
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> Result<ContentDigest, RegimePlanError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| RegimePlanError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| RegimePlanError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| RegimePlanError::EncodingFailure)?,
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

    fn count(&mut self, value: usize) -> Result<(), RegimePlanError> {
        let value = u64::try_from(value).map_err(|_| RegimePlanError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), RegimePlanError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), RegimePlanError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), RegimePlanError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), RegimePlanError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), RegimePlanError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn regime(&mut self, regime: SpecialistRegime) -> Result<(), RegimePlanError> {
        self.scalar(match regime {
            SpecialistRegime::ConversationPersonalAssistant => "conversation-personal-assistant",
            SpecialistRegime::ResearchDeepResearch => "research-deep-research",
            SpecialistRegime::SoftwareEngineering => "software-engineering",
            SpecialistRegime::ActionAutomation => "action-automation",
            SpecialistRegime::CreationArtifact => "creation-artifact",
            SpecialistRegime::MonitoringLongRunningWork => "monitoring-long-running-work",
        })
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
