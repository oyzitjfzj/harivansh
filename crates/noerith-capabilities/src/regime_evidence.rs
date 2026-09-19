extern crate alloc;

use crate::{
    execution_environment::{ExecutionEnvironmentProfileIdentity, VerifiedExecutionEnvironment},
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    qualification::EvidenceStatus,
    qualification_population::{
        QualificationPlanPopulationPurpose, VerifiedQualificationPlanPopulation,
    },
    regime::{RegimePipelinePlan, SixRegimeQualificationPlan, SpecialistRegime},
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

pub const REGIME_EVIDENCE_CANONICAL_PROFILE: &str =
    "NOERITH/REGIME-EXECUTION-EVIDENCE/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0REGIME-EXECUTION-EVIDENCE\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegimeEvidenceKind {
    IntegrationContract,
    CompletionRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegimeObservedEvidenceRecord {
    pub evidence_ref: Reference,
    pub evidence_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub kind: RegimeEvidenceKind,
    pub regime: SpecialistRegime,
    pub pipeline_ref: Reference,
    pub pipeline_version: OpaqueVersion,
    pub pipeline_digest: ContentDigest,
    pub requirement_ref: Reference,
    pub environment_ref: Reference,
    pub environment_version: OpaqueVersion,
    pub environment_digest: ContentDigest,
    pub test_method_ref: Reference,
    pub test_run_ref: Reference,
    pub producer_ref: Reference,
    pub observed_result_ref: Reference,
    pub environment_evidence_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub validity_ref: Reference,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
    pub status: EvidenceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegimeExecutionEvidenceBundle {
    pub records: Vec<RegimeObservedEvidenceRecord>,
    pub environments: Vec<VerifiedExecutionEnvironment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegimeExecutionEvidence {
    regime: SpecialistRegime,
    pipeline_ref: Reference,
    pipeline_version: OpaqueVersion,
    pipeline_digest: ContentDigest,
    integration_evidence_refs: BTreeSet<Reference>,
    completion_evidence_refs: BTreeSet<Reference>,
    environments: Vec<ExecutionEnvironmentProfileIdentity>,
    canonical_profile_ref: &'static str,
}

impl VerifiedRegimeExecutionEvidence {
    pub fn regime(&self) -> SpecialistRegime {
        self.regime
    }

    pub fn pipeline_ref(&self) -> &Reference {
        &self.pipeline_ref
    }

    pub fn pipeline_version(&self) -> &OpaqueVersion {
        &self.pipeline_version
    }

    pub fn pipeline_digest(&self) -> &ContentDigest {
        &self.pipeline_digest
    }

    /// Exact content-digest references for the verified integration records.
    pub fn integration_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.integration_evidence_refs
    }

    /// Exact content-digest references for the verified completion records.
    pub fn completion_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.completion_evidence_refs
    }

    pub fn environments(&self) -> &[ExecutionEnvironmentProfileIdentity] {
        &self.environments
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegimeEvidenceError {
    Plan(crate::regime::RegimePlanError),
    VerifiedPlanMismatch,
    SandboxQualificationPopulationMismatch,
    SandboxQualificationPlanNotPreregistered(String),
    MissingRegime(SpecialistRegime),
    EmptyEvidence,
    EmptyEnvironmentPopulation,
    UnsupportedDigestAlgorithm(String),
    EvidenceDigestMismatch(String),
    EvidenceShapeInvalid(String),
    EvidencePipelineMismatch(String),
    UnexpectedRequirement(String),
    DuplicateRequirement(String),
    DuplicateEvidenceRef(String),
    IncompleteIntegrationCoverage,
    IncompleteCompletionCoverage,
    RequirementFailed(String),
    RequirementIndeterminate(String),
    DuplicateEnvironment(String),
    UnknownEnvironment(String),
    MissingEnvironmentQualificationEvidence(String),
    MissingEnvironmentInvalidationDependencies(String),
    UnusedEnvironment(String),
    EncodingFailure,
}

impl fmt::Display for RegimeEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "regime execution evidence rejected: {self:?}")
    }
}

pub fn compute_regime_observed_evidence_digest(
    record: &RegimeObservedEvidenceRecord,
) -> Result<ContentDigest, RegimeEvidenceError> {
    validate_record_shape(record)?;
    let transcript = canonical_regime_observed_evidence_transcript(record)?;
    sha256_digest(&transcript)
}

pub fn canonical_regime_observed_evidence_transcript(
    record: &RegimeObservedEvidenceRecord,
) -> Result<Vec<u8>, RegimeEvidenceError> {
    validate_record_shape(record)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&record.evidence_ref)?;
    encoder.version(&record.evidence_version)?;
    encoder.kind(record.kind)?;
    encoder.regime(record.regime)?;
    encoder.reference(&record.pipeline_ref)?;
    encoder.version(&record.pipeline_version)?;
    encoder.digest(&record.pipeline_digest)?;
    encoder.reference(&record.requirement_ref)?;
    encoder.reference(&record.environment_ref)?;
    encoder.version(&record.environment_version)?;
    encoder.digest(&record.environment_digest)?;
    encoder.reference(&record.test_method_ref)?;
    encoder.reference(&record.test_run_ref)?;
    encoder.reference(&record.producer_ref)?;
    encoder.reference(&record.observed_result_ref)?;
    encoder.ref_set(&record.environment_evidence_refs)?;
    encoder.ref_set(&record.provenance_refs)?;
    encoder.reference(&record.validity_ref)?;
    encoder.ref_set(&record.invalidation_dependency_refs)?;
    encoder.status(record.status)?;
    Ok(encoder.finish())
}

pub fn verify_regime_execution_evidence(
    plan: &SixRegimeQualificationPlan,
    verified_plan: &VerifiedSixRegimeQualificationPlan,
    sandbox_population: &VerifiedQualificationPlanPopulation,
    regime: SpecialistRegime,
    bundle: &RegimeExecutionEvidenceBundle,
) -> Result<VerifiedRegimeExecutionEvidence, RegimeEvidenceError> {
    let current_plan =
        verify_six_regime_qualification_plan(plan).map_err(RegimeEvidenceError::Plan)?;
    if &current_plan != verified_plan {
        return Err(RegimeEvidenceError::VerifiedPlanMismatch);
    }
    if sandbox_population.purpose() != QualificationPlanPopulationPurpose::ExecutionEnvironment
        || sandbox_population.identity() != &plan.sandbox_qualification_population
    {
        return Err(RegimeEvidenceError::SandboxQualificationPopulationMismatch);
    }

    let pipeline = plan
        .pipelines
        .iter()
        .find(|pipeline| pipeline.regime == regime)
        .ok_or(RegimeEvidenceError::MissingRegime(regime))?;

    if bundle.records.is_empty() {
        return Err(RegimeEvidenceError::EmptyEvidence);
    }
    if bundle.environments.is_empty() {
        return Err(RegimeEvidenceError::EmptyEnvironmentPopulation);
    }

    let environments = index_environments(sandbox_population, &bundle.environments)?;
    let mut used_environments = BTreeSet::new();
    let mut evidence_refs = BTreeSet::new();
    let mut integration_by_requirement = BTreeMap::<Reference, Reference>::new();
    let mut completion_by_requirement = BTreeMap::<Reference, Reference>::new();

    for record in &bundle.records {
        verify_record_integrity(record)?;
        verify_pipeline_binding(pipeline, record)?;
        if !evidence_refs.insert(record.evidence_ref.clone()) {
            return Err(RegimeEvidenceError::DuplicateEvidenceRef(
                record.evidence_ref.to_string(),
            ));
        }
        verify_status(record)?;

        let key = environment_key(
            &record.environment_ref,
            &record.environment_version,
            &record.environment_digest,
        );
        let environment = environments.get(&key).ok_or_else(|| {
            RegimeEvidenceError::UnknownEnvironment(alloc::format!(
                "{}@{}",
                record.environment_ref,
                record.environment_version.as_str()
            ))
        })?;
        if record
            .environment_evidence_refs
            .is_disjoint(environment.evidence_refs())
        {
            return Err(
                RegimeEvidenceError::MissingEnvironmentQualificationEvidence(
                    record.evidence_ref.to_string(),
                ),
            );
        }
        if !environment
            .invalidation_dependency_refs()
            .is_subset(&record.invalidation_dependency_refs)
        {
            return Err(
                RegimeEvidenceError::MissingEnvironmentInvalidationDependencies(
                    record.evidence_ref.to_string(),
                ),
            );
        }
        used_environments.insert(key);

        let target = match record.kind {
            RegimeEvidenceKind::IntegrationContract => {
                if !pipeline
                    .required_integration_contract_refs
                    .contains(&record.requirement_ref)
                {
                    return Err(RegimeEvidenceError::UnexpectedRequirement(
                        record.requirement_ref.to_string(),
                    ));
                }
                &mut integration_by_requirement
            }
            RegimeEvidenceKind::CompletionRequirement => {
                if !pipeline
                    .completion_evidence_requirement_refs
                    .contains(&record.requirement_ref)
                {
                    return Err(RegimeEvidenceError::UnexpectedRequirement(
                        record.requirement_ref.to_string(),
                    ));
                }
                &mut completion_by_requirement
            }
        };
        if target
            .insert(
                record.requirement_ref.clone(),
                record.content_digest.value.clone(),
            )
            .is_some()
        {
            return Err(RegimeEvidenceError::DuplicateRequirement(
                record.requirement_ref.to_string(),
            ));
        }
    }

    let integration_requirements: BTreeSet<Reference> =
        integration_by_requirement.keys().cloned().collect();
    if integration_requirements != pipeline.required_integration_contract_refs {
        return Err(RegimeEvidenceError::IncompleteIntegrationCoverage);
    }
    let completion_requirements: BTreeSet<Reference> =
        completion_by_requirement.keys().cloned().collect();
    if completion_requirements != pipeline.completion_evidence_requirement_refs {
        return Err(RegimeEvidenceError::IncompleteCompletionCoverage);
    }

    for (key, environment) in &environments {
        if !used_environments.contains(key) {
            return Err(RegimeEvidenceError::UnusedEnvironment(alloc::format!(
                "{}@{}",
                environment.subject().environment_ref,
                environment.subject().environment_version.as_str()
            )));
        }
    }

    let mut environment_identities: Vec<ExecutionEnvironmentProfileIdentity> = used_environments
        .iter()
        .map(|key| {
            environments
                .get(key)
                .expect("used environment was indexed")
                .subject()
                .clone()
        })
        .collect();
    environment_identities.sort_by(|left, right| {
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

    Ok(VerifiedRegimeExecutionEvidence {
        regime,
        pipeline_ref: pipeline.pipeline_ref.clone(),
        pipeline_version: pipeline.pipeline_version.clone(),
        pipeline_digest: pipeline.content_digest.clone(),
        integration_evidence_refs: integration_by_requirement.into_values().collect(),
        completion_evidence_refs: completion_by_requirement.into_values().collect(),
        environments: environment_identities,
        canonical_profile_ref: REGIME_EVIDENCE_CANONICAL_PROFILE,
    })
}

type EnvironmentKey = (String, String, String, String);

fn index_environments<'a>(
    sandbox_population: &VerifiedQualificationPlanPopulation,
    environments: &'a [VerifiedExecutionEnvironment],
) -> Result<BTreeMap<EnvironmentKey, &'a VerifiedExecutionEnvironment>, RegimeEvidenceError> {
    let mut indexed = BTreeMap::new();
    for environment in environments {
        let identity = environment.plan_identity();
        if !sandbox_population.contains_exact(
            &identity.plan_ref,
            &identity.plan_version,
            &identity.plan_digest,
        ) {
            return Err(
                RegimeEvidenceError::SandboxQualificationPlanNotPreregistered(alloc::format!(
                    "{}@{}",
                    identity.plan_ref,
                    identity.plan_version.as_str()
                )),
            );
        }
        let subject = environment.subject();
        let key = environment_key(
            &subject.environment_ref,
            &subject.environment_version,
            &subject.content_digest,
        );
        if indexed.insert(key, environment).is_some() {
            return Err(RegimeEvidenceError::DuplicateEnvironment(alloc::format!(
                "{}@{}",
                subject.environment_ref,
                subject.environment_version.as_str()
            )));
        }
    }
    Ok(indexed)
}

fn environment_key(
    reference: &Reference,
    version: &OpaqueVersion,
    digest: &ContentDigest,
) -> EnvironmentKey {
    (
        reference.to_string(),
        version.as_str().into(),
        digest.algorithm_ref.to_string(),
        digest.value.to_string(),
    )
}

fn verify_record_integrity(
    record: &RegimeObservedEvidenceRecord,
) -> Result<(), RegimeEvidenceError> {
    require_sha256(&record.content_digest)?;
    let computed = compute_regime_observed_evidence_digest(record)?;
    if computed != record.content_digest {
        return Err(RegimeEvidenceError::EvidenceDigestMismatch(
            record.evidence_ref.to_string(),
        ));
    }
    Ok(())
}

fn verify_pipeline_binding(
    pipeline: &RegimePipelinePlan,
    record: &RegimeObservedEvidenceRecord,
) -> Result<(), RegimeEvidenceError> {
    if record.regime != pipeline.regime
        || record.pipeline_ref != pipeline.pipeline_ref
        || record.pipeline_version != pipeline.pipeline_version
        || record.pipeline_digest != pipeline.content_digest
    {
        return Err(RegimeEvidenceError::EvidencePipelineMismatch(
            record.evidence_ref.to_string(),
        ));
    }
    Ok(())
}

fn verify_status(record: &RegimeObservedEvidenceRecord) -> Result<(), RegimeEvidenceError> {
    match record.status {
        EvidenceStatus::Pass => Ok(()),
        EvidenceStatus::Fail => Err(RegimeEvidenceError::RequirementFailed(
            record.requirement_ref.to_string(),
        )),
        EvidenceStatus::Indeterminate => Err(RegimeEvidenceError::RequirementIndeterminate(
            record.requirement_ref.to_string(),
        )),
    }
}

fn validate_record_shape(record: &RegimeObservedEvidenceRecord) -> Result<(), RegimeEvidenceError> {
    if record.environment_evidence_refs.is_empty()
        || record.provenance_refs.is_empty()
        || record.invalidation_dependency_refs.is_empty()
    {
        return Err(RegimeEvidenceError::EvidenceShapeInvalid(
            record.evidence_ref.to_string(),
        ));
    }
    Ok(())
}

fn require_sha256(digest: &ContentDigest) -> Result<(), RegimeEvidenceError> {
    if digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(RegimeEvidenceError::UnsupportedDigestAlgorithm(
            digest.algorithm_ref.to_string(),
        ));
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> Result<ContentDigest, RegimeEvidenceError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| RegimeEvidenceError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| RegimeEvidenceError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| RegimeEvidenceError::EncodingFailure)?,
    })
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn count(&mut self, value: usize) -> Result<(), RegimeEvidenceError> {
        let value = u64::try_from(value).map_err(|_| RegimeEvidenceError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), RegimeEvidenceError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), RegimeEvidenceError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), RegimeEvidenceError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), RegimeEvidenceError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), RegimeEvidenceError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn kind(&mut self, value: RegimeEvidenceKind) -> Result<(), RegimeEvidenceError> {
        self.scalar(match value {
            RegimeEvidenceKind::IntegrationContract => "integration-contract",
            RegimeEvidenceKind::CompletionRequirement => "completion-requirement",
        })
    }

    fn regime(&mut self, value: SpecialistRegime) -> Result<(), RegimeEvidenceError> {
        self.scalar(match value {
            SpecialistRegime::ConversationPersonalAssistant => "conversation-personal-assistant",
            SpecialistRegime::ResearchDeepResearch => "research-deep-research",
            SpecialistRegime::SoftwareEngineering => "software-engineering",
            SpecialistRegime::ActionAutomation => "action-automation",
            SpecialistRegime::CreationArtifact => "creation-artifact",
            SpecialistRegime::MonitoringLongRunningWork => "monitoring-long-running-work",
        })
    }

    fn status(&mut self, value: EvidenceStatus) -> Result<(), RegimeEvidenceError> {
        self.scalar(match value {
            EvidenceStatus::Pass => "pass",
            EvidenceStatus::Fail => "fail",
            EvidenceStatus::Indeterminate => "indeterminate",
        })
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
