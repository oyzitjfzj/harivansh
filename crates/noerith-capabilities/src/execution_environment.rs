extern crate alloc;

use crate::{
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    qualification::EvidenceStatus,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const EXECUTION_ENVIRONMENT_PROFILE_CANONICAL_PROFILE: &str =
    "NOERITH/EXECUTION-ENVIRONMENT-PROFILE/CANONICAL-2026-09";
pub const EXECUTION_ENVIRONMENT_PLAN_CANONICAL_PROFILE: &str =
    "NOERITH/EXECUTION-ENVIRONMENT-QUALIFICATION-PLAN/CANONICAL-2026-09";
const PROFILE_DOMAIN: &[u8] = b"NOERITH\0EXECUTION-ENVIRONMENT-PROFILE\0CANONICAL-2026-09\0";
const PLAN_DOMAIN: &[u8] =
    b"NOERITH\0EXECUTION-ENVIRONMENT-QUALIFICATION-PLAN\0CANONICAL-2026-09\0";
const ENVIRONMENT_QUALIFICATION_VERIFICATION_DOMAIN: &[u8] =
    b"NOERITH\0EXECUTION-ENVIRONMENT-QUALIFICATION-VERIFICATION\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbientAuthorityMode {
    DefaultDeny,
    DefaultAllow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspacePersistenceMode {
    Ephemeral,
    DurableScoped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationContract {
    pub boundary_ref: Reference,
    pub enforcement_control_refs: BTreeSet<Reference>,
    pub threat_model_refs: BTreeSet<Reference>,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAccessContract {
    pub ambient_authority: AmbientAuthorityMode,
    pub filesystem_scope_policy_ref: Reference,
    pub network_scope_policy_ref: Reference,
    pub device_scope_policy_ref: Reference,
    pub process_scope_policy_ref: Reference,
    pub ipc_scope_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceControlContract {
    pub cpu_limit_policy_ref: Reference,
    pub memory_limit_policy_ref: Reference,
    pub process_limit_policy_ref: Reference,
    pub wall_clock_limit_policy_ref: Reference,
    pub io_limit_policy_ref: Reference,
    pub termination_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretDeliveryContract {
    pub secret_handle_contract_ref: Reference,
    pub injection_policy_ref: Reference,
    pub redaction_policy_ref: Reference,
    pub cleanup_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceLifecycleContract {
    pub persistence_mode: WorkspacePersistenceMode,
    pub task_scope_policy_ref: Reference,
    pub reuse_policy_ref: Reference,
    pub reset_policy_ref: Reference,
    pub correction_deletion_policy_ref: Reference,
    pub teardown_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplyChainContract {
    pub dependency_policy_ref: Reference,
    pub provenance_policy_ref: Reference,
    pub integrity_policy_ref: Reference,
    pub vulnerability_invalidation_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactBoundaryContract {
    pub import_policy_ref: Reference,
    pub export_policy_ref: Reference,
    pub provenance_policy_ref: Reference,
    pub data_loss_prevention_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationContract {
    pub environment_identity_evidence_ref: Reference,
    pub runtime_integrity_evidence_ref: Reference,
    pub platform_integrity_evidence_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproducibilityContract {
    pub source_identity_policy_ref: Reference,
    pub environment_capture_policy_ref: Reference,
    pub execution_recipe_ref: Reference,
    pub result_comparison_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupContract {
    pub process_cleanup_policy_ref: Reference,
    pub workspace_cleanup_policy_ref: Reference,
    pub secret_cleanup_policy_ref: Reference,
    pub temporary_resource_cleanup_policy_ref: Reference,
    pub verification_policy_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEnvironmentProfile {
    pub environment_ref: Reference,
    pub environment_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub runtime_ref: Reference,
    pub runtime_version: OpaqueVersion,
    pub runtime_artifact_ref: Reference,
    pub runtime_artifact_digest: ContentDigest,
    pub platform_ref: Reference,
    pub platform_version: OpaqueVersion,
    pub provenance_refs: BTreeSet<Reference>,
    pub isolation: IsolationContract,
    pub access: ResourceAccessContract,
    pub resources: ResourceControlContract,
    pub secrets: SecretDeliveryContract,
    pub workspace: WorkspaceLifecycleContract,
    pub supply_chain: SupplyChainContract,
    pub artifacts: ArtifactBoundaryContract,
    pub attestation: AttestationContract,
    pub reproducibility: ReproducibilityContract,
    pub cleanup: CleanupContract,
    pub qualification_requirement_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEnvironmentProfileIdentity {
    pub environment_ref: Reference,
    pub environment_version: OpaqueVersion,
    pub content_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExecutionEnvironmentProfile {
    identity: ExecutionEnvironmentProfileIdentity,
    runtime_ref: Reference,
    runtime_version: OpaqueVersion,
    platform_ref: Reference,
    platform_version: OpaqueVersion,
    canonical_profile_ref: &'static str,
}

impl VerifiedExecutionEnvironmentProfile {
    pub fn identity(&self) -> &ExecutionEnvironmentProfileIdentity {
        &self.identity
    }

    pub fn runtime_ref(&self) -> &Reference {
        &self.runtime_ref
    }

    pub fn runtime_version(&self) -> &OpaqueVersion {
        &self.runtime_version
    }

    pub fn platform_ref(&self) -> &Reference {
        &self.platform_ref
    }

    pub fn platform_version(&self) -> &OpaqueVersion {
        &self.platform_version
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEnvironmentQualificationPlanIdentity {
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub plan_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEnvironmentQualificationPlan {
    pub identity: ExecutionEnvironmentQualificationPlanIdentity,
    pub subject: ExecutionEnvironmentProfileIdentity,
    pub workload_scope_refs: BTreeSet<Reference>,
    pub threat_scope_refs: BTreeSet<Reference>,
    pub required_evidence_refs: BTreeSet<Reference>,
    pub portability_requirement_refs: BTreeSet<Reference>,
    pub performance_requirement_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEnvironmentEvidenceRecord {
    pub evidence_ref: Reference,
    pub subject: ExecutionEnvironmentProfileIdentity,
    pub plan_identity: ExecutionEnvironmentQualificationPlanIdentity,
    pub requirement_ref: Reference,
    pub test_method_ref: Reference,
    pub test_run_ref: Reference,
    pub producer_ref: Reference,
    pub provenance_refs: BTreeSet<Reference>,
    pub environment_evidence_refs: BTreeSet<Reference>,
    pub observed_result_ref: Reference,
    pub validity_ref: Reference,
    pub status: EvidenceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExecutionEnvironment {
    subject: ExecutionEnvironmentProfileIdentity,
    plan_identity: ExecutionEnvironmentQualificationPlanIdentity,
    workload_scope_refs: BTreeSet<Reference>,
    threat_scope_refs: BTreeSet<Reference>,
    evidence_refs: BTreeSet<Reference>,
    invalidation_dependency_refs: BTreeSet<Reference>,
    verification_digest: ContentDigest,
}

impl VerifiedExecutionEnvironment {
    pub fn subject(&self) -> &ExecutionEnvironmentProfileIdentity {
        &self.subject
    }

    pub fn plan_identity(&self) -> &ExecutionEnvironmentQualificationPlanIdentity {
        &self.plan_identity
    }

    pub fn workload_scope_refs(&self) -> &BTreeSet<Reference> {
        &self.workload_scope_refs
    }

    pub fn threat_scope_refs(&self) -> &BTreeSet<Reference> {
        &self.threat_scope_refs
    }

    pub fn evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.evidence_refs
    }

    pub fn invalidation_dependency_refs(&self) -> &BTreeSet<Reference> {
        &self.invalidation_dependency_refs
    }

    pub fn verification_digest(&self) -> &ContentDigest {
        &self.verification_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionEnvironmentError {
    InvalidProfile,
    DefaultAllowRejected,
    UnsupportedDigestAlgorithm(String),
    ProfileDigestMismatch,
    InvalidPlan,
    PlanDigestMismatch,
    PlanSubjectMismatch,
    PlanDropsProfileRequirement(String),
    EvidenceSubjectMismatch(String),
    EvidencePlanMismatch(String),
    UnexpectedRequirementEvidence(String),
    DuplicateEvidenceRef(String),
    DuplicateRequirementEvidence(String),
    IncompleteEvidenceCoverage,
    EvidenceMissingProvenanceOrEnvironment(String),
    RequirementFailed(String),
    RequirementIndeterminate(String),
    EncodingFailure,
}

impl fmt::Display for ExecutionEnvironmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "execution environment rejected: {self:?}")
    }
}

pub fn compute_execution_environment_profile_digest(
    profile: &ExecutionEnvironmentProfile,
) -> Result<ContentDigest, ExecutionEnvironmentError> {
    validate_profile_shape(profile)?;
    let transcript = canonical_execution_environment_profile_transcript(profile)?;
    digest_bytes(&transcript)
}

pub fn verify_execution_environment_profile_integrity(
    profile: &ExecutionEnvironmentProfile,
) -> Result<VerifiedExecutionEnvironmentProfile, ExecutionEnvironmentError> {
    if profile.content_digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(ExecutionEnvironmentError::UnsupportedDigestAlgorithm(
            profile.content_digest.algorithm_ref.to_string(),
        ));
    }
    let computed = compute_execution_environment_profile_digest(profile)?;
    if computed != profile.content_digest {
        return Err(ExecutionEnvironmentError::ProfileDigestMismatch);
    }
    Ok(VerifiedExecutionEnvironmentProfile {
        identity: ExecutionEnvironmentProfileIdentity {
            environment_ref: profile.environment_ref.clone(),
            environment_version: profile.environment_version.clone(),
            content_digest: computed,
        },
        runtime_ref: profile.runtime_ref.clone(),
        runtime_version: profile.runtime_version.clone(),
        platform_ref: profile.platform_ref.clone(),
        platform_version: profile.platform_version.clone(),
        canonical_profile_ref: EXECUTION_ENVIRONMENT_PROFILE_CANONICAL_PROFILE,
    })
}

pub fn compute_execution_environment_plan_digest(
    plan: &ExecutionEnvironmentQualificationPlan,
) -> Result<ContentDigest, ExecutionEnvironmentError> {
    validate_plan_shape(plan)?;
    let transcript = canonical_execution_environment_plan_transcript(plan)?;
    digest_bytes(&transcript)
}

pub fn qualify_execution_environment(
    profile: &ExecutionEnvironmentProfile,
    verified_profile: &VerifiedExecutionEnvironmentProfile,
    plan: &ExecutionEnvironmentQualificationPlan,
    evidence: &[ExecutionEnvironmentEvidenceRecord],
) -> Result<VerifiedExecutionEnvironment, ExecutionEnvironmentError> {
    let current = verify_execution_environment_profile_integrity(profile)?;
    if &current != verified_profile {
        return Err(ExecutionEnvironmentError::ProfileDigestMismatch);
    }
    if plan.subject != *verified_profile.identity() {
        return Err(ExecutionEnvironmentError::PlanSubjectMismatch);
    }
    verify_plan_integrity(plan)?;

    let mandatory = profile_required_evidence(profile);
    if let Some(missing) = mandatory
        .iter()
        .find(|required| !plan.required_evidence_refs.contains(*required))
    {
        return Err(ExecutionEnvironmentError::PlanDropsProfileRequirement(
            missing.to_string(),
        ));
    }

    let mut by_requirement = BTreeMap::<Reference, &ExecutionEnvironmentEvidenceRecord>::new();
    let mut evidence_refs = BTreeSet::new();
    for record in evidence {
        if record.subject != plan.subject {
            return Err(ExecutionEnvironmentError::EvidenceSubjectMismatch(
                record.evidence_ref.to_string(),
            ));
        }
        if record.plan_identity != plan.identity {
            return Err(ExecutionEnvironmentError::EvidencePlanMismatch(
                record.evidence_ref.to_string(),
            ));
        }
        if !plan
            .required_evidence_refs
            .contains(&record.requirement_ref)
        {
            return Err(ExecutionEnvironmentError::UnexpectedRequirementEvidence(
                record.requirement_ref.to_string(),
            ));
        }
        if record.provenance_refs.is_empty() || record.environment_evidence_refs.is_empty() {
            return Err(
                ExecutionEnvironmentError::EvidenceMissingProvenanceOrEnvironment(
                    record.evidence_ref.to_string(),
                ),
            );
        }
        if !evidence_refs.insert(record.evidence_ref.clone()) {
            return Err(ExecutionEnvironmentError::DuplicateEvidenceRef(
                record.evidence_ref.to_string(),
            ));
        }
        if by_requirement
            .insert(record.requirement_ref.clone(), record)
            .is_some()
        {
            return Err(ExecutionEnvironmentError::DuplicateRequirementEvidence(
                record.requirement_ref.to_string(),
            ));
        }
    }

    let covered: BTreeSet<Reference> = by_requirement.keys().cloned().collect();
    if covered != plan.required_evidence_refs {
        return Err(ExecutionEnvironmentError::IncompleteEvidenceCoverage);
    }

    for requirement in &plan.required_evidence_refs {
        let record = by_requirement
            .get(requirement)
            .ok_or(ExecutionEnvironmentError::IncompleteEvidenceCoverage)?;
        match record.status {
            EvidenceStatus::Pass => {}
            EvidenceStatus::Fail => {
                return Err(ExecutionEnvironmentError::RequirementFailed(
                    requirement.to_string(),
                ));
            }
            EvidenceStatus::Indeterminate => {
                return Err(ExecutionEnvironmentError::RequirementIndeterminate(
                    requirement.to_string(),
                ));
            }
        }
    }

    let mut invalidation_dependency_refs = profile.invalidation_dependency_refs.clone();
    invalidation_dependency_refs.extend(plan.invalidation_dependency_refs.iter().cloned());
    let verification_digest = compute_execution_environment_verification_digest(
        plan,
        &by_requirement,
        &invalidation_dependency_refs,
    )?;

    Ok(VerifiedExecutionEnvironment {
        subject: plan.subject.clone(),
        plan_identity: plan.identity.clone(),
        workload_scope_refs: plan.workload_scope_refs.clone(),
        threat_scope_refs: plan.threat_scope_refs.clone(),
        evidence_refs,
        invalidation_dependency_refs,
        verification_digest,
    })
}

fn compute_execution_environment_verification_digest(
    plan: &ExecutionEnvironmentQualificationPlan,
    evidence_by_requirement: &BTreeMap<Reference, &ExecutionEnvironmentEvidenceRecord>,
    invalidation_dependency_refs: &BTreeSet<Reference>,
) -> Result<ContentDigest, ExecutionEnvironmentError> {
    let mut encoder = Encoder::new();
    encoder.raw(ENVIRONMENT_QUALIFICATION_VERIFICATION_DOMAIN);
    encoder.profile_identity(&plan.subject)?;
    encoder.qualification_plan_identity(&plan.identity)?;
    encoder.ref_set(&plan.workload_scope_refs)?;
    encoder.ref_set(&plan.threat_scope_refs)?;
    encoder.ref_set(invalidation_dependency_refs)?;
    encoder.count(evidence_by_requirement.len())?;
    for record in evidence_by_requirement.values() {
        encoder.evidence_record(record)?;
    }
    digest_bytes(&encoder.finish())
}

pub fn canonical_execution_environment_profile_transcript(
    profile: &ExecutionEnvironmentProfile,
) -> Result<Vec<u8>, ExecutionEnvironmentError> {
    validate_profile_shape(profile)?;
    let mut encoder = Encoder::new();
    encoder.raw(PROFILE_DOMAIN);
    encoder.reference(&profile.environment_ref)?;
    encoder.version(&profile.environment_version)?;
    encoder.reference(&profile.runtime_ref)?;
    encoder.version(&profile.runtime_version)?;
    encoder.reference(&profile.runtime_artifact_ref)?;
    encoder.digest(&profile.runtime_artifact_digest)?;
    encoder.reference(&profile.platform_ref)?;
    encoder.version(&profile.platform_version)?;
    encoder.ref_set(&profile.provenance_refs)?;

    encoder.reference(&profile.isolation.boundary_ref)?;
    encoder.ref_set(&profile.isolation.enforcement_control_refs)?;
    encoder.ref_set(&profile.isolation.threat_model_refs)?;
    encoder.ref_set(&profile.isolation.evidence_requirement_refs)?;

    encoder.scalar(match profile.access.ambient_authority {
        AmbientAuthorityMode::DefaultDeny => "default-deny",
        AmbientAuthorityMode::DefaultAllow => "default-allow",
    })?;
    encoder.reference(&profile.access.filesystem_scope_policy_ref)?;
    encoder.reference(&profile.access.network_scope_policy_ref)?;
    encoder.reference(&profile.access.device_scope_policy_ref)?;
    encoder.reference(&profile.access.process_scope_policy_ref)?;
    encoder.reference(&profile.access.ipc_scope_policy_ref)?;
    encoder.ref_set(&profile.access.evidence_requirement_refs)?;

    encoder.reference(&profile.resources.cpu_limit_policy_ref)?;
    encoder.reference(&profile.resources.memory_limit_policy_ref)?;
    encoder.reference(&profile.resources.process_limit_policy_ref)?;
    encoder.reference(&profile.resources.wall_clock_limit_policy_ref)?;
    encoder.reference(&profile.resources.io_limit_policy_ref)?;
    encoder.reference(&profile.resources.termination_policy_ref)?;
    encoder.ref_set(&profile.resources.evidence_requirement_refs)?;

    encoder.reference(&profile.secrets.secret_handle_contract_ref)?;
    encoder.reference(&profile.secrets.injection_policy_ref)?;
    encoder.reference(&profile.secrets.redaction_policy_ref)?;
    encoder.reference(&profile.secrets.cleanup_policy_ref)?;
    encoder.ref_set(&profile.secrets.evidence_requirement_refs)?;

    encoder.scalar(match profile.workspace.persistence_mode {
        WorkspacePersistenceMode::Ephemeral => "ephemeral",
        WorkspacePersistenceMode::DurableScoped => "durable-scoped",
    })?;
    encoder.reference(&profile.workspace.task_scope_policy_ref)?;
    encoder.reference(&profile.workspace.reuse_policy_ref)?;
    encoder.reference(&profile.workspace.reset_policy_ref)?;
    encoder.reference(&profile.workspace.correction_deletion_policy_ref)?;
    encoder.reference(&profile.workspace.teardown_policy_ref)?;
    encoder.ref_set(&profile.workspace.evidence_requirement_refs)?;

    encoder.reference(&profile.supply_chain.dependency_policy_ref)?;
    encoder.reference(&profile.supply_chain.provenance_policy_ref)?;
    encoder.reference(&profile.supply_chain.integrity_policy_ref)?;
    encoder.reference(&profile.supply_chain.vulnerability_invalidation_policy_ref)?;
    encoder.ref_set(&profile.supply_chain.evidence_requirement_refs)?;

    encoder.reference(&profile.artifacts.import_policy_ref)?;
    encoder.reference(&profile.artifacts.export_policy_ref)?;
    encoder.reference(&profile.artifacts.provenance_policy_ref)?;
    encoder.reference(&profile.artifacts.data_loss_prevention_policy_ref)?;
    encoder.ref_set(&profile.artifacts.evidence_requirement_refs)?;

    encoder.reference(&profile.attestation.environment_identity_evidence_ref)?;
    encoder.reference(&profile.attestation.runtime_integrity_evidence_ref)?;
    encoder.reference(&profile.attestation.platform_integrity_evidence_ref)?;
    encoder.ref_set(&profile.attestation.evidence_requirement_refs)?;

    encoder.reference(&profile.reproducibility.source_identity_policy_ref)?;
    encoder.reference(&profile.reproducibility.environment_capture_policy_ref)?;
    encoder.reference(&profile.reproducibility.execution_recipe_ref)?;
    encoder.reference(&profile.reproducibility.result_comparison_policy_ref)?;
    encoder.ref_set(&profile.reproducibility.evidence_requirement_refs)?;

    encoder.reference(&profile.cleanup.process_cleanup_policy_ref)?;
    encoder.reference(&profile.cleanup.workspace_cleanup_policy_ref)?;
    encoder.reference(&profile.cleanup.secret_cleanup_policy_ref)?;
    encoder.reference(&profile.cleanup.temporary_resource_cleanup_policy_ref)?;
    encoder.reference(&profile.cleanup.verification_policy_ref)?;
    encoder.ref_set(&profile.cleanup.evidence_requirement_refs)?;

    encoder.ref_set(&profile.qualification_requirement_refs)?;
    encoder.ref_set(&profile.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

pub fn canonical_execution_environment_plan_transcript(
    plan: &ExecutionEnvironmentQualificationPlan,
) -> Result<Vec<u8>, ExecutionEnvironmentError> {
    validate_plan_shape(plan)?;
    let mut encoder = Encoder::new();
    encoder.raw(PLAN_DOMAIN);
    encoder.reference(&plan.identity.plan_ref)?;
    encoder.version(&plan.identity.plan_version)?;
    encoder.profile_identity(&plan.subject)?;
    encoder.ref_set(&plan.workload_scope_refs)?;
    encoder.ref_set(&plan.threat_scope_refs)?;
    encoder.ref_set(&plan.required_evidence_refs)?;
    encoder.ref_set(&plan.portability_requirement_refs)?;
    encoder.ref_set(&plan.performance_requirement_refs)?;
    encoder.ref_set(&plan.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

fn validate_profile_shape(
    profile: &ExecutionEnvironmentProfile,
) -> Result<(), ExecutionEnvironmentError> {
    if profile.access.ambient_authority != AmbientAuthorityMode::DefaultDeny {
        return Err(ExecutionEnvironmentError::DefaultAllowRejected);
    }
    let required_sets = [
        &profile.provenance_refs,
        &profile.isolation.enforcement_control_refs,
        &profile.isolation.threat_model_refs,
        &profile.isolation.evidence_requirement_refs,
        &profile.access.evidence_requirement_refs,
        &profile.resources.evidence_requirement_refs,
        &profile.secrets.evidence_requirement_refs,
        &profile.workspace.evidence_requirement_refs,
        &profile.supply_chain.evidence_requirement_refs,
        &profile.artifacts.evidence_requirement_refs,
        &profile.attestation.evidence_requirement_refs,
        &profile.reproducibility.evidence_requirement_refs,
        &profile.cleanup.evidence_requirement_refs,
        &profile.qualification_requirement_refs,
        &profile.invalidation_dependency_refs,
    ];
    if required_sets.iter().any(|values| values.is_empty()) {
        return Err(ExecutionEnvironmentError::InvalidProfile);
    }
    if profile
        .runtime_artifact_digest
        .algorithm_ref
        .as_str()
        .trim()
        .is_empty()
        || profile
            .runtime_artifact_digest
            .value
            .as_str()
            .trim()
            .is_empty()
    {
        return Err(ExecutionEnvironmentError::InvalidProfile);
    }
    Ok(())
}

fn validate_plan_shape(
    plan: &ExecutionEnvironmentQualificationPlan,
) -> Result<(), ExecutionEnvironmentError> {
    if plan.workload_scope_refs.is_empty()
        || plan.threat_scope_refs.is_empty()
        || plan.required_evidence_refs.is_empty()
        || plan.portability_requirement_refs.is_empty()
        || plan.performance_requirement_refs.is_empty()
        || plan.invalidation_dependency_refs.is_empty()
    {
        return Err(ExecutionEnvironmentError::InvalidPlan);
    }
    Ok(())
}

fn verify_plan_integrity(
    plan: &ExecutionEnvironmentQualificationPlan,
) -> Result<(), ExecutionEnvironmentError> {
    if plan.identity.plan_digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(ExecutionEnvironmentError::UnsupportedDigestAlgorithm(
            plan.identity.plan_digest.algorithm_ref.to_string(),
        ));
    }
    if compute_execution_environment_plan_digest(plan)? != plan.identity.plan_digest {
        return Err(ExecutionEnvironmentError::PlanDigestMismatch);
    }
    Ok(())
}

fn profile_required_evidence(profile: &ExecutionEnvironmentProfile) -> BTreeSet<Reference> {
    let mut required = profile.qualification_requirement_refs.clone();
    for refs in [
        &profile.isolation.evidence_requirement_refs,
        &profile.access.evidence_requirement_refs,
        &profile.resources.evidence_requirement_refs,
        &profile.secrets.evidence_requirement_refs,
        &profile.workspace.evidence_requirement_refs,
        &profile.supply_chain.evidence_requirement_refs,
        &profile.artifacts.evidence_requirement_refs,
        &profile.attestation.evidence_requirement_refs,
        &profile.reproducibility.evidence_requirement_refs,
        &profile.cleanup.evidence_requirement_refs,
    ] {
        required.extend(refs.iter().cloned());
    }
    required
}

fn digest_bytes(bytes: &[u8]) -> Result<ContentDigest, ExecutionEnvironmentError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| ExecutionEnvironmentError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| ExecutionEnvironmentError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| ExecutionEnvironmentError::EncodingFailure)?,
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

    fn count(&mut self, value: usize) -> Result<(), ExecutionEnvironmentError> {
        let value = u64::try_from(value).map_err(|_| ExecutionEnvironmentError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), ExecutionEnvironmentError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), ExecutionEnvironmentError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), ExecutionEnvironmentError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), ExecutionEnvironmentError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), ExecutionEnvironmentError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn profile_identity(
        &mut self,
        value: &ExecutionEnvironmentProfileIdentity,
    ) -> Result<(), ExecutionEnvironmentError> {
        self.reference(&value.environment_ref)?;
        self.version(&value.environment_version)?;
        self.digest(&value.content_digest)
    }

    fn qualification_plan_identity(
        &mut self,
        value: &ExecutionEnvironmentQualificationPlanIdentity,
    ) -> Result<(), ExecutionEnvironmentError> {
        self.reference(&value.plan_ref)?;
        self.version(&value.plan_version)?;
        self.digest(&value.plan_digest)
    }

    fn evidence_status(&mut self, value: EvidenceStatus) -> Result<(), ExecutionEnvironmentError> {
        self.scalar(match value {
            EvidenceStatus::Pass => "pass",
            EvidenceStatus::Fail => "fail",
            EvidenceStatus::Indeterminate => "indeterminate",
        })
    }

    fn evidence_record(
        &mut self,
        record: &ExecutionEnvironmentEvidenceRecord,
    ) -> Result<(), ExecutionEnvironmentError> {
        self.reference(&record.evidence_ref)?;
        self.profile_identity(&record.subject)?;
        self.qualification_plan_identity(&record.plan_identity)?;
        self.reference(&record.requirement_ref)?;
        self.reference(&record.test_method_ref)?;
        self.reference(&record.test_run_ref)?;
        self.reference(&record.producer_ref)?;
        self.ref_set(&record.provenance_refs)?;
        self.ref_set(&record.environment_evidence_refs)?;
        self.reference(&record.observed_result_ref)?;
        self.reference(&record.validity_ref)?;
        self.evidence_status(record.status)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
