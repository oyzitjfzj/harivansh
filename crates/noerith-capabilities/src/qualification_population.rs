extern crate alloc;

use crate::{
    execution_environment::{
        ExecutionEnvironmentQualificationPlan, compute_execution_environment_plan_digest,
    },
    grader::{EvidenceGraderPlan, compute_evidence_grader_plan_digest},
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const QUALIFICATION_PLAN_POPULATION_CANONICAL_PROFILE: &str =
    "NOERITH/QUALIFICATION-PLAN-POPULATION/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0QUALIFICATION-PLAN-POPULATION\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QualificationPlanPopulationPurpose {
    ExecutionEnvironment,
    EvidenceGrader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationPlanMemberIdentity {
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub plan_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationPlanPopulationIdentity {
    pub population_ref: Reference,
    pub population_version: OpaqueVersion,
    pub population_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationPlanPopulation {
    pub identity: QualificationPlanPopulationIdentity,
    pub purpose: QualificationPlanPopulationPurpose,
    pub source_contract_refs: alloc::collections::BTreeSet<Reference>,
    pub member_plan_identities: Vec<QualificationPlanMemberIdentity>,
    pub invalidation_dependency_refs: alloc::collections::BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQualificationPlanPopulation {
    identity: QualificationPlanPopulationIdentity,
    purpose: QualificationPlanPopulationPurpose,
    member_plan_identities: Vec<QualificationPlanMemberIdentity>,
    canonical_profile_ref: &'static str,
}

impl VerifiedQualificationPlanPopulation {
    pub fn identity(&self) -> &QualificationPlanPopulationIdentity {
        &self.identity
    }

    pub fn purpose(&self) -> QualificationPlanPopulationPurpose {
        self.purpose
    }

    pub fn member_plan_identities(&self) -> &[QualificationPlanMemberIdentity] {
        &self.member_plan_identities
    }

    pub fn member_count(&self) -> usize {
        self.member_plan_identities.len()
    }

    pub fn contains_exact(
        &self,
        plan_ref: &Reference,
        plan_version: &OpaqueVersion,
        plan_digest: &ContentDigest,
    ) -> bool {
        self.member_plan_identities.iter().any(|member| {
            &member.plan_ref == plan_ref
                && &member.plan_version == plan_version
                && &member.plan_digest == plan_digest
        })
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualificationPlanPopulationError {
    EmptySourceContracts,
    EmptyInvalidationDependencies,
    EmptyMemberPopulation,
    UnsupportedDigestAlgorithm(String),
    DuplicateMember(String),
    MemberIdentityCollision {
        plan_ref: String,
        plan_version: String,
    },
    PopulationDigestMismatch,
    PurposeMismatch,
    DuplicateSuppliedPlan(String),
    ExecutionEnvironmentPlanInvalid(String),
    EvidenceGraderPlanInvalid(String),
    MemberSetMismatch,
    EncodingFailure,
}

impl fmt::Display for QualificationPlanPopulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "qualification-plan population rejected: {self:?}"
        )
    }
}

pub fn compute_qualification_plan_population_digest(
    population: &QualificationPlanPopulation,
) -> Result<ContentDigest, QualificationPlanPopulationError> {
    let transcript = canonical_qualification_plan_population_transcript(population)?;
    sha256_digest(&transcript)
}

pub fn canonical_qualification_plan_population_transcript(
    population: &QualificationPlanPopulation,
) -> Result<Vec<u8>, QualificationPlanPopulationError> {
    let members = validate_population_shape(population)?;

    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&population.identity.population_ref)?;
    encoder.version(&population.identity.population_version)?;
    encoder.purpose(population.purpose)?;
    encoder.ref_set(&population.source_contract_refs)?;
    encoder.count(members.len())?;
    for ((plan_ref, plan_version), plan_digest) in members {
        encoder.reference(&plan_ref)?;
        encoder.version(&plan_version)?;
        encoder.digest(&plan_digest)?;
    }
    encoder.ref_set(&population.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

pub fn verify_execution_environment_qualification_population(
    population: &QualificationPlanPopulation,
    plans: &[ExecutionEnvironmentQualificationPlan],
) -> Result<VerifiedQualificationPlanPopulation, QualificationPlanPopulationError> {
    if population.purpose != QualificationPlanPopulationPurpose::ExecutionEnvironment {
        return Err(QualificationPlanPopulationError::PurposeMismatch);
    }
    verify_population_integrity(population)?;

    let expected = member_index(population)?;
    let mut current = BTreeMap::<PlanKey, ContentDigest>::new();
    for plan in plans {
        let computed = compute_execution_environment_plan_digest(plan).map_err(|_| {
            QualificationPlanPopulationError::ExecutionEnvironmentPlanInvalid(
                plan.identity.plan_ref.to_string(),
            )
        })?;
        if computed != plan.identity.plan_digest {
            return Err(
                QualificationPlanPopulationError::ExecutionEnvironmentPlanInvalid(
                    plan.identity.plan_ref.to_string(),
                ),
            );
        }
        require_sha256(&plan.identity.plan_digest)?;
        let key = (
            plan.identity.plan_ref.clone(),
            plan.identity.plan_version.clone(),
        );
        if current.insert(key, computed).is_some() {
            return Err(QualificationPlanPopulationError::DuplicateSuppliedPlan(
                plan.identity.plan_ref.to_string(),
            ));
        }
    }
    if current != expected {
        return Err(QualificationPlanPopulationError::MemberSetMismatch);
    }
    verified_population(population)
}

pub fn verify_evidence_grader_qualification_population(
    population: &QualificationPlanPopulation,
    plans: &[EvidenceGraderPlan],
) -> Result<VerifiedQualificationPlanPopulation, QualificationPlanPopulationError> {
    if population.purpose != QualificationPlanPopulationPurpose::EvidenceGrader {
        return Err(QualificationPlanPopulationError::PurposeMismatch);
    }
    verify_population_integrity(population)?;

    let expected = member_index(population)?;
    let mut current = BTreeMap::<PlanKey, ContentDigest>::new();
    for plan in plans {
        let computed = compute_evidence_grader_plan_digest(plan).map_err(|_| {
            QualificationPlanPopulationError::EvidenceGraderPlanInvalid(
                plan.identity.plan_ref.to_string(),
            )
        })?;
        if computed != plan.identity.plan_digest {
            return Err(QualificationPlanPopulationError::EvidenceGraderPlanInvalid(
                plan.identity.plan_ref.to_string(),
            ));
        }
        require_sha256(&plan.identity.plan_digest)?;
        let key = (
            plan.identity.plan_ref.clone(),
            plan.identity.plan_version.clone(),
        );
        if current.insert(key, computed).is_some() {
            return Err(QualificationPlanPopulationError::DuplicateSuppliedPlan(
                plan.identity.plan_ref.to_string(),
            ));
        }
    }
    if current != expected {
        return Err(QualificationPlanPopulationError::MemberSetMismatch);
    }
    verified_population(population)
}

type PlanKey = (Reference, OpaqueVersion);

fn verify_population_integrity(
    population: &QualificationPlanPopulation,
) -> Result<(), QualificationPlanPopulationError> {
    require_sha256(&population.identity.population_digest)?;
    let computed = compute_qualification_plan_population_digest(population)?;
    if computed != population.identity.population_digest {
        return Err(QualificationPlanPopulationError::PopulationDigestMismatch);
    }
    Ok(())
}

fn verified_population(
    population: &QualificationPlanPopulation,
) -> Result<VerifiedQualificationPlanPopulation, QualificationPlanPopulationError> {
    let members = member_index(population)?
        .into_iter()
        .map(
            |((plan_ref, plan_version), plan_digest)| QualificationPlanMemberIdentity {
                plan_ref,
                plan_version,
                plan_digest,
            },
        )
        .collect();
    Ok(VerifiedQualificationPlanPopulation {
        identity: population.identity.clone(),
        purpose: population.purpose,
        member_plan_identities: members,
        canonical_profile_ref: QUALIFICATION_PLAN_POPULATION_CANONICAL_PROFILE,
    })
}

fn member_index(
    population: &QualificationPlanPopulation,
) -> Result<BTreeMap<PlanKey, ContentDigest>, QualificationPlanPopulationError> {
    validate_population_shape(population)
}

fn validate_population_shape(
    population: &QualificationPlanPopulation,
) -> Result<BTreeMap<PlanKey, ContentDigest>, QualificationPlanPopulationError> {
    if population.source_contract_refs.is_empty() {
        return Err(QualificationPlanPopulationError::EmptySourceContracts);
    }
    if population.invalidation_dependency_refs.is_empty() {
        return Err(QualificationPlanPopulationError::EmptyInvalidationDependencies);
    }
    if population.member_plan_identities.is_empty() {
        return Err(QualificationPlanPopulationError::EmptyMemberPopulation);
    }

    let mut members = BTreeMap::<PlanKey, ContentDigest>::new();
    for member in &population.member_plan_identities {
        require_sha256(&member.plan_digest)?;
        let key = (member.plan_ref.clone(), member.plan_version.clone());
        if let Some(existing) = members.get(&key) {
            if existing == &member.plan_digest {
                return Err(QualificationPlanPopulationError::DuplicateMember(
                    member.plan_ref.to_string(),
                ));
            }
            return Err(QualificationPlanPopulationError::MemberIdentityCollision {
                plan_ref: member.plan_ref.to_string(),
                plan_version: member.plan_version.as_str().to_string(),
            });
        }
        members.insert(key, member.plan_digest.clone());
    }
    Ok(members)
}

fn require_sha256(digest: &ContentDigest) -> Result<(), QualificationPlanPopulationError> {
    if digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(
            QualificationPlanPopulationError::UnsupportedDigestAlgorithm(
                digest.algorithm_ref.to_string(),
            ),
        );
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> Result<ContentDigest, QualificationPlanPopulationError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}")
            .map_err(|_| QualificationPlanPopulationError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| QualificationPlanPopulationError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| QualificationPlanPopulationError::EncodingFailure)?,
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

    fn count(&mut self, value: usize) -> Result<(), QualificationPlanPopulationError> {
        let value =
            u64::try_from(value).map_err(|_| QualificationPlanPopulationError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), QualificationPlanPopulationError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), QualificationPlanPopulationError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), QualificationPlanPopulationError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), QualificationPlanPopulationError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(
        &mut self,
        values: &alloc::collections::BTreeSet<Reference>,
    ) -> Result<(), QualificationPlanPopulationError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn purpose(
        &mut self,
        purpose: QualificationPlanPopulationPurpose,
    ) -> Result<(), QualificationPlanPopulationError> {
        self.scalar(match purpose {
            QualificationPlanPopulationPurpose::ExecutionEnvironment => "execution-environment",
            QualificationPlanPopulationPurpose::EvidenceGrader => "evidence-grader",
        })
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
