extern crate alloc;

use crate::{
    catalog::VerifiedCapabilityCatalog,
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    qualification::{QualificationPlanIdentity, QualificationSubject},
    regime::{RegimeCapabilityRequirement, SixRegimeQualificationPlan, SpecialistRegime},
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

pub const REGIME_CAPABILITY_BINDING_CANONICAL_PROFILE: &str =
    "NOERITH/REGIME-CAPABILITY-BINDING/CANONICAL-2026-09-V2";
const DOMAIN: &[u8] = b"NOERITH\0REGIME-CAPABILITY-BINDING\0CANONICAL-2026-09-V2\0";

/// Content-bound evidence that one exact qualified capability subject is a
/// candidate satisfying one preregistered regime capability requirement. This
/// record is conformance evidence only; it grants no runtime dispatch or effect
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegimeCapabilityBindingRecord {
    pub binding_ref: Reference,
    pub binding_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub regime: SpecialistRegime,
    pub pipeline_ref: Reference,
    pub pipeline_version: OpaqueVersion,
    pub pipeline_digest: ContentDigest,
    pub requirement_ref: Reference,
    pub subject: QualificationSubject,
    pub qualification_plan_identity: QualificationPlanIdentity,
    pub qualification_evidence_refs: BTreeSet<Reference>,
    pub qualification_validity_requirement_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegimeCapabilityConformance {
    regime: SpecialistRegime,
    pipeline_ref: Reference,
    pipeline_version: OpaqueVersion,
    pipeline_digest: ContentDigest,
    subjects_by_requirement: BTreeMap<Reference, Vec<QualificationSubject>>,
    binding_evidence_refs: BTreeSet<Reference>,
    canonical_profile_ref: &'static str,
}

impl VerifiedRegimeCapabilityConformance {
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

    pub fn subjects_for(&self, requirement_ref: &Reference) -> Option<&[QualificationSubject]> {
        self.subjects_by_requirement
            .get(requirement_ref)
            .map(Vec::as_slice)
    }

    pub fn requirement_count(&self) -> usize {
        self.subjects_by_requirement.len()
    }

    pub fn binding_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.binding_evidence_refs
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegimeCapabilityError {
    Plan(crate::regime::RegimePlanError),
    VerifiedPlanMismatch,
    MissingRegime(SpecialistRegime),
    EmptyBindings,
    UnsupportedDigestAlgorithm(String),
    BindingDigestMismatch(String),
    BindingShapeInvalid(String),
    BindingPipelineMismatch(String),
    UnexpectedRequirement(String),
    DuplicateBinding(String),
    BindingIdentityCollision {
        binding_ref: String,
        binding_version: String,
    },
    DuplicateSubjectForRequirement {
        requirement_ref: String,
        capability_ref: String,
    },
    UnknownCapabilitySubject(String),
    UnqualifiedCapabilitySubject(String),
    QualificationSubjectMismatch(String),
    QualificationPlanMismatch(String),
    QualificationEvidenceMismatch(String),
    QualificationValidityMismatch(String),
    QualificationMissingOperation {
        requirement_ref: String,
        operation_ref: String,
    },
    MissingQualificationInvalidationDependency {
        capability_ref: String,
        dependency_ref: String,
    },
    MissingRequirementBinding(String),
    EncodingFailure,
}

impl fmt::Display for RegimeCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "regime capability conformance rejected: {self:?}"
        )
    }
}

pub fn compute_regime_capability_binding_digest(
    record: &RegimeCapabilityBindingRecord,
) -> Result<ContentDigest, RegimeCapabilityError> {
    let transcript = canonical_regime_capability_binding_transcript(record)?;
    sha256_digest(&transcript)
}

pub fn canonical_regime_capability_binding_transcript(
    record: &RegimeCapabilityBindingRecord,
) -> Result<Vec<u8>, RegimeCapabilityError> {
    validate_binding_shape(record)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&record.binding_ref)?;
    encoder.version(&record.binding_version)?;
    encoder.regime(record.regime)?;
    encoder.reference(&record.pipeline_ref)?;
    encoder.version(&record.pipeline_version)?;
    encoder.digest(&record.pipeline_digest)?;
    encoder.reference(&record.requirement_ref)?;
    encoder.qualification_subject(&record.subject)?;
    encoder.qualification_plan_identity(&record.qualification_plan_identity)?;
    encoder.ref_set(&record.qualification_evidence_refs)?;
    encoder.ref_set(&record.qualification_validity_requirement_refs)?;
    encoder.ref_set(&record.provenance_refs)?;
    encoder.ref_set(&record.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

pub fn verify_regime_capability_conformance(
    plan: &SixRegimeQualificationPlan,
    verified_plan: &VerifiedSixRegimeQualificationPlan,
    regime: SpecialistRegime,
    catalog: &VerifiedCapabilityCatalog,
    bindings: &[RegimeCapabilityBindingRecord],
) -> Result<VerifiedRegimeCapabilityConformance, RegimeCapabilityError> {
    let current_plan =
        verify_six_regime_qualification_plan(plan).map_err(RegimeCapabilityError::Plan)?;
    if &current_plan != verified_plan {
        return Err(RegimeCapabilityError::VerifiedPlanMismatch);
    }
    let pipeline = plan
        .pipelines
        .iter()
        .find(|pipeline| pipeline.regime == regime)
        .ok_or(RegimeCapabilityError::MissingRegime(regime))?;
    if bindings.is_empty() {
        return Err(RegimeCapabilityError::EmptyBindings);
    }

    let requirements: BTreeMap<&Reference, &RegimeCapabilityRequirement> = pipeline
        .required_capabilities
        .iter()
        .map(|requirement| (&requirement.requirement_ref, requirement))
        .collect();

    let mut binding_identities = BTreeMap::<(Reference, OpaqueVersion), ContentDigest>::new();
    let mut subject_keys = BTreeSet::<String>::new();
    let mut subjects_by_requirement = BTreeMap::<Reference, Vec<QualificationSubject>>::new();
    let mut binding_evidence_refs = BTreeSet::new();

    for binding in bindings {
        verify_binding_integrity(binding)?;
        verify_pipeline_binding(pipeline, binding)?;

        let Some(requirement) = requirements.get(&binding.requirement_ref) else {
            return Err(RegimeCapabilityError::UnexpectedRequirement(
                binding.requirement_ref.to_string(),
            ));
        };

        let binding_key = (binding.binding_ref.clone(), binding.binding_version.clone());
        if let Some(existing_digest) = binding_identities.get(&binding_key) {
            if existing_digest == &binding.content_digest {
                return Err(RegimeCapabilityError::DuplicateBinding(
                    binding.binding_ref.to_string(),
                ));
            }
            return Err(RegimeCapabilityError::BindingIdentityCollision {
                binding_ref: binding.binding_ref.to_string(),
                binding_version: binding.binding_version.as_str().to_string(),
            });
        }
        binding_identities.insert(binding_key, binding.content_digest.clone());
        if !binding_evidence_refs.insert(binding.content_digest.value.clone()) {
            return Err(RegimeCapabilityError::DuplicateBinding(
                binding.binding_ref.to_string(),
            ));
        }

        let subject_key = alloc::format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            binding.requirement_ref,
            binding.subject.capability_ref,
            binding.subject.capability_version.as_str(),
            binding.subject.manifest_digest.algorithm_ref,
            binding.subject.manifest_digest.value,
            binding.subject.adapter_ref,
            binding.subject.adapter_version.as_str(),
            binding.subject.environment_ref,
            binding.subject.environment_version.as_str(),
            binding.subject.environment_digest.algorithm_ref,
            binding.subject.environment_digest.value,
        );
        if !subject_keys.insert(subject_key) {
            return Err(RegimeCapabilityError::DuplicateSubjectForRequirement {
                requirement_ref: binding.requirement_ref.to_string(),
                capability_ref: binding.subject.capability_ref.to_string(),
            });
        }

        let entry = catalog
            .lookup_exact(
                &binding.subject.capability_ref,
                &binding.subject.capability_version,
                &binding.subject.manifest_digest,
            )
            .ok_or_else(|| {
                RegimeCapabilityError::UnknownCapabilitySubject(
                    binding.subject.capability_ref.to_string(),
                )
            })?;
        if entry.qualifications.is_empty() {
            return Err(RegimeCapabilityError::UnqualifiedCapabilitySubject(
                binding.subject.capability_ref.to_string(),
            ));
        }
        let qualification = match catalog
            .lookup_exact_qualification(&binding.subject, &binding.qualification_plan_identity)
        {
            Some(qualification) => qualification,
            None if entry
                .qualifications
                .iter()
                .any(|qualification| qualification.subject() == &binding.subject) =>
            {
                return Err(RegimeCapabilityError::QualificationPlanMismatch(
                    binding.subject.capability_ref.to_string(),
                ));
            }
            None => {
                return Err(RegimeCapabilityError::QualificationSubjectMismatch(
                    binding.subject.capability_ref.to_string(),
                ));
            }
        };
        if qualification.evidence_refs() != &binding.qualification_evidence_refs {
            return Err(RegimeCapabilityError::QualificationEvidenceMismatch(
                binding.subject.capability_ref.to_string(),
            ));
        }
        if qualification.validity_requirement_refs()
            != &binding.qualification_validity_requirement_refs
        {
            return Err(RegimeCapabilityError::QualificationValidityMismatch(
                binding.subject.capability_ref.to_string(),
            ));
        }
        for operation_ref in &requirement.required_operation_refs {
            if !qualification.operation_refs().contains(operation_ref) {
                return Err(RegimeCapabilityError::QualificationMissingOperation {
                    requirement_ref: binding.requirement_ref.to_string(),
                    operation_ref: operation_ref.to_string(),
                });
            }
        }
        for dependency_ref in qualification.invalidation_dependency_refs() {
            if !binding
                .invalidation_dependency_refs
                .contains(dependency_ref)
            {
                return Err(
                    RegimeCapabilityError::MissingQualificationInvalidationDependency {
                        capability_ref: binding.subject.capability_ref.to_string(),
                        dependency_ref: dependency_ref.to_string(),
                    },
                );
            }
        }

        subjects_by_requirement
            .entry(binding.requirement_ref.clone())
            .or_default()
            .push(binding.subject.clone());
    }

    for requirement in &pipeline.required_capabilities {
        if !subjects_by_requirement.contains_key(&requirement.requirement_ref) {
            return Err(RegimeCapabilityError::MissingRequirementBinding(
                requirement.requirement_ref.to_string(),
            ));
        }
    }

    for subjects in subjects_by_requirement.values_mut() {
        subjects.sort_by(|left, right| {
            (
                left.capability_ref.as_str(),
                left.capability_version.as_str(),
                left.manifest_digest.value.as_str(),
                left.adapter_ref.as_str(),
                left.adapter_version.as_str(),
                left.environment_ref.as_str(),
                left.environment_version.as_str(),
                left.environment_digest.algorithm_ref.as_str(),
                left.environment_digest.value.as_str(),
            )
                .cmp(&(
                    right.capability_ref.as_str(),
                    right.capability_version.as_str(),
                    right.manifest_digest.value.as_str(),
                    right.adapter_ref.as_str(),
                    right.adapter_version.as_str(),
                    right.environment_ref.as_str(),
                    right.environment_version.as_str(),
                    right.environment_digest.algorithm_ref.as_str(),
                    right.environment_digest.value.as_str(),
                ))
        });
    }

    Ok(VerifiedRegimeCapabilityConformance {
        regime,
        pipeline_ref: pipeline.pipeline_ref.clone(),
        pipeline_version: pipeline.pipeline_version.clone(),
        pipeline_digest: pipeline.content_digest.clone(),
        subjects_by_requirement,
        binding_evidence_refs,
        canonical_profile_ref: REGIME_CAPABILITY_BINDING_CANONICAL_PROFILE,
    })
}

fn verify_binding_integrity(
    binding: &RegimeCapabilityBindingRecord,
) -> Result<(), RegimeCapabilityError> {
    require_sha256(&binding.content_digest)?;
    let computed = compute_regime_capability_binding_digest(binding)?;
    if computed != binding.content_digest {
        return Err(RegimeCapabilityError::BindingDigestMismatch(
            binding.binding_ref.to_string(),
        ));
    }
    Ok(())
}

fn verify_pipeline_binding(
    pipeline: &crate::regime::RegimePipelinePlan,
    binding: &RegimeCapabilityBindingRecord,
) -> Result<(), RegimeCapabilityError> {
    if binding.regime != pipeline.regime
        || binding.pipeline_ref != pipeline.pipeline_ref
        || binding.pipeline_version != pipeline.pipeline_version
        || binding.pipeline_digest != pipeline.content_digest
    {
        return Err(RegimeCapabilityError::BindingPipelineMismatch(
            binding.binding_ref.to_string(),
        ));
    }
    Ok(())
}

fn validate_binding_shape(
    binding: &RegimeCapabilityBindingRecord,
) -> Result<(), RegimeCapabilityError> {
    if binding.qualification_evidence_refs.is_empty()
        || binding.qualification_validity_requirement_refs.is_empty()
        || binding.provenance_refs.is_empty()
        || binding.invalidation_dependency_refs.is_empty()
    {
        return Err(RegimeCapabilityError::BindingShapeInvalid(
            binding.binding_ref.to_string(),
        ));
    }
    Ok(())
}

fn require_sha256(digest: &ContentDigest) -> Result<(), RegimeCapabilityError> {
    if digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(RegimeCapabilityError::UnsupportedDigestAlgorithm(
            digest.algorithm_ref.to_string(),
        ));
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> Result<ContentDigest, RegimeCapabilityError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| RegimeCapabilityError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| RegimeCapabilityError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| RegimeCapabilityError::EncodingFailure)?,
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

    fn count(&mut self, value: usize) -> Result<(), RegimeCapabilityError> {
        let value = u64::try_from(value).map_err(|_| RegimeCapabilityError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), RegimeCapabilityError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), RegimeCapabilityError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), RegimeCapabilityError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), RegimeCapabilityError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), RegimeCapabilityError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn qualification_subject(
        &mut self,
        subject: &QualificationSubject,
    ) -> Result<(), RegimeCapabilityError> {
        self.reference(&subject.capability_ref)?;
        self.version(&subject.capability_version)?;
        self.digest(&subject.manifest_digest)?;
        self.reference(&subject.artifact_ref)?;
        self.reference(&subject.adapter_ref)?;
        self.version(&subject.adapter_version)?;
        self.reference(&subject.environment_ref)?;
        self.version(&subject.environment_version)?;
        self.digest(&subject.environment_digest)
    }

    fn qualification_plan_identity(
        &mut self,
        identity: &QualificationPlanIdentity,
    ) -> Result<(), RegimeCapabilityError> {
        self.reference(&identity.plan_ref)?;
        self.version(&identity.plan_version)?;
        self.digest(&identity.plan_digest)
    }

    fn regime(&mut self, regime: SpecialistRegime) -> Result<(), RegimeCapabilityError> {
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
