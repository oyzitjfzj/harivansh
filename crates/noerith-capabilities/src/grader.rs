extern crate alloc;

use crate::{
    manifest::{ContentDigest, OpaqueVersion, Reference},
    qualification::EvidenceStatus,
    regime::SpecialistRegime,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const GRADER_PLAN_CANONICAL_PROFILE: &str = "NOERITH/EVIDENCE-GRADER-PLAN/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0EVIDENCE-GRADER-PLAN\0CANONICAL-2026-09\0";
const GRADER_QUALIFICATION_VERIFICATION_DOMAIN: &[u8] =
    b"NOERITH\0EVIDENCE-GRADER-QUALIFICATION-VERIFICATION\0CANONICAL-2026-09\0";
const GRADE_VERIFICATION_DOMAIN: &[u8] = b"NOERITH\0GRADE-VERIFICATION\0CANONICAL-2026-09\0";
const SHA256_ALGORITHM_REF: &str = "digest:sha-256";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraderIdentity {
    pub grader_ref: Reference,
    pub grader_version: OpaqueVersion,
    pub implementation_ref: Reference,
    pub implementation_version: OpaqueVersion,
    pub configuration_ref: Reference,
    pub configuration_version: OpaqueVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceGraderPlanIdentity {
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub plan_digest: ContentDigest,
}

/// Predeclared grader qualification. It names what the measuring instrument is,
/// what it is allowed to judge, how it was calibrated, and what invalidates the
/// claim. The plan is not itself a pass result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceGraderPlan {
    pub identity: EvidenceGraderPlanIdentity,
    pub grader: GraderIdentity,
    pub rubric_ref: Reference,
    pub rubric_version: OpaqueVersion,
    pub mandatory_criterion_refs: BTreeSet<Reference>,
    pub calibrated_scope_refs: BTreeSet<Reference>,
    pub qualification_requirement_refs: BTreeSet<Reference>,
    pub calibration_corpus_ref: Reference,
    pub heldout_calibration_partition_ref: Reference,
    pub disagreement_policy_ref: Reference,
    pub abstention_policy_ref: Reference,
    pub anti_gaming_policy_ref: Reference,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraderQualificationEvidenceRecord {
    pub evidence_ref: Reference,
    pub grader: GraderIdentity,
    pub plan_identity: EvidenceGraderPlanIdentity,
    pub requirement_ref: Reference,
    pub test_method_ref: Reference,
    pub test_run_ref: Reference,
    pub producer_ref: Reference,
    pub provenance_refs: BTreeSet<Reference>,
    pub observed_result_ref: Reference,
    pub validity_ref: Reference,
    pub status: EvidenceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvidenceGrader {
    identity: EvidenceGraderPlanIdentity,
    grader: GraderIdentity,
    rubric_ref: Reference,
    rubric_version: OpaqueVersion,
    mandatory_criterion_refs: BTreeSet<Reference>,
    calibrated_scope_refs: BTreeSet<Reference>,
    invalidation_dependency_refs: BTreeSet<Reference>,
    qualification_evidence_refs: BTreeSet<Reference>,
    verification_digest: ContentDigest,
}

impl VerifiedEvidenceGrader {
    pub fn identity(&self) -> &EvidenceGraderPlanIdentity {
        &self.identity
    }

    pub fn grader(&self) -> &GraderIdentity {
        &self.grader
    }

    pub fn rubric_ref(&self) -> &Reference {
        &self.rubric_ref
    }

    pub fn rubric_version(&self) -> &OpaqueVersion {
        &self.rubric_version
    }

    pub fn mandatory_criterion_refs(&self) -> &BTreeSet<Reference> {
        &self.mandatory_criterion_refs
    }

    pub fn calibrated_scope_refs(&self) -> &BTreeSet<Reference> {
        &self.calibrated_scope_refs
    }

    pub fn invalidation_dependency_refs(&self) -> &BTreeSet<Reference> {
        &self.invalidation_dependency_refs
    }

    pub fn qualification_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.qualification_evidence_refs
    }

    pub fn verification_digest(&self) -> &ContentDigest {
        &self.verification_digest
    }
}

/// Exact object being graded. The grade cannot be moved to another trial,
/// output, trace, environment or capability-evidence surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradeSubject {
    pub regime: SpecialistRegime,
    pub task_ref: Reference,
    pub trial_ref: Reference,
    pub output_digest: ContentDigest,
    pub trace_ref: Reference,
    pub environment_ref: Reference,
    pub environment_version: OpaqueVersion,
    pub evaluation_scope_refs: BTreeSet<Reference>,
    pub execution_evidence_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradeRequest {
    pub request_ref: Reference,
    pub subject: GradeSubject,
    pub grader_plan_identity: EvidenceGraderPlanIdentity,
    pub mandatory_criterion_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriterionGrade {
    pub criterion_ref: Reference,
    pub status: EvidenceStatus,
    pub evidence_refs: BTreeSet<Reference>,
}

/// Raw attributable result from exactly one grader. Cross-grader aggregation is
/// deliberately outside this record so disagreement cannot be hidden here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradeRecord {
    pub grade_ref: Reference,
    pub request_ref: Reference,
    pub subject: GradeSubject,
    pub grader: GraderIdentity,
    pub grader_plan_identity: EvidenceGraderPlanIdentity,
    pub rubric_ref: Reference,
    pub rubric_version: OpaqueVersion,
    pub criterion_results: Vec<CriterionGrade>,
    pub provenance_refs: BTreeSet<Reference>,
    pub validity_ref: Reference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGradeRecord {
    grade_ref: Reference,
    request_ref: Reference,
    subject: GradeSubject,
    grader: GraderIdentity,
    grader_plan_identity: EvidenceGraderPlanIdentity,
    status: EvidenceStatus,
    criterion_results: BTreeMap<Reference, CriterionGrade>,
    provenance_refs: BTreeSet<Reference>,
    verification_digest: ContentDigest,
}

impl VerifiedGradeRecord {
    pub fn grade_ref(&self) -> &Reference {
        &self.grade_ref
    }

    pub fn request_ref(&self) -> &Reference {
        &self.request_ref
    }

    pub fn subject(&self) -> &GradeSubject {
        &self.subject
    }

    pub fn grader(&self) -> &GraderIdentity {
        &self.grader
    }

    pub fn grader_plan_identity(&self) -> &EvidenceGraderPlanIdentity {
        &self.grader_plan_identity
    }

    pub fn status(&self) -> EvidenceStatus {
        self.status
    }

    pub fn criterion_results(&self) -> &BTreeMap<Reference, CriterionGrade> {
        &self.criterion_results
    }

    pub fn provenance_refs(&self) -> &BTreeSet<Reference> {
        &self.provenance_refs
    }

    pub fn verification_digest(&self) -> &ContentDigest {
        &self.verification_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraderError {
    InvalidPlan,
    CalibrationPartitionCollision,
    UnsupportedDigestAlgorithm(String),
    PlanDigestMismatch,
    EncodingFailure,
    EvidencePlanMismatch(String),
    EvidenceGraderMismatch(String),
    UnexpectedQualificationRequirement(String),
    DuplicateQualificationRequirement(String),
    DuplicateQualificationEvidence(String),
    IncompleteQualificationEvidence,
    QualificationEvidenceMissingProvenance(String),
    QualificationRequirementFailed(String),
    QualificationRequirementIndeterminate(String),
    InvalidGradeRequest,
    GradeOutsideCalibratedScope,
    GradeRequestMismatch,
    GradeSubjectMismatch,
    GradePlanMismatch,
    GradeGraderMismatch,
    GradeRubricMismatch,
    DuplicateCriterion(String),
    UnexpectedCriterion(String),
    IncompleteCriterionCoverage,
    CriterionEvidenceMissing(String),
    GradeProvenanceMissing,
}

impl fmt::Display for GraderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "evidence grader rejected: {self:?}")
    }
}

pub fn compute_evidence_grader_plan_digest(
    plan: &EvidenceGraderPlan,
) -> Result<ContentDigest, GraderError> {
    validate_plan_shape(plan)?;
    let transcript = canonical_grader_plan_transcript(plan)?;
    let digest = Sha256::digest(&transcript);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| GraderError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| GraderError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| GraderError::EncodingFailure)?,
    })
}

pub fn canonical_grader_plan_transcript(plan: &EvidenceGraderPlan) -> Result<Vec<u8>, GraderError> {
    validate_plan_shape(plan)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&plan.identity.plan_ref)?;
    encoder.version(&plan.identity.plan_version)?;
    encoder.grader(&plan.grader)?;
    encoder.reference(&plan.rubric_ref)?;
    encoder.version(&plan.rubric_version)?;
    encoder.ref_set(&plan.mandatory_criterion_refs)?;
    encoder.ref_set(&plan.calibrated_scope_refs)?;
    encoder.ref_set(&plan.qualification_requirement_refs)?;
    encoder.reference(&plan.calibration_corpus_ref)?;
    encoder.reference(&plan.heldout_calibration_partition_ref)?;
    encoder.reference(&plan.disagreement_policy_ref)?;
    encoder.reference(&plan.abstention_policy_ref)?;
    encoder.reference(&plan.anti_gaming_policy_ref)?;
    encoder.ref_set(&plan.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

pub fn qualify_evidence_grader(
    plan: &EvidenceGraderPlan,
    evidence: &[GraderQualificationEvidenceRecord],
) -> Result<VerifiedEvidenceGrader, GraderError> {
    verify_plan_integrity(plan)?;

    let mut by_requirement = BTreeMap::<Reference, &GraderQualificationEvidenceRecord>::new();
    let mut evidence_refs = BTreeSet::new();

    for record in evidence {
        if record.plan_identity != plan.identity {
            return Err(GraderError::EvidencePlanMismatch(
                record.evidence_ref.to_string(),
            ));
        }
        if record.grader != plan.grader {
            return Err(GraderError::EvidenceGraderMismatch(
                record.evidence_ref.to_string(),
            ));
        }
        if !plan
            .qualification_requirement_refs
            .contains(&record.requirement_ref)
        {
            return Err(GraderError::UnexpectedQualificationRequirement(
                record.requirement_ref.to_string(),
            ));
        }
        if record.provenance_refs.is_empty() {
            return Err(GraderError::QualificationEvidenceMissingProvenance(
                record.evidence_ref.to_string(),
            ));
        }
        if !evidence_refs.insert(record.evidence_ref.clone()) {
            return Err(GraderError::DuplicateQualificationEvidence(
                record.evidence_ref.to_string(),
            ));
        }
        if by_requirement
            .insert(record.requirement_ref.clone(), record)
            .is_some()
        {
            return Err(GraderError::DuplicateQualificationRequirement(
                record.requirement_ref.to_string(),
            ));
        }
    }

    let covered: BTreeSet<Reference> = by_requirement.keys().cloned().collect();
    if covered != plan.qualification_requirement_refs {
        return Err(GraderError::IncompleteQualificationEvidence);
    }

    for requirement in &plan.qualification_requirement_refs {
        let record = by_requirement
            .get(requirement)
            .ok_or(GraderError::IncompleteQualificationEvidence)?;
        match record.status {
            EvidenceStatus::Pass => {}
            EvidenceStatus::Fail => {
                return Err(GraderError::QualificationRequirementFailed(
                    requirement.to_string(),
                ));
            }
            EvidenceStatus::Indeterminate => {
                return Err(GraderError::QualificationRequirementIndeterminate(
                    requirement.to_string(),
                ));
            }
        }
    }

    let verification_digest =
        compute_grader_qualification_verification_digest(plan, &by_requirement)?;

    Ok(VerifiedEvidenceGrader {
        identity: plan.identity.clone(),
        grader: plan.grader.clone(),
        rubric_ref: plan.rubric_ref.clone(),
        rubric_version: plan.rubric_version.clone(),
        mandatory_criterion_refs: plan.mandatory_criterion_refs.clone(),
        calibrated_scope_refs: plan.calibrated_scope_refs.clone(),
        invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
        qualification_evidence_refs: evidence_refs,
        verification_digest,
    })
}

pub fn verify_grade_record(
    grader: &VerifiedEvidenceGrader,
    request: &GradeRequest,
    record: &GradeRecord,
) -> Result<VerifiedGradeRecord, GraderError> {
    validate_grade_request(grader, request)?;

    if record.request_ref != request.request_ref {
        return Err(GraderError::GradeRequestMismatch);
    }
    if record.subject != request.subject {
        return Err(GraderError::GradeSubjectMismatch);
    }
    if record.grader_plan_identity != *grader.identity()
        || record.grader_plan_identity != request.grader_plan_identity
    {
        return Err(GraderError::GradePlanMismatch);
    }
    if record.grader != *grader.grader() {
        return Err(GraderError::GradeGraderMismatch);
    }
    if record.rubric_ref != *grader.rubric_ref()
        || record.rubric_version != *grader.rubric_version()
    {
        return Err(GraderError::GradeRubricMismatch);
    }
    if record.provenance_refs.is_empty() {
        return Err(GraderError::GradeProvenanceMissing);
    }

    let mut criteria = BTreeMap::new();
    let mut has_fail = false;
    let mut has_indeterminate = false;
    for result in &record.criterion_results {
        if !request
            .mandatory_criterion_refs
            .contains(&result.criterion_ref)
        {
            return Err(GraderError::UnexpectedCriterion(
                result.criterion_ref.to_string(),
            ));
        }
        if result.evidence_refs.is_empty() {
            return Err(GraderError::CriterionEvidenceMissing(
                result.criterion_ref.to_string(),
            ));
        }
        if criteria
            .insert(result.criterion_ref.clone(), result.clone())
            .is_some()
        {
            return Err(GraderError::DuplicateCriterion(
                result.criterion_ref.to_string(),
            ));
        }
        match result.status {
            EvidenceStatus::Pass => {}
            EvidenceStatus::Fail => has_fail = true,
            EvidenceStatus::Indeterminate => has_indeterminate = true,
        }
    }

    let covered: BTreeSet<Reference> = criteria.keys().cloned().collect();
    if covered != request.mandatory_criterion_refs {
        return Err(GraderError::IncompleteCriterionCoverage);
    }

    let status = if has_fail {
        EvidenceStatus::Fail
    } else if has_indeterminate {
        EvidenceStatus::Indeterminate
    } else {
        EvidenceStatus::Pass
    };
    let verification_digest = compute_grade_verification_digest(grader, record, &criteria, status)?;

    Ok(VerifiedGradeRecord {
        grade_ref: record.grade_ref.clone(),
        request_ref: record.request_ref.clone(),
        subject: record.subject.clone(),
        grader: record.grader.clone(),
        grader_plan_identity: record.grader_plan_identity.clone(),
        status,
        criterion_results: criteria,
        provenance_refs: record.provenance_refs.clone(),
        verification_digest,
    })
}

fn compute_grader_qualification_verification_digest(
    plan: &EvidenceGraderPlan,
    evidence_by_requirement: &BTreeMap<Reference, &GraderQualificationEvidenceRecord>,
) -> Result<ContentDigest, GraderError> {
    let mut encoder = Encoder::new();
    encoder.raw(GRADER_QUALIFICATION_VERIFICATION_DOMAIN);
    encoder.grader_plan_identity(&plan.identity)?;
    encoder.grader(&plan.grader)?;
    encoder.reference(&plan.rubric_ref)?;
    encoder.version(&plan.rubric_version)?;
    encoder.ref_set(&plan.mandatory_criterion_refs)?;
    encoder.ref_set(&plan.calibrated_scope_refs)?;
    encoder.ref_set(&plan.invalidation_dependency_refs)?;
    encoder.count(evidence_by_requirement.len())?;
    for record in evidence_by_requirement.values() {
        encoder.grader_qualification_record(record)?;
    }
    digest_bytes(&encoder.finish())
}

fn compute_grade_verification_digest(
    grader: &VerifiedEvidenceGrader,
    record: &GradeRecord,
    criteria: &BTreeMap<Reference, CriterionGrade>,
    status: EvidenceStatus,
) -> Result<ContentDigest, GraderError> {
    let mut encoder = Encoder::new();
    encoder.raw(GRADE_VERIFICATION_DOMAIN);
    encoder.reference(&record.grade_ref)?;
    encoder.reference(&record.request_ref)?;
    encoder.grade_subject(&record.subject)?;
    encoder.grader(&record.grader)?;
    encoder.grader_plan_identity(&record.grader_plan_identity)?;
    encoder.reference(&record.rubric_ref)?;
    encoder.version(&record.rubric_version)?;
    encoder.count(criteria.len())?;
    for criterion in criteria.values() {
        encoder.criterion_grade(criterion)?;
    }
    encoder.ref_set(&record.provenance_refs)?;
    encoder.reference(&record.validity_ref)?;
    encoder.digest(grader.verification_digest())?;
    encoder.evidence_status(status)?;
    digest_bytes(&encoder.finish())
}

fn digest_bytes(bytes: &[u8]) -> Result<ContentDigest, GraderError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| GraderError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| GraderError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| GraderError::EncodingFailure)?,
    })
}

fn validate_plan_shape(plan: &EvidenceGraderPlan) -> Result<(), GraderError> {
    if plan.mandatory_criterion_refs.is_empty()
        || plan.calibrated_scope_refs.is_empty()
        || plan.qualification_requirement_refs.is_empty()
        || plan.invalidation_dependency_refs.is_empty()
    {
        return Err(GraderError::InvalidPlan);
    }
    if plan.calibration_corpus_ref == plan.heldout_calibration_partition_ref {
        return Err(GraderError::CalibrationPartitionCollision);
    }
    Ok(())
}

fn verify_plan_integrity(plan: &EvidenceGraderPlan) -> Result<(), GraderError> {
    validate_plan_shape(plan)?;
    if plan.identity.plan_digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(GraderError::UnsupportedDigestAlgorithm(
            plan.identity.plan_digest.algorithm_ref.to_string(),
        ));
    }
    if compute_evidence_grader_plan_digest(plan)? != plan.identity.plan_digest {
        return Err(GraderError::PlanDigestMismatch);
    }
    Ok(())
}

fn validate_grade_request(
    grader: &VerifiedEvidenceGrader,
    request: &GradeRequest,
) -> Result<(), GraderError> {
    if request.grader_plan_identity != *grader.identity()
        || request.mandatory_criterion_refs != *grader.mandatory_criterion_refs()
        || request.subject.evaluation_scope_refs.is_empty()
        || request.subject.execution_evidence_refs.is_empty()
    {
        return Err(GraderError::InvalidGradeRequest);
    }
    if !request
        .subject
        .evaluation_scope_refs
        .is_subset(grader.calibrated_scope_refs())
    {
        return Err(GraderError::GradeOutsideCalibratedScope);
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

    fn count(&mut self, value: usize) -> Result<(), GraderError> {
        let value = u64::try_from(value).map_err(|_| GraderError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), GraderError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), GraderError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), GraderError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), GraderError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), GraderError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn grader(&mut self, grader: &GraderIdentity) -> Result<(), GraderError> {
        self.reference(&grader.grader_ref)?;
        self.version(&grader.grader_version)?;
        self.reference(&grader.implementation_ref)?;
        self.version(&grader.implementation_version)?;
        self.reference(&grader.configuration_ref)?;
        self.version(&grader.configuration_version)
    }

    fn grader_plan_identity(
        &mut self,
        identity: &EvidenceGraderPlanIdentity,
    ) -> Result<(), GraderError> {
        self.reference(&identity.plan_ref)?;
        self.version(&identity.plan_version)?;
        self.digest(&identity.plan_digest)
    }

    fn evidence_status(&mut self, value: EvidenceStatus) -> Result<(), GraderError> {
        self.scalar(match value {
            EvidenceStatus::Pass => "pass",
            EvidenceStatus::Fail => "fail",
            EvidenceStatus::Indeterminate => "indeterminate",
        })
    }

    fn regime(&mut self, value: SpecialistRegime) -> Result<(), GraderError> {
        self.scalar(match value {
            SpecialistRegime::ConversationPersonalAssistant => "conversation-personal-assistant",
            SpecialistRegime::ResearchDeepResearch => "research-deep-research",
            SpecialistRegime::SoftwareEngineering => "software-engineering",
            SpecialistRegime::ActionAutomation => "action-automation",
            SpecialistRegime::CreationArtifact => "creation-artifact",
            SpecialistRegime::MonitoringLongRunningWork => "monitoring-long-running-work",
        })
    }

    fn grade_subject(&mut self, subject: &GradeSubject) -> Result<(), GraderError> {
        self.regime(subject.regime)?;
        self.reference(&subject.task_ref)?;
        self.reference(&subject.trial_ref)?;
        self.digest(&subject.output_digest)?;
        self.reference(&subject.trace_ref)?;
        self.reference(&subject.environment_ref)?;
        self.version(&subject.environment_version)?;
        self.ref_set(&subject.evaluation_scope_refs)?;
        self.ref_set(&subject.execution_evidence_refs)
    }

    fn grader_qualification_record(
        &mut self,
        record: &GraderQualificationEvidenceRecord,
    ) -> Result<(), GraderError> {
        self.reference(&record.evidence_ref)?;
        self.grader(&record.grader)?;
        self.grader_plan_identity(&record.plan_identity)?;
        self.reference(&record.requirement_ref)?;
        self.reference(&record.test_method_ref)?;
        self.reference(&record.test_run_ref)?;
        self.reference(&record.producer_ref)?;
        self.ref_set(&record.provenance_refs)?;
        self.reference(&record.observed_result_ref)?;
        self.reference(&record.validity_ref)?;
        self.evidence_status(record.status)
    }

    fn criterion_grade(&mut self, criterion: &CriterionGrade) -> Result<(), GraderError> {
        self.reference(&criterion.criterion_ref)?;
        self.evidence_status(criterion.status)?;
        self.ref_set(&criterion.evidence_refs)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
