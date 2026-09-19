extern crate alloc;

use crate::{
    evaluation_corpus::{EvaluationPartition, VerifiedEvaluationCorpus},
    execution_environment::VerifiedExecutionEnvironment,
    grader::VerifiedGradeRecord,
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    quality_floor::{
        QualityFloorError, QualityFloorPlan, QualityGateCoverage, QualityGateId,
        VerifiedQualityFloorPlan, verify_quality_floor_plan,
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

pub const QUALITY_TRIAL_SET_CANONICAL_PROFILE: &str = "NOERITH/QUALITY-TRIAL-SET/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0QUALITY-TRIAL-SET\0CANONICAL-2026-09\0";
const QUALITY_TRIAL_VERIFICATION_DOMAIN: &[u8] =
    b"NOERITH\0QUALITY-TRIAL-EVIDENCE-COMPOSITION\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityTrialRecord {
    pub trial_ref: Reference,
    pub corpus_ref: Reference,
    pub corpus_version: OpaqueVersion,
    pub corpus_digest: ContentDigest,
    pub task_ref: Reference,
    pub task_version: OpaqueVersion,
    pub task_digest: ContentDigest,
    pub regime: SpecialistRegime,
    pub partition: EvaluationPartition,
    pub candidate_configuration_ref: Reference,
    pub candidate_configuration_version: OpaqueVersion,
    pub candidate_configuration_digest: ContentDigest,
    pub model_ref: Reference,
    pub model_version: OpaqueVersion,
    pub provider_ref: Reference,
    pub adapter_ref: Reference,
    pub adapter_version: OpaqueVersion,
    pub environment_ref: Reference,
    pub environment_version: OpaqueVersion,
    pub environment_digest: ContentDigest,
    pub seed_ref: Reference,
    pub input_digest: ContentDigest,
    pub output_digest: ContentDigest,
    pub trace_ref: Reference,
    pub execution_evidence_refs: BTreeSet<Reference>,
    pub grader_result_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityTrialSet {
    pub trial_set_ref: Reference,
    pub trial_set_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub plan_digest: ContentDigest,
    pub gate: QualityGateId,
    pub trial_protocol_ref: Reference,
    pub seed_manifest_ref: Reference,
    pub hardware_manifest_ref: Reference,
    pub candidate_configuration_manifest_ref: Option<Reference>,
    pub preregistration_evidence_ref: Reference,
    pub trials: Vec<QualityTrialRecord>,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

/// Exact verified owner evidence required to admit a trial set. The wrapper
/// borrows already-verified corpus, grader and execution-environment objects so
/// this layer cannot manufacture qualification by restating raw identifiers.
#[derive(Debug, Clone, Copy)]
pub struct QualityTrialVerificationEvidence<'a> {
    pub corpora: &'a [VerifiedEvaluationCorpus],
    pub grades: &'a [VerifiedGradeRecord],
    pub environments: &'a [VerifiedExecutionEnvironment],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExactCorpusEvidenceIdentity {
    corpus_ref: Reference,
    corpus_version: OpaqueVersion,
    digest_algorithm_ref: Reference,
    digest_value_ref: Reference,
}

impl ExactCorpusEvidenceIdentity {
    pub(crate) fn from_verified(corpus: &VerifiedEvaluationCorpus) -> Self {
        Self {
            corpus_ref: corpus.corpus_ref().clone(),
            corpus_version: corpus.corpus_version().clone(),
            digest_algorithm_ref: corpus.content_digest().algorithm_ref.clone(),
            digest_value_ref: corpus.content_digest().value.clone(),
        }
    }

    pub(crate) fn logical_key(&self) -> (Reference, OpaqueVersion) {
        (self.corpus_ref.clone(), self.corpus_version.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExactGradeEvidenceIdentity {
    grade_ref: Reference,
    verification_algorithm_ref: Reference,
    verification_value_ref: Reference,
}

impl ExactGradeEvidenceIdentity {
    pub(crate) fn from_verified(grade: &VerifiedGradeRecord) -> Self {
        Self {
            grade_ref: grade.grade_ref().clone(),
            verification_algorithm_ref: grade.verification_digest().algorithm_ref.clone(),
            verification_value_ref: grade.verification_digest().value.clone(),
        }
    }

}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExactEnvironmentEvidenceIdentity {
    environment_ref: Reference,
    environment_version: OpaqueVersion,
    profile_digest_algorithm_ref: Reference,
    profile_digest_value_ref: Reference,
    verification_algorithm_ref: Reference,
    verification_value_ref: Reference,
}

impl ExactEnvironmentEvidenceIdentity {
    pub(crate) fn from_verified(environment: &VerifiedExecutionEnvironment) -> Self {
        let subject = environment.subject();
        Self {
            environment_ref: subject.environment_ref.clone(),
            environment_version: subject.environment_version.clone(),
            profile_digest_algorithm_ref: subject.content_digest.algorithm_ref.clone(),
            profile_digest_value_ref: subject.content_digest.value.clone(),
            verification_algorithm_ref: environment.verification_digest().algorithm_ref.clone(),
            verification_value_ref: environment.verification_digest().value.clone(),
        }
    }

    pub(crate) fn logical_key(&self) -> (Reference, OpaqueVersion) {
        (
            self.environment_ref.clone(),
            self.environment_version.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExecutionIdentity {
    task_ref: Reference,
    seed_ref: Reference,
    input_digest_algorithm_ref: Reference,
    input_digest_value_ref: Reference,
    candidate_configuration_ref: Reference,
    candidate_configuration_version: OpaqueVersion,
    candidate_digest_algorithm_ref: Reference,
    candidate_digest_value_ref: Reference,
}

impl ExecutionIdentity {
    pub(crate) fn from_trial(trial: &QualityTrialRecord) -> Self {
        Self {
            task_ref: trial.task_ref.clone(),
            seed_ref: trial.seed_ref.clone(),
            input_digest_algorithm_ref: trial.input_digest.algorithm_ref.clone(),
            input_digest_value_ref: trial.input_digest.value.clone(),
            candidate_configuration_ref: trial.candidate_configuration_ref.clone(),
            candidate_configuration_version: trial.candidate_configuration_version.clone(),
            candidate_digest_algorithm_ref: trial.candidate_configuration_digest.algorithm_ref.clone(),
            candidate_digest_value_ref: trial.candidate_configuration_digest.value.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQualityTrialSet {
    trial_set_ref: Reference,
    trial_set_version: OpaqueVersion,
    content_digest: ContentDigest,
    plan_ref: Reference,
    plan_version: OpaqueVersion,
    plan_digest: ContentDigest,
    gate: QualityGateId,
    trial_refs: BTreeSet<Reference>,
    execution_identities: BTreeSet<ExecutionIdentity>,
    corpus_refs: BTreeSet<Reference>,
    exact_corpus_identities: BTreeSet<ExactCorpusEvidenceIdentity>,
    grade_refs: BTreeSet<Reference>,
    exact_grade_identities: BTreeSet<ExactGradeEvidenceIdentity>,
    environment_refs: BTreeSet<Reference>,
    exact_environment_identities: BTreeSet<ExactEnvironmentEvidenceIdentity>,
    regimes: BTreeSet<SpecialistRegime>,
    verification_digest: ContentDigest,
    canonical_profile_ref: &'static str,
}

impl VerifiedQualityTrialSet {
    pub fn trial_set_ref(&self) -> &Reference {
        &self.trial_set_ref
    }

    pub fn trial_set_version(&self) -> &OpaqueVersion {
        &self.trial_set_version
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

    pub fn trial_refs(&self) -> &BTreeSet<Reference> {
        &self.trial_refs
    }

    pub(crate) fn execution_identities(&self) -> &BTreeSet<ExecutionIdentity> {
        &self.execution_identities
    }

    pub fn corpus_refs(&self) -> &BTreeSet<Reference> {
        &self.corpus_refs
    }

    pub(crate) fn exact_corpus_identities(&self) -> &BTreeSet<ExactCorpusEvidenceIdentity> {
        &self.exact_corpus_identities
    }

    pub fn grade_refs(&self) -> &BTreeSet<Reference> {
        &self.grade_refs
    }

    pub(crate) fn exact_grade_identities(&self) -> &BTreeSet<ExactGradeEvidenceIdentity> {
        &self.exact_grade_identities
    }

    pub fn environment_refs(&self) -> &BTreeSet<Reference> {
        &self.environment_refs
    }

    pub(crate) fn exact_environment_identities(
        &self,
    ) -> &BTreeSet<ExactEnvironmentEvidenceIdentity> {
        &self.exact_environment_identities
    }

    pub fn regimes(&self) -> &BTreeSet<SpecialistRegime> {
        &self.regimes
    }

    pub fn verification_digest(&self) -> &ContentDigest {
        &self.verification_digest
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityTrialError {
    FloorPlan(QualityFloorError),
    VerifiedPlanMismatch,
    PlanBindingMismatch,
    ProtocolBindingMismatch,
    CandidateConfigurationManifestMismatch,
    EmptyTrialSet,
    DuplicateTrialRef(String),
    DuplicateExecutionIdentity(String),
    UndeclaredCorpus(String),
    DuplicateCorpusEvidence(String),
    MissingCorpusEvidence(String),
    CorpusIdentityMismatch(String),
    MissingTaskEvidence(String),
    TaskIdentityMismatch(String),
    DuplicateGradeEvidence(String),
    MissingGradeEvidence(String),
    GradeEvidenceReused(String),
    GradeSubjectMismatch(String),
    UndeclaredGraderPlan(String),
    DuplicateEnvironmentEvidence(String),
    MissingEnvironmentEvidence(String),
    EnvironmentIdentityMismatch(String),
    UndeclaredEnvironmentPlan(String),
    UnusedCorpusEvidence(String),
    UnusedGradeEvidence(String),
    UnusedEnvironmentEvidence(String),
    DevelopmentTrialRejected(String),
    Q07RequiresHeldout(String),
    MissingQ07Regime(SpecialistRegime),
    MissingTrialEvidence(String),
    MissingProvenance,
    MissingInvalidationDependencies,
    UnsupportedDigestAlgorithm(String),
    DigestMismatch,
    EncodingFailure,
}

impl fmt::Display for QualityTrialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "quality trial set rejected: {self:?}")
    }
}

pub fn compute_quality_trial_set_digest(
    set: &QualityTrialSet,
) -> Result<ContentDigest, QualityTrialError> {
    validate_trial_set_shape(set)?;
    let transcript = canonical_quality_trial_set_transcript(set)?;
    let digest = Sha256::digest(&transcript);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| QualityTrialError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| QualityTrialError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| QualityTrialError::EncodingFailure)?,
    })
}

pub fn verify_quality_trial_set(
    plan: &QualityFloorPlan,
    verified_plan: &VerifiedQualityFloorPlan,
    set: &QualityTrialSet,
    evidence: QualityTrialVerificationEvidence<'_>,
) -> Result<VerifiedQualityTrialSet, QualityTrialError> {
    let current_plan = verify_quality_floor_plan(plan).map_err(QualityTrialError::FloorPlan)?;
    if &current_plan != verified_plan {
        return Err(QualityTrialError::VerifiedPlanMismatch);
    }
    if set.content_digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(QualityTrialError::UnsupportedDigestAlgorithm(
            set.content_digest.algorithm_ref.to_string(),
        ));
    }
    let current_digest = compute_quality_trial_set_digest(set)?;
    if current_digest != set.content_digest {
        return Err(QualityTrialError::DigestMismatch);
    }
    if set.plan_ref != plan.plan_ref
        || set.plan_version != plan.plan_version
        || set.plan_digest != plan.content_digest
        || set.gate != plan.gate
    {
        return Err(QualityTrialError::PlanBindingMismatch);
    }
    if set.trial_protocol_ref != plan.trial_protocol_ref
        || set.seed_manifest_ref != plan.seed_manifest_ref
        || set.hardware_manifest_ref != plan.hardware_manifest_ref
        || set.preregistration_evidence_ref != plan.preregistration_evidence_ref
    {
        return Err(QualityTrialError::ProtocolBindingMismatch);
    }

    if let QualityGateCoverage::Q07(coverage) = &plan.coverage
        && set.candidate_configuration_manifest_ref.as_ref()
            != Some(&coverage.candidate_configuration_manifest_ref)
    {
        return Err(QualityTrialError::CandidateConfigurationManifestMismatch);
    }
    if !plan
        .invalidation_dependency_refs
        .is_subset(&set.invalidation_dependency_refs)
    {
        return Err(QualityTrialError::MissingInvalidationDependencies);
    }

    let corpus_by_identity = index_corpora(evidence.corpora)?;
    let grade_by_ref = index_grades(evidence.grades)?;
    let environment_by_identity = index_environments(evidence.environments)?;
    let declared_corpora = declared_corpus_refs(plan);

    let mut trial_refs = BTreeSet::new();
    let mut execution_identities = BTreeSet::new();
    let mut corpus_refs = BTreeSet::new();
    let mut grade_refs = BTreeSet::new();
    let mut environment_refs = BTreeSet::new();
    let mut regimes = BTreeSet::new();
    let mut used_corpora = BTreeSet::new();
    let mut used_grades = BTreeSet::new();
    let mut used_environments = BTreeSet::new();

    for trial in &set.trials {
        if !trial_refs.insert(trial.trial_ref.clone()) {
            return Err(QualityTrialError::DuplicateTrialRef(
                trial.trial_ref.to_string(),
            ));
        }
        if !execution_identities.insert(ExecutionIdentity::from_trial(trial)) {
            return Err(QualityTrialError::DuplicateExecutionIdentity(
                trial.trial_ref.to_string(),
            ));
        }
        if !declared_corpora.contains(&trial.corpus_ref) {
            return Err(QualityTrialError::UndeclaredCorpus(
                trial.corpus_ref.to_string(),
            ));
        }
        if trial.partition == EvaluationPartition::Development {
            return Err(QualityTrialError::DevelopmentTrialRejected(
                trial.trial_ref.to_string(),
            ));
        }
        if plan.gate == QualityGateId::Q07ModelsExperts
            && trial.partition != EvaluationPartition::Heldout
        {
            return Err(QualityTrialError::Q07RequiresHeldout(
                trial.trial_ref.to_string(),
            ));
        }
        if trial.execution_evidence_refs.is_empty()
            || trial.grader_result_refs.is_empty()
            || trial.provenance_refs.is_empty()
            || trial.invalidation_dependency_refs.is_empty()
        {
            return Err(QualityTrialError::MissingTrialEvidence(
                trial.trial_ref.to_string(),
            ));
        }

        verify_trial_corpus(trial, &corpus_by_identity, &mut used_corpora)?;
        verify_trial_environment(
            plan,
            trial,
            &environment_by_identity,
            &mut used_environments,
        )?;
        verify_trial_grades(plan, trial, &grade_by_ref, &mut used_grades)?;

        corpus_refs.insert(trial.corpus_ref.clone());
        grade_refs.extend(trial.grader_result_refs.iter().cloned());
        environment_refs.insert(trial.environment_ref.clone());
        regimes.insert(trial.regime);
    }

    require_no_unused_corpus_evidence(&corpus_by_identity, &used_corpora)?;
    require_no_unused_grade_evidence(&grade_by_ref, &used_grades)?;
    require_no_unused_environment_evidence(&environment_by_identity, &used_environments)?;

    let exact_corpus_identities: BTreeSet<ExactCorpusEvidenceIdentity> = used_corpora
        .iter()
        .map(|identity| {
            ExactCorpusEvidenceIdentity::from_verified(
                *corpus_by_identity
                    .get(identity)
                    .expect("used corpus identity came from verified evidence"),
            )
        })
        .collect();
    let exact_grade_identities: BTreeSet<ExactGradeEvidenceIdentity> = used_grades
        .iter()
        .map(|grade_ref| {
            ExactGradeEvidenceIdentity::from_verified(
                *grade_by_ref
                    .get(grade_ref)
                    .expect("used grade identity came from verified evidence"),
            )
        })
        .collect();
    let exact_environment_identities: BTreeSet<ExactEnvironmentEvidenceIdentity> =
        used_environments
            .iter()
            .map(|identity| {
                ExactEnvironmentEvidenceIdentity::from_verified(
                    *environment_by_identity
                        .get(identity)
                        .expect("used environment identity came from verified evidence"),
                )
            })
            .collect();

    if plan.gate == QualityGateId::Q07ModelsExperts {
        for regime in SpecialistRegime::ALL {
            if !regimes.contains(&regime) {
                return Err(QualityTrialError::MissingQ07Regime(regime));
            }
        }
    }

    let verification_digest = compute_quality_trial_verification_digest(
        set,
        &current_digest,
        &exact_corpus_identities,
        &exact_grade_identities,
        &exact_environment_identities,
    )?;

    Ok(VerifiedQualityTrialSet {
        trial_set_ref: set.trial_set_ref.clone(),
        trial_set_version: set.trial_set_version.clone(),
        content_digest: current_digest,
        plan_ref: set.plan_ref.clone(),
        plan_version: set.plan_version.clone(),
        plan_digest: set.plan_digest.clone(),
        gate: set.gate,
        trial_refs,
        execution_identities,
        corpus_refs,
        exact_corpus_identities,
        grade_refs,
        exact_grade_identities,
        environment_refs,
        exact_environment_identities,
        regimes,
        verification_digest,
        canonical_profile_ref: QUALITY_TRIAL_SET_CANONICAL_PROFILE,
    })
}

fn compute_quality_trial_verification_digest(
    set: &QualityTrialSet,
    raw_digest: &ContentDigest,
    corpora: &BTreeSet<ExactCorpusEvidenceIdentity>,
    grades: &BTreeSet<ExactGradeEvidenceIdentity>,
    environments: &BTreeSet<ExactEnvironmentEvidenceIdentity>,
) -> Result<ContentDigest, QualityTrialError> {
    let mut encoder = Encoder::new();
    encoder.raw(QUALITY_TRIAL_VERIFICATION_DOMAIN);
    encoder.digest(raw_digest)?;
    encoder.reference(&set.plan_ref)?;
    encoder.version(&set.plan_version)?;
    encoder.digest(&set.plan_digest)?;
    encoder.gate(set.gate)?;

    encoder.count(corpora.len())?;
    for corpus in corpora {
        encoder.reference(&corpus.corpus_ref)?;
        encoder.version(&corpus.corpus_version)?;
        encoder.reference(&corpus.digest_algorithm_ref)?;
        encoder.reference(&corpus.digest_value_ref)?;
    }

    encoder.count(grades.len())?;
    for grade in grades {
        encoder.reference(&grade.grade_ref)?;
        encoder.reference(&grade.verification_algorithm_ref)?;
        encoder.reference(&grade.verification_value_ref)?;
    }

    encoder.count(environments.len())?;
    for environment in environments {
        encoder.reference(&environment.environment_ref)?;
        encoder.version(&environment.environment_version)?;
        encoder.reference(&environment.profile_digest_algorithm_ref)?;
        encoder.reference(&environment.profile_digest_value_ref)?;
        encoder.reference(&environment.verification_algorithm_ref)?;
        encoder.reference(&environment.verification_value_ref)?;
    }

    digest_bytes(&encoder.finish())
}

fn digest_bytes(bytes: &[u8]) -> Result<ContentDigest, QualityTrialError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| QualityTrialError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| QualityTrialError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| QualityTrialError::EncodingFailure)?,
    })
}

pub fn canonical_quality_trial_set_transcript(
    set: &QualityTrialSet,
) -> Result<Vec<u8>, QualityTrialError> {
    validate_trial_set_shape(set)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&set.trial_set_ref)?;
    encoder.version(&set.trial_set_version)?;
    encoder.reference(&set.plan_ref)?;
    encoder.version(&set.plan_version)?;
    encoder.digest(&set.plan_digest)?;
    encoder.gate(set.gate)?;
    encoder.reference(&set.trial_protocol_ref)?;
    encoder.reference(&set.seed_manifest_ref)?;
    encoder.reference(&set.hardware_manifest_ref)?;
    encoder.optional_reference(set.candidate_configuration_manifest_ref.as_ref())?;
    encoder.reference(&set.preregistration_evidence_ref)?;

    let mut trials: Vec<&QualityTrialRecord> = set.trials.iter().collect();
    trials.sort_by(|left, right| left.trial_ref.cmp(&right.trial_ref));
    encoder.count(trials.len())?;
    for trial in trials {
        encoder.trial(trial)?;
    }
    encoder.ref_set(&set.provenance_refs)?;
    encoder.ref_set(&set.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

fn validate_trial_set_shape(set: &QualityTrialSet) -> Result<(), QualityTrialError> {
    if set.trials.is_empty() {
        return Err(QualityTrialError::EmptyTrialSet);
    }
    if set.provenance_refs.is_empty() {
        return Err(QualityTrialError::MissingProvenance);
    }
    if set.invalidation_dependency_refs.is_empty() {
        return Err(QualityTrialError::MissingInvalidationDependencies);
    }
    let mut trial_refs = BTreeSet::new();
    let mut execution_identities = BTreeSet::new();
    for trial in &set.trials {
        if !trial_refs.insert(trial.trial_ref.clone()) {
            return Err(QualityTrialError::DuplicateTrialRef(
                trial.trial_ref.to_string(),
            ));
        }
        if !execution_identities.insert(ExecutionIdentity::from_trial(trial)) {
            return Err(QualityTrialError::DuplicateExecutionIdentity(
                trial.trial_ref.to_string(),
            ));
        }
        if trial.execution_evidence_refs.is_empty()
            || trial.grader_result_refs.is_empty()
            || trial.provenance_refs.is_empty()
            || trial.invalidation_dependency_refs.is_empty()
        {
            return Err(QualityTrialError::MissingTrialEvidence(
                trial.trial_ref.to_string(),
            ));
        }
    }
    Ok(())
}

fn index_corpora(
    corpora: &[VerifiedEvaluationCorpus],
) -> Result<BTreeMap<(Reference, OpaqueVersion), &VerifiedEvaluationCorpus>, QualityTrialError> {
    let mut by_identity = BTreeMap::new();
    for corpus in corpora {
        let key = (corpus.corpus_ref().clone(), corpus.corpus_version().clone());
        if by_identity.insert(key, corpus).is_some() {
            return Err(QualityTrialError::DuplicateCorpusEvidence(
                corpus.corpus_ref().to_string(),
            ));
        }
    }
    Ok(by_identity)
}

fn index_grades(
    grades: &[VerifiedGradeRecord],
) -> Result<BTreeMap<Reference, &VerifiedGradeRecord>, QualityTrialError> {
    let mut by_ref = BTreeMap::new();
    for grade in grades {
        if by_ref.insert(grade.grade_ref().clone(), grade).is_some() {
            return Err(QualityTrialError::DuplicateGradeEvidence(
                grade.grade_ref().to_string(),
            ));
        }
    }
    Ok(by_ref)
}

fn index_environments(
    environments: &[VerifiedExecutionEnvironment],
) -> Result<BTreeMap<(Reference, OpaqueVersion), &VerifiedExecutionEnvironment>, QualityTrialError>
{
    let mut by_identity = BTreeMap::new();
    for environment in environments {
        let subject = environment.subject();
        let key = (
            subject.environment_ref.clone(),
            subject.environment_version.clone(),
        );
        if by_identity.insert(key, environment).is_some() {
            return Err(QualityTrialError::DuplicateEnvironmentEvidence(
                subject.environment_ref.to_string(),
            ));
        }
    }
    Ok(by_identity)
}

fn verify_trial_corpus(
    trial: &QualityTrialRecord,
    corpora: &BTreeMap<(Reference, OpaqueVersion), &VerifiedEvaluationCorpus>,
    used: &mut BTreeSet<(Reference, OpaqueVersion)>,
) -> Result<(), QualityTrialError> {
    let key = (trial.corpus_ref.clone(), trial.corpus_version.clone());
    let corpus = corpora
        .get(&key)
        .ok_or_else(|| QualityTrialError::MissingCorpusEvidence(trial.corpus_ref.to_string()))?;
    if corpus.content_digest() != &trial.corpus_digest || corpus.regime() != trial.regime {
        return Err(QualityTrialError::CorpusIdentityMismatch(
            trial.trial_ref.to_string(),
        ));
    }
    let task = corpus
        .task(&trial.task_ref)
        .ok_or_else(|| QualityTrialError::MissingTaskEvidence(trial.task_ref.to_string()))?;
    if task.task_version() != &trial.task_version
        || task.task_content_digest() != &trial.task_digest
        || task.regime() != trial.regime
        || task.partition() != trial.partition
    {
        return Err(QualityTrialError::TaskIdentityMismatch(
            trial.trial_ref.to_string(),
        ));
    }
    used.insert(key);
    Ok(())
}

fn verify_trial_environment(
    plan: &QualityFloorPlan,
    trial: &QualityTrialRecord,
    environments: &BTreeMap<(Reference, OpaqueVersion), &VerifiedExecutionEnvironment>,
    used: &mut BTreeSet<(Reference, OpaqueVersion)>,
) -> Result<(), QualityTrialError> {
    let key = (
        trial.environment_ref.clone(),
        trial.environment_version.clone(),
    );
    let environment = environments.get(&key).ok_or_else(|| {
        QualityTrialError::MissingEnvironmentEvidence(trial.environment_ref.to_string())
    })?;
    let subject = environment.subject();
    if subject.content_digest != trial.environment_digest {
        return Err(QualityTrialError::EnvironmentIdentityMismatch(
            trial.trial_ref.to_string(),
        ));
    }
    if !plan
        .environment_qualification_plan_refs
        .contains(&environment.plan_identity().plan_ref)
    {
        return Err(QualityTrialError::UndeclaredEnvironmentPlan(
            environment.plan_identity().plan_ref.to_string(),
        ));
    }
    used.insert(key);
    Ok(())
}

fn verify_trial_grades(
    plan: &QualityFloorPlan,
    trial: &QualityTrialRecord,
    grades: &BTreeMap<Reference, &VerifiedGradeRecord>,
    used: &mut BTreeSet<Reference>,
) -> Result<(), QualityTrialError> {
    for grade_ref in &trial.grader_result_refs {
        let grade = grades
            .get(grade_ref)
            .ok_or_else(|| QualityTrialError::MissingGradeEvidence(grade_ref.to_string()))?;
        if !used.insert(grade_ref.clone()) {
            return Err(QualityTrialError::GradeEvidenceReused(
                grade_ref.to_string(),
            ));
        }
        if !plan
            .grader_plan_refs
            .contains(&grade.grader_plan_identity().plan_ref)
        {
            return Err(QualityTrialError::UndeclaredGraderPlan(
                grade.grader_plan_identity().plan_ref.to_string(),
            ));
        }
        let subject = grade.subject();
        if subject.regime != trial.regime
            || subject.task_ref != trial.task_ref
            || subject.trial_ref != trial.trial_ref
            || subject.output_digest != trial.output_digest
            || subject.trace_ref != trial.trace_ref
            || subject.environment_ref != trial.environment_ref
            || subject.environment_version != trial.environment_version
            || subject.execution_evidence_refs != trial.execution_evidence_refs
        {
            return Err(QualityTrialError::GradeSubjectMismatch(
                grade_ref.to_string(),
            ));
        }
    }
    Ok(())
}

fn require_no_unused_corpus_evidence(
    corpora: &BTreeMap<(Reference, OpaqueVersion), &VerifiedEvaluationCorpus>,
    used: &BTreeSet<(Reference, OpaqueVersion)>,
) -> Result<(), QualityTrialError> {
    if let Some((identity, _)) = corpora
        .iter()
        .find(|(identity, _)| !used.contains(*identity))
    {
        return Err(QualityTrialError::UnusedCorpusEvidence(
            identity.0.to_string(),
        ));
    }
    Ok(())
}

fn require_no_unused_grade_evidence(
    grades: &BTreeMap<Reference, &VerifiedGradeRecord>,
    used: &BTreeSet<Reference>,
) -> Result<(), QualityTrialError> {
    if let Some((grade_ref, _)) = grades
        .iter()
        .find(|(grade_ref, _)| !used.contains(*grade_ref))
    {
        return Err(QualityTrialError::UnusedGradeEvidence(
            grade_ref.to_string(),
        ));
    }
    Ok(())
}

fn require_no_unused_environment_evidence(
    environments: &BTreeMap<(Reference, OpaqueVersion), &VerifiedExecutionEnvironment>,
    used: &BTreeSet<(Reference, OpaqueVersion)>,
) -> Result<(), QualityTrialError> {
    if let Some((identity, _)) = environments
        .iter()
        .find(|(identity, _)| !used.contains(*identity))
    {
        return Err(QualityTrialError::UnusedEnvironmentEvidence(
            identity.0.to_string(),
        ));
    }
    Ok(())
}

fn declared_corpus_refs(plan: &QualityFloorPlan) -> BTreeSet<Reference> {
    let mut declared = plan.evaluation_corpus_refs.clone();
    match &plan.coverage {
        QualityGateCoverage::Q06(coverage) => {
            declared.insert(coverage.long_history_memory_corpus_ref.clone());
            declared.insert(coverage.multi_session_reasoning_corpus_ref.clone());
            declared.insert(coverage.correction_case_corpus_ref.clone());
            declared.insert(coverage.poisoning_case_corpus_ref.clone());
            declared.insert(coverage.lifecycle_case_corpus_ref.clone());
            declared.insert(coverage.abstention_unknown_case_corpus_ref.clone());
        }
        QualityGateCoverage::Q07(coverage) => {
            declared.extend(coverage.heldout_regime_corpus_refs.values().cloned());
        }
    }
    declared
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

    fn count(&mut self, value: usize) -> Result<(), QualityTrialError> {
        let value = u64::try_from(value).map_err(|_| QualityTrialError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), QualityTrialError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), QualityTrialError> {
        self.scalar(value.as_str())
    }

    fn optional_reference(&mut self, value: Option<&Reference>) -> Result<(), QualityTrialError> {
        match value {
            Some(reference) => {
                self.raw(&[1]);
                self.reference(reference)
            }
            None => {
                self.raw(&[0]);
                Ok(())
            }
        }
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), QualityTrialError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), QualityTrialError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), QualityTrialError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn gate(&mut self, gate: QualityGateId) -> Result<(), QualityTrialError> {
        self.scalar(match gate {
            QualityGateId::Q06MemoryContext => "Q06-memory-context",
            QualityGateId::Q07ModelsExperts => "Q07-models-experts",
        })
    }

    fn regime(&mut self, regime: SpecialistRegime) -> Result<(), QualityTrialError> {
        self.scalar(match regime {
            SpecialistRegime::ConversationPersonalAssistant => "conversation-personal-assistant",
            SpecialistRegime::ResearchDeepResearch => "research-deep-research",
            SpecialistRegime::SoftwareEngineering => "software-engineering",
            SpecialistRegime::ActionAutomation => "action-automation",
            SpecialistRegime::CreationArtifact => "creation-artifact",
            SpecialistRegime::MonitoringLongRunningWork => "monitoring-long-running-work",
        })
    }

    fn partition(&mut self, partition: EvaluationPartition) -> Result<(), QualityTrialError> {
        self.scalar(match partition {
            EvaluationPartition::Development => "development",
            EvaluationPartition::Heldout => "heldout",
            EvaluationPartition::Adversarial => "adversarial",
        })
    }

    fn trial(&mut self, trial: &QualityTrialRecord) -> Result<(), QualityTrialError> {
        self.reference(&trial.trial_ref)?;
        self.reference(&trial.corpus_ref)?;
        self.version(&trial.corpus_version)?;
        self.digest(&trial.corpus_digest)?;
        self.reference(&trial.task_ref)?;
        self.version(&trial.task_version)?;
        self.digest(&trial.task_digest)?;
        self.regime(trial.regime)?;
        self.partition(trial.partition)?;
        self.reference(&trial.candidate_configuration_ref)?;
        self.version(&trial.candidate_configuration_version)?;
        self.digest(&trial.candidate_configuration_digest)?;
        self.reference(&trial.model_ref)?;
        self.version(&trial.model_version)?;
        self.reference(&trial.provider_ref)?;
        self.reference(&trial.adapter_ref)?;
        self.version(&trial.adapter_version)?;
        self.reference(&trial.environment_ref)?;
        self.version(&trial.environment_version)?;
        self.digest(&trial.environment_digest)?;
        self.reference(&trial.seed_ref)?;
        self.digest(&trial.input_digest)?;
        self.digest(&trial.output_digest)?;
        self.reference(&trial.trace_ref)?;
        self.ref_set(&trial.execution_evidence_refs)?;
        self.ref_set(&trial.grader_result_refs)?;
        self.ref_set(&trial.provenance_refs)?;
        self.ref_set(&trial.invalidation_dependency_refs)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
