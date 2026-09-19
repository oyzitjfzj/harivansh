extern crate alloc;

use crate::{
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    regime::SpecialistRegime,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const EVALUATION_CORPUS_CANONICAL_PROFILE: &str = "NOERITH/EVALUATION-CORPUS/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0EVALUATION-CORPUS\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvaluationPartition {
    Development,
    Heldout,
    Adversarial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationExposureClass {
    Public,
    Restricted,
    Sequestered,
}

/// One immutable evaluation case. All references describe measurement scope;
/// none grants execution or effect authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationTaskDefinition {
    pub task_ref: Reference,
    pub task_version: OpaqueVersion,
    pub task_content_digest: ContentDigest,
    pub regime: SpecialistRegime,
    pub partition: EvaluationPartition,
    pub contamination_family_ref: Reference,
    pub source_refs: BTreeSet<Reference>,
    pub provenance_refs: BTreeSet<Reference>,
    pub data_use_policy_refs: BTreeSet<Reference>,
    pub domain_refs: BTreeSet<Reference>,
    pub coverage_stratum_refs: BTreeSet<Reference>,
    pub required_capability_refs: BTreeSet<Reference>,
    pub environment_requirement_refs: BTreeSet<Reference>,
    pub completion_contract_refs: BTreeSet<Reference>,
    pub grader_criterion_refs: BTreeSet<Reference>,
    pub evaluation_affordance_policy_ref: Reference,
    pub exposure_class: EvaluationExposureClass,
    pub exposure_evidence_refs: BTreeSet<Reference>,
    pub validation_evidence_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

/// Content-bound corpus for exactly one specialist regime. Statistical
/// interpretation and quality floors live outside this structural object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationCorpusDefinition {
    pub corpus_ref: Reference,
    pub corpus_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub regime: SpecialistRegime,
    pub task_distribution_ref: Reference,
    pub coverage_model_ref: Reference,
    pub sampling_policy_ref: Reference,
    pub anti_gaming_policy_ref: Reference,
    pub exposure_control_policy_ref: Reference,
    pub development_partition_ref: Reference,
    pub heldout_partition_ref: Reference,
    pub adversarial_partition_ref: Reference,
    pub tasks: Vec<EvaluationTaskDefinition>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

/// Exact task identity retained only after the enclosing corpus has passed its
/// canonical integrity and anti-leakage checks. This is structural evidence,
/// never a quality-pass claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvaluationTask {
    task_ref: Reference,
    task_version: OpaqueVersion,
    task_content_digest: ContentDigest,
    regime: SpecialistRegime,
    partition: EvaluationPartition,
}

impl VerifiedEvaluationTask {
    pub fn task_ref(&self) -> &Reference {
        &self.task_ref
    }

    pub fn task_version(&self) -> &OpaqueVersion {
        &self.task_version
    }

    pub fn task_content_digest(&self) -> &ContentDigest {
        &self.task_content_digest
    }

    pub fn regime(&self) -> SpecialistRegime {
        self.regime
    }

    pub fn partition(&self) -> EvaluationPartition {
        self.partition
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvaluationCorpus {
    corpus_ref: Reference,
    corpus_version: OpaqueVersion,
    content_digest: ContentDigest,
    regime: SpecialistRegime,
    partition_counts: BTreeMap<EvaluationPartition, usize>,
    tasks_by_ref: BTreeMap<Reference, VerifiedEvaluationTask>,
    canonical_profile_ref: &'static str,
}

impl VerifiedEvaluationCorpus {
    pub fn corpus_ref(&self) -> &Reference {
        &self.corpus_ref
    }

    pub fn corpus_version(&self) -> &OpaqueVersion {
        &self.corpus_version
    }

    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    pub fn regime(&self) -> SpecialistRegime {
        self.regime
    }

    pub fn partition_count(&self, partition: EvaluationPartition) -> usize {
        self.partition_counts.get(&partition).copied().unwrap_or(0)
    }

    pub fn task(&self, task_ref: &Reference) -> Option<&VerifiedEvaluationTask> {
        self.tasks_by_ref.get(task_ref)
    }

    pub fn task_refs(&self) -> impl Iterator<Item = &Reference> {
        self.tasks_by_ref.keys()
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationCorpusError {
    EmptyCorpus,
    PartitionIdentityCollision,
    MissingPartition(EvaluationPartition),
    DuplicateTask(String),
    TaskRegimeMismatch(String),
    ContaminationFamilyCrossesPartitions(String),
    MissingTaskEvidence(String),
    UnsupportedDigestAlgorithm(String),
    DigestMismatch,
    EncodingFailure,
}

impl fmt::Display for EvaluationCorpusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "evaluation corpus rejected: {self:?}")
    }
}

pub fn compute_evaluation_corpus_digest(
    corpus: &EvaluationCorpusDefinition,
) -> Result<ContentDigest, EvaluationCorpusError> {
    validate_corpus_shape(corpus)?;
    let transcript = canonical_evaluation_corpus_transcript(corpus)?;
    let digest = Sha256::digest(&transcript);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| EvaluationCorpusError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| EvaluationCorpusError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| EvaluationCorpusError::EncodingFailure)?,
    })
}

pub fn verify_evaluation_corpus(
    corpus: &EvaluationCorpusDefinition,
) -> Result<VerifiedEvaluationCorpus, EvaluationCorpusError> {
    if corpus.content_digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(EvaluationCorpusError::UnsupportedDigestAlgorithm(
            corpus.content_digest.algorithm_ref.to_string(),
        ));
    }
    let computed = compute_evaluation_corpus_digest(corpus)?;
    if computed != corpus.content_digest {
        return Err(EvaluationCorpusError::DigestMismatch);
    }

    let mut partition_counts = BTreeMap::new();
    let mut tasks_by_ref = BTreeMap::new();
    for task in &corpus.tasks {
        *partition_counts.entry(task.partition).or_insert(0) += 1;
        let previous = tasks_by_ref.insert(
            task.task_ref.clone(),
            VerifiedEvaluationTask {
                task_ref: task.task_ref.clone(),
                task_version: task.task_version.clone(),
                task_content_digest: task.task_content_digest.clone(),
                regime: task.regime,
                partition: task.partition,
            },
        );
        debug_assert!(previous.is_none());
    }

    Ok(VerifiedEvaluationCorpus {
        corpus_ref: corpus.corpus_ref.clone(),
        corpus_version: corpus.corpus_version.clone(),
        content_digest: computed,
        regime: corpus.regime,
        partition_counts,
        tasks_by_ref,
        canonical_profile_ref: EVALUATION_CORPUS_CANONICAL_PROFILE,
    })
}

pub fn canonical_evaluation_corpus_transcript(
    corpus: &EvaluationCorpusDefinition,
) -> Result<Vec<u8>, EvaluationCorpusError> {
    validate_corpus_shape(corpus)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encoder.reference(&corpus.corpus_ref)?;
    encoder.version(&corpus.corpus_version)?;
    encoder.regime(corpus.regime)?;
    encoder.reference(&corpus.task_distribution_ref)?;
    encoder.reference(&corpus.coverage_model_ref)?;
    encoder.reference(&corpus.sampling_policy_ref)?;
    encoder.reference(&corpus.anti_gaming_policy_ref)?;
    encoder.reference(&corpus.exposure_control_policy_ref)?;
    encoder.reference(&corpus.development_partition_ref)?;
    encoder.reference(&corpus.heldout_partition_ref)?;
    encoder.reference(&corpus.adversarial_partition_ref)?;

    let mut tasks: Vec<&EvaluationTaskDefinition> = corpus.tasks.iter().collect();
    tasks.sort_by(|left, right| left.task_ref.cmp(&right.task_ref));
    encoder.count(tasks.len())?;
    for task in tasks {
        encoder.task(task)?;
    }
    encoder.ref_set(&corpus.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

fn validate_corpus_shape(corpus: &EvaluationCorpusDefinition) -> Result<(), EvaluationCorpusError> {
    if corpus.tasks.is_empty() || corpus.invalidation_dependency_refs.is_empty() {
        return Err(EvaluationCorpusError::EmptyCorpus);
    }
    if corpus.development_partition_ref == corpus.heldout_partition_ref
        || corpus.development_partition_ref == corpus.adversarial_partition_ref
        || corpus.heldout_partition_ref == corpus.adversarial_partition_ref
    {
        return Err(EvaluationCorpusError::PartitionIdentityCollision);
    }

    let mut task_refs = BTreeSet::new();
    let mut family_partition = BTreeMap::<Reference, EvaluationPartition>::new();
    let mut seen_partitions = BTreeSet::new();

    for task in &corpus.tasks {
        if !task_refs.insert(task.task_ref.clone()) {
            return Err(EvaluationCorpusError::DuplicateTask(
                task.task_ref.to_string(),
            ));
        }
        if task.regime != corpus.regime {
            return Err(EvaluationCorpusError::TaskRegimeMismatch(
                task.task_ref.to_string(),
            ));
        }
        seen_partitions.insert(task.partition);
        if let Some(existing) =
            family_partition.insert(task.contamination_family_ref.clone(), task.partition)
            && existing != task.partition
        {
            return Err(EvaluationCorpusError::ContaminationFamilyCrossesPartitions(
                task.contamination_family_ref.to_string(),
            ));
        }
        validate_task_evidence(task)?;
    }

    for partition in [
        EvaluationPartition::Development,
        EvaluationPartition::Heldout,
        EvaluationPartition::Adversarial,
    ] {
        if !seen_partitions.contains(&partition) {
            return Err(EvaluationCorpusError::MissingPartition(partition));
        }
    }
    Ok(())
}

fn validate_task_evidence(task: &EvaluationTaskDefinition) -> Result<(), EvaluationCorpusError> {
    let required_sets = [
        &task.source_refs,
        &task.provenance_refs,
        &task.data_use_policy_refs,
        &task.domain_refs,
        &task.coverage_stratum_refs,
        &task.required_capability_refs,
        &task.environment_requirement_refs,
        &task.completion_contract_refs,
        &task.grader_criterion_refs,
        &task.exposure_evidence_refs,
        &task.validation_evidence_refs,
        &task.invalidation_dependency_refs,
    ];
    if required_sets.iter().any(|values| values.is_empty())
        || task
            .task_content_digest
            .algorithm_ref
            .as_str()
            .trim()
            .is_empty()
        || task.task_content_digest.value.as_str().trim().is_empty()
    {
        return Err(EvaluationCorpusError::MissingTaskEvidence(
            task.task_ref.to_string(),
        ));
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

    fn count(&mut self, value: usize) -> Result<(), EvaluationCorpusError> {
        let value = u64::try_from(value).map_err(|_| EvaluationCorpusError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), EvaluationCorpusError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), EvaluationCorpusError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), EvaluationCorpusError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), EvaluationCorpusError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), EvaluationCorpusError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn regime(&mut self, regime: SpecialistRegime) -> Result<(), EvaluationCorpusError> {
        self.scalar(match regime {
            SpecialistRegime::ConversationPersonalAssistant => "conversation-personal-assistant",
            SpecialistRegime::ResearchDeepResearch => "research-deep-research",
            SpecialistRegime::SoftwareEngineering => "software-engineering",
            SpecialistRegime::ActionAutomation => "action-automation",
            SpecialistRegime::CreationArtifact => "creation-artifact",
            SpecialistRegime::MonitoringLongRunningWork => "monitoring-long-running-work",
        })
    }

    fn task(&mut self, task: &EvaluationTaskDefinition) -> Result<(), EvaluationCorpusError> {
        self.reference(&task.task_ref)?;
        self.version(&task.task_version)?;
        self.digest(&task.task_content_digest)?;
        self.regime(task.regime)?;
        self.scalar(match task.partition {
            EvaluationPartition::Development => "development",
            EvaluationPartition::Heldout => "heldout",
            EvaluationPartition::Adversarial => "adversarial",
        })?;
        self.reference(&task.contamination_family_ref)?;
        self.ref_set(&task.source_refs)?;
        self.ref_set(&task.provenance_refs)?;
        self.ref_set(&task.data_use_policy_refs)?;
        self.ref_set(&task.domain_refs)?;
        self.ref_set(&task.coverage_stratum_refs)?;
        self.ref_set(&task.required_capability_refs)?;
        self.ref_set(&task.environment_requirement_refs)?;
        self.ref_set(&task.completion_contract_refs)?;
        self.ref_set(&task.grader_criterion_refs)?;
        self.reference(&task.evaluation_affordance_policy_ref)?;
        self.scalar(match task.exposure_class {
            EvaluationExposureClass::Public => "public",
            EvaluationExposureClass::Restricted => "restricted",
            EvaluationExposureClass::Sequestered => "sequestered",
        })?;
        self.ref_set(&task.exposure_evidence_refs)?;
        self.ref_set(&task.validation_evidence_refs)?;
        self.ref_set(&task.invalidation_dependency_refs)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
