extern crate alloc;

use crate::{
    integrity::SHA256_ALGORITHM_REF,
    manifest::{ContentDigest, OpaqueVersion, Reference},
    quality_floor::Q07ComparisonAxis,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

pub const CANDIDATE_CONFIGURATION_CANONICAL_PROFILE: &str =
    "NOERITH/CANDIDATE-CONFIGURATION/CANONICAL-2026-09";
pub const CANDIDATE_CONFIGURATION_MANIFEST_CANONICAL_PROFILE: &str =
    "NOERITH/CANDIDATE-CONFIGURATION-MANIFEST/CANONICAL-2026-09";

const CONFIGURATION_DOMAIN: &[u8] = b"NOERITH\0CANDIDATE-CONFIGURATION\0CANONICAL-2026-09\0";
const MANIFEST_DOMAIN: &[u8] = b"NOERITH\0CANDIDATE-CONFIGURATION-MANIFEST\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CandidateModelBinding {
    pub provider_ref: Reference,
    pub model_ref: Reference,
    pub model_version: OpaqueVersion,
    pub adapter_ref: Reference,
    pub adapter_version: OpaqueVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConfiguration {
    pub configuration_ref: Reference,
    pub configuration_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub model: CandidateModelBinding,
    pub worker_topology_ref: Reference,
    pub worker_count: u32,
    pub worker_coordination_policy_ref: Reference,
    pub reasoning_effort_ref: Reference,
    pub context_strategy_ref: Reference,
    pub retrieval_strategy_ref: Reference,
    pub provenance_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConfigurationManifest {
    pub manifest_ref: Reference,
    pub manifest_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub source_contract_refs: BTreeSet<Reference>,
    pub experiment_design_ref: Reference,
    pub randomization_policy_ref: Reference,
    pub blocking_policy_ref: Reference,
    pub comparison_estimand_refs: BTreeMap<Q07ComparisonAxis, Reference>,
    pub configurations: Vec<CandidateConfiguration>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCandidateConfiguration {
    configuration_ref: Reference,
    configuration_version: OpaqueVersion,
    content_digest: ContentDigest,
    model: CandidateModelBinding,
    worker_topology_ref: Reference,
    worker_count: u32,
    worker_coordination_policy_ref: Reference,
    reasoning_effort_ref: Reference,
    context_strategy_ref: Reference,
    retrieval_strategy_ref: Reference,
    canonical_profile_ref: &'static str,
}

impl VerifiedCandidateConfiguration {
    pub fn configuration_ref(&self) -> &Reference {
        &self.configuration_ref
    }

    pub fn configuration_version(&self) -> &OpaqueVersion {
        &self.configuration_version
    }

    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    pub fn model(&self) -> &CandidateModelBinding {
        &self.model
    }

    pub fn worker_topology_ref(&self) -> &Reference {
        &self.worker_topology_ref
    }

    pub fn worker_count(&self) -> u32 {
        self.worker_count
    }

    pub fn worker_coordination_policy_ref(&self) -> &Reference {
        &self.worker_coordination_policy_ref
    }

    pub fn reasoning_effort_ref(&self) -> &Reference {
        &self.reasoning_effort_ref
    }

    pub fn context_strategy_ref(&self) -> &Reference {
        &self.context_strategy_ref
    }

    pub fn retrieval_strategy_ref(&self) -> &Reference {
        &self.retrieval_strategy_ref
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCandidateConfigurationManifest {
    manifest_ref: Reference,
    manifest_version: OpaqueVersion,
    content_digest: ContentDigest,
    comparison_estimand_refs: BTreeMap<Q07ComparisonAxis, Reference>,
    configurations: BTreeMap<(Reference, OpaqueVersion), VerifiedCandidateConfiguration>,
    canonical_profile_ref: &'static str,
}

impl VerifiedCandidateConfigurationManifest {
    pub fn manifest_ref(&self) -> &Reference {
        &self.manifest_ref
    }

    pub fn manifest_version(&self) -> &OpaqueVersion {
        &self.manifest_version
    }

    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    pub fn comparison_estimand_ref(&self, axis: Q07ComparisonAxis) -> Option<&Reference> {
        self.comparison_estimand_refs.get(&axis)
    }

    pub fn comparison_estimand_refs(&self) -> &BTreeMap<Q07ComparisonAxis, Reference> {
        &self.comparison_estimand_refs
    }

    pub fn configurations(&self) -> impl Iterator<Item = &VerifiedCandidateConfiguration> {
        self.configurations.values()
    }

    pub fn configuration(
        &self,
        configuration_ref: &Reference,
        configuration_version: &OpaqueVersion,
    ) -> Option<&VerifiedCandidateConfiguration> {
        self.configurations
            .get(&(configuration_ref.clone(), configuration_version.clone()))
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateConfigurationError {
    MissingConfigurationProvenance(String),
    MissingConfigurationInvalidationDependencies(String),
    InvalidWorkerCount(String),
    UnsupportedDigestAlgorithm(String),
    ConfigurationDigestMismatch(String),
    EmptyManifest,
    MissingManifestSourceContracts,
    MissingManifestInvalidationDependencies,
    MissingComparisonEstimand(Q07ComparisonAxis),
    UnexpectedComparisonEstimandCount,
    DuplicateConfiguration(String),
    ConfigurationVersionDigestCollision {
        configuration_ref: String,
        configuration_version: String,
    },
    MissingComparisonAxisVariation(Q07ComparisonAxis),
    MissingSingleWorkerConfiguration,
    MissingMultipleWorkerConfiguration,
    ManifestDigestMismatch,
    EncodingFailure,
}

impl fmt::Display for CandidateConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "candidate configuration rejected: {self:?}")
    }
}

pub fn compute_candidate_configuration_digest(
    configuration: &CandidateConfiguration,
) -> Result<ContentDigest, CandidateConfigurationError> {
    validate_configuration_shape(configuration)?;
    let transcript = canonical_candidate_configuration_transcript(configuration)?;
    sha256_digest(&transcript)
}

pub fn verify_candidate_configuration(
    configuration: &CandidateConfiguration,
) -> Result<VerifiedCandidateConfiguration, CandidateConfigurationError> {
    require_sha256(&configuration.content_digest)?;
    let computed = compute_candidate_configuration_digest(configuration)?;
    if computed != configuration.content_digest {
        return Err(CandidateConfigurationError::ConfigurationDigestMismatch(
            configuration.configuration_ref.to_string(),
        ));
    }
    Ok(VerifiedCandidateConfiguration {
        configuration_ref: configuration.configuration_ref.clone(),
        configuration_version: configuration.configuration_version.clone(),
        content_digest: computed,
        model: configuration.model.clone(),
        worker_topology_ref: configuration.worker_topology_ref.clone(),
        worker_count: configuration.worker_count,
        worker_coordination_policy_ref: configuration.worker_coordination_policy_ref.clone(),
        reasoning_effort_ref: configuration.reasoning_effort_ref.clone(),
        context_strategy_ref: configuration.context_strategy_ref.clone(),
        retrieval_strategy_ref: configuration.retrieval_strategy_ref.clone(),
        canonical_profile_ref: CANDIDATE_CONFIGURATION_CANONICAL_PROFILE,
    })
}

pub fn compute_candidate_configuration_manifest_digest(
    manifest: &CandidateConfigurationManifest,
) -> Result<ContentDigest, CandidateConfigurationError> {
    validate_manifest_shape(manifest)?;
    let transcript = canonical_candidate_configuration_manifest_transcript(manifest)?;
    sha256_digest(&transcript)
}

pub fn verify_candidate_configuration_manifest(
    manifest: &CandidateConfigurationManifest,
) -> Result<VerifiedCandidateConfigurationManifest, CandidateConfigurationError> {
    require_sha256(&manifest.content_digest)?;
    validate_manifest_shape(manifest)?;

    let mut configurations = BTreeMap::new();
    for configuration in &manifest.configurations {
        let verified = verify_candidate_configuration(configuration)?;
        configurations.insert(
            (
                verified.configuration_ref().clone(),
                verified.configuration_version().clone(),
            ),
            verified,
        );
    }

    validate_q07_comparison_coverage(&configurations)?;

    let computed = compute_candidate_configuration_manifest_digest(manifest)?;
    if computed != manifest.content_digest {
        return Err(CandidateConfigurationError::ManifestDigestMismatch);
    }

    Ok(VerifiedCandidateConfigurationManifest {
        manifest_ref: manifest.manifest_ref.clone(),
        manifest_version: manifest.manifest_version.clone(),
        content_digest: computed,
        comparison_estimand_refs: manifest.comparison_estimand_refs.clone(),
        configurations,
        canonical_profile_ref: CANDIDATE_CONFIGURATION_MANIFEST_CANONICAL_PROFILE,
    })
}

pub fn canonical_candidate_configuration_transcript(
    configuration: &CandidateConfiguration,
) -> Result<Vec<u8>, CandidateConfigurationError> {
    validate_configuration_shape(configuration)?;
    let mut encoder = Encoder::new();
    encoder.raw(CONFIGURATION_DOMAIN);
    encoder.reference(&configuration.configuration_ref)?;
    encoder.version(&configuration.configuration_version)?;
    encoder.model(&configuration.model)?;
    encoder.reference(&configuration.worker_topology_ref)?;
    encoder.u32(configuration.worker_count);
    encoder.reference(&configuration.worker_coordination_policy_ref)?;
    encoder.reference(&configuration.reasoning_effort_ref)?;
    encoder.reference(&configuration.context_strategy_ref)?;
    encoder.reference(&configuration.retrieval_strategy_ref)?;
    encoder.ref_set(&configuration.provenance_refs)?;
    encoder.ref_set(&configuration.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

pub fn canonical_candidate_configuration_manifest_transcript(
    manifest: &CandidateConfigurationManifest,
) -> Result<Vec<u8>, CandidateConfigurationError> {
    validate_manifest_shape(manifest)?;
    for configuration in &manifest.configurations {
        verify_candidate_configuration(configuration)?;
    }

    let mut encoder = Encoder::new();
    encoder.raw(MANIFEST_DOMAIN);
    encoder.reference(&manifest.manifest_ref)?;
    encoder.version(&manifest.manifest_version)?;
    encoder.ref_set(&manifest.source_contract_refs)?;
    encoder.reference(&manifest.experiment_design_ref)?;
    encoder.reference(&manifest.randomization_policy_ref)?;
    encoder.reference(&manifest.blocking_policy_ref)?;
    encoder.count(manifest.comparison_estimand_refs.len())?;
    for axis in Q07ComparisonAxis::ALL {
        encoder.axis(axis)?;
        let estimand_ref = manifest
            .comparison_estimand_refs
            .get(&axis)
            .ok_or(CandidateConfigurationError::MissingComparisonEstimand(axis))?;
        encoder.reference(estimand_ref)?;
    }

    let mut configurations: Vec<&CandidateConfiguration> = manifest.configurations.iter().collect();
    configurations.sort_by(|left, right| {
        left.configuration_ref
            .cmp(&right.configuration_ref)
            .then_with(|| left.configuration_version.cmp(&right.configuration_version))
    });
    encoder.count(configurations.len())?;
    for configuration in configurations {
        encoder.reference(&configuration.configuration_ref)?;
        encoder.version(&configuration.configuration_version)?;
        encoder.digest(&configuration.content_digest)?;
    }
    encoder.ref_set(&manifest.invalidation_dependency_refs)?;
    Ok(encoder.finish())
}

fn validate_configuration_shape(
    configuration: &CandidateConfiguration,
) -> Result<(), CandidateConfigurationError> {
    if configuration.provenance_refs.is_empty() {
        return Err(CandidateConfigurationError::MissingConfigurationProvenance(
            configuration.configuration_ref.to_string(),
        ));
    }
    if configuration.invalidation_dependency_refs.is_empty() {
        return Err(
            CandidateConfigurationError::MissingConfigurationInvalidationDependencies(
                configuration.configuration_ref.to_string(),
            ),
        );
    }
    if configuration.worker_count == 0 {
        return Err(CandidateConfigurationError::InvalidWorkerCount(
            configuration.configuration_ref.to_string(),
        ));
    }
    Ok(())
}

fn validate_manifest_shape(
    manifest: &CandidateConfigurationManifest,
) -> Result<(), CandidateConfigurationError> {
    if manifest.configurations.is_empty() {
        return Err(CandidateConfigurationError::EmptyManifest);
    }
    if manifest.source_contract_refs.is_empty() {
        return Err(CandidateConfigurationError::MissingManifestSourceContracts);
    }
    if manifest.invalidation_dependency_refs.is_empty() {
        return Err(CandidateConfigurationError::MissingManifestInvalidationDependencies);
    }
    if manifest.comparison_estimand_refs.len() != Q07ComparisonAxis::ALL.len() {
        return Err(CandidateConfigurationError::UnexpectedComparisonEstimandCount);
    }
    for axis in Q07ComparisonAxis::ALL {
        if !manifest.comparison_estimand_refs.contains_key(&axis) {
            return Err(CandidateConfigurationError::MissingComparisonEstimand(axis));
        }
    }

    let mut by_identity = BTreeMap::<(Reference, OpaqueVersion), ContentDigest>::new();
    for configuration in &manifest.configurations {
        validate_configuration_shape(configuration)?;
        let key = (
            configuration.configuration_ref.clone(),
            configuration.configuration_version.clone(),
        );
        match by_identity.get(&key) {
            Some(existing) if existing == &configuration.content_digest => {
                return Err(CandidateConfigurationError::DuplicateConfiguration(
                    configuration.configuration_ref.to_string(),
                ));
            }
            Some(_) => {
                return Err(
                    CandidateConfigurationError::ConfigurationVersionDigestCollision {
                        configuration_ref: configuration.configuration_ref.to_string(),
                        configuration_version: configuration
                            .configuration_version
                            .as_str()
                            .to_string(),
                    },
                );
            }
            None => {
                by_identity.insert(key, configuration.content_digest.clone());
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WorkerTopologyLevel {
    topology_ref: Reference,
    worker_count: u32,
    coordination_policy_ref: Reference,
}

fn validate_q07_comparison_coverage(
    configurations: &BTreeMap<(Reference, OpaqueVersion), VerifiedCandidateConfiguration>,
) -> Result<(), CandidateConfigurationError> {
    let mut models = BTreeSet::new();
    let mut worker_topologies = BTreeSet::new();
    let mut reasoning_efforts = BTreeSet::new();
    let mut context_strategies = BTreeSet::new();
    let mut retrieval_strategies = BTreeSet::new();
    let mut has_single_worker = false;
    let mut has_multiple_workers = false;

    for configuration in configurations.values() {
        models.insert(configuration.model().clone());
        worker_topologies.insert(WorkerTopologyLevel {
            topology_ref: configuration.worker_topology_ref().clone(),
            worker_count: configuration.worker_count(),
            coordination_policy_ref: configuration.worker_coordination_policy_ref().clone(),
        });
        reasoning_efforts.insert(configuration.reasoning_effort_ref().clone());
        context_strategies.insert(configuration.context_strategy_ref().clone());
        retrieval_strategies.insert(configuration.retrieval_strategy_ref().clone());
        has_single_worker |= configuration.worker_count() == 1;
        has_multiple_workers |= configuration.worker_count() > 1;
    }

    for (axis, level_count) in [
        (Q07ComparisonAxis::CandidateModel, models.len()),
        (Q07ComparisonAxis::WorkerTopology, worker_topologies.len()),
        (Q07ComparisonAxis::ReasoningEffort, reasoning_efforts.len()),
        (Q07ComparisonAxis::ContextStrategy, context_strategies.len()),
        (
            Q07ComparisonAxis::RetrievalStrategy,
            retrieval_strategies.len(),
        ),
    ] {
        if level_count < 2 {
            return Err(CandidateConfigurationError::MissingComparisonAxisVariation(
                axis,
            ));
        }
    }
    if !has_single_worker {
        return Err(CandidateConfigurationError::MissingSingleWorkerConfiguration);
    }
    if !has_multiple_workers {
        return Err(CandidateConfigurationError::MissingMultipleWorkerConfiguration);
    }
    Ok(())
}

fn require_sha256(digest: &ContentDigest) -> Result<(), CandidateConfigurationError> {
    if digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(CandidateConfigurationError::UnsupportedDigestAlgorithm(
            digest.algorithm_ref.to_string(),
        ));
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> Result<ContentDigest, CandidateConfigurationError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| CandidateConfigurationError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| CandidateConfigurationError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| CandidateConfigurationError::EncodingFailure)?,
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

    fn count(&mut self, value: usize) -> Result<(), CandidateConfigurationError> {
        let value =
            u64::try_from(value).map_err(|_| CandidateConfigurationError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn scalar(&mut self, value: &str) -> Result<(), CandidateConfigurationError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), CandidateConfigurationError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), CandidateConfigurationError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), CandidateConfigurationError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), CandidateConfigurationError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn model(&mut self, value: &CandidateModelBinding) -> Result<(), CandidateConfigurationError> {
        self.reference(&value.provider_ref)?;
        self.reference(&value.model_ref)?;
        self.version(&value.model_version)?;
        self.reference(&value.adapter_ref)?;
        self.version(&value.adapter_version)
    }

    fn axis(&mut self, value: Q07ComparisonAxis) -> Result<(), CandidateConfigurationError> {
        self.scalar(match value {
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
