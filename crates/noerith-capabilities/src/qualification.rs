extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

use crate::{
    integrity::SHA256_ALGORITHM_REF,
    manifest::{
        CapabilityManifest, ContentDigest, ExternalStateChange, OpaqueVersion, Reference,
        ReversibilityClaim, SupportClaim, validate_manifest,
    },
};

const QUALIFICATION_VERIFICATION_DOMAIN: &[u8] =
    b"NOERITH\0CAPABILITY-QUALIFICATION-VERIFICATION\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationSubject {
    pub capability_ref: Reference,
    pub capability_version: OpaqueVersion,
    pub manifest_digest: ContentDigest,
    pub artifact_ref: Reference,
    pub adapter_ref: Reference,
    pub adapter_version: OpaqueVersion,
    pub environment_ref: Reference,
    pub environment_version: OpaqueVersion,
    pub environment_digest: ContentDigest,
}

impl QualificationSubject {
    pub fn from_manifest(
        manifest: &CapabilityManifest,
        environment_ref: Reference,
        environment_version: OpaqueVersion,
        environment_digest: ContentDigest,
    ) -> Self {
        Self {
            capability_ref: manifest.capability_ref.clone(),
            capability_version: manifest.capability_version.clone(),
            manifest_digest: manifest.content_digest.clone(),
            artifact_ref: manifest.artifact_ref.clone(),
            adapter_ref: manifest.adapter_ref.clone(),
            adapter_version: manifest.adapter_version.clone(),
            environment_ref,
            environment_version,
            environment_digest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperatingCeiling {
    E0ReadOnly,
    E1OpaqueWrite,
    E2DeduplicatedWrite,
    E3ObservableWrite,
    E4CompensatableWrite,
    E5SharedAtomic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationPlanIdentity {
    pub plan_ref: Reference,
    pub plan_version: OpaqueVersion,
    pub plan_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationPlan {
    pub identity: QualificationPlanIdentity,
    pub operation_refs: BTreeSet<Reference>,
    pub required_evidence_refs: BTreeSet<Reference>,
    pub evaluation_corpus_refs: BTreeSet<Reference>,
    pub tooling_refs: BTreeSet<Reference>,
    pub requested_ceiling: OperatingCeiling,
    pub validity_requirement_refs: BTreeSet<Reference>,
    pub invalidation_dependency_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStatus {
    Pass,
    Fail,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationEvidenceRecord {
    pub evidence_ref: Reference,
    pub subject: QualificationSubject,
    pub plan_identity: QualificationPlanIdentity,
    pub requirement_ref: Reference,
    pub test_method_ref: Reference,
    pub test_run_ref: Reference,
    pub producer_ref: Reference,
    pub provenance_refs: BTreeSet<Reference>,
    pub observed_result_ref: Reference,
    pub environment_evidence_refs: BTreeSet<Reference>,
    pub validity_ref: Reference,
    pub status: EvidenceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCapabilityQualification {
    subject: QualificationSubject,
    plan_identity: QualificationPlanIdentity,
    operation_refs: BTreeSet<Reference>,
    demonstrated_ceiling: OperatingCeiling,
    evidence_refs: BTreeSet<Reference>,
    validity_requirement_refs: BTreeSet<Reference>,
    invalidation_dependency_refs: BTreeSet<Reference>,
    verification_digest: ContentDigest,
}

impl VerifiedCapabilityQualification {
    pub fn subject(&self) -> &QualificationSubject {
        &self.subject
    }

    pub fn plan_identity(&self) -> &QualificationPlanIdentity {
        &self.plan_identity
    }

    pub fn operation_refs(&self) -> &BTreeSet<Reference> {
        &self.operation_refs
    }

    pub fn demonstrated_ceiling(&self) -> OperatingCeiling {
        self.demonstrated_ceiling
    }

    pub fn evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.evidence_refs
    }

    pub fn validity_requirement_refs(&self) -> &BTreeSet<Reference> {
        &self.validity_requirement_refs
    }

    pub fn invalidation_dependency_refs(&self) -> &BTreeSet<Reference> {
        &self.invalidation_dependency_refs
    }

    pub fn verification_digest(&self) -> &ContentDigest {
        &self.verification_digest
    }
}

pub fn qualify_capability(
    manifest: &CapabilityManifest,
    subject: &QualificationSubject,
    plan: &QualificationPlan,
    evidence: &[QualificationEvidenceRecord],
) -> Result<VerifiedCapabilityQualification, QualificationError> {
    validate_manifest(manifest).map_err(|_| QualificationError::ManifestInvalid)?;
    validate_subject(manifest, subject)?;
    validate_plan(manifest, plan)?;

    let mut by_requirement = BTreeMap::<Reference, &QualificationEvidenceRecord>::new();
    let mut evidence_refs = BTreeSet::new();

    for record in evidence {
        validate_evidence_shape(record)?;
        if &record.subject != subject {
            return Err(QualificationError::EvidenceSubjectMismatch(
                record.evidence_ref.to_string(),
            ));
        }
        if record.plan_identity != plan.identity {
            return Err(QualificationError::EvidencePlanMismatch(
                record.evidence_ref.to_string(),
            ));
        }
        if !plan
            .required_evidence_refs
            .contains(&record.requirement_ref)
        {
            return Err(QualificationError::UnexpectedRequirementEvidence(
                record.requirement_ref.to_string(),
            ));
        }
        if !evidence_refs.insert(record.evidence_ref.clone()) {
            return Err(QualificationError::DuplicateEvidenceRef(
                record.evidence_ref.to_string(),
            ));
        }
        if by_requirement
            .insert(record.requirement_ref.clone(), record)
            .is_some()
        {
            return Err(QualificationError::DuplicateRequirementEvidence(
                record.requirement_ref.to_string(),
            ));
        }
    }

    let present: BTreeSet<Reference> = by_requirement.keys().cloned().collect();
    if present != plan.required_evidence_refs {
        return Err(QualificationError::IncompleteEvidenceCoverage);
    }

    for requirement_ref in &plan.required_evidence_refs {
        let record = by_requirement
            .get(requirement_ref)
            .ok_or(QualificationError::IncompleteEvidenceCoverage)?;
        match record.status {
            EvidenceStatus::Pass => {}
            EvidenceStatus::Fail => {
                return Err(QualificationError::RequirementFailed(
                    requirement_ref.to_string(),
                ));
            }
            EvidenceStatus::Indeterminate => {
                return Err(QualificationError::RequirementIndeterminate(
                    requirement_ref.to_string(),
                ));
            }
        }
    }

    let verification_digest =
        compute_capability_qualification_verification_digest(subject, plan, &by_requirement)?;

    Ok(VerifiedCapabilityQualification {
        subject: subject.clone(),
        plan_identity: plan.identity.clone(),
        operation_refs: plan.operation_refs.clone(),
        demonstrated_ceiling: plan.requested_ceiling,
        evidence_refs,
        validity_requirement_refs: plan.validity_requirement_refs.clone(),
        invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
        verification_digest,
    })
}

fn compute_capability_qualification_verification_digest(
    subject: &QualificationSubject,
    plan: &QualificationPlan,
    evidence_by_requirement: &BTreeMap<Reference, &QualificationEvidenceRecord>,
) -> Result<ContentDigest, QualificationError> {
    let mut encoder = Encoder::new();
    encoder.raw(QUALIFICATION_VERIFICATION_DOMAIN);
    encoder.qualification_subject(subject)?;
    encoder.qualification_plan_identity(&plan.identity)?;
    encoder.ref_set(&plan.operation_refs)?;
    encoder.operating_ceiling(plan.requested_ceiling)?;
    encoder.ref_set(&plan.validity_requirement_refs)?;
    encoder.ref_set(&plan.invalidation_dependency_refs)?;
    encoder.count(evidence_by_requirement.len())?;
    for record in evidence_by_requirement.values() {
        encoder.qualification_evidence_record(record)?;
    }
    sha256_digest(&encoder.finish())
}

fn sha256_digest(bytes: &[u8]) -> Result<ContentDigest, QualificationError> {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| QualificationError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| QualificationError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| QualificationError::EncodingFailure)?,
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

    fn count(&mut self, value: usize) -> Result<(), QualificationError> {
        let value = u64::try_from(value).map_err(|_| QualificationError::EncodingFailure)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn scalar(&mut self, value: &str) -> Result<(), QualificationError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn reference(&mut self, value: &Reference) -> Result<(), QualificationError> {
        self.scalar(value.as_str())
    }

    fn version(&mut self, value: &OpaqueVersion) -> Result<(), QualificationError> {
        self.scalar(value.as_str())
    }

    fn digest(&mut self, value: &ContentDigest) -> Result<(), QualificationError> {
        self.reference(&value.algorithm_ref)?;
        self.reference(&value.value)
    }

    fn ref_set(&mut self, values: &BTreeSet<Reference>) -> Result<(), QualificationError> {
        self.count(values.len())?;
        for value in values {
            self.reference(value)?;
        }
        Ok(())
    }

    fn qualification_subject(
        &mut self,
        subject: &QualificationSubject,
    ) -> Result<(), QualificationError> {
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
    ) -> Result<(), QualificationError> {
        self.reference(&identity.plan_ref)?;
        self.version(&identity.plan_version)?;
        self.digest(&identity.plan_digest)
    }

    fn operating_ceiling(&mut self, value: OperatingCeiling) -> Result<(), QualificationError> {
        self.scalar(match value {
            OperatingCeiling::E0ReadOnly => "e0-read-only",
            OperatingCeiling::E1OpaqueWrite => "e1-opaque-write",
            OperatingCeiling::E2DeduplicatedWrite => "e2-deduplicated-write",
            OperatingCeiling::E3ObservableWrite => "e3-observable-write",
            OperatingCeiling::E4CompensatableWrite => "e4-compensatable-write",
            OperatingCeiling::E5SharedAtomic => "e5-shared-atomic",
        })
    }

    fn evidence_status(&mut self, value: EvidenceStatus) -> Result<(), QualificationError> {
        self.scalar(match value {
            EvidenceStatus::Pass => "pass",
            EvidenceStatus::Fail => "fail",
            EvidenceStatus::Indeterminate => "indeterminate",
        })
    }

    fn qualification_evidence_record(
        &mut self,
        record: &QualificationEvidenceRecord,
    ) -> Result<(), QualificationError> {
        self.reference(&record.evidence_ref)?;
        self.qualification_subject(&record.subject)?;
        self.qualification_plan_identity(&record.plan_identity)?;
        self.reference(&record.requirement_ref)?;
        self.reference(&record.test_method_ref)?;
        self.reference(&record.test_run_ref)?;
        self.reference(&record.producer_ref)?;
        self.ref_set(&record.provenance_refs)?;
        self.reference(&record.observed_result_ref)?;
        self.ref_set(&record.environment_evidence_refs)?;
        self.reference(&record.validity_ref)?;
        self.evidence_status(record.status)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn validate_subject(
    manifest: &CapabilityManifest,
    subject: &QualificationSubject,
) -> Result<(), QualificationError> {
    if subject.capability_ref != manifest.capability_ref
        || subject.capability_version != manifest.capability_version
        || subject.manifest_digest != manifest.content_digest
        || subject.artifact_ref != manifest.artifact_ref
        || subject.adapter_ref != manifest.adapter_ref
        || subject.adapter_version != manifest.adapter_version
    {
        return Err(QualificationError::SubjectManifestMismatch);
    }
    Ok(())
}

fn validate_plan(
    manifest: &CapabilityManifest,
    plan: &QualificationPlan,
) -> Result<(), QualificationError> {
    if plan.operation_refs.is_empty()
        || plan.required_evidence_refs.is_empty()
        || plan.evaluation_corpus_refs.is_empty()
        || plan.tooling_refs.is_empty()
        || plan.validity_requirement_refs.is_empty()
        || plan.invalidation_dependency_refs.is_empty()
    {
        return Err(QualificationError::InvalidPlan);
    }

    let manifest_operations: BTreeSet<Reference> = manifest
        .operations
        .iter()
        .map(|operation| operation.operation_ref.clone())
        .collect();
    if !plan.operation_refs.is_subset(&manifest_operations) {
        return Err(QualificationError::PlanOperationOutsideManifest);
    }

    if !manifest
        .qualification_requirement_refs
        .is_subset(&plan.required_evidence_refs)
    {
        return Err(QualificationError::PlanDropsManifestRequirement);
    }

    let mandatory_claim_evidence = scoped_claim_evidence_requirements(manifest, plan);
    if let Some(missing) = mandatory_claim_evidence
        .iter()
        .find(|requirement| !plan.required_evidence_refs.contains(*requirement))
    {
        return Err(QualificationError::PlanDropsOperationClaimRequirement(
            missing.to_string(),
        ));
    }

    validate_claim_compatibility(manifest, plan)?;
    Ok(())
}

fn scoped_claim_evidence_requirements(
    manifest: &CapabilityManifest,
    plan: &QualificationPlan,
) -> BTreeSet<Reference> {
    let mut required = BTreeSet::new();
    for operation in manifest
        .operations
        .iter()
        .filter(|operation| plan.operation_refs.contains(&operation.operation_ref))
    {
        required.extend(operation.risk.evidence_requirement_refs.iter().cloned());
        required.extend(
            operation
                .resource_cost
                .evidence_requirement_refs
                .iter()
                .cloned(),
        );
        required.extend(
            operation
                .failure_recovery
                .evidence_requirement_refs
                .iter()
                .cloned(),
        );
        match &operation.risk.reversibility {
            ReversibilityClaim::Reversible {
                evidence_requirement_refs,
                ..
            }
            | ReversibilityClaim::Compensatable {
                evidence_requirement_refs,
                ..
            }
            | ReversibilityClaim::Irreversible {
                evidence_requirement_refs,
            } => required.extend(evidence_requirement_refs.iter().cloned()),
            ReversibilityClaim::NotApplicable | ReversibilityClaim::Unknown => {}
        }
        extend_support_evidence(&mut required, &operation.idempotency.support);
        extend_support_evidence(&mut required, &operation.status_query);
        extend_support_evidence(&mut required, &operation.cancellation);
        extend_support_evidence(&mut required, &operation.compensation);
        extend_support_evidence(&mut required, &operation.retry);
        extend_support_evidence(&mut required, &operation.shared_atomicity);
    }
    required
}

fn extend_support_evidence(target: &mut BTreeSet<Reference>, claim: &SupportClaim) {
    if let SupportClaim::Supported {
        evidence_requirement_refs,
        ..
    } = claim
    {
        target.extend(evidence_requirement_refs.iter().cloned());
    }
}

fn validate_claim_compatibility(
    manifest: &CapabilityManifest,
    plan: &QualificationPlan,
) -> Result<(), QualificationError> {
    let scoped: Vec<_> = manifest
        .operations
        .iter()
        .filter(|operation| plan.operation_refs.contains(&operation.operation_ref))
        .collect();
    let mutating: Vec<_> = scoped
        .iter()
        .copied()
        .filter(|operation| {
            operation.effect.external_state_change == ExternalStateChange::MayMutate
        })
        .collect();

    let compatible = match plan.requested_ceiling {
        OperatingCeiling::E0ReadOnly => mutating.is_empty(),
        OperatingCeiling::E1OpaqueWrite => !mutating.is_empty(),
        OperatingCeiling::E2DeduplicatedWrite => {
            !mutating.is_empty()
                && mutating
                    .iter()
                    .all(|operation| operation.idempotency.support.is_supported())
        }
        OperatingCeiling::E3ObservableWrite => {
            !mutating.is_empty()
                && mutating.iter().all(|operation| {
                    operation.idempotency.support.is_supported()
                        && operation.status_query.is_supported()
                })
        }
        OperatingCeiling::E4CompensatableWrite => {
            !mutating.is_empty()
                && mutating.iter().all(|operation| {
                    operation.idempotency.support.is_supported()
                        && operation.status_query.is_supported()
                        && operation.compensation.is_supported()
                        && matches!(
                            operation.risk.reversibility,
                            ReversibilityClaim::Compensatable { .. }
                        )
                })
        }
        OperatingCeiling::E5SharedAtomic => {
            !mutating.is_empty()
                && mutating
                    .iter()
                    .all(|operation| operation.shared_atomicity.is_supported())
        }
    };

    if !compatible {
        return Err(QualificationError::CeilingContradictsManifestClaims);
    }
    Ok(())
}

fn validate_evidence_shape(record: &QualificationEvidenceRecord) -> Result<(), QualificationError> {
    if record.provenance_refs.is_empty() || record.environment_evidence_refs.is_empty() {
        return Err(QualificationError::EvidenceMissingProvenanceOrEnvironment(
            record.evidence_ref.to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualificationError {
    ManifestInvalid,
    SubjectManifestMismatch,
    InvalidPlan,
    PlanOperationOutsideManifest,
    PlanDropsManifestRequirement,
    PlanDropsOperationClaimRequirement(String),
    CeilingContradictsManifestClaims,
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

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capability qualification rejected: {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        CapabilityDependency, CapabilityFieldRole, CapabilityOperation, EffectClaim,
        EnvironmentRequirements, FailureRecoveryContract, FreshnessRequirements, IdempotencyClaim,
        OperationConditions, OperationRiskContract, OperationSchema, OutboundDisclosure,
        OutcomeObservationContract, ResourceCostContract, SchemaExtensionPolicy, SchemaField,
        TargetBindingRequirements,
    };

    fn r(value: &str) -> Reference {
        Reference::new(value).unwrap()
    }

    fn v(value: &str) -> OpaqueVersion {
        OpaqueVersion::new(value).unwrap()
    }

    fn refs(values: &[&str]) -> BTreeSet<Reference> {
        values.iter().map(|value| r(value)).collect()
    }

    fn supported(name: &str) -> SupportClaim {
        SupportClaim::Supported {
            contract_ref: r(&alloc::format!("contract:{name}")),
            evidence_requirement_refs: refs(&[&alloc::format!("evidence:{name}")]),
        }
    }

    fn schema(name: &str, output: bool) -> OperationSchema {
        OperationSchema {
            schema_ref: r(&alloc::format!("schema:{name}")),
            fields: alloc::vec![SchemaField {
                field_ref: r(&alloc::format!("field:{name}")),
                schema_ref: r("schema:string"),
                role: if output {
                    CapabilityFieldRole::EvidenceReference
                } else {
                    CapabilityFieldRole::Data
                },
                required: true,
            }],
            extension_policy: SchemaExtensionPolicy::Closed,
        }
    }

    fn operation() -> CapabilityOperation {
        CapabilityOperation {
            operation_ref: r("operation:send"),
            purpose_ref: r("purpose:send"),
            description_ref: r("description:send"),
            input: schema("in", false),
            output: schema("out", true),
            conditions: OperationConditions {
                precondition_refs: refs(&["precondition:target-current"]),
                postcondition_refs: refs(&["postcondition:provider-result-captured"]),
            },
            effect: EffectClaim {
                external_state_change: ExternalStateChange::MayMutate,
                outbound_disclosure: OutboundDisclosure::MayDisclose,
                effect_semantics_ref: r("effect:write"),
                target_binding: TargetBindingRequirements {
                    resource_binding_ref: None,
                    account_binding_ref: Some(r("binding:account")),
                    principal_binding_ref: Some(r("binding:recipient")),
                },
                outcome_observation: OutcomeObservationContract {
                    observation_method_ref: r("observation:status"),
                    evidence_schema_ref: r("schema:receipt"),
                },
            },
            risk: OperationRiskContract {
                risk_class_refs: refs(&["risk:external-write"]),
                consequence_model_ref: r("consequence:model-send"),
                reversibility: ReversibilityClaim::Unknown,
                evidence_requirement_refs: refs(&["evidence:risk"]),
            },
            resource_cost: ResourceCostContract {
                resource_estimate_refs: refs(&["resource-estimate:send"]),
                cost_model_ref: r("cost-model:provider-send"),
                evidence_requirement_refs: refs(&["evidence:resource-cost"]),
            },
            failure_recovery: FailureRecoveryContract {
                failure_mode_refs: refs(&["failure:acceptance-unknown"]),
                recovery_strategy_refs: refs(&["recovery:reconcile"]),
                ambiguity_handling_ref: r("ambiguity:preserve"),
                evidence_requirement_refs: refs(&["evidence:recovery"]),
            },
            accessed_data_class_refs: refs(&["data:message"]),
            disclosed_data_class_refs: refs(&["data:message"]),
            required_permission_scope_refs: refs(&["permission:send"]),
            principal_requirement_refs: refs(&["principal:authenticated"]),
            workload_requirement_refs: refs(&["workload:adapter"]),
            environment: EnvironmentRequirements {
                sandbox_profile_ref: Some(r("sandbox:adapter")),
                filesystem_scope_refs: BTreeSet::new(),
                network_destination_refs: refs(&["network:provider"]),
                device_capability_refs: BTreeSet::new(),
                resource_limit_refs: refs(&["resource:bounded"]),
            },
            idempotency: IdempotencyClaim {
                support: supported("idempotency"),
                key_binding_ref: Some(r("binding:effect")),
                retention_requirement_ref: Some(r("retention:dedup")),
            },
            status_query: supported("status"),
            cancellation: supported("cancel"),
            compensation: SupportClaim::Unsupported,
            retry: supported("retry"),
            shared_atomicity: SupportClaim::Unsupported,
            timeout_requirement_ref: r("timeout:provider"),
            freshness: FreshnessRequirements {
                version_requirement_refs: refs(&["version:manifest", "version:adapter"]),
                stale_call_rejection_ref: r("freshness:reject"),
                maximum_request_age_ref: Some(r("age:provider")),
            },
        }
    }

    fn manifest() -> CapabilityManifest {
        CapabilityManifest {
            capability_ref: r("capability:send"),
            capability_version: v("provider/capability@opaque-7"),
            content_digest: ContentDigest {
                algorithm_ref: r("digest:sha-256"),
                value: r("sha256:manifest-a"),
            },
            publisher_ref: r("publisher:a"),
            issuer_ref: r("issuer:a"),
            source_ref: r("source:a"),
            artifact_ref: r("artifact:adapter-a"),
            adapter_ref: r("adapter:a"),
            adapter_version: v("adapter/build+opaque"),
            provenance_refs: refs(&["provenance:source", "provenance:build"]),
            dependencies: alloc::vec![CapabilityDependency {
                dependency_ref: r("dependency:transport"),
                version_requirement_ref: r("requirement:dep-version"),
                integrity_requirement_ref: r("requirement:dep-integrity"),
                risk_evidence_requirement_refs: refs(&["evidence:dep-risk"]),
            }],
            operations: alloc::vec![operation()],
            qualification_requirement_refs: refs(&[
                "qualification:schema",
                "qualification:sandbox",
                "qualification:effects",
            ]),
        }
    }

    fn subject(manifest: &CapabilityManifest) -> QualificationSubject {
        QualificationSubject::from_manifest(
            manifest,
            r("environment:linux-a"),
            v("env/opaque-3"),
            ContentDigest {
                algorithm_ref: r("digest:sha-256"),
                value: r("sha256:environment-profile-d1"),
            },
        )
    }

    fn plan() -> QualificationPlan {
        QualificationPlan {
            identity: QualificationPlanIdentity {
                plan_ref: r("plan:s05-send"),
                plan_version: v("plan/2026-09+locked"),
                plan_digest: ContentDigest {
                    algorithm_ref: r("digest:sha-256"),
                    value: r("sha256:plan-a"),
                },
            },
            operation_refs: refs(&["operation:send"]),
            required_evidence_refs: refs(&[
                "qualification:schema",
                "qualification:sandbox",
                "qualification:effects",
                "qualification:adversarial-output",
                "evidence:risk",
                "evidence:resource-cost",
                "evidence:recovery",
                "evidence:idempotency",
                "evidence:status",
                "evidence:cancel",
                "evidence:retry",
            ]),
            evaluation_corpus_refs: refs(&["eval:capability-heldout-a"]),
            tooling_refs: refs(&["tool:conformance-runner-a"]),
            requested_ceiling: OperatingCeiling::E3ObservableWrite,
            validity_requirement_refs: refs(&["validity:current-security-review"]),
            invalidation_dependency_refs: refs(&[
                "invalidate:manifest-change",
                "invalidate:adapter-change",
                "invalidate:environment-change",
            ]),
        }
    }

    fn evidence(
        subject: &QualificationSubject,
        plan: &QualificationPlan,
    ) -> Vec<QualificationEvidenceRecord> {
        plan.required_evidence_refs
            .iter()
            .map(|requirement| QualificationEvidenceRecord {
                evidence_ref: r(&alloc::format!("evidence:run:{}", requirement.as_str())),
                subject: subject.clone(),
                plan_identity: plan.identity.clone(),
                requirement_ref: requirement.clone(),
                test_method_ref: r("method:adversarial-conformance"),
                test_run_ref: r("run:immutable-a"),
                producer_ref: r("producer:qualification-harness"),
                provenance_refs: refs(&["provenance:test-run"]),
                observed_result_ref: r("result:pass"),
                environment_evidence_refs: refs(&["environment-evidence:linux-a"]),
                validity_ref: r("validity:test-window-a"),
                status: EvidenceStatus::Pass,
            })
            .collect()
    }

    #[test]
    fn exact_subject_and_total_passing_plan_issue_verified_ceiling() {
        let manifest = manifest();
        let subject = subject(&manifest);
        let plan = plan();
        let records = evidence(&subject, &plan);
        let verified = qualify_capability(&manifest, &subject, &plan, &records).unwrap();
        assert_eq!(verified.subject(), &subject);
        assert_eq!(
            verified.demonstrated_ceiling(),
            OperatingCeiling::E3ObservableWrite
        );
        assert_eq!(
            verified.evidence_refs().len(),
            plan.required_evidence_refs.len()
        );
    }

    #[test]
    fn plan_cannot_drop_operation_claim_evidence() {
        let manifest = manifest();
        let subject = subject(&manifest);
        let mut plan = plan();
        plan.required_evidence_refs.remove(&r("evidence:status"));
        let records = evidence(&subject, &plan);
        assert_eq!(
            qualify_capability(&manifest, &subject, &plan, &records),
            Err(QualificationError::PlanDropsOperationClaimRequirement(
                "evidence:status".into()
            ))
        );
    }

    #[test]
    fn manifest_or_adapter_subject_substitution_fails_closed() {
        let manifest = manifest();
        let mut subject = subject(&manifest);
        subject.adapter_version = v("adapter/changed");
        let plan = plan();
        let records = evidence(&subject, &plan);
        assert_eq!(
            qualify_capability(&manifest, &subject, &plan, &records),
            Err(QualificationError::SubjectManifestMismatch)
        );
    }

    #[test]
    fn evidence_from_another_environment_cannot_be_replayed() {
        let manifest = manifest();
        let subject = subject(&manifest);
        let plan = plan();
        let mut records = evidence(&subject, &plan);
        records[0].subject.environment_version = v("env/other");
        assert!(matches!(
            qualify_capability(&manifest, &subject, &plan, &records),
            Err(QualificationError::EvidenceSubjectMismatch(_))
        ));
    }

    #[test]
    fn evidence_from_same_environment_alias_with_different_content_digest_cannot_replay() {
        let manifest = manifest();
        let subject = QualificationSubject::from_manifest(
            &manifest,
            r("environment:linux-a"),
            v("env/opaque-3"),
            ContentDigest {
                algorithm_ref: r("digest:sha-256"),
                value: r("sha256:environment-profile-d1"),
            },
        );
        let plan = plan();
        let mut records = evidence(&subject, &plan);
        records[0].subject.environment_digest = ContentDigest {
            algorithm_ref: r("digest:sha-256"),
            value: r("sha256:environment-profile-d2"),
        };

        assert!(matches!(
            qualify_capability(&manifest, &subject, &plan, &records),
            Err(QualificationError::EvidenceSubjectMismatch(_))
        ));
    }

    #[test]
    fn failed_or_indeterminate_requirement_never_qualifies() {
        for status in [EvidenceStatus::Fail, EvidenceStatus::Indeterminate] {
            let manifest = manifest();
            let subject = subject(&manifest);
            let plan = plan();
            let mut records = evidence(&subject, &plan);
            records[0].status = status;
            assert!(qualify_capability(&manifest, &subject, &plan, &records).is_err());
        }
    }

    #[test]
    fn missing_or_duplicate_requirement_evidence_never_qualifies() {
        let manifest = manifest();
        let subject = subject(&manifest);
        let plan = plan();
        let mut records = evidence(&subject, &plan);
        records.pop();
        assert_eq!(
            qualify_capability(&manifest, &subject, &plan, &records),
            Err(QualificationError::IncompleteEvidenceCoverage)
        );

        let mut records = evidence(&subject, &plan);
        let mut duplicate = records[0].clone();
        duplicate.evidence_ref = r("evidence:distinct-id-same-requirement");
        records.push(duplicate);
        assert!(matches!(
            qualify_capability(&manifest, &subject, &plan, &records),
            Err(QualificationError::DuplicateRequirementEvidence(_))
        ));
    }

    #[test]
    fn plan_cannot_drop_manifest_required_qualification() {
        let manifest = manifest();
        let subject = subject(&manifest);
        let mut plan = plan();
        plan.required_evidence_refs
            .remove(&r("qualification:effects"));
        let records = evidence(&subject, &plan);
        assert_eq!(
            qualify_capability(&manifest, &subject, &plan, &records),
            Err(QualificationError::PlanDropsManifestRequirement)
        );
    }

    #[test]
    fn plan_cannot_claim_operations_outside_exact_manifest() {
        let manifest = manifest();
        let subject = subject(&manifest);
        let mut plan = plan();
        plan.operation_refs.insert(r("operation:not-in-manifest"));
        let records = evidence(&subject, &plan);
        assert_eq!(
            qualify_capability(&manifest, &subject, &plan, &records),
            Err(QualificationError::PlanOperationOutsideManifest)
        );
    }

    #[test]
    fn operating_class_cannot_exceed_even_the_manifest_claim_surface() {
        let mut manifest = manifest();
        let initial_subject = subject(&manifest);
        let mut plan = plan();
        plan.requested_ceiling = OperatingCeiling::E5SharedAtomic;
        let records = evidence(&initial_subject, &plan);
        assert_eq!(
            qualify_capability(&manifest, &initial_subject, &plan, &records),
            Err(QualificationError::CeilingContradictsManifestClaims)
        );

        manifest.operations[0].shared_atomicity = supported("shared-atomic");
        plan.required_evidence_refs
            .insert(r("evidence:shared-atomic"));
        let updated_subject = subject(&manifest);
        let records = evidence(&updated_subject, &plan);
        assert!(qualify_capability(&manifest, &updated_subject, &plan, &records).is_ok());
    }

    #[test]
    fn e4_requires_explicit_compensatable_reversibility_not_only_a_compensation_method() {
        let mut manifest = manifest();
        manifest.operations[0].compensation = supported("compensation");
        let initial_subject = subject(&manifest);
        let mut plan = plan();
        plan.requested_ceiling = OperatingCeiling::E4CompensatableWrite;
        plan.required_evidence_refs
            .insert(r("evidence:compensation"));
        let records = evidence(&initial_subject, &plan);
        assert_eq!(
            qualify_capability(&manifest, &initial_subject, &plan, &records),
            Err(QualificationError::CeilingContradictsManifestClaims)
        );

        manifest.operations[0].risk.reversibility = ReversibilityClaim::Compensatable {
            contract_ref: r("reversibility:compensatable"),
            evidence_requirement_refs: refs(&["evidence:reversibility"]),
        };
        plan.required_evidence_refs
            .insert(r("evidence:reversibility"));
        let updated_subject = subject(&manifest);
        let records = evidence(&updated_subject, &plan);
        assert!(qualify_capability(&manifest, &updated_subject, &plan, &records).is_ok());
    }

    #[test]
    fn evidence_without_provenance_or_environment_is_not_a_pass() {
        let manifest = manifest();
        let subject = subject(&manifest);
        let plan = plan();
        let mut records = evidence(&subject, &plan);
        records[0].provenance_refs.clear();
        assert!(matches!(
            qualify_capability(&manifest, &subject, &plan, &records),
            Err(QualificationError::EvidenceMissingProvenanceOrEnvironment(
                _
            ))
        ));
    }

    #[test]
    fn s05_capability_qualification_identity_changes_when_leaf_evidence_content_changes() {
        let manifest = manifest();
        let subject = subject(&manifest);
        let plan = plan();

        let first_records = evidence(&subject, &plan);
        let mut second_records = first_records.clone();
        second_records[0].test_run_ref = r("run:immutable-b");
        second_records[0].observed_result_ref = r("result:pass-recomputed");

        let first = qualify_capability(&manifest, &subject, &plan, &first_records).unwrap();
        let second = qualify_capability(&manifest, &subject, &plan, &second_records).unwrap();

        assert_eq!(first.evidence_refs(), second.evidence_refs());
        assert_ne!(
            first.verification_digest(),
            second.verification_digest(),
            "same logical evidence refs must not hide different capability evidence content",
        );
    }
}
