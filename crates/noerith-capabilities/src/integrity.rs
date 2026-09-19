extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

use crate::manifest::{
    CapabilityDependency, CapabilityFieldRole, CapabilityManifest, CapabilityOperation,
    ContentDigest, EffectClaim, EnvironmentRequirements, ExternalStateChange,
    FailureRecoveryContract, FreshnessRequirements, IdempotencyClaim, OpaqueVersion,
    OperationConditions, OperationRiskContract, OperationSchema, OutboundDisclosure, Reference,
    ResourceCostContract, ReversibilityClaim, SchemaExtensionPolicy, SchemaField, SupportClaim,
    TargetBindingRequirements, validate_manifest,
};

pub const MANIFEST_CANONICAL_PROFILE: &str = "NOERITH/CAPABILITY-MANIFEST/CANONICAL-2026-09";
pub const SHA256_ALGORITHM_REF: &str = "digest:sha-256";
const DOMAIN: &[u8] = b"NOERITH\0CAPABILITY-MANIFEST\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifestIntegrity {
    capability_ref: Reference,
    capability_version: OpaqueVersion,
    content_digest: ContentDigest,
    canonical_profile_ref: &'static str,
}

impl VerifiedManifestIntegrity {
    pub fn capability_ref(&self) -> &Reference {
        &self.capability_ref
    }

    pub fn capability_version(&self) -> &OpaqueVersion {
        &self.capability_version
    }

    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

pub fn compute_manifest_digest(
    manifest: &CapabilityManifest,
) -> Result<ContentDigest, IntegrityError> {
    validate_manifest(manifest).map_err(|_| IntegrityError::ManifestInvalid)?;
    let transcript = canonical_manifest_transcript(manifest)?;
    let digest = Sha256::digest(&transcript);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").map_err(|_| IntegrityError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(SHA256_ALGORITHM_REF)
            .map_err(|_| IntegrityError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| IntegrityError::EncodingFailure)?,
    })
}

pub fn verify_manifest_integrity(
    manifest: &CapabilityManifest,
) -> Result<VerifiedManifestIntegrity, IntegrityError> {
    if manifest.content_digest.algorithm_ref.as_str() != SHA256_ALGORITHM_REF {
        return Err(IntegrityError::UnsupportedDigestAlgorithm(
            manifest.content_digest.algorithm_ref.to_string(),
        ));
    }
    let computed = compute_manifest_digest(manifest)?;
    if computed != manifest.content_digest {
        return Err(IntegrityError::DigestMismatch);
    }
    Ok(VerifiedManifestIntegrity {
        capability_ref: manifest.capability_ref.clone(),
        capability_version: manifest.capability_version.clone(),
        content_digest: computed,
        canonical_profile_ref: MANIFEST_CANONICAL_PROFILE,
    })
}

pub fn canonical_manifest_transcript(
    manifest: &CapabilityManifest,
) -> Result<Vec<u8>, IntegrityError> {
    validate_manifest(manifest).map_err(|_| IntegrityError::ManifestInvalid)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);
    encode_reference(&mut encoder, &manifest.capability_ref)?;
    encode_version(&mut encoder, &manifest.capability_version)?;
    encode_reference(&mut encoder, &manifest.publisher_ref)?;
    encode_reference(&mut encoder, &manifest.issuer_ref)?;
    encode_reference(&mut encoder, &manifest.source_ref)?;
    encode_reference(&mut encoder, &manifest.artifact_ref)?;
    encode_reference(&mut encoder, &manifest.adapter_ref)?;
    encode_version(&mut encoder, &manifest.adapter_version)?;
    encode_ref_set(&mut encoder, &manifest.provenance_refs)?;

    let mut dependencies: Vec<&CapabilityDependency> = manifest.dependencies.iter().collect();
    dependencies.sort_by(|left, right| left.dependency_ref.cmp(&right.dependency_ref));
    encoder.count(dependencies.len())?;
    for dependency in dependencies {
        encode_dependency(&mut encoder, dependency)?;
    }

    let mut operations: Vec<&CapabilityOperation> = manifest.operations.iter().collect();
    operations.sort_by(|left, right| left.operation_ref.cmp(&right.operation_ref));
    encoder.count(operations.len())?;
    for operation in operations {
        encode_operation(&mut encoder, operation)?;
    }

    encode_ref_set(&mut encoder, &manifest.qualification_requirement_refs)?;
    Ok(encoder.finish())
}

fn encode_dependency(
    encoder: &mut Encoder,
    dependency: &CapabilityDependency,
) -> Result<(), IntegrityError> {
    encode_reference(encoder, &dependency.dependency_ref)?;
    encode_reference(encoder, &dependency.version_requirement_ref)?;
    encode_reference(encoder, &dependency.integrity_requirement_ref)?;
    encode_ref_set(encoder, &dependency.risk_evidence_requirement_refs)
}

fn encode_operation(
    encoder: &mut Encoder,
    operation: &CapabilityOperation,
) -> Result<(), IntegrityError> {
    encode_reference(encoder, &operation.operation_ref)?;
    encode_reference(encoder, &operation.purpose_ref)?;
    encode_reference(encoder, &operation.description_ref)?;
    encode_schema(encoder, &operation.input)?;
    encode_schema(encoder, &operation.output)?;
    encode_conditions(encoder, &operation.conditions)?;
    encode_effect(encoder, &operation.effect)?;
    encode_risk(encoder, &operation.risk)?;
    encode_resource_cost(encoder, &operation.resource_cost)?;
    encode_failure_recovery(encoder, &operation.failure_recovery)?;
    encode_ref_set(encoder, &operation.accessed_data_class_refs)?;
    encode_ref_set(encoder, &operation.disclosed_data_class_refs)?;
    encode_ref_set(encoder, &operation.required_permission_scope_refs)?;
    encode_ref_set(encoder, &operation.principal_requirement_refs)?;
    encode_ref_set(encoder, &operation.workload_requirement_refs)?;
    encode_environment(encoder, &operation.environment)?;
    encode_idempotency(encoder, &operation.idempotency)?;
    encode_support(encoder, &operation.status_query)?;
    encode_support(encoder, &operation.cancellation)?;
    encode_support(encoder, &operation.compensation)?;
    encode_support(encoder, &operation.retry)?;
    encode_support(encoder, &operation.shared_atomicity)?;
    encode_reference(encoder, &operation.timeout_requirement_ref)?;
    encode_freshness(encoder, &operation.freshness)
}

fn encode_schema(encoder: &mut Encoder, schema: &OperationSchema) -> Result<(), IntegrityError> {
    encode_reference(encoder, &schema.schema_ref)?;
    let mut fields: Vec<&SchemaField> = schema.fields.iter().collect();
    fields.sort_by(|left, right| left.field_ref.cmp(&right.field_ref));
    encoder.count(fields.len())?;
    for field in fields {
        encode_reference(encoder, &field.field_ref)?;
        encode_reference(encoder, &field.schema_ref)?;
        encoder.tag(match field.role {
            CapabilityFieldRole::Data => 0,
            CapabilityFieldRole::AuthorityReference => 1,
            CapabilityFieldRole::EvidenceReference => 2,
            CapabilityFieldRole::SecretHandleReference => 3,
        });
        encoder.bool(field.required);
    }
    match &schema.extension_policy {
        SchemaExtensionPolicy::Closed => encoder.tag(0),
        SchemaExtensionPolicy::Namespaced {
            extension_schema_refs,
        } => {
            encoder.tag(1);
            encode_ref_set(encoder, extension_schema_refs)?;
        }
    }
    Ok(())
}

fn encode_conditions(
    encoder: &mut Encoder,
    conditions: &OperationConditions,
) -> Result<(), IntegrityError> {
    encode_ref_set(encoder, &conditions.precondition_refs)?;
    encode_ref_set(encoder, &conditions.postcondition_refs)
}

fn encode_effect(encoder: &mut Encoder, effect: &EffectClaim) -> Result<(), IntegrityError> {
    encoder.tag(match effect.external_state_change {
        ExternalStateChange::None => 0,
        ExternalStateChange::MayMutate => 1,
    });
    encoder.tag(match effect.outbound_disclosure {
        OutboundDisclosure::None => 0,
        OutboundDisclosure::MayDisclose => 1,
    });
    encode_reference(encoder, &effect.effect_semantics_ref)?;
    encode_target_binding(encoder, &effect.target_binding)?;
    encode_reference(encoder, &effect.outcome_observation.observation_method_ref)?;
    encode_reference(encoder, &effect.outcome_observation.evidence_schema_ref)
}

fn encode_risk(encoder: &mut Encoder, risk: &OperationRiskContract) -> Result<(), IntegrityError> {
    encode_ref_set(encoder, &risk.risk_class_refs)?;
    encode_reference(encoder, &risk.consequence_model_ref)?;
    encode_reversibility(encoder, &risk.reversibility)?;
    encode_ref_set(encoder, &risk.evidence_requirement_refs)
}

fn encode_reversibility(
    encoder: &mut Encoder,
    claim: &ReversibilityClaim,
) -> Result<(), IntegrityError> {
    match claim {
        ReversibilityClaim::NotApplicable => encoder.tag(0),
        ReversibilityClaim::Unknown => encoder.tag(1),
        ReversibilityClaim::Reversible {
            contract_ref,
            evidence_requirement_refs,
        } => {
            encoder.tag(2);
            encode_reference(encoder, contract_ref)?;
            encode_ref_set(encoder, evidence_requirement_refs)?;
        }
        ReversibilityClaim::Compensatable {
            contract_ref,
            evidence_requirement_refs,
        } => {
            encoder.tag(3);
            encode_reference(encoder, contract_ref)?;
            encode_ref_set(encoder, evidence_requirement_refs)?;
        }
        ReversibilityClaim::Irreversible {
            evidence_requirement_refs,
        } => {
            encoder.tag(4);
            encode_ref_set(encoder, evidence_requirement_refs)?;
        }
    }
    Ok(())
}

fn encode_resource_cost(
    encoder: &mut Encoder,
    contract: &ResourceCostContract,
) -> Result<(), IntegrityError> {
    encode_ref_set(encoder, &contract.resource_estimate_refs)?;
    encode_reference(encoder, &contract.cost_model_ref)?;
    encode_ref_set(encoder, &contract.evidence_requirement_refs)
}

fn encode_failure_recovery(
    encoder: &mut Encoder,
    contract: &FailureRecoveryContract,
) -> Result<(), IntegrityError> {
    encode_ref_set(encoder, &contract.failure_mode_refs)?;
    encode_ref_set(encoder, &contract.recovery_strategy_refs)?;
    encode_reference(encoder, &contract.ambiguity_handling_ref)?;
    encode_ref_set(encoder, &contract.evidence_requirement_refs)
}

fn encode_target_binding(
    encoder: &mut Encoder,
    binding: &TargetBindingRequirements,
) -> Result<(), IntegrityError> {
    encode_optional_ref(encoder, binding.resource_binding_ref.as_ref())?;
    encode_optional_ref(encoder, binding.account_binding_ref.as_ref())?;
    encode_optional_ref(encoder, binding.principal_binding_ref.as_ref())
}

fn encode_environment(
    encoder: &mut Encoder,
    environment: &EnvironmentRequirements,
) -> Result<(), IntegrityError> {
    encode_optional_ref(encoder, environment.sandbox_profile_ref.as_ref())?;
    encode_ref_set(encoder, &environment.filesystem_scope_refs)?;
    encode_ref_set(encoder, &environment.network_destination_refs)?;
    encode_ref_set(encoder, &environment.device_capability_refs)?;
    encode_ref_set(encoder, &environment.resource_limit_refs)
}

fn encode_idempotency(
    encoder: &mut Encoder,
    claim: &IdempotencyClaim,
) -> Result<(), IntegrityError> {
    encode_support(encoder, &claim.support)?;
    encode_optional_ref(encoder, claim.key_binding_ref.as_ref())?;
    encode_optional_ref(encoder, claim.retention_requirement_ref.as_ref())
}

fn encode_support(encoder: &mut Encoder, claim: &SupportClaim) -> Result<(), IntegrityError> {
    match claim {
        SupportClaim::Unknown => encoder.tag(0),
        SupportClaim::Unsupported => encoder.tag(1),
        SupportClaim::Supported {
            contract_ref,
            evidence_requirement_refs,
        } => {
            encoder.tag(2);
            encode_reference(encoder, contract_ref)?;
            encode_ref_set(encoder, evidence_requirement_refs)?;
        }
    }
    Ok(())
}

fn encode_freshness(
    encoder: &mut Encoder,
    freshness: &FreshnessRequirements,
) -> Result<(), IntegrityError> {
    encode_ref_set(encoder, &freshness.version_requirement_refs)?;
    encode_reference(encoder, &freshness.stale_call_rejection_ref)?;
    encode_optional_ref(encoder, freshness.maximum_request_age_ref.as_ref())
}

fn encode_optional_ref(
    encoder: &mut Encoder,
    value: Option<&Reference>,
) -> Result<(), IntegrityError> {
    match value {
        None => encoder.tag(0),
        Some(reference) => {
            encoder.tag(1);
            encode_reference(encoder, reference)?;
        }
    }
    Ok(())
}

fn encode_ref_set(
    encoder: &mut Encoder,
    values: &alloc::collections::BTreeSet<Reference>,
) -> Result<(), IntegrityError> {
    encoder.count(values.len())?;
    for value in values {
        encode_reference(encoder, value)?;
    }
    Ok(())
}

fn encode_reference(encoder: &mut Encoder, value: &Reference) -> Result<(), IntegrityError> {
    encoder.text(value.as_str())
}

fn encode_version(encoder: &mut Encoder, value: &OpaqueVersion) -> Result<(), IntegrityError> {
    encoder.text(value.as_str())
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

    fn tag(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn bool(&mut self, value: bool) {
        self.tag(u8::from(value));
    }

    fn count(&mut self, value: usize) -> Result<(), IntegrityError> {
        let value = u64::try_from(value).map_err(|_| IntegrityError::LengthOverflow)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), IntegrityError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    ManifestInvalid,
    UnsupportedDigestAlgorithm(String),
    DigestMismatch,
    LengthOverflow,
    EncodingFailure,
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "capability manifest integrity rejected: {self:?}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        CapabilityDependency, EnvironmentRequirements, FailureRecoveryContract, IdempotencyClaim,
        OperationConditions, OperationRiskContract, OutcomeObservationContract,
        ResourceCostContract, ReversibilityClaim,
    };
    use alloc::collections::BTreeSet;

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

    fn operation(operation_ref: &str, field_ref: &str) -> CapabilityOperation {
        CapabilityOperation {
            operation_ref: r(operation_ref),
            purpose_ref: r("purpose:test"),
            description_ref: r("description:test"),
            input: OperationSchema {
                schema_ref: r("schema:input"),
                fields: alloc::vec![SchemaField {
                    field_ref: r(field_ref),
                    schema_ref: r("schema:string"),
                    role: CapabilityFieldRole::Data,
                    required: true,
                }],
                extension_policy: SchemaExtensionPolicy::Closed,
            },
            output: OperationSchema {
                schema_ref: r("schema:output"),
                fields: alloc::vec![SchemaField {
                    field_ref: r("field:evidence"),
                    schema_ref: r("schema:evidence"),
                    role: CapabilityFieldRole::EvidenceReference,
                    required: true,
                }],
                extension_policy: SchemaExtensionPolicy::Closed,
            },
            conditions: OperationConditions {
                precondition_refs: refs(&["precondition:current-target"]),
                postcondition_refs: refs(&["postcondition:result-captured"]),
            },
            effect: EffectClaim {
                external_state_change: ExternalStateChange::MayMutate,
                outbound_disclosure: OutboundDisclosure::MayDisclose,
                effect_semantics_ref: r("effect:external-write"),
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
                consequence_model_ref: r("consequence:model-a"),
                reversibility: ReversibilityClaim::Unknown,
                evidence_requirement_refs: refs(&["evidence:risk"]),
            },
            resource_cost: ResourceCostContract {
                resource_estimate_refs: refs(&["resource-estimate:bounded"]),
                cost_model_ref: r("cost-model:provider-a"),
                evidence_requirement_refs: refs(&["evidence:resource-cost"]),
            },
            failure_recovery: FailureRecoveryContract {
                failure_mode_refs: refs(&["failure:acceptance-unknown"]),
                recovery_strategy_refs: refs(&["recovery:reconcile"]),
                ambiguity_handling_ref: r("ambiguity:preserve"),
                evidence_requirement_refs: refs(&["evidence:recovery"]),
            },
            accessed_data_class_refs: refs(&["data:input"]),
            disclosed_data_class_refs: refs(&["data:input"]),
            required_permission_scope_refs: refs(&["permission:write"]),
            principal_requirement_refs: refs(&["principal:authenticated"]),
            workload_requirement_refs: refs(&["workload:qualified"]),
            environment: EnvironmentRequirements {
                sandbox_profile_ref: Some(r("sandbox:adapter")),
                filesystem_scope_refs: BTreeSet::new(),
                network_destination_refs: refs(&["network:provider"]),
                device_capability_refs: BTreeSet::new(),
                resource_limit_refs: refs(&["resource:bounded"]),
            },
            idempotency: IdempotencyClaim {
                support: supported("idempotency"),
                key_binding_ref: Some(r("binding:effect-intent")),
                retention_requirement_ref: Some(r("retention:dedup")),
            },
            status_query: supported("status"),
            cancellation: supported("cancel"),
            compensation: SupportClaim::Unsupported,
            retry: supported("retry"),
            shared_atomicity: SupportClaim::Unsupported,
            timeout_requirement_ref: r("timeout:bounded"),
            freshness: FreshnessRequirements {
                version_requirement_refs: refs(&["version:manifest", "version:adapter"]),
                stale_call_rejection_ref: r("freshness:reject"),
                maximum_request_age_ref: Some(r("age:bounded")),
            },
        }
    }

    fn dependency(dependency_ref: &str) -> CapabilityDependency {
        CapabilityDependency {
            dependency_ref: r(dependency_ref),
            version_requirement_ref: r("requirement:dependency-version"),
            integrity_requirement_ref: r("requirement:dependency-integrity"),
            risk_evidence_requirement_refs: refs(&["evidence:dependency-risk"]),
        }
    }

    fn manifest() -> CapabilityManifest {
        CapabilityManifest {
            capability_ref: r("capability:test"),
            capability_version: v("opaque/version+A"),
            content_digest: ContentDigest {
                algorithm_ref: r(SHA256_ALGORITHM_REF),
                value: r("sha256:placeholder"),
            },
            publisher_ref: r("publisher:test"),
            issuer_ref: r("issuer:test"),
            source_ref: r("source:test"),
            artifact_ref: r("artifact:test"),
            adapter_ref: r("adapter:test"),
            adapter_version: v("adapter/opaque+A"),
            provenance_refs: refs(&["provenance:build", "provenance:source"]),
            dependencies: alloc::vec![dependency("dependency:b"), dependency("dependency:a")],
            operations: alloc::vec![
                operation("operation:b", "field:b"),
                operation("operation:a", "field:a"),
            ],
            qualification_requirement_refs: refs(&["qualification:effects"]),
        }
    }

    fn finalized_manifest() -> CapabilityManifest {
        let mut value = manifest();
        value.content_digest = compute_manifest_digest(&value).unwrap();
        value
    }

    #[test]
    fn matching_claim_produces_private_verified_integrity() {
        let value = finalized_manifest();
        let verified = verify_manifest_integrity(&value).unwrap();
        assert_eq!(verified.capability_ref(), &value.capability_ref);
        assert_eq!(verified.content_digest(), &value.content_digest);
        assert_eq!(verified.canonical_profile_ref(), MANIFEST_CANONICAL_PROFILE);
    }

    #[test]
    fn material_field_change_invalidates_claim() {
        let mut value = finalized_manifest();
        value.operations[0].required_permission_scope_refs = refs(&["permission:broader"]);
        assert_eq!(
            verify_manifest_integrity(&value),
            Err(IntegrityError::DigestMismatch)
        );
    }

    #[test]
    fn new_operation_semantics_are_all_content_bound() {
        let base = finalized_manifest();

        let mut changed = base.clone();
        changed.operations[0]
            .conditions
            .precondition_refs
            .insert(r("precondition:new"));
        assert_eq!(
            verify_manifest_integrity(&changed),
            Err(IntegrityError::DigestMismatch)
        );

        let mut changed = base.clone();
        changed.operations[0]
            .risk
            .risk_class_refs
            .insert(r("risk:new"));
        assert_eq!(
            verify_manifest_integrity(&changed),
            Err(IntegrityError::DigestMismatch)
        );

        let mut changed = base.clone();
        changed.operations[0].resource_cost.cost_model_ref = r("cost-model:new");
        assert_eq!(
            verify_manifest_integrity(&changed),
            Err(IntegrityError::DigestMismatch)
        );

        let mut changed = base;
        changed.operations[0]
            .failure_recovery
            .ambiguity_handling_ref = r("ambiguity:new");
        assert_eq!(
            verify_manifest_integrity(&changed),
            Err(IntegrityError::DigestMismatch)
        );
    }

    #[test]
    fn semantic_set_vector_reordering_preserves_digest() {
        let left = manifest();
        let mut right = left.clone();
        right.operations.reverse();
        right.dependencies.reverse();
        right.operations[0].input.fields.reverse();
        assert_eq!(
            compute_manifest_digest(&left).unwrap(),
            compute_manifest_digest(&right).unwrap()
        );
    }

    #[test]
    fn option_presence_and_string_framing_do_not_collapse() {
        let left = manifest();
        let mut right = left.clone();
        right.operations[0].freshness.maximum_request_age_ref = None;
        assert_ne!(
            compute_manifest_digest(&left).unwrap(),
            compute_manifest_digest(&right).unwrap()
        );

        let mut a = manifest();
        a.publisher_ref = r("publisher:ab");
        a.issuer_ref = r("issuer:c");
        let mut b = manifest();
        b.publisher_ref = r("publisher:a");
        b.issuer_ref = r("issuer:bc");
        assert_ne!(
            compute_manifest_digest(&a).unwrap(),
            compute_manifest_digest(&b).unwrap()
        );
    }

    #[test]
    fn unknown_digest_algorithm_fails_closed() {
        let mut value = finalized_manifest();
        value.content_digest.algorithm_ref = r("digest:not-implemented");
        assert!(matches!(
            verify_manifest_integrity(&value),
            Err(IntegrityError::UnsupportedDigestAlgorithm(_))
        ));
    }

    #[test]
    fn digest_field_is_an_envelope_assertion_not_recursive_input() {
        let mut left = manifest();
        let mut right = manifest();
        left.content_digest.value = r("sha256:any-assertion-a");
        right.content_digest.value = r("sha256:any-assertion-b");
        assert_eq!(
            compute_manifest_digest(&left).unwrap(),
            compute_manifest_digest(&right).unwrap()
        );
    }
}
