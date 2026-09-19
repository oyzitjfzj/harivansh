extern crate alloc;

use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference(String);

impl Reference {
    pub fn new(value: impl Into<String>) -> Result<Self, ManifestError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ManifestError::EmptyReference);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueVersion(String);

impl OpaqueVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, ManifestError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ManifestError::EmptyVersion);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigest {
    pub algorithm_ref: Reference,
    pub value: Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityFieldRole {
    Data,
    AuthorityReference,
    EvidenceReference,
    SecretHandleReference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaField {
    pub field_ref: Reference,
    pub schema_ref: Reference,
    pub role: CapabilityFieldRole,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaExtensionPolicy {
    Closed,
    Namespaced {
        extension_schema_refs: BTreeSet<Reference>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSchema {
    pub schema_ref: Reference,
    pub fields: Vec<SchemaField>,
    pub extension_policy: SchemaExtensionPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalStateChange {
    None,
    MayMutate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundDisclosure {
    None,
    MayDisclose,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetBindingRequirements {
    pub resource_binding_ref: Option<Reference>,
    pub account_binding_ref: Option<Reference>,
    pub principal_binding_ref: Option<Reference>,
}

impl TargetBindingRequirements {
    fn is_empty(&self) -> bool {
        self.resource_binding_ref.is_none()
            && self.account_binding_ref.is_none()
            && self.principal_binding_ref.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeObservationContract {
    pub observation_method_ref: Reference,
    pub evidence_schema_ref: Reference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectClaim {
    pub external_state_change: ExternalStateChange,
    pub outbound_disclosure: OutboundDisclosure,
    pub effect_semantics_ref: Reference,
    pub target_binding: TargetBindingRequirements,
    pub outcome_observation: OutcomeObservationContract,
}

/// Semantic conditions are references to independently defined/checkable
/// contracts. A schema proves shape; it does not prove that the world is in a
/// state where the operation is safe/correct to invoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationConditions {
    pub precondition_refs: BTreeSet<Reference>,
    pub postcondition_refs: BTreeSet<Reference>,
}

/// Reversibility remains separate from retry and compensation. In particular,
/// a compensating operation records a later action; it does not erase the fact
/// that the original external effect happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReversibilityClaim {
    NotApplicable,
    Unknown,
    Reversible {
        contract_ref: Reference,
        evidence_requirement_refs: BTreeSet<Reference>,
    },
    Compensatable {
        contract_ref: Reference,
        evidence_requirement_refs: BTreeSet<Reference>,
    },
    Irreversible {
        evidence_requirement_refs: BTreeSet<Reference>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRiskContract {
    pub risk_class_refs: BTreeSet<Reference>,
    pub consequence_model_ref: Reference,
    pub reversibility: ReversibilityClaim,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

/// Environment resource limits are hard ceilings; these refs describe expected
/// consumption/cost for planning and qualification. They never grant resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceCostContract {
    pub resource_estimate_refs: BTreeSet<Reference>,
    pub cost_model_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

/// Overall failure/recovery semantics are explicit because transport errors,
/// provider rejection and acceptance-unknown states are not interchangeable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureRecoveryContract {
    pub failure_mode_refs: BTreeSet<Reference>,
    pub recovery_strategy_refs: BTreeSet<Reference>,
    pub ambiguity_handling_ref: Reference,
    pub evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportClaim {
    Unknown,
    Unsupported,
    Supported {
        contract_ref: Reference,
        evidence_requirement_refs: BTreeSet<Reference>,
    },
}

impl SupportClaim {
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyClaim {
    pub support: SupportClaim,
    pub key_binding_ref: Option<Reference>,
    pub retention_requirement_ref: Option<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentRequirements {
    pub sandbox_profile_ref: Option<Reference>,
    pub filesystem_scope_refs: BTreeSet<Reference>,
    pub network_destination_refs: BTreeSet<Reference>,
    pub device_capability_refs: BTreeSet<Reference>,
    pub resource_limit_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessRequirements {
    pub version_requirement_refs: BTreeSet<Reference>,
    pub stale_call_rejection_ref: Reference,
    pub maximum_request_age_ref: Option<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityOperation {
    pub operation_ref: Reference,
    pub purpose_ref: Reference,
    pub description_ref: Reference,
    pub input: OperationSchema,
    pub output: OperationSchema,
    pub conditions: OperationConditions,
    pub effect: EffectClaim,
    pub risk: OperationRiskContract,
    pub resource_cost: ResourceCostContract,
    pub failure_recovery: FailureRecoveryContract,
    pub accessed_data_class_refs: BTreeSet<Reference>,
    pub disclosed_data_class_refs: BTreeSet<Reference>,
    pub required_permission_scope_refs: BTreeSet<Reference>,
    pub principal_requirement_refs: BTreeSet<Reference>,
    pub workload_requirement_refs: BTreeSet<Reference>,
    pub environment: EnvironmentRequirements,
    pub idempotency: IdempotencyClaim,
    pub status_query: SupportClaim,
    pub cancellation: SupportClaim,
    pub compensation: SupportClaim,
    pub retry: SupportClaim,
    pub shared_atomicity: SupportClaim,
    pub timeout_requirement_ref: Reference,
    pub freshness: FreshnessRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDependency {
    pub dependency_ref: Reference,
    pub version_requirement_ref: Reference,
    pub integrity_requirement_ref: Reference,
    pub risk_evidence_requirement_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityManifest {
    pub capability_ref: Reference,
    pub capability_version: OpaqueVersion,
    pub content_digest: ContentDigest,
    pub publisher_ref: Reference,
    pub issuer_ref: Reference,
    pub source_ref: Reference,
    pub artifact_ref: Reference,
    pub adapter_ref: Reference,
    pub adapter_version: OpaqueVersion,
    pub provenance_refs: BTreeSet<Reference>,
    pub dependencies: Vec<CapabilityDependency>,
    pub operations: Vec<CapabilityOperation>,
    pub qualification_requirement_refs: BTreeSet<Reference>,
}

/// Structural validation only. A valid manifest is still an unqualified
/// description: it is not current availability, permission, consent, a secret,
/// execution authority, or proof that a provider behaves as claimed.
pub fn validate_manifest(manifest: &CapabilityManifest) -> Result<(), ManifestError> {
    if manifest.provenance_refs.is_empty() {
        return Err(ManifestError::MissingProvenance);
    }
    if manifest.qualification_requirement_refs.is_empty() {
        return Err(ManifestError::MissingQualificationRequirements);
    }
    if manifest.operations.is_empty() {
        return Err(ManifestError::MissingOperation);
    }

    validate_ref_set(&manifest.provenance_refs)?;
    validate_ref_set(&manifest.qualification_requirement_refs)?;

    let mut operation_refs = BTreeSet::new();
    for operation in &manifest.operations {
        if !operation_refs.insert(operation.operation_ref.clone()) {
            return Err(ManifestError::DuplicateOperation(
                operation.operation_ref.to_string(),
            ));
        }
        validate_operation(operation)?;
    }

    let mut dependency_refs = BTreeSet::new();
    for dependency in &manifest.dependencies {
        if !dependency_refs.insert(dependency.dependency_ref.clone()) {
            return Err(ManifestError::DuplicateDependency(
                dependency.dependency_ref.to_string(),
            ));
        }
        if dependency.risk_evidence_requirement_refs.is_empty() {
            return Err(ManifestError::MissingDependencyRiskEvidence(
                dependency.dependency_ref.to_string(),
            ));
        }
        validate_ref_set(&dependency.risk_evidence_requirement_refs)?;
    }

    Ok(())
}

fn validate_operation(operation: &CapabilityOperation) -> Result<(), ManifestError> {
    validate_schema(&operation.input, SchemaDirection::Input)?;
    validate_schema(&operation.output, SchemaDirection::Output)?;
    validate_conditions(&operation.conditions, &operation.operation_ref)?;
    validate_risk(
        &operation.risk,
        &operation.compensation,
        &operation.effect,
        &operation.operation_ref,
    )?;
    validate_resource_cost(&operation.resource_cost, &operation.operation_ref)?;
    validate_failure_recovery(&operation.failure_recovery, &operation.operation_ref)?;
    validate_ref_set(&operation.accessed_data_class_refs)?;
    validate_ref_set(&operation.disclosed_data_class_refs)?;
    validate_ref_set(&operation.required_permission_scope_refs)?;
    validate_ref_set(&operation.principal_requirement_refs)?;
    validate_ref_set(&operation.workload_requirement_refs)?;
    validate_environment(&operation.environment)?;
    validate_freshness(&operation.freshness)?;
    validate_idempotency(&operation.idempotency)?;
    validate_support_claim(&operation.status_query, "status")?;
    validate_support_claim(&operation.cancellation, "cancellation")?;
    validate_support_claim(&operation.compensation, "compensation")?;
    validate_support_claim(&operation.retry, "retry")?;
    validate_support_claim(&operation.shared_atomicity, "shared_atomicity")?;

    if operation.effect.external_state_change == ExternalStateChange::MayMutate
        && operation.effect.target_binding.is_empty()
    {
        return Err(ManifestError::MutationMissingTargetBinding(
            operation.operation_ref.to_string(),
        ));
    }

    match operation.effect.outbound_disclosure {
        OutboundDisclosure::None if !operation.disclosed_data_class_refs.is_empty() => {
            return Err(ManifestError::DisclosureContradiction(
                operation.operation_ref.to_string(),
            ));
        }
        OutboundDisclosure::MayDisclose if operation.disclosed_data_class_refs.is_empty() => {
            return Err(ManifestError::DisclosureDataClassMissing(
                operation.operation_ref.to_string(),
            ));
        }
        _ => {}
    }

    if operation.effect.external_state_change == ExternalStateChange::None
        && (operation.idempotency.support.is_supported()
            || operation.compensation.is_supported()
            || operation.shared_atomicity.is_supported())
    {
        return Err(ManifestError::ReadOnlyCarriesWriteSemantics(
            operation.operation_ref.to_string(),
        ));
    }

    if operation.effect.external_state_change == ExternalStateChange::MayMutate
        && operation.idempotency.support.is_supported()
        && operation.retry.is_supported()
        && operation.idempotency.retention_requirement_ref.is_none()
    {
        return Err(ManifestError::IdempotencyRetentionMissing(
            operation.operation_ref.to_string(),
        ));
    }

    Ok(())
}

fn validate_conditions(
    conditions: &OperationConditions,
    operation_ref: &Reference,
) -> Result<(), ManifestError> {
    if conditions.precondition_refs.is_empty() {
        return Err(ManifestError::MissingOperationPreconditions(
            operation_ref.to_string(),
        ));
    }
    if conditions.postcondition_refs.is_empty() {
        return Err(ManifestError::MissingOperationPostconditions(
            operation_ref.to_string(),
        ));
    }
    validate_ref_set(&conditions.precondition_refs)?;
    validate_ref_set(&conditions.postcondition_refs)
}

fn validate_risk(
    risk: &OperationRiskContract,
    compensation: &SupportClaim,
    effect: &EffectClaim,
    operation_ref: &Reference,
) -> Result<(), ManifestError> {
    if risk.risk_class_refs.is_empty() || risk.evidence_requirement_refs.is_empty() {
        return Err(ManifestError::MissingRiskContract(
            operation_ref.to_string(),
        ));
    }
    validate_ref_set(&risk.risk_class_refs)?;
    validate_ref_set(&risk.evidence_requirement_refs)?;
    match &risk.reversibility {
        ReversibilityClaim::NotApplicable => {
            if effect.external_state_change == ExternalStateChange::MayMutate
                || effect.outbound_disclosure == OutboundDisclosure::MayDisclose
            {
                return Err(
                    ManifestError::ReversibilityNotApplicableToConsequentialOperation(
                        operation_ref.to_string(),
                    ),
                );
            }
        }
        ReversibilityClaim::Unknown => {}
        ReversibilityClaim::Reversible {
            evidence_requirement_refs,
            ..
        }
        | ReversibilityClaim::Irreversible {
            evidence_requirement_refs,
        } => {
            if evidence_requirement_refs.is_empty() {
                return Err(ManifestError::ConcreteReversibilityMissingEvidence(
                    operation_ref.to_string(),
                ));
            }
            validate_ref_set(evidence_requirement_refs)?;
        }
        ReversibilityClaim::Compensatable {
            evidence_requirement_refs,
            ..
        } => {
            if evidence_requirement_refs.is_empty() {
                return Err(ManifestError::ConcreteReversibilityMissingEvidence(
                    operation_ref.to_string(),
                ));
            }
            validate_ref_set(evidence_requirement_refs)?;
            if !compensation.is_supported() {
                return Err(ManifestError::CompensatableWithoutCompensation(
                    operation_ref.to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_resource_cost(
    contract: &ResourceCostContract,
    operation_ref: &Reference,
) -> Result<(), ManifestError> {
    if contract.resource_estimate_refs.is_empty() || contract.evidence_requirement_refs.is_empty() {
        return Err(ManifestError::MissingResourceCostContract(
            operation_ref.to_string(),
        ));
    }
    validate_ref_set(&contract.resource_estimate_refs)?;
    validate_ref_set(&contract.evidence_requirement_refs)
}

fn validate_failure_recovery(
    contract: &FailureRecoveryContract,
    operation_ref: &Reference,
) -> Result<(), ManifestError> {
    if contract.failure_mode_refs.is_empty()
        || contract.recovery_strategy_refs.is_empty()
        || contract.evidence_requirement_refs.is_empty()
    {
        return Err(ManifestError::MissingFailureRecoveryContract(
            operation_ref.to_string(),
        ));
    }
    validate_ref_set(&contract.failure_mode_refs)?;
    validate_ref_set(&contract.recovery_strategy_refs)?;
    validate_ref_set(&contract.evidence_requirement_refs)
}

#[derive(Debug, Clone, Copy)]
enum SchemaDirection {
    Input,
    Output,
}

fn validate_schema(
    schema: &OperationSchema,
    direction: SchemaDirection,
) -> Result<(), ManifestError> {
    let mut field_refs = BTreeSet::new();
    for field in &schema.fields {
        if !field_refs.insert(field.field_ref.clone()) {
            return Err(ManifestError::DuplicateSchemaField {
                schema_ref: schema.schema_ref.to_string(),
                field_ref: field.field_ref.to_string(),
            });
        }
        if matches!(direction, SchemaDirection::Output)
            && field.role == CapabilityFieldRole::AuthorityReference
        {
            return Err(ManifestError::ProviderOutputCannotMintAuthority(
                field.field_ref.to_string(),
            ));
        }
    }

    match &schema.extension_policy {
        SchemaExtensionPolicy::Closed => {}
        SchemaExtensionPolicy::Namespaced {
            extension_schema_refs,
        } => {
            if extension_schema_refs.is_empty() {
                return Err(ManifestError::EmptyExtensionSet(
                    schema.schema_ref.to_string(),
                ));
            }
            validate_ref_set(extension_schema_refs)?;
            if extension_schema_refs
                .iter()
                .any(|reference| !looks_namespaced(reference.as_str()))
            {
                return Err(ManifestError::UnnamespacedExtension(
                    schema.schema_ref.to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_environment(environment: &EnvironmentRequirements) -> Result<(), ManifestError> {
    validate_ref_set(&environment.filesystem_scope_refs)?;
    validate_ref_set(&environment.network_destination_refs)?;
    validate_ref_set(&environment.device_capability_refs)?;
    validate_ref_set(&environment.resource_limit_refs)?;
    Ok(())
}

fn validate_freshness(freshness: &FreshnessRequirements) -> Result<(), ManifestError> {
    if freshness.version_requirement_refs.is_empty() {
        return Err(ManifestError::MissingFreshnessVersionRequirement);
    }
    validate_ref_set(&freshness.version_requirement_refs)?;
    Ok(())
}

fn validate_idempotency(claim: &IdempotencyClaim) -> Result<(), ManifestError> {
    validate_support_claim(&claim.support, "idempotency")?;
    match &claim.support {
        SupportClaim::Supported { .. } => {
            if claim.key_binding_ref.is_none() || claim.retention_requirement_ref.is_none() {
                return Err(ManifestError::SupportedIdempotencyIncomplete);
            }
        }
        SupportClaim::Unknown | SupportClaim::Unsupported => {
            if claim.key_binding_ref.is_some() || claim.retention_requirement_ref.is_some() {
                return Err(ManifestError::UnsupportedSemanticsCarrySupportData(
                    "idempotency",
                ));
            }
        }
    }
    Ok(())
}

fn validate_support_claim(
    claim: &SupportClaim,
    semantic: &'static str,
) -> Result<(), ManifestError> {
    if let SupportClaim::Supported {
        evidence_requirement_refs,
        ..
    } = claim
    {
        if evidence_requirement_refs.is_empty() {
            return Err(ManifestError::SupportedSemanticsMissingEvidence(semantic));
        }
        validate_ref_set(evidence_requirement_refs)?;
    }
    Ok(())
}

fn validate_ref_set(values: &BTreeSet<Reference>) -> Result<(), ManifestError> {
    if values.iter().any(|value| value.as_str().trim().is_empty()) {
        return Err(ManifestError::EmptyReference);
    }
    Ok(())
}

fn looks_namespaced(value: &str) -> bool {
    let value = value.trim();
    value.contains(':') || value.contains('/') || value.contains('.')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    EmptyReference,
    EmptyVersion,
    MissingProvenance,
    MissingQualificationRequirements,
    MissingOperation,
    DuplicateOperation(String),
    DuplicateDependency(String),
    MissingDependencyRiskEvidence(String),
    DuplicateSchemaField {
        schema_ref: String,
        field_ref: String,
    },
    EmptyExtensionSet(String),
    UnnamespacedExtension(String),
    ProviderOutputCannotMintAuthority(String),
    MissingOperationPreconditions(String),
    MissingOperationPostconditions(String),
    MissingRiskContract(String),
    ReversibilityNotApplicableToConsequentialOperation(String),
    ConcreteReversibilityMissingEvidence(String),
    CompensatableWithoutCompensation(String),
    MissingResourceCostContract(String),
    MissingFailureRecoveryContract(String),
    MutationMissingTargetBinding(String),
    DisclosureContradiction(String),
    DisclosureDataClassMissing(String),
    ReadOnlyCarriesWriteSemantics(String),
    SupportedSemanticsMissingEvidence(&'static str),
    UnsupportedSemanticsCarrySupportData(&'static str),
    SupportedIdempotencyIncomplete,
    IdempotencyRetentionMissing(String),
    MissingFreshnessVersionRequirement,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capability manifest rejected: {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(value: &str) -> Reference {
        Reference::new(value).unwrap()
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

    fn schema(name: &str, direction: SchemaDirection) -> OperationSchema {
        let role = match direction {
            SchemaDirection::Input => CapabilityFieldRole::Data,
            SchemaDirection::Output => CapabilityFieldRole::EvidenceReference,
        };
        OperationSchema {
            schema_ref: r(&alloc::format!("schema:{name}")),
            fields: alloc::vec![SchemaField {
                field_ref: r(&alloc::format!("field:{name}")),
                schema_ref: r("schema:string"),
                role,
                required: true,
            }],
            extension_policy: SchemaExtensionPolicy::Closed,
        }
    }

    fn operation() -> CapabilityOperation {
        CapabilityOperation {
            operation_ref: r("operation:send"),
            purpose_ref: r("purpose:user-requested-send"),
            description_ref: r("description:send-message"),
            input: schema("input", SchemaDirection::Input),
            output: schema("output", SchemaDirection::Output),
            conditions: OperationConditions {
                precondition_refs: refs(&[
                    "precondition:recipient-current",
                    "precondition:account-current",
                ]),
                postcondition_refs: refs(&["postcondition:provider-result-captured"]),
            },
            effect: EffectClaim {
                external_state_change: ExternalStateChange::MayMutate,
                outbound_disclosure: OutboundDisclosure::MayDisclose,
                effect_semantics_ref: r("effect:external-consequential"),
                target_binding: TargetBindingRequirements {
                    resource_binding_ref: None,
                    account_binding_ref: Some(r("binding:account")),
                    principal_binding_ref: Some(r("binding:recipient")),
                },
                outcome_observation: OutcomeObservationContract {
                    observation_method_ref: r("observation:provider-receipt-and-status"),
                    evidence_schema_ref: r("schema:provider-receipt"),
                },
            },
            risk: OperationRiskContract {
                risk_class_refs: refs(&["risk:external-message", "risk:privacy-disclosure"]),
                consequence_model_ref: r("consequence:model-message-send"),
                reversibility: ReversibilityClaim::Unknown,
                evidence_requirement_refs: refs(&["evidence:risk-model"]),
            },
            resource_cost: ResourceCostContract {
                resource_estimate_refs: refs(&["resource-estimate:network-request"]),
                cost_model_ref: r("cost-model:provider-send"),
                evidence_requirement_refs: refs(&["evidence:resource-cost-profile"]),
            },
            failure_recovery: FailureRecoveryContract {
                failure_mode_refs: refs(&["failure:pre-send", "failure:acceptance-unknown"]),
                recovery_strategy_refs: refs(&["recovery:reconcile-before-retry"]),
                ambiguity_handling_ref: r("ambiguity:preserve-acceptance-unknown"),
                evidence_requirement_refs: refs(&["evidence:failure-recovery-contract"]),
            },
            accessed_data_class_refs: refs(&["data:message-content"]),
            disclosed_data_class_refs: refs(&["data:message-content"]),
            required_permission_scope_refs: refs(&["permission:send-message"]),
            principal_requirement_refs: refs(&["principal:authenticated"]),
            workload_requirement_refs: refs(&["workload:qualified-adapter"]),
            environment: EnvironmentRequirements {
                sandbox_profile_ref: Some(r("sandbox:network-adapter")),
                filesystem_scope_refs: BTreeSet::new(),
                network_destination_refs: refs(&["network:provider-endpoint"]),
                device_capability_refs: BTreeSet::new(),
                resource_limit_refs: refs(&["resource:bounded-request"]),
            },
            idempotency: IdempotencyClaim {
                support: supported("idempotency"),
                key_binding_ref: Some(r("binding:effect-intent-id")),
                retention_requirement_ref: Some(r("retention:provider-dedup-window")),
            },
            status_query: supported("status"),
            cancellation: supported("cancel"),
            compensation: SupportClaim::Unsupported,
            retry: supported("retry"),
            shared_atomicity: SupportClaim::Unsupported,
            timeout_requirement_ref: r("timeout:qualified-provider"),
            freshness: FreshnessRequirements {
                version_requirement_refs: refs(&[
                    "version:manifest",
                    "version:adapter",
                    "version:authority",
                ]),
                stale_call_rejection_ref: r("freshness:reject-stale-call"),
                maximum_request_age_ref: Some(r("age:qualified-request-window")),
            },
        }
    }

    fn manifest() -> CapabilityManifest {
        CapabilityManifest {
            capability_ref: r("capability:message-send"),
            capability_version: OpaqueVersion::new("provider-build/2026.09+opaque").unwrap(),
            content_digest: ContentDigest {
                algorithm_ref: r("digest:sha-256"),
                value: r("sha256:manifest-content"),
            },
            publisher_ref: r("publisher:provider-a"),
            issuer_ref: r("issuer:provider-a"),
            source_ref: r("source:provider-contract"),
            artifact_ref: r("artifact:adapter-build"),
            adapter_ref: r("adapter:provider-a"),
            adapter_version: OpaqueVersion::new("adapter/release-7+opaque").unwrap(),
            provenance_refs: refs(&["provenance:build", "provenance:source"]),
            dependencies: alloc::vec![CapabilityDependency {
                dependency_ref: r("dependency:transport"),
                version_requirement_ref: r("requirement:transport-version"),
                integrity_requirement_ref: r("requirement:transport-integrity"),
                risk_evidence_requirement_refs: refs(&["evidence:dependency-risk"]),
            }],
            operations: alloc::vec![operation()],
            qualification_requirement_refs: refs(&[
                "qualification:schema",
                "qualification:sandbox",
                "qualification:effects",
                "qualification:outcome",
            ]),
        }
    }

    #[test]
    fn production_shape_accepts_opaque_versions_and_zero_bearer_authority() {
        let value = manifest();
        assert!(validate_manifest(&value).is_ok());
        assert_eq!(
            value.capability_version.as_str(),
            "provider-build/2026.09+opaque"
        );
        assert_eq!(value.adapter_version.as_str(), "adapter/release-7+opaque");
    }

    #[test]
    fn operation_requires_explicit_conditions_risk_cost_and_recovery() {
        let mut value = manifest();
        value.operations[0].conditions.precondition_refs.clear();
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::MissingOperationPreconditions(_))
        ));

        let mut value = manifest();
        value.operations[0].risk.risk_class_refs.clear();
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::MissingRiskContract(_))
        ));

        let mut value = manifest();
        value.operations[0]
            .resource_cost
            .resource_estimate_refs
            .clear();
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::MissingResourceCostContract(_))
        ));

        let mut value = manifest();
        value.operations[0]
            .failure_recovery
            .failure_mode_refs
            .clear();
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::MissingFailureRecoveryContract(_))
        ));
    }

    #[test]
    fn compensatable_reversibility_requires_real_compensation_contract() {
        let mut value = manifest();
        value.operations[0].risk.reversibility = ReversibilityClaim::Compensatable {
            contract_ref: r("reversibility:compensatable"),
            evidence_requirement_refs: refs(&["evidence:compensation"]),
        };
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::CompensatableWithoutCompensation(_))
        ));
        value.operations[0].compensation = supported("compensation");
        assert!(validate_manifest(&value).is_ok());
    }

    #[test]
    fn consequential_operation_cannot_claim_reversibility_not_applicable() {
        let mut value = manifest();
        value.operations[0].risk.reversibility = ReversibilityClaim::NotApplicable;
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::ReversibilityNotApplicableToConsequentialOperation(_))
        ));
    }

    #[test]
    fn duplicate_operations_and_schema_fields_fail_closed() {
        let mut value = manifest();
        value.operations.push(value.operations[0].clone());
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::DuplicateOperation(_))
        ));

        let mut value = manifest();
        let duplicate = value.operations[0].input.fields[0].clone();
        value.operations[0].input.fields.push(duplicate);
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::DuplicateSchemaField { .. })
        ));
    }

    #[test]
    fn provider_output_cannot_mint_authority_by_schema_role() {
        let mut value = manifest();
        value.operations[0].output.fields[0].role = CapabilityFieldRole::AuthorityReference;
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::ProviderOutputCannotMintAuthority(_))
        ));
    }

    #[test]
    fn privileged_extension_surface_must_be_explicit_and_namespaced() {
        let mut value = manifest();
        value.operations[0].input.extension_policy = SchemaExtensionPolicy::Namespaced {
            extension_schema_refs: BTreeSet::new(),
        };
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::EmptyExtensionSet(_))
        ));

        let mut value = manifest();
        value.operations[0].input.extension_policy = SchemaExtensionPolicy::Namespaced {
            extension_schema_refs: refs(&["ambiguousextension"]),
        };
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::UnnamespacedExtension(_))
        ));
    }

    #[test]
    fn mutating_operation_requires_exact_target_binding() {
        let mut value = manifest();
        value.operations[0].effect.target_binding = TargetBindingRequirements {
            resource_binding_ref: None,
            account_binding_ref: None,
            principal_binding_ref: None,
        };
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::MutationMissingTargetBinding(_))
        ));
    }

    #[test]
    fn disclosure_claim_and_data_classes_cannot_contradict_each_other() {
        let mut value = manifest();
        value.operations[0].disclosed_data_class_refs.clear();
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::DisclosureDataClassMissing(_))
        ));

        let mut value = manifest();
        value.operations[0].effect.outbound_disclosure = OutboundDisclosure::None;
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::DisclosureContradiction(_))
        ));
    }

    #[test]
    fn support_claims_cannot_be_upgraded_by_missing_or_conflicting_metadata() {
        let mut value = manifest();
        value.operations[0].status_query = SupportClaim::Supported {
            contract_ref: r("contract:status"),
            evidence_requirement_refs: BTreeSet::new(),
        };
        assert_eq!(
            validate_manifest(&value),
            Err(ManifestError::SupportedSemanticsMissingEvidence("status"))
        );

        let mut value = manifest();
        value.operations[0].idempotency.support = SupportClaim::Unsupported;
        assert_eq!(
            validate_manifest(&value),
            Err(ManifestError::UnsupportedSemanticsCarrySupportData(
                "idempotency"
            ))
        );
    }

    #[test]
    fn supported_idempotency_requires_key_and_retention_binding() {
        let mut value = manifest();
        value.operations[0].idempotency.retention_requirement_ref = None;
        assert_eq!(
            validate_manifest(&value),
            Err(ManifestError::SupportedIdempotencyIncomplete)
        );
    }

    #[test]
    fn read_only_claim_cannot_hide_write_specific_semantics() {
        let mut value = manifest();
        value.operations[0].effect.external_state_change = ExternalStateChange::None;
        assert!(matches!(
            validate_manifest(&value),
            Err(ManifestError::ReadOnlyCarriesWriteSemantics(_))
        ));
    }

    #[test]
    fn static_manifest_does_not_need_or_expose_current_availability_or_credentials() {
        let value = manifest();
        assert!(validate_manifest(&value).is_ok());
        assert!(
            value.operations[0]
                .environment
                .filesystem_scope_refs
                .is_empty()
        );
        assert!(
            value.operations[0]
                .input
                .fields
                .iter()
                .all(|field| field.role != CapabilityFieldRole::SecretHandleReference)
        );
    }
}
