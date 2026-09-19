extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use crate::{
    manifest::{CapabilityManifest, Reference, validate_manifest},
    qualification::{
        QualificationPlanIdentity, QualificationSubject, VerifiedCapabilityQualification,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadinessState {
    Ready,
    Degraded,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationState {
    Active,
    Unknown,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationAvailability {
    pub operation_ref: Reference,
    pub readiness: ReadinessState,
    pub evidence_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyAvailability {
    pub dependency_ref: Reference,
    pub readiness: ReadinessState,
    pub evidence_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationObservation {
    pub state: RevocationState,
    pub epoch_ref: Reference,
    pub evidence_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilitySnapshot {
    pub snapshot_ref: Reference,
    pub subject: QualificationSubject,
    pub qualification_plan: QualificationPlanIdentity,
    pub state_revision: u64,
    pub state_epoch_ref: Reference,
    pub observed_at_ref: Reference,
    pub freshness_window_ref: Reference,
    pub revalidation_requirement_ref: Reference,
    pub revocation: RevocationObservation,
    pub operations: Vec<OperationAvailability>,
    pub dependencies: Vec<DependencyAvailability>,
    pub observer_ref: Reference,
    pub provenance_refs: BTreeSet<Reference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCapabilityAvailability {
    snapshot: AvailabilitySnapshot,
    aggregate_readiness: ReadinessState,
}

impl VerifiedCapabilityAvailability {
    pub fn snapshot(&self) -> &AvailabilitySnapshot {
        &self.snapshot
    }

    pub fn aggregate_readiness(&self) -> ReadinessState {
        self.aggregate_readiness
    }

    pub fn revocation_state(&self) -> RevocationState {
        self.snapshot.revocation.state
    }

    pub fn operation_readiness(&self, operation_ref: &Reference) -> Option<ReadinessState> {
        self.snapshot
            .operations
            .iter()
            .find(|entry| &entry.operation_ref == operation_ref)
            .map(|entry| entry.readiness)
    }
}

/// Validate one complete operational observation against the exact static
/// manifest and the exact evidence-gated qualification. This gate validates
/// structure and binding only. Fresh wall-clock/current-store comparison and
/// CAS/fencing belong to the authoritative availability state owner.
pub fn verify_availability_snapshot(
    manifest: &CapabilityManifest,
    qualification: &VerifiedCapabilityQualification,
    snapshot: AvailabilitySnapshot,
) -> Result<VerifiedCapabilityAvailability, AvailabilityError> {
    validate_manifest(manifest).map_err(|_| AvailabilityError::ManifestInvalid)?;

    if qualification.subject() != &snapshot.subject
        || qualification.plan_identity() != &snapshot.qualification_plan
    {
        return Err(AvailabilityError::QualificationBindingMismatch);
    }
    if snapshot.subject.capability_ref != manifest.capability_ref
        || snapshot.subject.capability_version != manifest.capability_version
        || snapshot.subject.manifest_digest != manifest.content_digest
        || snapshot.subject.artifact_ref != manifest.artifact_ref
        || snapshot.subject.adapter_ref != manifest.adapter_ref
        || snapshot.subject.adapter_version != manifest.adapter_version
    {
        return Err(AvailabilityError::ManifestSubjectMismatch);
    }
    if snapshot.state_revision == 0 {
        return Err(AvailabilityError::InvalidStateRevision);
    }
    if snapshot.provenance_refs.is_empty() || snapshot.revocation.evidence_refs.is_empty() {
        return Err(AvailabilityError::MissingObservationEvidence);
    }

    let expected_operations = qualification.operation_refs();
    let mut operations = BTreeMap::<Reference, ReadinessState>::new();
    for entry in &snapshot.operations {
        if entry.evidence_refs.is_empty() {
            return Err(AvailabilityError::MissingOperationEvidence(
                entry.operation_ref.to_string(),
            ));
        }
        if !expected_operations.contains(&entry.operation_ref) {
            return Err(AvailabilityError::UnknownOperation(
                entry.operation_ref.to_string(),
            ));
        }
        if operations
            .insert(entry.operation_ref.clone(), entry.readiness)
            .is_some()
        {
            return Err(AvailabilityError::DuplicateOperation(
                entry.operation_ref.to_string(),
            ));
        }
    }
    let observed_operations: BTreeSet<Reference> = operations.keys().cloned().collect();
    if observed_operations != *expected_operations {
        return Err(AvailabilityError::IncompleteOperationCoverage);
    }

    let expected_dependencies: BTreeSet<Reference> = manifest
        .dependencies
        .iter()
        .map(|dependency| dependency.dependency_ref.clone())
        .collect();
    let mut dependencies = BTreeMap::<Reference, ReadinessState>::new();
    for entry in &snapshot.dependencies {
        if entry.evidence_refs.is_empty() {
            return Err(AvailabilityError::MissingDependencyEvidence(
                entry.dependency_ref.to_string(),
            ));
        }
        if !expected_dependencies.contains(&entry.dependency_ref) {
            return Err(AvailabilityError::UnknownDependency(
                entry.dependency_ref.to_string(),
            ));
        }
        if dependencies
            .insert(entry.dependency_ref.clone(), entry.readiness)
            .is_some()
        {
            return Err(AvailabilityError::DuplicateDependency(
                entry.dependency_ref.to_string(),
            ));
        }
    }
    let observed_dependencies: BTreeSet<Reference> = dependencies.keys().cloned().collect();
    if observed_dependencies != expected_dependencies {
        return Err(AvailabilityError::IncompleteDependencyCoverage);
    }

    let aggregate_readiness = aggregate_state(
        snapshot.revocation.state,
        operations.values().copied(),
        dependencies.values().copied(),
    );

    Ok(VerifiedCapabilityAvailability {
        snapshot,
        aggregate_readiness,
    })
}

fn aggregate_state(
    revocation: RevocationState,
    operations: impl Iterator<Item = ReadinessState>,
    dependencies: impl Iterator<Item = ReadinessState>,
) -> ReadinessState {
    match revocation {
        RevocationState::Revoked => return ReadinessState::Unavailable,
        RevocationState::Unknown => return ReadinessState::Unknown,
        RevocationState::Active => {}
    }

    let mut aggregate = ReadinessState::Ready;
    for state in operations.chain(dependencies) {
        aggregate = worse(aggregate, state);
        if aggregate == ReadinessState::Unavailable {
            break;
        }
    }
    aggregate
}

fn worse(left: ReadinessState, right: ReadinessState) -> ReadinessState {
    use ReadinessState::{Degraded, Ready, Unavailable, Unknown};
    match (left, right) {
        (Unavailable, _) | (_, Unavailable) => Unavailable,
        (Unknown, _) | (_, Unknown) => Unknown,
        (Degraded, _) | (_, Degraded) => Degraded,
        (Ready, Ready) => Ready,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvailabilityError {
    ManifestInvalid,
    QualificationBindingMismatch,
    ManifestSubjectMismatch,
    InvalidStateRevision,
    MissingObservationEvidence,
    UnknownOperation(String),
    DuplicateOperation(String),
    MissingOperationEvidence(String),
    IncompleteOperationCoverage,
    UnknownDependency(String),
    DuplicateDependency(String),
    MissingDependencyEvidence(String),
    IncompleteDependencyCoverage,
}

impl fmt::Display for AvailabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capability availability rejected: {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        manifest::{
            CapabilityDependency, CapabilityFieldRole, CapabilityOperation, ContentDigest,
            EffectClaim, EnvironmentRequirements, ExternalStateChange, FailureRecoveryContract,
            FreshnessRequirements, IdempotencyClaim, OpaqueVersion, OperationConditions,
            OperationRiskContract, OperationSchema, OutboundDisclosure, OutcomeObservationContract,
            ResourceCostContract, ReversibilityClaim, SchemaExtensionPolicy, SchemaField,
            SupportClaim, TargetBindingRequirements,
        },
        qualification::{
            EvidenceStatus, OperatingCeiling, QualificationEvidenceRecord, QualificationPlan,
            QualificationPlanIdentity, QualificationSubject, qualify_capability,
        },
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

    fn manifest() -> CapabilityManifest {
        let input = OperationSchema {
            schema_ref: r("schema:input"),
            fields: alloc::vec![SchemaField {
                field_ref: r("field:payload"),
                schema_ref: r("schema:string"),
                role: CapabilityFieldRole::Data,
                required: true,
            }],
            extension_policy: SchemaExtensionPolicy::Closed,
        };
        let output = OperationSchema {
            schema_ref: r("schema:output"),
            fields: alloc::vec![SchemaField {
                field_ref: r("field:receipt"),
                schema_ref: r("schema:string"),
                role: CapabilityFieldRole::EvidenceReference,
                required: true,
            }],
            extension_policy: SchemaExtensionPolicy::Closed,
        };
        CapabilityManifest {
            capability_ref: r("capability:send"),
            capability_version: v("capability/opaque-7"),
            content_digest: ContentDigest {
                algorithm_ref: r("digest:sha-256"),
                value: r("sha256:manifest"),
            },
            publisher_ref: r("publisher:a"),
            issuer_ref: r("issuer:a"),
            source_ref: r("source:a"),
            artifact_ref: r("artifact:a"),
            adapter_ref: r("adapter:a"),
            adapter_version: v("adapter/opaque-3"),
            provenance_refs: refs(&["provenance:a"]),
            dependencies: alloc::vec![CapabilityDependency {
                dependency_ref: r("dependency:provider-api"),
                version_requirement_ref: r("requirement:provider-version"),
                integrity_requirement_ref: r("requirement:provider-integrity"),
                risk_evidence_requirement_refs: refs(&["evidence:provider-risk"]),
            }],
            operations: alloc::vec![CapabilityOperation {
                operation_ref: r("operation:send"),
                purpose_ref: r("purpose:send"),
                description_ref: r("description:send"),
                input,
                output,
                conditions: OperationConditions {
                    precondition_refs: refs(&["precondition:target-current"]),
                    postcondition_refs: refs(&["postcondition:result-captured"]),
                },
                effect: EffectClaim {
                    external_state_change: ExternalStateChange::MayMutate,
                    outbound_disclosure: OutboundDisclosure::MayDisclose,
                    effect_semantics_ref: r("effect:write"),
                    target_binding: TargetBindingRequirements {
                        resource_binding_ref: None,
                        account_binding_ref: Some(r("binding:account")),
                        principal_binding_ref: Some(r("binding:target")),
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
            }],
            qualification_requirement_refs: refs(&["qualification:effects"]),
        }
    }

    fn qualification(manifest: &CapabilityManifest) -> VerifiedCapabilityQualification {
        let subject = QualificationSubject::from_manifest(
            manifest,
            r("environment:device-a"),
            v("environment/opaque-4"),
            ContentDigest {
                algorithm_ref: r("digest:sha-256"),
                value: r("sha256:environment-profile-device-a"),
            },
        );
        let plan = QualificationPlan {
            identity: QualificationPlanIdentity {
                plan_ref: r("plan:a"),
                plan_version: v("plan/opaque-1"),
                plan_digest: ContentDigest {
                    algorithm_ref: r("digest:sha-256"),
                    value: r("sha256:plan"),
                },
            },
            operation_refs: refs(&["operation:send"]),
            required_evidence_refs: refs(&[
                "qualification:effects",
                "evidence:risk",
                "evidence:resource-cost",
                "evidence:recovery",
                "evidence:idempotency",
                "evidence:status",
                "evidence:cancel",
                "evidence:retry",
            ]),
            evaluation_corpus_refs: refs(&["eval:a"]),
            tooling_refs: refs(&["tool:a"]),
            requested_ceiling: OperatingCeiling::E3ObservableWrite,
            validity_requirement_refs: refs(&["validity:a"]),
            invalidation_dependency_refs: refs(&["invalidate:manifest"]),
        };
        let evidence = plan
            .required_evidence_refs
            .iter()
            .map(|requirement_ref| QualificationEvidenceRecord {
                evidence_ref: r(&alloc::format!("evidence:run:{}", requirement_ref.as_str())),
                subject: subject.clone(),
                plan_identity: plan.identity.clone(),
                requirement_ref: requirement_ref.clone(),
                test_method_ref: r("method:fault-suite"),
                test_run_ref: r("run:a"),
                producer_ref: r("producer:harness"),
                provenance_refs: refs(&["provenance:test"]),
                observed_result_ref: r("result:pass"),
                environment_evidence_refs: refs(&["environment-evidence:a"]),
                validity_ref: r("validity:window-a"),
                status: EvidenceStatus::Pass,
            })
            .collect::<Vec<_>>();
        qualify_capability(manifest, &subject, &plan, &evidence).unwrap()
    }

    fn snapshot(qualification: &VerifiedCapabilityQualification) -> AvailabilitySnapshot {
        AvailabilitySnapshot {
            snapshot_ref: r("availability:a"),
            subject: qualification.subject().clone(),
            qualification_plan: qualification.plan_identity().clone(),
            state_revision: 7,
            state_epoch_ref: r("availability-epoch:12"),
            observed_at_ref: r("time-observation:a"),
            freshness_window_ref: r("freshness-window:a"),
            revalidation_requirement_ref: r("revalidate:on-expiry-or-change"),
            revocation: RevocationObservation {
                state: RevocationState::Active,
                epoch_ref: r("revocation-epoch:9"),
                evidence_refs: refs(&["evidence:revocation-current"]),
            },
            operations: alloc::vec![OperationAvailability {
                operation_ref: r("operation:send"),
                readiness: ReadinessState::Ready,
                evidence_refs: refs(&["evidence:operation-probe"]),
            }],
            dependencies: alloc::vec![DependencyAvailability {
                dependency_ref: r("dependency:provider-api"),
                readiness: ReadinessState::Ready,
                evidence_refs: refs(&["evidence:dependency-probe"]),
            }],
            observer_ref: r("observer:availability-monitor"),
            provenance_refs: refs(&["provenance:availability-observation"]),
        }
    }

    #[test]
    fn exact_qualified_ready_snapshot_is_structurally_verified() {
        let manifest = manifest();
        let qualification = qualification(&manifest);
        let verified =
            verify_availability_snapshot(&manifest, &qualification, snapshot(&qualification))
                .unwrap();
        assert_eq!(verified.aggregate_readiness(), ReadinessState::Ready);
        assert_eq!(verified.revocation_state(), RevocationState::Active);
    }

    #[test]
    fn revocation_and_unknown_are_not_hidden_by_green_health() {
        let manifest = manifest();
        let qualification = qualification(&manifest);
        for (revocation, expected) in [
            (RevocationState::Revoked, ReadinessState::Unavailable),
            (RevocationState::Unknown, ReadinessState::Unknown),
        ] {
            let mut value = snapshot(&qualification);
            value.revocation.state = revocation;
            let verified = verify_availability_snapshot(&manifest, &qualification, value).unwrap();
            assert_eq!(verified.aggregate_readiness(), expected);
        }
    }

    #[test]
    fn unknown_operation_or_missing_coverage_fails_closed() {
        let manifest = manifest();
        let qualification = qualification(&manifest);
        let mut value = snapshot(&qualification);
        value.operations[0].operation_ref = r("operation:not-qualified");
        assert!(matches!(
            verify_availability_snapshot(&manifest, &qualification, value),
            Err(AvailabilityError::UnknownOperation(_))
        ));

        let mut value = snapshot(&qualification);
        value.operations.clear();
        assert_eq!(
            verify_availability_snapshot(&manifest, &qualification, value),
            Err(AvailabilityError::IncompleteOperationCoverage)
        );
    }

    #[test]
    fn dependency_failure_is_visible_in_aggregate_state() {
        let manifest = manifest();
        let qualification = qualification(&manifest);
        let mut value = snapshot(&qualification);
        value.dependencies[0].readiness = ReadinessState::Unavailable;
        let verified = verify_availability_snapshot(&manifest, &qualification, value).unwrap();
        assert_eq!(verified.aggregate_readiness(), ReadinessState::Unavailable);
    }

    #[test]
    fn observation_cannot_float_to_another_qualification_subject() {
        let manifest = manifest();
        let qualification = qualification(&manifest);
        let mut value = snapshot(&qualification);
        value.subject.environment_version = v("environment/changed");
        assert_eq!(
            verify_availability_snapshot(&manifest, &qualification, value),
            Err(AvailabilityError::QualificationBindingMismatch)
        );
    }

    #[test]
    fn duplicate_dependency_observations_fail_closed() {
        let manifest = manifest();
        let qualification = qualification(&manifest);
        let mut value = snapshot(&qualification);
        value.dependencies.push(value.dependencies[0].clone());
        assert!(matches!(
            verify_availability_snapshot(&manifest, &qualification, value),
            Err(AvailabilityError::DuplicateDependency(_))
        ));
    }
}
