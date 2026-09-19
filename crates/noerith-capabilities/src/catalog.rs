extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use crate::{
    availability::VerifiedCapabilityAvailability,
    manifest::{CapabilityManifest, ContentDigest, OpaqueVersion, Reference, validate_manifest},
    qualification::{
        QualificationPlanIdentity, QualificationSubject, VerifiedCapabilityQualification,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityCatalogEntry {
    pub manifest: CapabilityManifest,
    pub qualifications: Vec<VerifiedCapabilityQualification>,
    pub availabilities: Vec<VerifiedCapabilityAvailability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityCatalogSnapshot {
    pub catalog_ref: Reference,
    pub state_revision: u64,
    pub state_epoch_ref: Reference,
    pub integrity_ref: Reference,
    pub freshness_ref: Reference,
    pub provenance_refs: BTreeSet<Reference>,
    pub entries: Vec<CapabilityCatalogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExactCatalogKey {
    capability_ref: Reference,
    capability_version: OpaqueVersion,
    digest_algorithm_ref: Reference,
    digest_value_ref: Reference,
}

impl ExactCatalogKey {
    fn from_manifest(manifest: &CapabilityManifest) -> Self {
        Self {
            capability_ref: manifest.capability_ref.clone(),
            capability_version: manifest.capability_version.clone(),
            digest_algorithm_ref: manifest.content_digest.algorithm_ref.clone(),
            digest_value_ref: manifest.content_digest.value.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExactSubjectKey {
    capability_ref: Reference,
    capability_version: OpaqueVersion,
    manifest_digest_algorithm_ref: Reference,
    manifest_digest_value_ref: Reference,
    artifact_ref: Reference,
    adapter_ref: Reference,
    adapter_version: OpaqueVersion,
    environment_ref: Reference,
    environment_version: OpaqueVersion,
    environment_digest_algorithm_ref: Reference,
    environment_digest_value_ref: Reference,
}

impl ExactSubjectKey {
    fn from_subject(subject: &QualificationSubject) -> Self {
        Self {
            capability_ref: subject.capability_ref.clone(),
            capability_version: subject.capability_version.clone(),
            manifest_digest_algorithm_ref: subject.manifest_digest.algorithm_ref.clone(),
            manifest_digest_value_ref: subject.manifest_digest.value.clone(),
            artifact_ref: subject.artifact_ref.clone(),
            adapter_ref: subject.adapter_ref.clone(),
            adapter_version: subject.adapter_version.clone(),
            environment_ref: subject.environment_ref.clone(),
            environment_version: subject.environment_version.clone(),
            environment_digest_algorithm_ref: subject.environment_digest.algorithm_ref.clone(),
            environment_digest_value_ref: subject.environment_digest.value.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExactQualificationKey {
    subject: ExactSubjectKey,
    plan_ref: Reference,
    plan_version: OpaqueVersion,
    plan_digest_algorithm_ref: Reference,
    plan_digest_value_ref: Reference,
}

impl ExactQualificationKey {
    fn new(subject: &QualificationSubject, plan: &QualificationPlanIdentity) -> Self {
        Self {
            subject: ExactSubjectKey::from_subject(subject),
            plan_ref: plan.plan_ref.clone(),
            plan_version: plan.plan_version.clone(),
            plan_digest_algorithm_ref: plan.plan_digest.algorithm_ref.clone(),
            plan_digest_value_ref: plan.plan_digest.value.clone(),
        }
    }

    fn from_qualification(qualification: &VerifiedCapabilityQualification) -> Self {
        Self::new(qualification.subject(), qualification.plan_identity())
    }

    fn from_availability(availability: &VerifiedCapabilityAvailability) -> Self {
        Self::new(
            &availability.snapshot().subject,
            &availability.snapshot().qualification_plan,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct VersionIdentityKey {
    capability_ref: Reference,
    capability_version: OpaqueVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCapabilityCatalog {
    snapshot: CapabilityCatalogSnapshot,
    exact_index: BTreeMap<ExactCatalogKey, usize>,
    operation_index: BTreeMap<Reference, BTreeSet<usize>>,
    qualification_index: BTreeMap<ExactQualificationKey, (usize, usize)>,
}

impl VerifiedCapabilityCatalog {
    pub fn snapshot(&self) -> &CapabilityCatalogSnapshot {
        &self.snapshot
    }

    pub fn entries(&self) -> &[CapabilityCatalogEntry] {
        &self.snapshot.entries
    }

    pub fn lookup_exact(
        &self,
        capability_ref: &Reference,
        capability_version: &OpaqueVersion,
        content_digest: &ContentDigest,
    ) -> Option<&CapabilityCatalogEntry> {
        let key = ExactCatalogKey {
            capability_ref: capability_ref.clone(),
            capability_version: capability_version.clone(),
            digest_algorithm_ref: content_digest.algorithm_ref.clone(),
            digest_value_ref: content_digest.value.clone(),
        };
        self.exact_index
            .get(&key)
            .and_then(|index| self.snapshot.entries.get(*index))
    }

    pub fn lookup_exact_qualification(
        &self,
        subject: &QualificationSubject,
        plan_identity: &QualificationPlanIdentity,
    ) -> Option<&VerifiedCapabilityQualification> {
        let key = ExactQualificationKey::new(subject, plan_identity);
        let (entry_index, qualification_index) = *self.qualification_index.get(&key)?;
        self.snapshot
            .entries
            .get(entry_index)?
            .qualifications
            .get(qualification_index)
    }

    /// Returns factual known candidates in deterministic catalog order. This is
    /// not semantic ranking and does not imply qualification, availability or
    /// authorization.
    pub fn known_by_operation(&self, operation_ref: &Reference) -> Vec<&CapabilityCatalogEntry> {
        self.operation_index
            .get(operation_ref)
            .into_iter()
            .flat_map(|indices| indices.iter())
            .filter_map(|index| self.snapshot.entries.get(*index))
            .collect()
    }

    /// Returns every exact current qualification that covered this operation.
    /// Returned wrappers preserve environment/plan/evidence context and imply
    /// neither ranking nor runtime authority.
    pub fn qualified_by_operation(
        &self,
        operation_ref: &Reference,
    ) -> Vec<(&CapabilityCatalogEntry, &VerifiedCapabilityQualification)> {
        self.known_by_operation(operation_ref)
            .into_iter()
            .flat_map(|entry| {
                entry
                    .qualifications
                    .iter()
                    .filter(move |qualification| {
                        qualification.operation_refs().contains(operation_ref)
                    })
                    .map(move |qualification| (entry, qualification))
            })
            .collect()
    }

    /// Exposes each exact availability observation without collapsing multiple
    /// environment/plan targets into one ambiguous scalar readiness value.
    pub fn observed_readiness_by_operation(
        &self,
        operation_ref: &Reference,
    ) -> Vec<(&CapabilityCatalogEntry, &VerifiedCapabilityAvailability)> {
        self.known_by_operation(operation_ref)
            .into_iter()
            .flat_map(|entry| {
                entry
                    .availabilities
                    .iter()
                    .filter(move |availability| {
                        availability.operation_readiness(operation_ref).is_some()
                    })
                    .map(move |availability| (entry, availability))
            })
            .collect()
    }
}

/// Build one coherent catalog snapshot. The resulting object is a descriptive
/// capability map only; it contains no permission, credential, dispatch lease,
/// secret, provider session or effect-commit token.
pub fn verify_catalog_snapshot(
    mut snapshot: CapabilityCatalogSnapshot,
) -> Result<VerifiedCapabilityCatalog, CatalogError> {
    if snapshot.state_revision == 0 {
        return Err(CatalogError::InvalidStateRevision);
    }
    if snapshot.provenance_refs.is_empty() {
        return Err(CatalogError::MissingProvenance);
    }

    let mut version_identity = BTreeMap::<VersionIdentityKey, ContentDigest>::new();
    let mut entries_by_key = BTreeMap::<ExactCatalogKey, CapabilityCatalogEntry>::new();

    for entry in snapshot.entries.drain(..) {
        validate_manifest(&entry.manifest).map_err(|_| {
            CatalogError::InvalidManifest(entry.manifest.capability_ref.to_string())
        })?;

        let version_key = VersionIdentityKey {
            capability_ref: entry.manifest.capability_ref.clone(),
            capability_version: entry.manifest.capability_version.clone(),
        };
        if let Some(existing_digest) = version_identity.get(&version_key) {
            if existing_digest != &entry.manifest.content_digest {
                return Err(CatalogError::CapabilityVersionDigestCollision {
                    capability_ref: entry.manifest.capability_ref.to_string(),
                    capability_version: entry.manifest.capability_version.as_str().to_string(),
                });
            }
        } else {
            version_identity.insert(version_key, entry.manifest.content_digest.clone());
        }

        let exact_key = ExactCatalogKey::from_manifest(&entry.manifest);
        if entries_by_key.contains_key(&exact_key) {
            return Err(CatalogError::DuplicateExactEntry(
                entry.manifest.capability_ref.to_string(),
            ));
        }

        let entry = normalize_entry(entry)?;
        entries_by_key.insert(exact_key, entry);
    }

    snapshot.entries = entries_by_key.into_values().collect();

    let mut exact_index = BTreeMap::<ExactCatalogKey, usize>::new();
    let mut operation_index = BTreeMap::<Reference, BTreeSet<usize>>::new();
    let mut qualification_index = BTreeMap::<ExactQualificationKey, (usize, usize)>::new();

    for (entry_index, entry) in snapshot.entries.iter().enumerate() {
        exact_index.insert(ExactCatalogKey::from_manifest(&entry.manifest), entry_index);
        for operation in &entry.manifest.operations {
            operation_index
                .entry(operation.operation_ref.clone())
                .or_default()
                .insert(entry_index);
        }
        for (qualification_offset, qualification) in entry.qualifications.iter().enumerate() {
            qualification_index.insert(
                ExactQualificationKey::from_qualification(qualification),
                (entry_index, qualification_offset),
            );
        }
    }

    Ok(VerifiedCapabilityCatalog {
        snapshot,
        exact_index,
        operation_index,
        qualification_index,
    })
}

fn normalize_entry(
    mut entry: CapabilityCatalogEntry,
) -> Result<CapabilityCatalogEntry, CatalogError> {
    let capability_ref = entry.manifest.capability_ref.to_string();
    let mut qualifications =
        BTreeMap::<ExactQualificationKey, VerifiedCapabilityQualification>::new();

    for qualification in entry.qualifications.drain(..) {
        validate_qualification_manifest_binding(&entry.manifest, &qualification)?;
        let key = ExactQualificationKey::from_qualification(&qualification);
        if qualifications.insert(key, qualification).is_some() {
            return Err(CatalogError::DuplicateCurrentQualification(
                capability_ref.clone(),
            ));
        }
    }

    let mut availabilities =
        BTreeMap::<ExactQualificationKey, VerifiedCapabilityAvailability>::new();
    for availability in entry.availabilities.drain(..) {
        let key = ExactQualificationKey::from_availability(&availability);
        let Some(qualification) = qualifications.get(&key) else {
            if qualifications.is_empty() {
                return Err(CatalogError::AvailabilityWithoutQualification(
                    capability_ref.clone(),
                ));
            }
            return Err(CatalogError::AvailabilityQualificationMismatch(
                capability_ref.clone(),
            ));
        };
        if availability.snapshot().subject != *qualification.subject()
            || availability.snapshot().qualification_plan != *qualification.plan_identity()
        {
            return Err(CatalogError::AvailabilityQualificationMismatch(
                capability_ref.clone(),
            ));
        }
        if availabilities.insert(key, availability).is_some() {
            return Err(CatalogError::DuplicateCurrentAvailability(
                capability_ref.clone(),
            ));
        }
    }

    entry.qualifications = qualifications.into_values().collect();
    entry.availabilities = availabilities.into_values().collect();
    Ok(entry)
}

fn validate_qualification_manifest_binding(
    manifest: &CapabilityManifest,
    qualification: &VerifiedCapabilityQualification,
) -> Result<(), CatalogError> {
    let subject = qualification.subject();
    if subject.capability_ref != manifest.capability_ref
        || subject.capability_version != manifest.capability_version
        || subject.manifest_digest != manifest.content_digest
        || subject.artifact_ref != manifest.artifact_ref
        || subject.adapter_ref != manifest.adapter_ref
        || subject.adapter_version != manifest.adapter_version
    {
        return Err(CatalogError::QualificationManifestMismatch(
            manifest.capability_ref.to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    InvalidStateRevision,
    MissingProvenance,
    InvalidManifest(String),
    DuplicateExactEntry(String),
    CapabilityVersionDigestCollision {
        capability_ref: String,
        capability_version: String,
    },
    QualificationManifestMismatch(String),
    DuplicateCurrentQualification(String),
    AvailabilityWithoutQualification(String),
    AvailabilityQualificationMismatch(String),
    DuplicateCurrentAvailability(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capability catalog rejected: {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        availability::{
            AvailabilitySnapshot, DependencyAvailability, OperationAvailability, ReadinessState,
            RevocationObservation, RevocationState, verify_availability_snapshot,
        },
        manifest::{
            CapabilityFieldRole, CapabilityOperation, EffectClaim, EnvironmentRequirements,
            ExternalStateChange, FailureRecoveryContract, FreshnessRequirements, IdempotencyClaim,
            OperationConditions, OperationRiskContract, OperationSchema, OutboundDisclosure,
            OutcomeObservationContract, ResourceCostContract, ReversibilityClaim,
            SchemaExtensionPolicy, SchemaField, SupportClaim, TargetBindingRequirements,
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

    fn read_manifest(version: &str, digest: &str) -> CapabilityManifest {
        CapabilityManifest {
            capability_ref: r("capability:lookup"),
            capability_version: v(version),
            content_digest: ContentDigest {
                algorithm_ref: r("digest:sha-256"),
                value: r(digest),
            },
            publisher_ref: r("publisher:a"),
            issuer_ref: r("issuer:a"),
            source_ref: r("source:a"),
            artifact_ref: r("artifact:a"),
            adapter_ref: r("adapter:a"),
            adapter_version: v("adapter/opaque-a"),
            provenance_refs: refs(&["provenance:a"]),
            dependencies: Vec::new(),
            operations: alloc::vec![CapabilityOperation {
                operation_ref: r("operation:lookup"),
                purpose_ref: r("purpose:lookup"),
                description_ref: r("description:lookup"),
                input: OperationSchema {
                    schema_ref: r("schema:lookup-input"),
                    fields: alloc::vec![SchemaField {
                        field_ref: r("field:key"),
                        schema_ref: r("schema:string"),
                        role: CapabilityFieldRole::Data,
                        required: true,
                    }],
                    extension_policy: SchemaExtensionPolicy::Closed,
                },
                output: OperationSchema {
                    schema_ref: r("schema:lookup-output"),
                    fields: alloc::vec![SchemaField {
                        field_ref: r("field:evidence"),
                        schema_ref: r("schema:evidence-ref"),
                        role: CapabilityFieldRole::EvidenceReference,
                        required: true,
                    }],
                    extension_policy: SchemaExtensionPolicy::Closed,
                },
                conditions: OperationConditions {
                    precondition_refs: refs(&["precondition:resource-readable"]),
                    postcondition_refs: refs(&["postcondition:evidence-returned"]),
                },
                effect: EffectClaim {
                    external_state_change: ExternalStateChange::None,
                    outbound_disclosure: OutboundDisclosure::None,
                    effect_semantics_ref: r("effect:read-only"),
                    target_binding: TargetBindingRequirements {
                        resource_binding_ref: Some(r("binding:resource")),
                        account_binding_ref: None,
                        principal_binding_ref: None,
                    },
                    outcome_observation: OutcomeObservationContract {
                        observation_method_ref: r("observation:return-value"),
                        evidence_schema_ref: r("schema:evidence-ref"),
                    },
                },
                risk: OperationRiskContract {
                    risk_class_refs: refs(&["risk:read-access"]),
                    consequence_model_ref: r("consequence:model-read"),
                    reversibility: ReversibilityClaim::NotApplicable,
                    evidence_requirement_refs: refs(&["evidence:risk"]),
                },
                resource_cost: ResourceCostContract {
                    resource_estimate_refs: refs(&["resource-estimate:lookup"]),
                    cost_model_ref: r("cost-model:local-read"),
                    evidence_requirement_refs: refs(&["evidence:resource-cost"]),
                },
                failure_recovery: FailureRecoveryContract {
                    failure_mode_refs: refs(&["failure:read-unavailable"]),
                    recovery_strategy_refs: refs(&["recovery:report-unavailable"]),
                    ambiguity_handling_ref: r("ambiguity:not-applicable-read"),
                    evidence_requirement_refs: refs(&["evidence:recovery"]),
                },
                accessed_data_class_refs: refs(&["data:lookup-source"]),
                disclosed_data_class_refs: BTreeSet::new(),
                required_permission_scope_refs: refs(&["permission:read-scoped"]),
                principal_requirement_refs: refs(&["principal:authenticated"]),
                workload_requirement_refs: refs(&["workload:qualified-reader"]),
                environment: EnvironmentRequirements {
                    sandbox_profile_ref: Some(r("sandbox:read-only")),
                    filesystem_scope_refs: BTreeSet::new(),
                    network_destination_refs: BTreeSet::new(),
                    device_capability_refs: BTreeSet::new(),
                    resource_limit_refs: refs(&["resource:bounded"]),
                },
                idempotency: IdempotencyClaim {
                    support: SupportClaim::Unsupported,
                    key_binding_ref: None,
                    retention_requirement_ref: None,
                },
                status_query: SupportClaim::Unsupported,
                cancellation: SupportClaim::Unsupported,
                compensation: SupportClaim::Unsupported,
                retry: SupportClaim::Unsupported,
                shared_atomicity: SupportClaim::Unsupported,
                timeout_requirement_ref: r("timeout:lookup"),
                freshness: FreshnessRequirements {
                    version_requirement_refs: refs(&["version:manifest"]),
                    stale_call_rejection_ref: r("freshness:reject-stale"),
                    maximum_request_age_ref: None,
                },
            }],
            qualification_requirement_refs: refs(&["qualification:read-contract"]),
        }
    }

    fn qualify(manifest: &CapabilityManifest) -> VerifiedCapabilityQualification {
        qualify_in_environment(
            manifest,
            "environment:portable",
            "environment/opaque-1",
            "plan:lookup",
            "plan/opaque-1",
            "sha256:plan-lookup",
        )
    }

    fn qualify_in_environment(
        manifest: &CapabilityManifest,
        environment_ref: &str,
        environment_version: &str,
        plan_ref: &str,
        plan_version: &str,
        plan_digest: &str,
    ) -> VerifiedCapabilityQualification {
        let subject = QualificationSubject::from_manifest(
            manifest,
            r(environment_ref),
            v(environment_version),
            ContentDigest {
                algorithm_ref: r("digest:sha-256"),
                value: r(&alloc::format!(
                    "sha256:profile:{environment_ref}:{environment_version}"
                )),
            },
        );
        let plan = QualificationPlan {
            identity: QualificationPlanIdentity {
                plan_ref: r(plan_ref),
                plan_version: v(plan_version),
                plan_digest: ContentDigest {
                    algorithm_ref: r("digest:sha-256"),
                    value: r(plan_digest),
                },
            },
            operation_refs: refs(&["operation:lookup"]),
            required_evidence_refs: refs(&[
                "qualification:read-contract",
                "evidence:risk",
                "evidence:resource-cost",
                "evidence:recovery",
            ]),
            evaluation_corpus_refs: refs(&["eval:lookup-heldout"]),
            tooling_refs: refs(&["tool:lookup-harness"]),
            requested_ceiling: OperatingCeiling::E0ReadOnly,
            validity_requirement_refs: refs(&["validity:security-review"]),
            invalidation_dependency_refs: refs(&["invalidate:manifest-change"]),
        };
        let evidence = plan
            .required_evidence_refs
            .iter()
            .map(|requirement_ref| QualificationEvidenceRecord {
                evidence_ref: r(&alloc::format!("evidence:run:{}", requirement_ref.as_str())),
                subject: subject.clone(),
                plan_identity: plan.identity.clone(),
                requirement_ref: requirement_ref.clone(),
                test_method_ref: r("method:read-only-conformance"),
                test_run_ref: r("run:lookup-a"),
                producer_ref: r("producer:harness"),
                provenance_refs: refs(&["provenance:test"]),
                observed_result_ref: r("result:pass"),
                environment_evidence_refs: refs(&["environment-evidence:portable"]),
                validity_ref: r("validity:test-window"),
                status: EvidenceStatus::Pass,
            })
            .collect::<Vec<_>>();
        qualify_capability(manifest, &subject, &plan, &evidence).unwrap()
    }

    fn availability(
        manifest: &CapabilityManifest,
        qualification: &VerifiedCapabilityQualification,
        readiness: ReadinessState,
    ) -> VerifiedCapabilityAvailability {
        verify_availability_snapshot(
            manifest,
            qualification,
            AvailabilitySnapshot {
                snapshot_ref: r(&alloc::format!(
                    "availability:lookup:{}:{}",
                    qualification.subject().environment_ref.as_str(),
                    qualification.plan_identity().plan_ref.as_str(),
                )),
                subject: qualification.subject().clone(),
                qualification_plan: qualification.plan_identity().clone(),
                state_revision: 3,
                state_epoch_ref: r("availability-epoch:3"),
                observed_at_ref: r("time-observation:3"),
                freshness_window_ref: r("freshness-window:3"),
                revalidation_requirement_ref: r("revalidate:on-change"),
                revocation: RevocationObservation {
                    state: RevocationState::Active,
                    epoch_ref: r("revocation-epoch:2"),
                    evidence_refs: refs(&["evidence:revocation"]),
                },
                operations: alloc::vec![OperationAvailability {
                    operation_ref: r("operation:lookup"),
                    readiness,
                    evidence_refs: refs(&["evidence:probe"]),
                }],
                dependencies: Vec::<DependencyAvailability>::new(),
                observer_ref: r("observer:availability"),
                provenance_refs: refs(&["provenance:availability"]),
            },
        )
        .unwrap()
    }

    fn snapshot(entries: Vec<CapabilityCatalogEntry>) -> CapabilityCatalogSnapshot {
        CapabilityCatalogSnapshot {
            catalog_ref: r("catalog:capability-map"),
            state_revision: 9,
            state_epoch_ref: r("catalog-epoch:9"),
            integrity_ref: r("integrity:catalog-9"),
            freshness_ref: r("freshness:catalog-9"),
            provenance_refs: refs(&["provenance:catalog-builder"]),
            entries,
        }
    }

    #[test]
    fn same_manifest_can_hold_multiple_exact_current_qualifications() {
        let manifest = read_manifest("provider/portable", "sha256:portable");
        let local = qualify_in_environment(
            &manifest,
            "environment:local-linux",
            "environment/linux-1",
            "plan:lookup-local",
            "plan/local-1",
            "sha256:plan-local",
        );
        let remote = qualify_in_environment(
            &manifest,
            "environment:remote-wasm",
            "environment/wasm-1",
            "plan:lookup-remote",
            "plan/remote-1",
            "sha256:plan-remote",
        );

        let catalog = verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
            manifest: manifest.clone(),
            qualifications: alloc::vec![local.clone(), remote.clone()],
            availabilities: Vec::new(),
        }]))
        .unwrap();

        assert_eq!(catalog.entries().len(), 1);
        assert_eq!(catalog.known_by_operation(&r("operation:lookup")).len(), 1);
        assert_eq!(
            catalog.qualified_by_operation(&r("operation:lookup")).len(),
            2
        );
        assert_eq!(
            catalog
                .lookup_exact_qualification(local.subject(), local.plan_identity())
                .unwrap(),
            &local
        );
        assert_eq!(
            catalog
                .lookup_exact_qualification(remote.subject(), remote.plan_identity())
                .unwrap(),
            &remote
        );
    }

    #[test]
    fn duplicate_current_exact_qualification_is_rejected() {
        let manifest = read_manifest("provider/portable", "sha256:portable");
        let qualification = qualify_in_environment(
            &manifest,
            "environment:local-linux",
            "environment/linux-1",
            "plan:lookup-local",
            "plan/local-1",
            "sha256:plan-local",
        );

        assert!(
            verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
                manifest,
                qualifications: alloc::vec![qualification.clone(), qualification],
                availabilities: Vec::new(),
            }]))
            .is_err(),
            "one current snapshot must not contain two current facts for the exact same qualification subject+plan",
        );
    }

    #[test]
    fn same_subject_distinct_plans_coexist_and_input_order_is_normalized() {
        let manifest = read_manifest("provider/portable", "sha256:portable");
        let alpha = qualify_in_environment(
            &manifest,
            "environment:local-linux",
            "environment/linux-1",
            "plan:lookup-alpha",
            "plan/alpha-1",
            "sha256:plan-alpha",
        );
        let zeta = qualify_in_environment(
            &manifest,
            "environment:local-linux",
            "environment/linux-1",
            "plan:lookup-zeta",
            "plan/zeta-1",
            "sha256:plan-zeta",
        );
        assert_eq!(alpha.subject(), zeta.subject());
        assert_ne!(alpha.plan_identity(), zeta.plan_identity());

        let left = verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
            manifest: manifest.clone(),
            qualifications: alloc::vec![zeta.clone(), alpha.clone()],
            availabilities: Vec::new(),
        }]))
        .unwrap();
        let right = verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
            manifest,
            qualifications: alloc::vec![alpha.clone(), zeta.clone()],
            availabilities: Vec::new(),
        }]))
        .unwrap();

        assert_eq!(left, right);
        assert_eq!(
            left.lookup_exact_qualification(alpha.subject(), alpha.plan_identity())
                .unwrap(),
            &alpha
        );
        assert_eq!(
            left.lookup_exact_qualification(zeta.subject(), zeta.plan_identity())
                .unwrap(),
            &zeta
        );

        let left_plans = left
            .qualified_by_operation(&r("operation:lookup"))
            .into_iter()
            .map(|(_, qualification)| qualification.plan_identity().clone())
            .collect::<Vec<_>>();
        let right_plans = right
            .qualified_by_operation(&r("operation:lookup"))
            .into_iter()
            .map(|(_, qualification)| qualification.plan_identity().clone())
            .collect::<Vec<_>>();
        assert_eq!(left_plans, right_plans);
    }

    #[test]
    fn multi_environment_queries_preserve_exact_qualification_and_readiness_context() {
        let manifest = read_manifest("provider/portable", "sha256:portable");
        let local = qualify_in_environment(
            &manifest,
            "environment:local-linux",
            "environment/linux-1",
            "plan:lookup-local",
            "plan/local-1",
            "sha256:plan-local",
        );
        let remote = qualify_in_environment(
            &manifest,
            "environment:remote-wasm",
            "environment/wasm-1",
            "plan:lookup-remote",
            "plan/remote-1",
            "sha256:plan-remote",
        );
        let local_availability = availability(&manifest, &local, ReadinessState::Ready);
        let remote_availability = availability(&manifest, &remote, ReadinessState::Degraded);

        let catalog = verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
            manifest,
            qualifications: alloc::vec![local.clone(), remote.clone()],
            availabilities: alloc::vec![local_availability, remote_availability],
        }]))
        .unwrap();

        let qualified = catalog.qualified_by_operation(&r("operation:lookup"));
        assert_eq!(qualified.len(), 2);
        assert!(
            qualified
                .iter()
                .any(|(_, value)| value.subject() == local.subject())
        );
        assert!(
            qualified
                .iter()
                .any(|(_, value)| value.subject() == remote.subject())
        );

        let readiness = catalog.observed_readiness_by_operation(&r("operation:lookup"));
        assert_eq!(readiness.len(), 2);
        assert!(readiness.iter().any(|(_, value)| {
            value.snapshot().subject == *local.subject()
                && value.operation_readiness(&r("operation:lookup")) == Some(ReadinessState::Ready)
        }));
        assert!(readiness.iter().any(|(_, value)| {
            value.snapshot().subject == *remote.subject()
                && value.operation_readiness(&r("operation:lookup"))
                    == Some(ReadinessState::Degraded)
        }));
    }

    #[test]
    fn availability_input_order_is_normalized_without_losing_exact_context() {
        let manifest = read_manifest("provider/portable", "sha256:portable");
        let local = qualify_in_environment(
            &manifest,
            "environment:local-linux",
            "environment/linux-1",
            "plan:lookup-local",
            "plan/local-1",
            "sha256:plan-local",
        );
        let remote = qualify_in_environment(
            &manifest,
            "environment:remote-wasm",
            "environment/wasm-1",
            "plan:lookup-remote",
            "plan/remote-1",
            "sha256:plan-remote",
        );
        let local_availability = availability(&manifest, &local, ReadinessState::Ready);
        let remote_availability = availability(&manifest, &remote, ReadinessState::Degraded);

        let left = verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
            manifest: manifest.clone(),
            qualifications: alloc::vec![remote.clone(), local.clone()],
            availabilities: alloc::vec![remote_availability.clone(), local_availability.clone(),],
        }]))
        .unwrap();

        let right = verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
            manifest,
            qualifications: alloc::vec![local, remote],
            availabilities: alloc::vec![local_availability, remote_availability],
        }]))
        .unwrap();

        assert_eq!(left, right);
        let left_targets = left
            .observed_readiness_by_operation(&r("operation:lookup"))
            .into_iter()
            .map(|(_, value)| {
                (
                    value.snapshot().subject.clone(),
                    value.snapshot().qualification_plan.clone(),
                )
            })
            .collect::<Vec<_>>();
        let right_targets = right
            .observed_readiness_by_operation(&r("operation:lookup"))
            .into_iter()
            .map(|(_, value)| {
                (
                    value.snapshot().subject.clone(),
                    value.snapshot().qualification_plan.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(left_targets, right_targets);
    }

    #[test]
    fn availability_for_an_unlisted_exact_qualification_is_rejected() {
        let manifest = read_manifest("provider/portable", "sha256:portable");
        let local = qualify_in_environment(
            &manifest,
            "environment:local-linux",
            "environment/linux-1",
            "plan:lookup-local",
            "plan/local-1",
            "sha256:plan-local",
        );
        let remote = qualify_in_environment(
            &manifest,
            "environment:remote-wasm",
            "environment/wasm-1",
            "plan:lookup-remote",
            "plan/remote-1",
            "sha256:plan-remote",
        );
        let remote_availability = availability(&manifest, &remote, ReadinessState::Ready);

        assert!(
            verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
                manifest,
                qualifications: alloc::vec![local],
                availabilities: alloc::vec![remote_availability],
            }]))
            .is_err(),
            "availability must match one exact current qualification, not merely the same manifest",
        );
    }

    #[test]
    fn duplicate_current_availability_target_is_rejected() {
        let manifest = read_manifest("provider/portable", "sha256:portable");
        let qualification = qualify_in_environment(
            &manifest,
            "environment:local-linux",
            "environment/linux-1",
            "plan:lookup-local",
            "plan/local-1",
            "sha256:plan-local",
        );
        let first = availability(&manifest, &qualification, ReadinessState::Ready);
        let duplicate_target = availability(&manifest, &qualification, ReadinessState::Degraded);

        assert!(
            verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
                manifest,
                qualifications: alloc::vec![qualification],
                availabilities: alloc::vec![first, duplicate_target],
            }]))
            .is_err(),
            "one immutable current catalog snapshot must have at most one availability observation per exact qualification target",
        );
    }

    #[test]
    fn known_qualified_and_available_remain_distinct_facts() {
        let known = read_manifest("provider/opaque-1", "sha256:manifest-1");
        let qualified_manifest = read_manifest("provider/opaque-2", "sha256:manifest-2");
        let qualification = qualify(&qualified_manifest);
        let available = availability(&qualified_manifest, &qualification, ReadinessState::Ready);

        let catalog = verify_catalog_snapshot(snapshot(alloc::vec![
            CapabilityCatalogEntry {
                manifest: known,
                qualifications: Vec::new(),
                availabilities: Vec::new(),
            },
            CapabilityCatalogEntry {
                manifest: qualified_manifest,
                qualifications: alloc::vec![qualification],
                availabilities: alloc::vec![available],
            },
        ]))
        .unwrap();

        assert_eq!(catalog.known_by_operation(&r("operation:lookup")).len(), 2);
        assert_eq!(
            catalog.qualified_by_operation(&r("operation:lookup")).len(),
            1
        );
        assert_eq!(
            catalog
                .observed_readiness_by_operation(&r("operation:lookup"))
                .len(),
            1
        );
    }

    #[test]
    fn qualification_is_never_generalized_to_an_untested_sibling_operation() {
        let mut manifest = read_manifest("provider/opaque-multi", "sha256:multi");
        let mut sibling = manifest.operations[0].clone();
        sibling.operation_ref = r("operation:unqualified-sibling");
        manifest.operations.push(sibling);
        let qualification = qualify(&manifest);
        assert!(
            !qualification
                .operation_refs()
                .contains(&r("operation:unqualified-sibling"))
        );

        let catalog = verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
            manifest,
            qualifications: alloc::vec![qualification],
            availabilities: Vec::new(),
        }]))
        .unwrap();
        assert_eq!(
            catalog
                .known_by_operation(&r("operation:unqualified-sibling"))
                .len(),
            1
        );
        assert!(
            catalog
                .qualified_by_operation(&r("operation:unqualified-sibling"))
                .is_empty()
        );
    }

    #[test]
    fn catalog_entry_input_order_is_not_hidden_candidate_priority() {
        let alpha = read_manifest("build/alpha", "sha256:alpha");
        let zeta = read_manifest("build/zeta", "sha256:zeta");

        let left = verify_catalog_snapshot(snapshot(alloc::vec![
            CapabilityCatalogEntry {
                manifest: zeta.clone(),
                qualifications: Vec::new(),
                availabilities: Vec::new(),
            },
            CapabilityCatalogEntry {
                manifest: alpha.clone(),
                qualifications: Vec::new(),
                availabilities: Vec::new(),
            },
        ]))
        .unwrap();

        let right = verify_catalog_snapshot(snapshot(alloc::vec![
            CapabilityCatalogEntry {
                manifest: alpha,
                qualifications: Vec::new(),
                availabilities: Vec::new(),
            },
            CapabilityCatalogEntry {
                manifest: zeta,
                qualifications: Vec::new(),
                availabilities: Vec::new(),
            },
        ]))
        .unwrap();

        assert_eq!(left, right);
        let left_refs = left
            .known_by_operation(&r("operation:lookup"))
            .into_iter()
            .map(|entry| entry.manifest.capability_version.clone())
            .collect::<Vec<_>>();
        let right_refs = right
            .known_by_operation(&r("operation:lookup"))
            .into_iter()
            .map(|entry| entry.manifest.capability_version.clone())
            .collect::<Vec<_>>();
        assert_eq!(left_refs, right_refs);
    }

    #[test]
    fn same_capability_and_version_cannot_resolve_to_two_digests() {
        let left = read_manifest("opaque-same", "sha256:left");
        let right = read_manifest("opaque-same", "sha256:right");
        let result = verify_catalog_snapshot(snapshot(alloc::vec![
            CapabilityCatalogEntry {
                manifest: left,
                qualifications: Vec::new(),
                availabilities: Vec::new(),
            },
            CapabilityCatalogEntry {
                manifest: right,
                qualifications: Vec::new(),
                availabilities: Vec::new(),
            },
        ]));
        assert!(matches!(
            result,
            Err(CatalogError::CapabilityVersionDigestCollision { .. })
        ));
    }

    #[test]
    fn exact_duplicate_is_rejected_but_distinct_opaque_versions_coexist() {
        let first = read_manifest("opaque-1", "sha256:first");
        let duplicate = first.clone();
        assert!(matches!(
            verify_catalog_snapshot(snapshot(alloc::vec![
                CapabilityCatalogEntry {
                    manifest: first,
                    qualifications: Vec::new(),
                    availabilities: Vec::new(),
                },
                CapabilityCatalogEntry {
                    manifest: duplicate,
                    qualifications: Vec::new(),
                    availabilities: Vec::new(),
                },
            ])),
            Err(CatalogError::DuplicateExactEntry(_))
        ));

        let one = read_manifest("build/zeta", "sha256:zeta");
        let two = read_manifest("build/alpha", "sha256:alpha");
        let catalog = verify_catalog_snapshot(snapshot(alloc::vec![
            CapabilityCatalogEntry {
                manifest: one,
                qualifications: Vec::new(),
                availabilities: Vec::new(),
            },
            CapabilityCatalogEntry {
                manifest: two,
                qualifications: Vec::new(),
                availabilities: Vec::new(),
            },
        ]))
        .unwrap();
        assert_eq!(catalog.entries().len(), 2);
    }

    #[test]
    fn availability_without_exact_qualification_is_rejected() {
        let manifest = read_manifest("opaque-1", "sha256:one");
        let qualification = qualify(&manifest);
        let available = availability(&manifest, &qualification, ReadinessState::Ready);
        assert!(matches!(
            verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
                manifest,
                qualifications: Vec::new(),
                availabilities: alloc::vec![available],
            }])),
            Err(CatalogError::AvailabilityWithoutQualification(_))
        ));
    }

    #[test]
    fn exact_lookup_is_content_bound_not_only_name_bound() {
        let manifest = read_manifest("opaque-1", "sha256:one");
        let digest = manifest.content_digest.clone();
        let catalog = verify_catalog_snapshot(snapshot(alloc::vec![CapabilityCatalogEntry {
            manifest: manifest.clone(),
            qualifications: Vec::new(),
            availabilities: Vec::new(),
        }]))
        .unwrap();

        assert!(
            catalog
                .lookup_exact(
                    &manifest.capability_ref,
                    &manifest.capability_version,
                    &digest
                )
                .is_some()
        );
        let wrong = ContentDigest {
            algorithm_ref: r("digest:sha-256"),
            value: r("sha256:other"),
        };
        assert!(
            catalog
                .lookup_exact(
                    &manifest.capability_ref,
                    &manifest.capability_version,
                    &wrong
                )
                .is_none()
        );
    }

    #[test]
    fn zero_revision_or_missing_provenance_never_builds_current_catalog() {
        let mut value = snapshot(Vec::new());
        value.state_revision = 0;
        assert_eq!(
            verify_catalog_snapshot(value),
            Err(CatalogError::InvalidStateRevision)
        );

        let mut value = snapshot(Vec::new());
        value.provenance_refs.clear();
        assert_eq!(
            verify_catalog_snapshot(value),
            Err(CatalogError::MissingProvenance)
        );
    }
}
