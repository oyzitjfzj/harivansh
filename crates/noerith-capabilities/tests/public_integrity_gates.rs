use noerith_capabilities::*;
use std::collections::BTreeSet;

fn r(value: &str) -> Reference {
    Reference::new(value).unwrap()
}

fn v(value: &str) -> OpaqueVersion {
    OpaqueVersion::new(value).unwrap()
}

fn refs(values: &[&str]) -> BTreeSet<Reference> {
    values.iter().map(|value| r(value)).collect()
}

fn environment_digest() -> ContentDigest {
    ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r("sha256:environment-profile-a"),
    }
}

fn manifest() -> CapabilityManifest {
    CapabilityManifest {
        capability_ref: r("capability:lookup"),
        capability_version: v("opaque/capability-A"),
        content_digest: ContentDigest {
            algorithm_ref: r(SHA256_ALGORITHM_REF),
            value: r("sha256:untrusted-placeholder"),
        },
        publisher_ref: r("publisher:a"),
        issuer_ref: r("issuer:a"),
        source_ref: r("source:a"),
        artifact_ref: r("artifact:a"),
        adapter_ref: r("adapter:a"),
        adapter_version: v("opaque/adapter-A"),
        provenance_refs: refs(&["provenance:a"]),
        dependencies: Vec::new(),
        operations: vec![CapabilityOperation {
            operation_ref: r("operation:lookup"),
            purpose_ref: r("purpose:lookup"),
            description_ref: r("description:lookup"),
            input: OperationSchema {
                schema_ref: r("schema:lookup-input"),
                fields: vec![SchemaField {
                    field_ref: r("field:key"),
                    schema_ref: r("schema:string"),
                    role: CapabilityFieldRole::Data,
                    required: true,
                }],
                extension_policy: SchemaExtensionPolicy::Closed,
            },
            output: OperationSchema {
                schema_ref: r("schema:lookup-output"),
                fields: vec![SchemaField {
                    field_ref: r("field:evidence"),
                    schema_ref: r("schema:evidence"),
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
                    resource_binding_ref: None,
                    account_binding_ref: None,
                    principal_binding_ref: None,
                },
                outcome_observation: OutcomeObservationContract {
                    observation_method_ref: r("observation:return-value"),
                    evidence_schema_ref: r("schema:evidence"),
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
            accessed_data_class_refs: refs(&["data:lookup"]),
            disclosed_data_class_refs: BTreeSet::new(),
            required_permission_scope_refs: refs(&["permission:read"]),
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
            timeout_requirement_ref: r("timeout:bounded"),
            freshness: FreshnessRequirements {
                version_requirement_refs: refs(&["version:manifest", "version:adapter"]),
                stale_call_rejection_ref: r("freshness:reject-stale"),
                maximum_request_age_ref: None,
            },
        }],
        qualification_requirement_refs: refs(&["qualification:read-contract"]),
    }
}

fn finalized_manifest() -> CapabilityManifest {
    let mut manifest = manifest();
    manifest.content_digest = compute_manifest_digest(&manifest).unwrap();
    manifest
}

fn plan() -> QualificationPlan {
    let mut plan = QualificationPlan {
        identity: QualificationPlanIdentity {
            plan_ref: r("plan:lookup"),
            plan_version: v("opaque/plan-A"),
            plan_digest: ContentDigest {
                algorithm_ref: r(SHA256_ALGORITHM_REF),
                value: r("sha256:untrusted-plan-placeholder"),
            },
        },
        operation_refs: refs(&["operation:lookup"]),
        required_evidence_refs: refs(&[
            "qualification:read-contract",
            "evidence:risk",
            "evidence:resource-cost",
            "evidence:recovery",
        ]),
        evaluation_corpus_refs: refs(&["eval:heldout-read"]),
        tooling_refs: refs(&["tool:conformance-runner"]),
        requested_ceiling: OperatingCeiling::E0ReadOnly,
        validity_requirement_refs: refs(&["validity:security-review"]),
        invalidation_dependency_refs: refs(&[
            "invalidate:manifest",
            "invalidate:adapter",
            "invalidate:environment",
        ]),
    };
    plan.identity.plan_digest = compute_qualification_plan_digest(&plan).unwrap();
    plan
}

fn qualifying_evidence(
    subject: &QualificationSubject,
    plan: &QualificationPlan,
) -> Vec<QualificationEvidenceRecord> {
    plan.required_evidence_refs
        .iter()
        .map(|requirement_ref| QualificationEvidenceRecord {
            evidence_ref: r(&format!("evidence:run:{}", requirement_ref.as_str())),
            subject: subject.clone(),
            plan_identity: plan.identity.clone(),
            requirement_ref: requirement_ref.clone(),
            test_method_ref: r("method:adversarial-conformance"),
            test_run_ref: r("run:immutable-A"),
            producer_ref: r("producer:independent-harness"),
            provenance_refs: refs(&["provenance:test-run"]),
            observed_result_ref: r("result:pass"),
            environment_evidence_refs: refs(&["environment-evidence:A"]),
            validity_ref: r("validity:window-A"),
            status: EvidenceStatus::Pass,
        })
        .collect()
}

fn qualify(
    manifest: &CapabilityManifest,
    integrity: &VerifiedManifestIntegrity,
) -> VerifiedCapabilityQualification {
    let subject = QualificationSubject::from_manifest(
        manifest,
        r("environment:A"),
        v("opaque/environment-A"),
        environment_digest(),
    );
    let plan = plan();
    let evidence = qualifying_evidence(&subject, &plan);
    qualify_capability(manifest, integrity, &subject, &plan, &evidence).unwrap()
}

#[test]
fn public_qualification_recomputes_manifest_integrity_before_issuing_verified_state() {
    let manifest = finalized_manifest();
    let integrity = verify_manifest_integrity(&manifest).unwrap();
    let verified = qualify(&manifest, &integrity);
    assert_eq!(verified.subject().manifest_digest, manifest.content_digest);

    let mut mutated = manifest.clone();
    mutated.source_ref = r("source:changed-after-integrity-proof");
    let subject = QualificationSubject::from_manifest(
        &mutated,
        r("environment:A"),
        v("opaque/environment-A"),
        environment_digest(),
    );
    let plan = plan();
    let evidence = qualifying_evidence(&subject, &plan);
    assert_eq!(
        qualify_capability(&mutated, &integrity, &subject, &plan, &evidence),
        Err(CapabilityGateError::Integrity(
            IntegrityError::DigestMismatch
        ))
    );
}

#[test]
fn public_qualification_requires_every_scoped_claim_evidence() {
    let manifest = finalized_manifest();
    let integrity = verify_manifest_integrity(&manifest).unwrap();
    let subject = QualificationSubject::from_manifest(
        &manifest,
        r("environment:A"),
        v("opaque/environment-A"),
        environment_digest(),
    );
    let mut incomplete = plan();
    incomplete
        .required_evidence_refs
        .remove(&r("evidence:recovery"));
    incomplete.identity.plan_digest = compute_qualification_plan_digest(&incomplete).unwrap();
    let evidence = qualifying_evidence(&subject, &incomplete);
    assert_eq!(
        qualify_capability(&manifest, &integrity, &subject, &incomplete, &evidence),
        Err(CapabilityGateError::Qualification(
            QualificationError::PlanDropsOperationClaimRequirement("evidence:recovery".into())
        ))
    );
}

#[test]
fn public_qualification_rejects_changed_plan_before_passing_evidence_is_appraised() {
    let manifest = finalized_manifest();
    let integrity = verify_manifest_integrity(&manifest).unwrap();
    let subject = QualificationSubject::from_manifest(
        &manifest,
        r("environment:A"),
        v("opaque/environment-A"),
        environment_digest(),
    );
    let mut changed_plan = plan();
    changed_plan.requested_ceiling = OperatingCeiling::E1OpaqueWrite;
    let evidence = qualifying_evidence(&subject, &changed_plan);
    assert_eq!(
        qualify_capability(&manifest, &integrity, &subject, &changed_plan, &evidence),
        Err(CapabilityGateError::QualificationPlanIntegrity(
            QualificationPlanIntegrityError::DigestMismatch
        ))
    );
}

#[test]
fn rehashing_changed_manifest_cannot_replay_an_older_integrity_proof() {
    let manifest = finalized_manifest();
    let old_integrity = verify_manifest_integrity(&manifest).unwrap();

    let mut changed = manifest.clone();
    changed.source_ref = r("source:new-release");
    changed.content_digest = compute_manifest_digest(&changed).unwrap();
    let subject = QualificationSubject::from_manifest(
        &changed,
        r("environment:A"),
        v("opaque/environment-A"),
        environment_digest(),
    );
    let plan = plan();
    let evidence = qualifying_evidence(&subject, &plan);

    assert_eq!(
        qualify_capability(&changed, &old_integrity, &subject, &plan, &evidence),
        Err(CapabilityGateError::IntegrityBindingMismatch)
    );
}

#[test]
fn public_availability_gate_rejects_manifest_changed_after_qualification() {
    let manifest = finalized_manifest();
    let integrity = verify_manifest_integrity(&manifest).unwrap();
    let qualification = qualify(&manifest, &integrity);
    let snapshot = AvailabilitySnapshot {
        snapshot_ref: r("availability:A"),
        subject: qualification.subject().clone(),
        qualification_plan: qualification.plan_identity().clone(),
        state_revision: 1,
        state_epoch_ref: r("availability-epoch:A"),
        observed_at_ref: r("time:observation-A"),
        freshness_window_ref: r("freshness:window-A"),
        revalidation_requirement_ref: r("revalidate:before-use"),
        revocation: RevocationObservation {
            state: RevocationState::Active,
            epoch_ref: r("revocation:A"),
            evidence_refs: refs(&["evidence:revocation-A"]),
        },
        operations: vec![OperationAvailability {
            operation_ref: r("operation:lookup"),
            readiness: ReadinessState::Ready,
            evidence_refs: refs(&["evidence:health-A"]),
        }],
        dependencies: Vec::new(),
        observer_ref: r("observer:health-A"),
        provenance_refs: refs(&["provenance:availability-A"]),
    };
    assert!(
        verify_availability_snapshot(&manifest, &integrity, &qualification, snapshot.clone())
            .is_ok()
    );

    let mut changed = manifest.clone();
    changed.publisher_ref = r("publisher:changed");
    changed.content_digest = compute_manifest_digest(&changed).unwrap();
    assert_eq!(
        verify_availability_snapshot(&changed, &integrity, &qualification, snapshot),
        Err(CapabilityGateError::IntegrityBindingMismatch)
    );
}

#[test]
fn public_catalog_gate_rejects_forged_digest_and_stale_qualification() {
    let manifest = finalized_manifest();
    let integrity = verify_manifest_integrity(&manifest).unwrap();
    let qualification = qualify(&manifest, &integrity);

    let valid = CapabilityCatalogSnapshot {
        catalog_ref: r("catalog:A"),
        state_revision: 1,
        state_epoch_ref: r("catalog-epoch:A"),
        integrity_ref: r("catalog-integrity:A"),
        freshness_ref: r("catalog-freshness:A"),
        provenance_refs: refs(&["provenance:catalog-A"]),
        entries: vec![CapabilityCatalogEntry {
            manifest: manifest.clone(),
            qualifications: vec![qualification.clone()],
            availabilities: Vec::new(),
        }],
    };
    assert!(verify_catalog_snapshot(valid).is_ok());

    let mut forged = manifest.clone();
    forged.source_ref = r("source:tampered-without-rehash");
    let forged_catalog = CapabilityCatalogSnapshot {
        catalog_ref: r("catalog:forged"),
        state_revision: 1,
        state_epoch_ref: r("catalog-epoch:forged"),
        integrity_ref: r("catalog-integrity:forged"),
        freshness_ref: r("catalog-freshness:forged"),
        provenance_refs: refs(&["provenance:catalog-forged"]),
        entries: vec![CapabilityCatalogEntry {
            manifest: forged,
            qualifications: Vec::new(),
            availabilities: Vec::new(),
        }],
    };
    assert_eq!(
        verify_catalog_snapshot(forged_catalog),
        Err(CapabilityGateError::Integrity(
            IntegrityError::DigestMismatch
        ))
    );

    let mut changed = manifest;
    changed.source_ref = r("source:legitimate-new-release");
    changed.content_digest = compute_manifest_digest(&changed).unwrap();
    let stale_qualification_catalog = CapabilityCatalogSnapshot {
        catalog_ref: r("catalog:stale-qualification"),
        state_revision: 2,
        state_epoch_ref: r("catalog-epoch:B"),
        integrity_ref: r("catalog-integrity:B"),
        freshness_ref: r("catalog-freshness:B"),
        provenance_refs: refs(&["provenance:catalog-B"]),
        entries: vec![CapabilityCatalogEntry {
            manifest: changed,
            qualifications: vec![qualification],
            availabilities: Vec::new(),
        }],
    };
    assert!(matches!(
        verify_catalog_snapshot(stale_qualification_catalog),
        Err(CapabilityGateError::Catalog(
            CatalogError::QualificationManifestMismatch(_)
        ))
    ));
}
