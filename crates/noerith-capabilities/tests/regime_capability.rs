mod regime_fixture {
    include!("regime_plan.rs");

    pub fn software_plan(required_operations: &[&str]) -> SixRegimeQualificationPlan {
        let mut plan = valid_plan();
        let pipeline = plan
            .pipelines
            .iter_mut()
            .find(|pipeline| pipeline.regime == SpecialistRegime::SoftwareEngineering)
            .unwrap();
        pipeline.required_capabilities[0].required_operation_refs = refs(required_operations);
        pipeline.content_digest = compute_regime_pipeline_digest(pipeline).unwrap();
        plan.content_digest = compute_six_regime_qualification_plan_digest(&plan).unwrap();
        plan
    }

    pub fn software_plan_with_second_requirement() -> SixRegimeQualificationPlan {
        let mut plan = software_plan(&["operation:lookup"]);
        let pipeline = plan
            .pipelines
            .iter_mut()
            .find(|pipeline| pipeline.regime == SpecialistRegime::SoftwareEngineering)
            .unwrap();
        pipeline
            .required_capabilities
            .push(RegimeCapabilityRequirement {
                requirement_ref: r("capability-set:software-engineering:secondary"),
                required_operation_refs: refs(&["operation:lookup"]),
            });
        pipeline.content_digest = compute_regime_pipeline_digest(pipeline).unwrap();
        plan.content_digest = compute_six_regime_qualification_plan_digest(&plan).unwrap();
        plan
    }
}

mod capability_fixture {
    include!("public_integrity_gates.rs");

    pub fn qualified_entry(suffix: &str) -> CapabilityCatalogEntry {
        let mut manifest = finalized_manifest();
        manifest.capability_ref = r(&format!("capability:{suffix}"));
        manifest.capability_version = v(&format!("capability-version:{suffix}"));
        manifest.artifact_ref = r(&format!("artifact:{suffix}"));
        manifest.adapter_ref = r(&format!("adapter:{suffix}"));
        manifest.adapter_version = v(&format!("adapter-version:{suffix}"));
        manifest.content_digest = compute_manifest_digest(&manifest).unwrap();
        let integrity = verify_manifest_integrity(&manifest).unwrap();
        let qualification = qualify(&manifest, &integrity);
        CapabilityCatalogEntry {
            manifest,
            qualifications: vec![qualification],
            availabilities: Vec::new(),
        }
    }

    pub fn qualified_entry_in_two_environments(
        suffix: &str,
    ) -> (
        CapabilityCatalogEntry,
        VerifiedCapabilityQualification,
        VerifiedCapabilityQualification,
    ) {
        let mut manifest = finalized_manifest();
        manifest.capability_ref = r(&format!("capability:{suffix}"));
        manifest.capability_version = v(&format!("capability-version:{suffix}"));
        manifest.artifact_ref = r(&format!("artifact:{suffix}"));
        manifest.adapter_ref = r(&format!("adapter:{suffix}"));
        manifest.adapter_version = v(&format!("adapter-version:{suffix}"));
        manifest.content_digest = compute_manifest_digest(&manifest).unwrap();
        let integrity = verify_manifest_integrity(&manifest).unwrap();
        let plan = plan();

        let local_subject = QualificationSubject::from_manifest(
            &manifest,
            r("environment:local-linux"),
            v("opaque/environment-local-linux"),
            ContentDigest {
                algorithm_ref: r(SHA256_ALGORITHM_REF),
                value: r("sha256:environment-profile-local-linux"),
            },
        );
        let local_evidence = qualifying_evidence(&local_subject, &plan);
        let local = qualify_capability(
            &manifest,
            &integrity,
            &local_subject,
            &plan,
            &local_evidence,
        )
        .unwrap();

        let remote_subject = QualificationSubject::from_manifest(
            &manifest,
            r("environment:remote-wasm"),
            v("opaque/environment-remote-wasm"),
            ContentDigest {
                algorithm_ref: r(SHA256_ALGORITHM_REF),
                value: r("sha256:environment-profile-remote-wasm"),
            },
        );
        let remote_evidence = qualifying_evidence(&remote_subject, &plan);
        let remote = qualify_capability(
            &manifest,
            &integrity,
            &remote_subject,
            &plan,
            &remote_evidence,
        )
        .unwrap();

        let entry = CapabilityCatalogEntry {
            manifest,
            qualifications: vec![local.clone(), remote.clone()],
            availabilities: Vec::new(),
        };
        (entry, local, remote)
    }

    pub fn known_unqualified_entry(suffix: &str) -> CapabilityCatalogEntry {
        let mut manifest = finalized_manifest();
        manifest.capability_ref = r(&format!("capability:{suffix}"));
        manifest.capability_version = v(&format!("capability-version:{suffix}"));
        manifest.artifact_ref = r(&format!("artifact:{suffix}"));
        manifest.adapter_ref = r(&format!("adapter:{suffix}"));
        manifest.adapter_version = v(&format!("adapter-version:{suffix}"));
        manifest.content_digest = compute_manifest_digest(&manifest).unwrap();
        CapabilityCatalogEntry {
            manifest,
            qualifications: Vec::new(),
            availabilities: Vec::new(),
        }
    }
}

use noerith_capabilities::{
    CapabilityCatalogEntry, CapabilityCatalogSnapshot, ContentDigest, OpaqueVersion, Reference,
    RegimeCapabilityBindingRecord, RegimeCapabilityError, SHA256_ALGORITHM_REF,
    SixRegimeQualificationPlan, SpecialistRegime, VerifiedCapabilityCatalog,
    VerifiedCapabilityQualification, compute_regime_capability_binding_digest,
    verify_catalog_snapshot, verify_regime_capability_conformance,
    verify_six_regime_qualification_plan,
};
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

fn pending_digest() -> ContentDigest {
    ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r("sha256:pending-regime-capability-binding"),
    }
}

fn catalog(entries: Vec<CapabilityCatalogEntry>) -> VerifiedCapabilityCatalog {
    verify_catalog_snapshot(CapabilityCatalogSnapshot {
        catalog_ref: r("catalog:s05-regime-capability"),
        state_revision: 1,
        state_epoch_ref: r("catalog-epoch:s05-regime-capability"),
        integrity_ref: r("catalog-integrity:s05-regime-capability"),
        freshness_ref: r("catalog-freshness:s05-regime-capability"),
        provenance_refs: refs(&["provenance:s05-regime-capability-catalog"]),
        entries,
    })
    .unwrap()
}

fn binding(
    plan: &SixRegimeQualificationPlan,
    requirement_ref: &str,
    qualification: &VerifiedCapabilityQualification,
    suffix: &str,
) -> RegimeCapabilityBindingRecord {
    let pipeline = plan
        .pipelines
        .iter()
        .find(|pipeline| pipeline.regime == SpecialistRegime::SoftwareEngineering)
        .unwrap();
    let mut invalidation_dependency_refs = qualification.invalidation_dependency_refs().clone();
    invalidation_dependency_refs.insert(r("dependency:regime-capability-binding-policy"));
    let mut record = RegimeCapabilityBindingRecord {
        binding_ref: r(&format!("regime-capability-binding:{suffix}")),
        binding_version: v("binding-v1"),
        content_digest: pending_digest(),
        regime: SpecialistRegime::SoftwareEngineering,
        pipeline_ref: pipeline.pipeline_ref.clone(),
        pipeline_version: pipeline.pipeline_version.clone(),
        pipeline_digest: pipeline.content_digest.clone(),
        requirement_ref: r(requirement_ref),
        subject: qualification.subject().clone(),
        qualification_plan_identity: qualification.plan_identity().clone(),
        qualification_evidence_refs: qualification.evidence_refs().clone(),
        qualification_validity_requirement_refs: qualification.validity_requirement_refs().clone(),
        provenance_refs: refs(&["provenance:regime-capability-conformance"]),
        invalidation_dependency_refs,
    };
    record.content_digest = compute_regime_capability_binding_digest(&record).unwrap();
    record
}

#[test]
fn s05_exact_qualified_capability_satisfies_preregistered_operations_without_current_availability()
{
    let plan = regime_fixture::software_plan(&["operation:lookup"]);
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let qualified_entry = capability_fixture::qualified_entry("lookup-a");
    let qualification = qualified_entry.qualifications[0].clone();
    let known_only = capability_fixture::known_unqualified_entry("known-only");
    let catalog = catalog(vec![qualified_entry, known_only]);
    let binding = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "lookup-a",
    );

    let verified = verify_regime_capability_conformance(
        &plan,
        &verified_plan,
        SpecialistRegime::SoftwareEngineering,
        &catalog,
        &[binding],
    )
    .unwrap();

    assert_eq!(verified.requirement_count(), 1);
    assert_eq!(
        verified
            .subjects_for(&r("capability-set:software-engineering"))
            .unwrap()
            .len(),
        1
    );
    assert!(
        catalog
            .entries()
            .iter()
            .all(|entry| entry.availabilities.is_empty())
    );
}

#[test]
fn s05_regime_binding_resolves_the_exact_environment_qualification_from_one_manifest() {
    let plan = regime_fixture::software_plan(&["operation:lookup"]);
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let (entry, local, remote) =
        capability_fixture::qualified_entry_in_two_environments("portable-lookup");
    assert_ne!(local.subject(), remote.subject());
    let catalog = catalog(vec![entry]);
    let remote_binding = binding(
        &plan,
        "capability-set:software-engineering",
        &remote,
        "portable-lookup-remote",
    );

    let verified = verify_regime_capability_conformance(
        &plan,
        &verified_plan,
        SpecialistRegime::SoftwareEngineering,
        &catalog,
        &[remote_binding],
    )
    .unwrap();

    let subjects = verified
        .subjects_for(&r("capability-set:software-engineering"))
        .unwrap();
    assert_eq!(subjects, core::slice::from_ref(remote.subject()));
    assert_ne!(&subjects[0], local.subject());
}

#[test]
fn s05_multiple_qualified_alternatives_may_satisfy_one_requirement_without_ranking() {
    let plan = regime_fixture::software_plan(&["operation:lookup"]);
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let first = capability_fixture::qualified_entry("lookup-a");
    let second = capability_fixture::qualified_entry("lookup-b");
    let first_qualification = first.qualifications[0].clone();
    let second_qualification = second.qualifications[0].clone();
    let catalog = catalog(vec![first, second]);
    let bindings = vec![
        binding(
            &plan,
            "capability-set:software-engineering",
            &first_qualification,
            "lookup-a",
        ),
        binding(
            &plan,
            "capability-set:software-engineering",
            &second_qualification,
            "lookup-b",
        ),
    ];

    let verified = verify_regime_capability_conformance(
        &plan,
        &verified_plan,
        SpecialistRegime::SoftwareEngineering,
        &catalog,
        &bindings,
    )
    .unwrap();
    assert_eq!(
        verified
            .subjects_for(&r("capability-set:software-engineering"))
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn s05_qualification_for_one_operation_never_generalizes_to_a_sibling_operation() {
    let plan = regime_fixture::software_plan(&["operation:lookup", "operation:write"]);
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let entry = capability_fixture::qualified_entry("lookup-only");
    let qualification = entry.qualifications[0].clone();
    let catalog = catalog(vec![entry]);
    let binding = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "lookup-only",
    );

    assert_eq!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[binding],
        ),
        Err(RegimeCapabilityError::QualificationMissingOperation {
            requirement_ref: "capability-set:software-engineering".into(),
            operation_ref: "operation:write".into(),
        })
    );
}

#[test]
fn s05_known_but_unqualified_capability_cannot_satisfy_a_requirement() {
    let plan = regime_fixture::software_plan(&["operation:lookup"]);
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let qualified_entry = capability_fixture::qualified_entry("qualified-template");
    let qualification = qualified_entry.qualifications[0].clone();
    let known_only = capability_fixture::known_unqualified_entry("known-only");
    let known_subject = noerith_capabilities::QualificationSubject::from_manifest(
        &known_only.manifest,
        r("environment:A"),
        v("opaque/environment-A"),
        ContentDigest {
            algorithm_ref: r(SHA256_ALGORITHM_REF),
            value: r("sha256:environment-profile-a"),
        },
    );
    let catalog = catalog(vec![qualified_entry, known_only]);
    let mut forged = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "known-only",
    );
    forged.subject = known_subject;
    forged.content_digest = compute_regime_capability_binding_digest(&forged).unwrap();

    assert!(matches!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[forged],
        ),
        Err(RegimeCapabilityError::UnqualifiedCapabilitySubject(_))
    ));
}

#[test]
fn s05_binding_digest_changes_when_only_exact_environment_content_changes() {
    let plan = regime_fixture::software_plan(&["operation:lookup"]);
    let entry = capability_fixture::qualified_entry("lookup-environment-digest");
    let qualification = entry.qualifications[0].clone();

    let first = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "environment-d1",
    );
    let mut second = first.clone();
    second.subject.environment_digest = ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r("sha256:environment-profile-d2"),
    };
    second.content_digest = compute_regime_capability_binding_digest(&second).unwrap();

    assert_ne!(
        first.content_digest, second.content_digest,
        "raw regime binding V2 must content-bind the exact tested environment profile digest",
    );
}

#[test]
fn s05_binding_cannot_swap_adapter_environment_or_qualification_plan() {
    let plan = regime_fixture::software_plan(&["operation:lookup"]);
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let entry = capability_fixture::qualified_entry("lookup-a");
    let qualification = entry.qualifications[0].clone();
    let catalog = catalog(vec![entry]);

    let mut changed_subject = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "changed-subject",
    );
    changed_subject.subject.adapter_ref = r("adapter:substituted");
    changed_subject.content_digest =
        compute_regime_capability_binding_digest(&changed_subject).unwrap();
    assert!(matches!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[changed_subject],
        ),
        Err(RegimeCapabilityError::QualificationSubjectMismatch(_))
    ));

    let mut changed_plan = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "changed-plan",
    );
    changed_plan.qualification_plan_identity.plan_version = v("substituted-plan-version");
    changed_plan.content_digest = compute_regime_capability_binding_digest(&changed_plan).unwrap();
    assert!(matches!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[changed_plan],
        ),
        Err(RegimeCapabilityError::QualificationPlanMismatch(_))
    ));
}

#[test]
fn s05_binding_cannot_forge_qualification_evidence_or_drop_invalidation_dependencies() {
    let plan = regime_fixture::software_plan(&["operation:lookup"]);
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let entry = capability_fixture::qualified_entry("lookup-a");
    let qualification = entry.qualifications[0].clone();
    let catalog = catalog(vec![entry]);

    let mut forged_evidence = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "forged-evidence",
    );
    forged_evidence
        .qualification_evidence_refs
        .insert(r("evidence:forged"));
    forged_evidence.content_digest =
        compute_regime_capability_binding_digest(&forged_evidence).unwrap();
    assert!(matches!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[forged_evidence],
        ),
        Err(RegimeCapabilityError::QualificationEvidenceMismatch(_))
    ));

    let mut missing_dependency = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "missing-dependency",
    );
    let dependency = qualification
        .invalidation_dependency_refs()
        .iter()
        .next()
        .unwrap()
        .clone();
    missing_dependency
        .invalidation_dependency_refs
        .remove(&dependency);
    missing_dependency.content_digest =
        compute_regime_capability_binding_digest(&missing_dependency).unwrap();
    assert_eq!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[missing_dependency],
        ),
        Err(
            RegimeCapabilityError::MissingQualificationInvalidationDependency {
                capability_ref: qualification.subject().capability_ref.to_string(),
                dependency_ref: dependency.to_string(),
            }
        )
    );
}

#[test]
fn s05_every_preregistered_requirement_needs_at_least_one_exact_binding() {
    let plan = regime_fixture::software_plan_with_second_requirement();
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let entry = capability_fixture::qualified_entry("lookup-a");
    let qualification = entry.qualifications[0].clone();
    let catalog = catalog(vec![entry]);
    let binding = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "only-primary",
    );

    assert_eq!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[binding],
        ),
        Err(RegimeCapabilityError::MissingRequirementBinding(
            "capability-set:software-engineering:secondary".into()
        ))
    );
}

#[test]
fn s05_binding_identity_collision_and_post_digest_mutation_fail_closed() {
    let plan = regime_fixture::software_plan(&["operation:lookup"]);
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let entry = capability_fixture::qualified_entry("lookup-a");
    let qualification = entry.qualifications[0].clone();
    let catalog = catalog(vec![entry]);
    let first = binding(
        &plan,
        "capability-set:software-engineering",
        &qualification,
        "same-id",
    );

    let mut collision = first.clone();
    collision
        .provenance_refs
        .insert(r("provenance:different-binding-content"));
    collision.content_digest = compute_regime_capability_binding_digest(&collision).unwrap();
    assert!(matches!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[first.clone(), collision],
        ),
        Err(RegimeCapabilityError::BindingIdentityCollision { .. })
    ));

    let mut mutated = first;
    mutated
        .provenance_refs
        .insert(r("provenance:changed-after-digest"));
    assert!(matches!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[mutated],
        ),
        Err(RegimeCapabilityError::BindingDigestMismatch(_))
    ));
}

#[test]
fn s05_binding_for_undeclared_requirement_is_rejected() {
    let plan = regime_fixture::software_plan(&["operation:lookup"]);
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let entry = capability_fixture::qualified_entry("lookup-a");
    let qualification = entry.qualifications[0].clone();
    let catalog = catalog(vec![entry]);
    let binding = binding(
        &plan,
        "capability-set:not-preregistered",
        &qualification,
        "undeclared",
    );

    assert_eq!(
        verify_regime_capability_conformance(
            &plan,
            &verified_plan,
            SpecialistRegime::SoftwareEngineering,
            &catalog,
            &[binding],
        ),
        Err(RegimeCapabilityError::UnexpectedRequirement(
            "capability-set:not-preregistered".into()
        ))
    );
}
