use noerith_capabilities::{
    AmbientAuthorityMode, ArtifactBoundaryContract, AttestationContract, CleanupContract,
    ContentDigest, EvidenceStatus, ExecutionEnvironmentError, ExecutionEnvironmentEvidenceRecord,
    ExecutionEnvironmentProfile, ExecutionEnvironmentQualificationPlan,
    ExecutionEnvironmentQualificationPlanIdentity, IsolationContract, OpaqueVersion, Reference,
    ReproducibilityContract, ResourceAccessContract, ResourceControlContract,
    SecretDeliveryContract, SupplyChainContract, WorkspaceLifecycleContract,
    WorkspacePersistenceMode, compute_execution_environment_plan_digest,
    compute_execution_environment_profile_digest, qualify_execution_environment,
    verify_execution_environment_profile_integrity,
};
use std::collections::BTreeSet;

fn r(value: &str) -> Reference {
    Reference::new(value).expect("valid reference")
}

fn v(value: &str) -> OpaqueVersion {
    OpaqueVersion::new(value).expect("valid version")
}

fn refs(values: &[&str]) -> BTreeSet<Reference> {
    values.iter().map(|value| r(value)).collect()
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest {
        algorithm_ref: r("digest:sha-256"),
        value: r(value),
    }
}

fn profile() -> ExecutionEnvironmentProfile {
    let mut profile = ExecutionEnvironmentProfile {
        environment_ref: r("environment:qualified-sandbox-a"),
        environment_version: v("2026-09-11"),
        content_digest: digest("sha256:placeholder-profile"),
        runtime_ref: r("runtime:portable-isolation-a"),
        runtime_version: v("runtime-17"),
        runtime_artifact_ref: r("artifact:runtime-image-a"),
        runtime_artifact_digest: digest("sha256:runtime-artifact-a"),
        platform_ref: r("platform:test-platform-a"),
        platform_version: v("platform-5"),
        provenance_refs: refs(&["provenance:runtime", "provenance:platform"]),
        isolation: IsolationContract {
            boundary_ref: r("isolation-boundary:task-process-host"),
            enforcement_control_refs: refs(&[
                "control:filesystem-isolation",
                "control:network-isolation",
                "control:process-isolation",
            ]),
            threat_model_refs: refs(&[
                "threat:boundary-escape",
                "threat:cross-task-access",
                "threat:host-access",
            ]),
            evidence_requirement_refs: refs(&["evidence-required:isolation-containment"]),
        },
        access: ResourceAccessContract {
            ambient_authority: AmbientAuthorityMode::DefaultDeny,
            filesystem_scope_policy_ref: r("policy:filesystem-task-scope"),
            network_scope_policy_ref: r("policy:network-destination-scope"),
            device_scope_policy_ref: r("policy:device-capability-scope"),
            process_scope_policy_ref: r("policy:process-scope"),
            ipc_scope_policy_ref: r("policy:ipc-scope"),
            evidence_requirement_refs: refs(&["evidence-required:default-deny-access"]),
        },
        resources: ResourceControlContract {
            cpu_limit_policy_ref: r("policy:cpu-limit"),
            memory_limit_policy_ref: r("policy:memory-limit"),
            process_limit_policy_ref: r("policy:process-limit"),
            wall_clock_limit_policy_ref: r("policy:elapsed-time-limit"),
            io_limit_policy_ref: r("policy:io-limit"),
            termination_policy_ref: r("policy:bounded-termination"),
            evidence_requirement_refs: refs(&["evidence-required:resource-containment"]),
        },
        secrets: SecretDeliveryContract {
            secret_handle_contract_ref: r("contract:short-lived-secret-handle"),
            injection_policy_ref: r("policy:secret-injection"),
            redaction_policy_ref: r("policy:secret-redaction"),
            cleanup_policy_ref: r("policy:secret-cleanup"),
            evidence_requirement_refs: refs(&["evidence-required:secret-nondisclosure"]),
        },
        workspace: WorkspaceLifecycleContract {
            persistence_mode: WorkspacePersistenceMode::Ephemeral,
            task_scope_policy_ref: r("policy:workspace-task-scope"),
            reuse_policy_ref: r("policy:no-cross-task-reuse"),
            reset_policy_ref: r("policy:workspace-reset"),
            correction_deletion_policy_ref: r("policy:workspace-correction-deletion"),
            teardown_policy_ref: r("policy:workspace-teardown"),
            evidence_requirement_refs: refs(&["evidence-required:workspace-isolation-cleanup"]),
        },
        supply_chain: SupplyChainContract {
            dependency_policy_ref: r("policy:dependency-admission"),
            provenance_policy_ref: r("policy:dependency-provenance"),
            integrity_policy_ref: r("policy:dependency-integrity"),
            vulnerability_invalidation_policy_ref: r("policy:runtime-advisory-invalidation"),
            evidence_requirement_refs: refs(&["evidence-required:supply-chain-integrity"]),
        },
        artifacts: ArtifactBoundaryContract {
            import_policy_ref: r("policy:artifact-import"),
            export_policy_ref: r("policy:artifact-export"),
            provenance_policy_ref: r("policy:artifact-provenance"),
            data_loss_prevention_policy_ref: r("policy:artifact-data-boundary"),
            evidence_requirement_refs: refs(&["evidence-required:artifact-boundary"]),
        },
        attestation: AttestationContract {
            environment_identity_evidence_ref: r("attestation:environment-identity"),
            runtime_integrity_evidence_ref: r("attestation:runtime-integrity"),
            platform_integrity_evidence_ref: r("attestation:platform-integrity"),
            evidence_requirement_refs: refs(&["evidence-required:environment-attestation"]),
        },
        reproducibility: ReproducibilityContract {
            source_identity_policy_ref: r("policy:repro-source-identity"),
            environment_capture_policy_ref: r("policy:repro-environment-capture"),
            execution_recipe_ref: r("recipe:qualified-execution"),
            result_comparison_policy_ref: r("policy:repro-result-comparison"),
            evidence_requirement_refs: refs(&["evidence-required:reproducibility"]),
        },
        cleanup: CleanupContract {
            process_cleanup_policy_ref: r("policy:cleanup-processes"),
            workspace_cleanup_policy_ref: r("policy:cleanup-workspace"),
            secret_cleanup_policy_ref: r("policy:cleanup-secrets"),
            temporary_resource_cleanup_policy_ref: r("policy:cleanup-temporary-resources"),
            verification_policy_ref: r("policy:cleanup-verification"),
            evidence_requirement_refs: refs(&["evidence-required:teardown-verification"]),
        },
        qualification_requirement_refs: refs(&["evidence-required:profile-conformance"]),
        invalidation_dependency_refs: refs(&[
            "dependency:runtime-version",
            "dependency:platform-version",
            "dependency:security-advisory-state",
            "dependency:policy-revisions",
        ]),
    };
    profile.content_digest = compute_execution_environment_profile_digest(&profile).unwrap();
    profile
}

fn required_evidence() -> BTreeSet<Reference> {
    refs(&[
        "evidence-required:isolation-containment",
        "evidence-required:default-deny-access",
        "evidence-required:resource-containment",
        "evidence-required:secret-nondisclosure",
        "evidence-required:workspace-isolation-cleanup",
        "evidence-required:supply-chain-integrity",
        "evidence-required:artifact-boundary",
        "evidence-required:environment-attestation",
        "evidence-required:reproducibility",
        "evidence-required:teardown-verification",
        "evidence-required:profile-conformance",
    ])
}

fn plan(profile: &ExecutionEnvironmentProfile) -> ExecutionEnvironmentQualificationPlan {
    let verified = verify_execution_environment_profile_integrity(profile).unwrap();
    let mut plan = ExecutionEnvironmentQualificationPlan {
        identity: ExecutionEnvironmentQualificationPlanIdentity {
            plan_ref: r("qualification-plan:environment-a"),
            plan_version: v("plan-8"),
            plan_digest: digest("sha256:placeholder-plan"),
        },
        subject: verified.identity().clone(),
        workload_scope_refs: refs(&[
            "workload:software-engineering",
            "workload:artifact-generation",
        ]),
        threat_scope_refs: refs(&[
            "threat:boundary-escape",
            "threat:secret-exposure",
            "threat:network-exfiltration",
            "threat:resource-abuse",
            "threat:stale-workspace",
            "threat:supply-chain-drift",
        ]),
        required_evidence_refs: required_evidence(),
        portability_requirement_refs: refs(&["evaluation:platform-portability"]),
        performance_requirement_refs: refs(&["evaluation:latency-resource-overhead"]),
        invalidation_dependency_refs: refs(&[
            "dependency:qualification-method",
            "dependency:threat-model",
        ]),
    };
    plan.identity.plan_digest = compute_execution_environment_plan_digest(&plan).unwrap();
    plan
}

fn evidence(
    plan: &ExecutionEnvironmentQualificationPlan,
) -> Vec<ExecutionEnvironmentEvidenceRecord> {
    plan.required_evidence_refs
        .iter()
        .enumerate()
        .map(|(index, requirement)| ExecutionEnvironmentEvidenceRecord {
            evidence_ref: r(&format!("environment-evidence:{index}")),
            subject: plan.subject.clone(),
            plan_identity: plan.identity.clone(),
            requirement_ref: requirement.clone(),
            test_method_ref: r("method:isolated-environment-conformance"),
            test_run_ref: r(&format!("run:environment-conformance:{index}")),
            producer_ref: r("producer:independent-environment-harness"),
            provenance_refs: refs(&["provenance:test-harness", "provenance:runtime-artifact"]),
            environment_evidence_refs: refs(&[
                "evidence:runtime-identity",
                "evidence:platform-identity",
            ]),
            observed_result_ref: r(&format!("result:environment-conformance:{index}")),
            validity_ref: r("validity:until-profile-or-threat-change"),
            status: EvidenceStatus::Pass,
        })
        .collect()
}

#[test]
fn s05_environment_profile_is_exact_content_bound_and_default_deny() {
    let profile = profile();
    let verified = verify_execution_environment_profile_integrity(&profile).unwrap();
    assert_eq!(verified.identity().content_digest, profile.content_digest);

    let mut changed = profile.clone();
    changed.runtime_version = v("runtime-18");
    assert_eq!(
        verify_execution_environment_profile_integrity(&changed),
        Err(ExecutionEnvironmentError::ProfileDigestMismatch)
    );

    let mut default_allow = profile;
    default_allow.access.ambient_authority = AmbientAuthorityMode::DefaultAllow;
    assert_eq!(
        compute_execution_environment_profile_digest(&default_allow),
        Err(ExecutionEnvironmentError::DefaultAllowRejected)
    );
}

#[test]
fn s05_environment_plan_cannot_drop_any_profile_control_evidence() {
    let profile = profile();
    let verified = verify_execution_environment_profile_integrity(&profile).unwrap();
    let mut plan = plan(&profile);
    plan.required_evidence_refs
        .remove(&r("evidence-required:secret-nondisclosure"));
    plan.identity.plan_digest = compute_execution_environment_plan_digest(&plan).unwrap();

    assert_eq!(
        qualify_execution_environment(&profile, &verified, &plan, &[]),
        Err(ExecutionEnvironmentError::PlanDropsProfileRequirement(
            "evidence-required:secret-nondisclosure".into()
        ))
    );
}

#[test]
fn s05_environment_qualification_requires_exact_complete_passing_evidence() {
    let profile = profile();
    let verified = verify_execution_environment_profile_integrity(&profile).unwrap();
    let plan = plan(&profile);
    let records = evidence(&plan);
    let qualified = qualify_execution_environment(&profile, &verified, &plan, &records).unwrap();
    assert_eq!(qualified.subject(), &plan.subject);
    assert_eq!(
        qualified.evidence_refs().len(),
        plan.required_evidence_refs.len()
    );

    let mut missing = records.clone();
    missing.pop();
    assert_eq!(
        qualify_execution_environment(&profile, &verified, &plan, &missing),
        Err(ExecutionEnvironmentError::IncompleteEvidenceCoverage)
    );

    let mut failed = records.clone();
    failed[0].status = EvidenceStatus::Fail;
    assert!(matches!(
        qualify_execution_environment(&profile, &verified, &plan, &failed),
        Err(ExecutionEnvironmentError::RequirementFailed(_))
    ));

    let mut unknown = records;
    unknown[0].status = EvidenceStatus::Indeterminate;
    assert!(matches!(
        qualify_execution_environment(&profile, &verified, &plan, &unknown),
        Err(ExecutionEnvironmentError::RequirementIndeterminate(_))
    ));
}

#[test]
fn s05_old_environment_qualification_cannot_ride_on_changed_runtime() {
    let profile = profile();
    let verified = verify_execution_environment_profile_integrity(&profile).unwrap();
    let plan = plan(&profile);
    let records = evidence(&plan);

    let mut changed = profile.clone();
    changed.runtime_version = v("runtime-security-revision-18");
    changed.content_digest = compute_execution_environment_profile_digest(&changed).unwrap();

    assert_eq!(
        qualify_execution_environment(&changed, &verified, &plan, &records),
        Err(ExecutionEnvironmentError::ProfileDigestMismatch)
    );
}

#[test]
fn s05_environment_evidence_cannot_be_replayed_from_other_subject_or_plan() {
    let profile = profile();
    let verified = verify_execution_environment_profile_integrity(&profile).unwrap();
    let plan = plan(&profile);

    let mut wrong_subject = evidence(&plan);
    wrong_subject[0].subject.environment_version = v("other-environment-version");
    assert!(matches!(
        qualify_execution_environment(&profile, &verified, &plan, &wrong_subject),
        Err(ExecutionEnvironmentError::EvidenceSubjectMismatch(_))
    ));

    let mut wrong_plan = evidence(&plan);
    wrong_plan[0].plan_identity.plan_version = v("other-plan");
    assert!(matches!(
        qualify_execution_environment(&profile, &verified, &plan, &wrong_plan),
        Err(ExecutionEnvironmentError::EvidencePlanMismatch(_))
    ));
}

#[test]
fn s05_environment_qualification_remains_historical_evidence_not_runtime_authority() {
    let profile = profile();
    let verified = verify_execution_environment_profile_integrity(&profile).unwrap();
    let plan = plan(&profile);
    let qualified = qualify_execution_environment(&profile, &verified, &plan, &evidence(&plan))
        .expect("qualification evidence");

    // The wrapper contains exact qualification scope/evidence only. Current
    // availability, task authority, credentials and external-effect release
    // remain separate owners and are intentionally absent from this contract.
    assert!(!qualified.workload_scope_refs().is_empty());
    assert!(!qualified.threat_scope_refs().is_empty());
    assert!(!qualified.invalidation_dependency_refs().is_empty());
}

#[test]
fn s05_environment_qualification_identity_changes_when_leaf_evidence_content_changes() {
    let profile = profile();
    let verified_profile = verify_execution_environment_profile_integrity(&profile).unwrap();
    let plan = plan(&profile);

    let first_records = evidence(&plan);
    let mut second_records = first_records.clone();
    second_records[0].test_run_ref = r("run:environment-conformance:changed-content");
    second_records[0].observed_result_ref = r("result:environment-conformance:recomputed");

    let first =
        qualify_execution_environment(&profile, &verified_profile, &plan, &first_records).unwrap();
    let second =
        qualify_execution_environment(&profile, &verified_profile, &plan, &second_records).unwrap();

    assert_eq!(first.evidence_refs(), second.evidence_refs());
    assert_ne!(
        first.verification_digest(),
        second.verification_digest(),
        "same logical evidence refs must not hide different environment qualification content",
    );
}
