use noerith_capabilities::{
    AmbientAuthorityMode, ArtifactBoundaryContract, AttestationContract, CleanupContract,
    ContentDigest, CriterionGrade, EvaluationCorpusDefinition, EvaluationExposureClass,
    EvaluationPartition, EvaluationTaskDefinition, EvidenceGraderPlan, EvidenceGraderPlanIdentity,
    EvidenceStatus, ExecutionEnvironmentEvidenceRecord, ExecutionEnvironmentProfile,
    ExecutionEnvironmentQualificationPlan, ExecutionEnvironmentQualificationPlanIdentity,
    GradeRecord, GradeRequest, GradeSubject, GraderIdentity, GraderQualificationEvidenceRecord,
    IsolationContract, OpaqueVersion, Q06CoverageContract, QualityCriterionKind,
    QualityFloorCriterion, QualityFloorPlan, QualityGateCoverage, QualityGateId, QualityTrialError,
    QualityTrialRecord, QualityTrialSet, QualityTrialVerificationEvidence, Reference,
    ReproducibilityContract, ResourceAccessContract, ResourceControlContract, SHA256_ALGORITHM_REF,
    SecretDeliveryContract, SpecialistRegime, SupplyChainContract, WorkspaceLifecycleContract,
    WorkspacePersistenceMode, compute_evaluation_corpus_digest,
    compute_evidence_grader_plan_digest, compute_execution_environment_plan_digest,
    compute_execution_environment_profile_digest, compute_quality_floor_plan_digest,
    compute_quality_trial_set_digest, qualify_evidence_grader, qualify_execution_environment,
    verify_evaluation_corpus, verify_execution_environment_profile_integrity, verify_grade_record,
    verify_quality_floor_plan, verify_quality_trial_set,
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

fn digest(value: &str) -> ContentDigest {
    ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r(value),
    }
}

fn criterion(kind: QualityCriterionKind, name: &str) -> QualityFloorCriterion {
    QualityFloorCriterion {
        kind,
        criterion_ref: r(name),
        measurement_target_ref: r(&format!("target:{name}")),
        threshold_policy_ref: r(&format!("threshold:{name}")),
        evidence_requirement_refs: refs(&[&format!("evidence:{name}")]),
    }
}

fn q06_plan() -> QualityFloorPlan {
    let mut plan = QualityFloorPlan {
        plan_ref: r("quality-floor:q06:trial-binding"),
        plan_version: v("locked-1"),
        content_digest: digest("sha256:placeholder-floor"),
        gate: QualityGateId::Q06MemoryContext,
        source_contract_refs: refs(&["source:master-blueprint"]),
        floor_criteria: vec![
            criterion(QualityCriterionKind::Recall, "q06:recall"),
            criterion(QualityCriterionKind::Fidelity, "q06:fidelity"),
            criterion(QualityCriterionKind::Privacy, "q06:privacy"),
            criterion(
                QualityCriterionKind::NoSilentLostConstraint,
                "q06:no-silent-loss",
            ),
        ],
        profile_metrics: Vec::new(),
        coverage: QualityGateCoverage::Q06(Q06CoverageContract {
            long_history_memory_corpus_ref: r("q06:long-history"),
            multi_session_reasoning_corpus_ref: r("q06:multi-session"),
            correction_case_corpus_ref: r("q06:corrections"),
            poisoning_case_corpus_ref: r("q06:poisoning"),
            lifecycle_case_corpus_ref: r("q06:lifecycle"),
            abstention_unknown_case_corpus_ref: r("q06:unknown"),
            protected_constraint_evidence_ref: r("q06:protected-evidence"),
        }),
        evaluation_corpus_refs: refs(&["evaluation-corpus:research"]),
        grader_plan_refs: refs(&["grader-plan:research"]),
        environment_qualification_plan_refs: refs(&["environment-plan:research"]),
        trial_protocol_ref: r("trial-protocol:q06"),
        statistical_model_ref: r("statistics:q06"),
        uncertainty_policy_ref: r("uncertainty:q06"),
        seed_manifest_ref: r("seeds:q06"),
        hardware_manifest_ref: r("hardware:q06"),
        confidence_target_ref: r("confidence:q06"),
        analysis_plan_ref: r("analysis:q06"),
        preregistration_evidence_ref: r("preregister:q06"),
        invalidation_dependency_refs: refs(&["dependency:q06-plan"]),
    };
    plan.content_digest = compute_quality_floor_plan_digest(&plan).unwrap();
    plan
}

fn eval_task(name: &str, partition: EvaluationPartition) -> EvaluationTaskDefinition {
    EvaluationTaskDefinition {
        task_ref: r(&format!("task:{name}")),
        task_version: v("task-v1"),
        task_content_digest: digest(&format!("sha256:task:{name}")),
        regime: SpecialistRegime::ResearchDeepResearch,
        partition,
        contamination_family_ref: r(&format!("family:{name}")),
        source_refs: refs(&["source:task"]),
        provenance_refs: refs(&["provenance:task"]),
        data_use_policy_refs: refs(&["policy:data-use"]),
        domain_refs: refs(&["domain:research"]),
        coverage_stratum_refs: refs(&["coverage:research"]),
        required_capability_refs: refs(&["capability:research"]),
        environment_requirement_refs: refs(&["environment-requirement:research"]),
        completion_contract_refs: refs(&["completion:research"]),
        grader_criterion_refs: refs(&["criterion:research"]),
        evaluation_affordance_policy_ref: r("policy:affordance"),
        exposure_class: if partition == EvaluationPartition::Development {
            EvaluationExposureClass::Public
        } else {
            EvaluationExposureClass::Sequestered
        },
        exposure_evidence_refs: refs(&["evidence:exposure"]),
        validation_evidence_refs: refs(&["evidence:validation"]),
        invalidation_dependency_refs: refs(&["dependency:task"]),
    }
}

fn corpus() -> EvaluationCorpusDefinition {
    let mut corpus = EvaluationCorpusDefinition {
        corpus_ref: r("evaluation-corpus:research"),
        corpus_version: v("corpus-v1"),
        content_digest: digest("sha256:placeholder-corpus"),
        regime: SpecialistRegime::ResearchDeepResearch,
        task_distribution_ref: r("distribution:research"),
        coverage_model_ref: r("coverage-model:research"),
        sampling_policy_ref: r("sampling:research"),
        anti_gaming_policy_ref: r("anti-gaming:research"),
        exposure_control_policy_ref: r("exposure-control:research"),
        development_partition_ref: r("partition:dev"),
        heldout_partition_ref: r("partition:heldout"),
        adversarial_partition_ref: r("partition:adversarial"),
        tasks: vec![
            eval_task("dev", EvaluationPartition::Development),
            eval_task("heldout", EvaluationPartition::Heldout),
            eval_task("adversarial", EvaluationPartition::Adversarial),
        ],
        invalidation_dependency_refs: refs(&["dependency:corpus"]),
    };
    corpus.content_digest = compute_evaluation_corpus_digest(&corpus).unwrap();
    corpus
}

fn environment_profile() -> ExecutionEnvironmentProfile {
    let requirement = refs(&["environment:req"]);
    let mut profile = ExecutionEnvironmentProfile {
        environment_ref: r("environment:research"),
        environment_version: v("env-v1"),
        content_digest: digest("sha256:placeholder-env"),
        runtime_ref: r("runtime:research"),
        runtime_version: v("runtime-v1"),
        runtime_artifact_ref: r("artifact:runtime"),
        runtime_artifact_digest: digest("sha256:runtime"),
        platform_ref: r("platform:test"),
        platform_version: v("platform-v1"),
        provenance_refs: refs(&["provenance:environment"]),
        isolation: IsolationContract {
            boundary_ref: r("boundary:isolation"),
            enforcement_control_refs: refs(&["control:isolation"]),
            threat_model_refs: refs(&["threat:escape"]),
            evidence_requirement_refs: requirement.clone(),
        },
        access: ResourceAccessContract {
            ambient_authority: AmbientAuthorityMode::DefaultDeny,
            filesystem_scope_policy_ref: r("policy:filesystem"),
            network_scope_policy_ref: r("policy:network"),
            device_scope_policy_ref: r("policy:device"),
            process_scope_policy_ref: r("policy:process"),
            ipc_scope_policy_ref: r("policy:ipc"),
            evidence_requirement_refs: requirement.clone(),
        },
        resources: ResourceControlContract {
            cpu_limit_policy_ref: r("policy:cpu"),
            memory_limit_policy_ref: r("policy:memory"),
            process_limit_policy_ref: r("policy:process-limit"),
            wall_clock_limit_policy_ref: r("policy:wall-clock"),
            io_limit_policy_ref: r("policy:io"),
            termination_policy_ref: r("policy:termination"),
            evidence_requirement_refs: requirement.clone(),
        },
        secrets: SecretDeliveryContract {
            secret_handle_contract_ref: r("contract:secret-handle"),
            injection_policy_ref: r("policy:secret-injection"),
            redaction_policy_ref: r("policy:secret-redaction"),
            cleanup_policy_ref: r("policy:secret-cleanup"),
            evidence_requirement_refs: requirement.clone(),
        },
        workspace: WorkspaceLifecycleContract {
            persistence_mode: WorkspacePersistenceMode::Ephemeral,
            task_scope_policy_ref: r("policy:workspace-task"),
            reuse_policy_ref: r("policy:workspace-reuse"),
            reset_policy_ref: r("policy:workspace-reset"),
            correction_deletion_policy_ref: r("policy:workspace-correction"),
            teardown_policy_ref: r("policy:workspace-teardown"),
            evidence_requirement_refs: requirement.clone(),
        },
        supply_chain: SupplyChainContract {
            dependency_policy_ref: r("policy:dependency"),
            provenance_policy_ref: r("policy:supply-provenance"),
            integrity_policy_ref: r("policy:supply-integrity"),
            vulnerability_invalidation_policy_ref: r("policy:vulnerability"),
            evidence_requirement_refs: requirement.clone(),
        },
        artifacts: ArtifactBoundaryContract {
            import_policy_ref: r("policy:artifact-import"),
            export_policy_ref: r("policy:artifact-export"),
            provenance_policy_ref: r("policy:artifact-provenance"),
            data_loss_prevention_policy_ref: r("policy:dlp"),
            evidence_requirement_refs: requirement.clone(),
        },
        attestation: AttestationContract {
            environment_identity_evidence_ref: r("attestation:environment"),
            runtime_integrity_evidence_ref: r("attestation:runtime"),
            platform_integrity_evidence_ref: r("attestation:platform"),
            evidence_requirement_refs: requirement.clone(),
        },
        reproducibility: ReproducibilityContract {
            source_identity_policy_ref: r("policy:source-identity"),
            environment_capture_policy_ref: r("policy:environment-capture"),
            execution_recipe_ref: r("recipe:execution"),
            result_comparison_policy_ref: r("policy:result-comparison"),
            evidence_requirement_refs: requirement.clone(),
        },
        cleanup: CleanupContract {
            process_cleanup_policy_ref: r("policy:cleanup-process"),
            workspace_cleanup_policy_ref: r("policy:cleanup-workspace"),
            secret_cleanup_policy_ref: r("policy:cleanup-secret"),
            temporary_resource_cleanup_policy_ref: r("policy:cleanup-temp"),
            verification_policy_ref: r("policy:cleanup-verify"),
            evidence_requirement_refs: requirement.clone(),
        },
        qualification_requirement_refs: requirement,
        invalidation_dependency_refs: refs(&["dependency:environment"]),
    };
    profile.content_digest = compute_execution_environment_profile_digest(&profile).unwrap();
    profile
}

fn qualified_environment() -> (
    ExecutionEnvironmentProfile,
    noerith_capabilities::VerifiedExecutionEnvironment,
) {
    qualified_environment_with_test_run("run:environment")
}

fn qualified_environment_with_test_run(
    test_run_ref: &str,
) -> (
    ExecutionEnvironmentProfile,
    noerith_capabilities::VerifiedExecutionEnvironment,
) {
    let profile = environment_profile();
    let verified_profile = verify_execution_environment_profile_integrity(&profile).unwrap();
    let mut plan = ExecutionEnvironmentQualificationPlan {
        identity: ExecutionEnvironmentQualificationPlanIdentity {
            plan_ref: r("environment-plan:research"),
            plan_version: v("env-plan-v1"),
            plan_digest: digest("sha256:placeholder-env-plan"),
        },
        subject: verified_profile.identity().clone(),
        workload_scope_refs: refs(&["workload:research"]),
        threat_scope_refs: refs(&["threat:escape"]),
        required_evidence_refs: refs(&["environment:req"]),
        portability_requirement_refs: refs(&["requirement:portable"]),
        performance_requirement_refs: refs(&["requirement:performance"]),
        invalidation_dependency_refs: refs(&["dependency:env-plan"]),
    };
    plan.identity.plan_digest = compute_execution_environment_plan_digest(&plan).unwrap();
    let evidence = vec![ExecutionEnvironmentEvidenceRecord {
        evidence_ref: r("environment:evidence"),
        subject: plan.subject.clone(),
        plan_identity: plan.identity.clone(),
        requirement_ref: r("environment:req"),
        test_method_ref: r("method:environment"),
        test_run_ref: r(test_run_ref),
        producer_ref: r("producer:environment-harness"),
        provenance_refs: refs(&["provenance:env-test"]),
        environment_evidence_refs: refs(&["evidence:runtime"]),
        observed_result_ref: r("result:environment"),
        validity_ref: r("validity:environment"),
        status: EvidenceStatus::Pass,
    }];
    let qualified =
        qualify_execution_environment(&profile, &verified_profile, &plan, &evidence).unwrap();
    (profile, qualified)
}

fn grader_plan() -> EvidenceGraderPlan {
    let mut plan = EvidenceGraderPlan {
        identity: EvidenceGraderPlanIdentity {
            plan_ref: r("grader-plan:research"),
            plan_version: v("grader-plan-v1"),
            plan_digest: digest("sha256:placeholder-grader-plan"),
        },
        grader: GraderIdentity {
            grader_ref: r("grader:research"),
            grader_version: v("grader-v1"),
            implementation_ref: r("artifact:grader"),
            implementation_version: v("grader-build-v1"),
            configuration_ref: r("config:grader"),
            configuration_version: v("config-v1"),
        },
        rubric_ref: r("rubric:research"),
        rubric_version: v("rubric-v1"),
        mandatory_criterion_refs: refs(&["criterion:research"]),
        calibrated_scope_refs: refs(&["scope:research"]),
        qualification_requirement_refs: refs(&["grader:req"]),
        calibration_corpus_ref: r("corpus:grader-dev"),
        heldout_calibration_partition_ref: r("corpus:grader-heldout"),
        disagreement_policy_ref: r("policy:disagreement"),
        abstention_policy_ref: r("policy:abstention"),
        anti_gaming_policy_ref: r("policy:grader-anti-gaming"),
        invalidation_dependency_refs: refs(&["dependency:grader"]),
    };
    plan.identity.plan_digest = compute_evidence_grader_plan_digest(&plan).unwrap();
    plan
}

fn qualified_grader(plan: &EvidenceGraderPlan) -> noerith_capabilities::VerifiedEvidenceGrader {
    let evidence = vec![GraderQualificationEvidenceRecord {
        evidence_ref: r("grader:evidence"),
        grader: plan.grader.clone(),
        plan_identity: plan.identity.clone(),
        requirement_ref: r("grader:req"),
        test_method_ref: r("method:grader"),
        test_run_ref: r("run:grader"),
        producer_ref: r("producer:grader-harness"),
        provenance_refs: refs(&["provenance:grader-test"]),
        observed_result_ref: r("result:grader"),
        validity_ref: r("validity:grader"),
        status: EvidenceStatus::Pass,
    }];
    qualify_evidence_grader(plan, &evidence).unwrap()
}

fn heldout_trial(
    corpus: &EvaluationCorpusDefinition,
    environment: &ExecutionEnvironmentProfile,
) -> QualityTrialRecord {
    let task = &corpus.tasks[1];
    QualityTrialRecord {
        trial_ref: r("trial:heldout:1"),
        corpus_ref: corpus.corpus_ref.clone(),
        corpus_version: corpus.corpus_version.clone(),
        corpus_digest: corpus.content_digest.clone(),
        task_ref: task.task_ref.clone(),
        task_version: task.task_version.clone(),
        task_digest: task.task_content_digest.clone(),
        regime: task.regime,
        partition: task.partition,
        candidate_configuration_ref: r("candidate:config-a"),
        candidate_configuration_version: v("config-v1"),
        candidate_configuration_digest: digest("sha256:candidate-config"),
        model_ref: r("model:a"),
        model_version: v("model-v1"),
        provider_ref: r("provider:a"),
        adapter_ref: r("adapter:a"),
        adapter_version: v("adapter-v1"),
        environment_ref: environment.environment_ref.clone(),
        environment_version: environment.environment_version.clone(),
        environment_digest: environment.content_digest.clone(),
        seed_ref: r("seed:1"),
        input_digest: digest("sha256:input-1"),
        output_digest: digest("sha256:output-1"),
        trace_ref: r("trace:1"),
        execution_evidence_refs: refs(&["execution:evidence-1"]),
        grader_result_refs: refs(&["grade:trial-1"]),
        provenance_refs: refs(&["provenance:trial-1"]),
        invalidation_dependency_refs: refs(&["dependency:trial-1"]),
    }
}

fn verified_grade_with_evidence(
    grader_plan: &EvidenceGraderPlan,
    trial: &QualityTrialRecord,
    grade_ref: &str,
    output_digest: ContentDigest,
    criterion_evidence_ref: &str,
) -> noerith_capabilities::VerifiedGradeRecord {
    let grader = qualified_grader(grader_plan);
    let subject = GradeSubject {
        regime: trial.regime,
        task_ref: trial.task_ref.clone(),
        trial_ref: trial.trial_ref.clone(),
        output_digest,
        trace_ref: trial.trace_ref.clone(),
        environment_ref: trial.environment_ref.clone(),
        environment_version: trial.environment_version.clone(),
        evaluation_scope_refs: refs(&["scope:research"]),
        execution_evidence_refs: trial.execution_evidence_refs.clone(),
    };
    let request = GradeRequest {
        request_ref: r(&format!("grade-request:{grade_ref}")),
        subject: subject.clone(),
        grader_plan_identity: grader_plan.identity.clone(),
        mandatory_criterion_refs: grader_plan.mandatory_criterion_refs.clone(),
    };
    let record = GradeRecord {
        grade_ref: r(grade_ref),
        request_ref: request.request_ref.clone(),
        subject,
        grader: grader_plan.grader.clone(),
        grader_plan_identity: grader_plan.identity.clone(),
        rubric_ref: grader_plan.rubric_ref.clone(),
        rubric_version: grader_plan.rubric_version.clone(),
        criterion_results: vec![CriterionGrade {
            criterion_ref: r("criterion:research"),
            status: EvidenceStatus::Pass,
            evidence_refs: refs(&[criterion_evidence_ref]),
        }],
        provenance_refs: refs(&["provenance:grade"]),
        validity_ref: r("validity:grade"),
    };
    verify_grade_record(&grader, &request, &record).unwrap()
}

fn verified_grade(
    grader_plan: &EvidenceGraderPlan,
    trial: &QualityTrialRecord,
    grade_ref: &str,
    output_digest: ContentDigest,
) -> noerith_capabilities::VerifiedGradeRecord {
    verified_grade_with_evidence(
        grader_plan,
        trial,
        grade_ref,
        output_digest,
        "grade:evidence",
    )
}

fn trial_set(plan: &QualityFloorPlan, trial: QualityTrialRecord) -> QualityTrialSet {
    let mut set = QualityTrialSet {
        trial_set_ref: r("trial-set:q06"),
        trial_set_version: v("trial-set-v1"),
        content_digest: digest("sha256:placeholder-trial-set"),
        plan_ref: plan.plan_ref.clone(),
        plan_version: plan.plan_version.clone(),
        plan_digest: plan.content_digest.clone(),
        gate: plan.gate,
        trial_protocol_ref: plan.trial_protocol_ref.clone(),
        seed_manifest_ref: plan.seed_manifest_ref.clone(),
        hardware_manifest_ref: plan.hardware_manifest_ref.clone(),
        candidate_configuration_manifest_ref: None,
        preregistration_evidence_ref: plan.preregistration_evidence_ref.clone(),
        trials: vec![trial],
        provenance_refs: refs(&["provenance:trial-set"]),
        invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
    };
    set.content_digest = compute_quality_trial_set_digest(&set).unwrap();
    set
}

struct Fixture {
    plan: QualityFloorPlan,
    set: QualityTrialSet,
    corpus: noerith_capabilities::VerifiedEvaluationCorpus,
    grade: noerith_capabilities::VerifiedGradeRecord,
    environment: noerith_capabilities::VerifiedExecutionEnvironment,
}

fn fixture() -> Fixture {
    let plan = q06_plan();
    let corpus_def = corpus();
    let corpus = verify_evaluation_corpus(&corpus_def).unwrap();
    let (environment_profile, environment) = qualified_environment();
    let trial = heldout_trial(&corpus_def, &environment_profile);
    let grader_plan = grader_plan();
    let grade = verified_grade(
        &grader_plan,
        &trial,
        "grade:trial-1",
        trial.output_digest.clone(),
    );
    let set = trial_set(&plan, trial);
    Fixture {
        plan,
        set,
        corpus,
        grade,
        environment,
    }
}

fn verify_fixture(
    fixture: &Fixture,
) -> Result<noerith_capabilities::VerifiedQualityTrialSet, QualityTrialError> {
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();
    verify_quality_trial_set(
        &fixture.plan,
        &verified_plan,
        &fixture.set,
        QualityTrialVerificationEvidence {
            corpora: core::slice::from_ref(&fixture.corpus),
            grades: core::slice::from_ref(&fixture.grade),
            environments: core::slice::from_ref(&fixture.environment),
        },
    )
}

#[test]
fn s05_trial_set_requires_exact_verified_owner_evidence() {
    let fixture = fixture();
    let verified = verify_fixture(&fixture).unwrap();
    assert_eq!(verified.trial_refs(), &refs(&["trial:heldout:1"]));
    assert_eq!(
        verified.corpus_refs(),
        &refs(&["evaluation-corpus:research"])
    );
    assert_eq!(verified.grade_refs(), &refs(&["grade:trial-1"]));
    assert_eq!(
        verified.environment_refs(),
        &refs(&["environment:research"])
    );
}

#[test]
fn s05_trial_task_digest_cannot_drift_from_verified_corpus() {
    let mut fixture = fixture();
    fixture.set.trials[0].task_digest = digest("sha256:forged-task");
    fixture.set.content_digest = compute_quality_trial_set_digest(&fixture.set).unwrap();
    assert!(matches!(
        verify_fixture(&fixture),
        Err(QualityTrialError::TaskIdentityMismatch(_))
    ));
}

#[test]
fn s05_trial_environment_digest_cannot_ride_on_same_ref_and_version() {
    let mut fixture = fixture();
    fixture.set.trials[0].environment_digest = digest("sha256:forged-environment");
    fixture.set.content_digest = compute_quality_trial_set_digest(&fixture.set).unwrap();
    assert!(matches!(
        verify_fixture(&fixture),
        Err(QualityTrialError::EnvironmentIdentityMismatch(_))
    ));
}

#[test]
fn s05_grade_must_describe_the_exact_trial_output_and_execution_subject() {
    let mut fixture = fixture();
    let plan = grader_plan();
    fixture.grade = verified_grade(
        &plan,
        &fixture.set.trials[0],
        "grade:trial-1",
        digest("sha256:different-output"),
    );
    assert!(matches!(
        verify_fixture(&fixture),
        Err(QualityTrialError::GradeSubjectMismatch(_))
    ));
}

#[test]
fn s05_missing_owner_evidence_fails_closed() {
    let fixture = fixture();
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();
    assert!(matches!(
        verify_quality_trial_set(
            &fixture.plan,
            &verified_plan,
            &fixture.set,
            QualityTrialVerificationEvidence {
                corpora: &[],
                grades: core::slice::from_ref(&fixture.grade),
                environments: core::slice::from_ref(&fixture.environment),
            },
        ),
        Err(QualityTrialError::MissingCorpusEvidence(_))
    ));
}

#[test]
fn s05_unused_verified_grade_is_rejected_instead_of_diluting_trial_identity() {
    let fixture = fixture();
    let plan = grader_plan();
    let extra = verified_grade(
        &plan,
        &fixture.set.trials[0],
        "grade:extra-unreferenced",
        fixture.set.trials[0].output_digest.clone(),
    );
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();
    assert!(matches!(
        verify_quality_trial_set(
            &fixture.plan,
            &verified_plan,
            &fixture.set,
            QualityTrialVerificationEvidence {
                corpora: core::slice::from_ref(&fixture.corpus),
                grades: &[fixture.grade.clone(), extra],
                environments: core::slice::from_ref(&fixture.environment),
            },
        ),
        Err(QualityTrialError::UnusedGradeEvidence(_))
    ));
}

#[test]
fn s05_one_verified_grade_cannot_be_reused_as_two_independent_trials() {
    let mut fixture = fixture();
    let mut second = fixture.set.trials[0].clone();
    second.trial_ref = r("trial:heldout:2");
    second.seed_ref = r("seed:2");
    second.input_digest = digest("sha256:input-2");
    second.grader_result_refs = refs(&["grade:trial-1"]);
    fixture.set.trials.push(second);
    fixture.set.content_digest = compute_quality_trial_set_digest(&fixture.set).unwrap();
    assert!(matches!(
        verify_fixture(&fixture),
        Err(QualityTrialError::GradeEvidenceReused(_))
    ));
}

#[test]
fn s05_development_attempt_cannot_be_smuggled_into_confirmatory_trial_set() {
    let mut fixture = fixture();
    let corpus_def = corpus();
    let development = &corpus_def.tasks[0];
    let trial = &mut fixture.set.trials[0];
    trial.task_ref = development.task_ref.clone();
    trial.task_version = development.task_version.clone();
    trial.task_digest = development.task_content_digest.clone();
    trial.partition = EvaluationPartition::Development;
    fixture.set.content_digest = compute_quality_trial_set_digest(&fixture.set).unwrap();
    assert!(matches!(
        verify_fixture(&fixture),
        Err(QualityTrialError::DevelopmentTrialRejected(_))
    ));
}

#[test]
fn s05_verified_trial_identity_changes_when_grade_content_changes_behind_same_ref() {
    let plan = q06_plan();
    let corpus_def = corpus();
    let corpus = verify_evaluation_corpus(&corpus_def).unwrap();
    let (environment_profile, environment) = qualified_environment();
    let trial = heldout_trial(&corpus_def, &environment_profile);
    let grader_plan = grader_plan();

    let first_grade = verified_grade_with_evidence(
        &grader_plan,
        &trial,
        "grade:trial-1",
        trial.output_digest.clone(),
        "grade:evidence:first",
    );
    let second_grade = verified_grade_with_evidence(
        &grader_plan,
        &trial,
        "grade:trial-1",
        trial.output_digest.clone(),
        "grade:evidence:second",
    );

    assert_eq!(first_grade.grade_ref(), second_grade.grade_ref());
    assert_ne!(
        first_grade.verification_digest(),
        second_grade.verification_digest(),
        "precondition: the two valid grades must have different exact evidence content",
    );

    let set = trial_set(&plan, trial);
    let raw_digest = set.content_digest.clone();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();

    let first = verify_quality_trial_set(
        &plan,
        &verified_plan,
        &set,
        QualityTrialVerificationEvidence {
            corpora: core::slice::from_ref(&corpus),
            grades: core::slice::from_ref(&first_grade),
            environments: core::slice::from_ref(&environment),
        },
    )
    .unwrap();
    let second = verify_quality_trial_set(
        &plan,
        &verified_plan,
        &set,
        QualityTrialVerificationEvidence {
            corpora: core::slice::from_ref(&corpus),
            grades: core::slice::from_ref(&second_grade),
            environments: core::slice::from_ref(&environment),
        },
    )
    .unwrap();

    assert_eq!(first.content_digest(), &raw_digest);
    assert_eq!(second.content_digest(), &raw_digest);
    assert_ne!(
        first.verification_digest(),
        second.verification_digest(),
        "verified trial evidence identity must change even when the raw declaration and grade ref stay stable",
    );
}
