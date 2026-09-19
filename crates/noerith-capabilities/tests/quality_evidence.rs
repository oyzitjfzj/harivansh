use noerith_capabilities::{
    AmbientAuthorityMode, ArtifactBoundaryContract, AttestationContract, CleanupContract,
    ContentDigest, CriterionGrade, EvaluationCorpusDefinition, EvaluationExposureClass,
    EvaluationPartition, EvaluationTaskDefinition, EvidenceGraderPlan, EvidenceGraderPlanIdentity,
    EvidenceStatus, ExecutionEnvironmentEvidenceRecord, ExecutionEnvironmentProfile,
    ExecutionEnvironmentQualificationPlan, ExecutionEnvironmentQualificationPlanIdentity,
    GradeRecord, GradeRequest, GradeSubject, GraderIdentity, GraderQualificationEvidenceRecord,
    IsolationContract, OpaqueVersion, Q07ComparisonAxis, Q07CoverageContract,
    QualityCorpusEvidence, QualityCoverageItem, QualityCoverageResult, QualityCriterionKind,
    QualityCriterionResult, QualityEvidenceBundle, QualityEvidenceError, QualityExperimentBinding,
    QualityFloorCriterion, QualityFloorPlan, QualityFloorResultSet, QualityGateCoverage,
    QualityGateId, QualityProfileMetric, QualityProfileMetricRole, QualityProfileResult, Reference,
    ReproducibilityContract, ResourceAccessContract, ResourceControlContract, SHA256_ALGORITHM_REF,
    SecretDeliveryContract, SpecialistRegime, SupplyChainContract, WorkspaceLifecycleContract,
    WorkspacePersistenceMode, compute_evaluation_corpus_digest,
    compute_evidence_grader_plan_digest, compute_execution_environment_plan_digest,
    compute_execution_environment_profile_digest, compute_quality_floor_plan_digest,
    compute_quality_floor_result_digest, qualify_evidence_grader, qualify_execution_environment,
    verify_evaluation_corpus, verify_execution_environment_profile_integrity, verify_grade_record,
    verify_quality_evidence_bundle,
};
use std::collections::{BTreeMap, BTreeSet};

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

fn regime_slug(regime: SpecialistRegime) -> &'static str {
    match regime {
        SpecialistRegime::ConversationPersonalAssistant => "conversation",
        SpecialistRegime::ResearchDeepResearch => "research",
        SpecialistRegime::SoftwareEngineering => "software",
        SpecialistRegime::ActionAutomation => "action",
        SpecialistRegime::CreationArtifact => "creation",
        SpecialistRegime::MonitoringLongRunningWork => "monitoring",
    }
}

fn task(regime: SpecialistRegime, partition: EvaluationPartition) -> EvaluationTaskDefinition {
    let slug = regime_slug(regime);
    let partition_slug = match partition {
        EvaluationPartition::Development => "development",
        EvaluationPartition::Heldout => "heldout",
        EvaluationPartition::Adversarial => "adversarial",
    };
    EvaluationTaskDefinition {
        task_ref: r(&format!("task:{slug}:{partition_slug}")),
        task_version: v("task-v1"),
        task_content_digest: digest(&format!("sha256:task:{slug}:{partition_slug}")),
        regime,
        partition,
        contamination_family_ref: r(&format!("family:{slug}:{partition_slug}")),
        source_refs: refs(&["source:curated"]),
        provenance_refs: refs(&["provenance:task"]),
        data_use_policy_refs: refs(&["policy:data-use"]),
        domain_refs: refs(&["domain:qualified"]),
        coverage_stratum_refs: refs(&["coverage:primary"]),
        required_capability_refs: refs(&["capability:subject"]),
        environment_requirement_refs: refs(&["environment-requirement:qualified"]),
        completion_contract_refs: refs(&["completion:task"]),
        grader_criterion_refs: refs(&["grader:criterion"]),
        evaluation_affordance_policy_ref: r("policy:eval-affordance"),
        exposure_class: match partition {
            EvaluationPartition::Development => EvaluationExposureClass::Restricted,
            EvaluationPartition::Heldout | EvaluationPartition::Adversarial => {
                EvaluationExposureClass::Sequestered
            }
        },
        exposure_evidence_refs: refs(&["evidence:exposure-control"]),
        validation_evidence_refs: refs(&["evidence:task-validation"]),
        invalidation_dependency_refs: refs(&["dependency:task-source"]),
    }
}

fn corpus(regime: SpecialistRegime) -> EvaluationCorpusDefinition {
    let slug = regime_slug(regime);
    let mut corpus = EvaluationCorpusDefinition {
        corpus_ref: r(&format!("corpus:{slug}")),
        corpus_version: v("corpus-v1"),
        content_digest: digest("sha256:placeholder-corpus"),
        regime,
        task_distribution_ref: r(&format!("distribution:{slug}")),
        coverage_model_ref: r("coverage-model:registered"),
        sampling_policy_ref: r("sampling:registered"),
        anti_gaming_policy_ref: r("anti-gaming:registered"),
        exposure_control_policy_ref: r("exposure:registered"),
        development_partition_ref: r(&format!("partition:{slug}:development")),
        heldout_partition_ref: r(&format!("partition:{slug}:heldout")),
        adversarial_partition_ref: r(&format!("partition:{slug}:adversarial")),
        tasks: vec![
            task(regime, EvaluationPartition::Development),
            task(regime, EvaluationPartition::Heldout),
            task(regime, EvaluationPartition::Adversarial),
        ],
        invalidation_dependency_refs: refs(&["dependency:corpus-source"]),
    };
    corpus.content_digest = compute_evaluation_corpus_digest(&corpus).unwrap();
    corpus
}

fn environment_profile() -> ExecutionEnvironmentProfile {
    let evidence = refs(&["env:requirement"]);
    let mut profile = ExecutionEnvironmentProfile {
        environment_ref: r("environment:quality-sandbox"),
        environment_version: v("env-v1"),
        content_digest: digest("sha256:placeholder-environment"),
        runtime_ref: r("runtime:quality-sandbox"),
        runtime_version: v("runtime-v1"),
        runtime_artifact_ref: r("artifact:runtime"),
        runtime_artifact_digest: digest("sha256:runtime"),
        platform_ref: r("platform:qualified"),
        platform_version: v("platform-v1"),
        provenance_refs: refs(&["provenance:environment"]),
        isolation: IsolationContract {
            boundary_ref: r("boundary:environment"),
            enforcement_control_refs: refs(&["control:isolation"]),
            threat_model_refs: refs(&["threat:cross-trial"]),
            evidence_requirement_refs: evidence.clone(),
        },
        access: ResourceAccessContract {
            ambient_authority: AmbientAuthorityMode::DefaultDeny,
            filesystem_scope_policy_ref: r("policy:fs"),
            network_scope_policy_ref: r("policy:network"),
            device_scope_policy_ref: r("policy:device"),
            process_scope_policy_ref: r("policy:process"),
            ipc_scope_policy_ref: r("policy:ipc"),
            evidence_requirement_refs: evidence.clone(),
        },
        resources: ResourceControlContract {
            cpu_limit_policy_ref: r("policy:cpu"),
            memory_limit_policy_ref: r("policy:memory"),
            process_limit_policy_ref: r("policy:process-limit"),
            wall_clock_limit_policy_ref: r("policy:wall-clock"),
            io_limit_policy_ref: r("policy:io"),
            termination_policy_ref: r("policy:termination"),
            evidence_requirement_refs: evidence.clone(),
        },
        secrets: SecretDeliveryContract {
            secret_handle_contract_ref: r("contract:secret-handle"),
            injection_policy_ref: r("policy:secret-injection"),
            redaction_policy_ref: r("policy:secret-redaction"),
            cleanup_policy_ref: r("policy:secret-cleanup"),
            evidence_requirement_refs: evidence.clone(),
        },
        workspace: WorkspaceLifecycleContract {
            persistence_mode: WorkspacePersistenceMode::Ephemeral,
            task_scope_policy_ref: r("policy:workspace-scope"),
            reuse_policy_ref: r("policy:no-reuse"),
            reset_policy_ref: r("policy:reset"),
            correction_deletion_policy_ref: r("policy:delete"),
            teardown_policy_ref: r("policy:teardown"),
            evidence_requirement_refs: evidence.clone(),
        },
        supply_chain: SupplyChainContract {
            dependency_policy_ref: r("policy:dependency"),
            provenance_policy_ref: r("policy:supply-provenance"),
            integrity_policy_ref: r("policy:supply-integrity"),
            vulnerability_invalidation_policy_ref: r("policy:vulnerability"),
            evidence_requirement_refs: evidence.clone(),
        },
        artifacts: ArtifactBoundaryContract {
            import_policy_ref: r("policy:artifact-import"),
            export_policy_ref: r("policy:artifact-export"),
            provenance_policy_ref: r("policy:artifact-provenance"),
            data_loss_prevention_policy_ref: r("policy:artifact-dlp"),
            evidence_requirement_refs: evidence.clone(),
        },
        attestation: AttestationContract {
            environment_identity_evidence_ref: r("attestation:environment"),
            runtime_integrity_evidence_ref: r("attestation:runtime"),
            platform_integrity_evidence_ref: r("attestation:platform"),
            evidence_requirement_refs: evidence.clone(),
        },
        reproducibility: ReproducibilityContract {
            source_identity_policy_ref: r("policy:source-identity"),
            environment_capture_policy_ref: r("policy:environment-capture"),
            execution_recipe_ref: r("recipe:quality-run"),
            result_comparison_policy_ref: r("policy:result-comparison"),
            evidence_requirement_refs: evidence.clone(),
        },
        cleanup: CleanupContract {
            process_cleanup_policy_ref: r("policy:process-cleanup"),
            workspace_cleanup_policy_ref: r("policy:workspace-cleanup"),
            secret_cleanup_policy_ref: r("policy:secret-cleanup-final"),
            temporary_resource_cleanup_policy_ref: r("policy:temp-cleanup"),
            verification_policy_ref: r("policy:cleanup-verification"),
            evidence_requirement_refs: evidence.clone(),
        },
        qualification_requirement_refs: evidence,
        invalidation_dependency_refs: refs(&["dependency:environment"]),
    };
    profile.content_digest = compute_execution_environment_profile_digest(&profile).unwrap();
    profile
}

fn qualified_environment() -> noerith_capabilities::VerifiedExecutionEnvironment {
    let profile = environment_profile();
    let verified_profile = verify_execution_environment_profile_integrity(&profile).unwrap();
    let mut plan = ExecutionEnvironmentQualificationPlan {
        identity: ExecutionEnvironmentQualificationPlanIdentity {
            plan_ref: r("environment-plan:quality"),
            plan_version: v("plan-v1"),
            plan_digest: digest("sha256:placeholder-environment-plan"),
        },
        subject: verified_profile.identity().clone(),
        workload_scope_refs: refs(&["workload:quality-evaluation"]),
        threat_scope_refs: refs(&["threat:cross-trial"]),
        required_evidence_refs: refs(&["env:requirement"]),
        portability_requirement_refs: refs(&["portability:registered"]),
        performance_requirement_refs: refs(&["performance:registered"]),
        invalidation_dependency_refs: refs(&["dependency:environment-plan"]),
    };
    plan.identity.plan_digest = compute_execution_environment_plan_digest(&plan).unwrap();
    let evidence = vec![ExecutionEnvironmentEvidenceRecord {
        evidence_ref: r("environment-evidence:quality"),
        subject: plan.subject.clone(),
        plan_identity: plan.identity.clone(),
        requirement_ref: r("env:requirement"),
        test_method_ref: r("method:environment-conformance"),
        test_run_ref: r("run:environment-conformance"),
        producer_ref: r("producer:environment-harness"),
        provenance_refs: refs(&["provenance:environment-run"]),
        environment_evidence_refs: refs(&["evidence:environment-observation"]),
        observed_result_ref: r("result:environment-conformance"),
        validity_ref: r("validity:environment"),
        status: EvidenceStatus::Pass,
    }];
    qualify_execution_environment(&profile, &verified_profile, &plan, &evidence).unwrap()
}

fn grader_plan() -> EvidenceGraderPlan {
    let mut plan = EvidenceGraderPlan {
        identity: EvidenceGraderPlanIdentity {
            plan_ref: r("grader-plan:quality"),
            plan_version: v("grader-plan-v1"),
            plan_digest: digest("sha256:placeholder-grader-plan"),
        },
        grader: GraderIdentity {
            grader_ref: r("grader:quality"),
            grader_version: v("grader-v1"),
            implementation_ref: r("artifact:grader"),
            implementation_version: v("grader-artifact-v1"),
            configuration_ref: r("config:grader"),
            configuration_version: v("grader-config-v1"),
        },
        rubric_ref: r("rubric:quality"),
        rubric_version: v("rubric-v1"),
        mandatory_criterion_refs: refs(&["grader:criterion"]),
        calibrated_scope_refs: refs(&["scope:quality-evaluation"]),
        qualification_requirement_refs: refs(&["grader:qualification"]),
        calibration_corpus_ref: r("corpus:grader-development"),
        heldout_calibration_partition_ref: r("corpus:grader-heldout"),
        disagreement_policy_ref: r("policy:grader-disagreement"),
        abstention_policy_ref: r("policy:grader-abstention"),
        anti_gaming_policy_ref: r("policy:grader-anti-gaming"),
        invalidation_dependency_refs: refs(&["dependency:grader"]),
    };
    plan.identity.plan_digest = compute_evidence_grader_plan_digest(&plan).unwrap();
    plan
}

fn qualified_grader(plan: &EvidenceGraderPlan) -> noerith_capabilities::VerifiedEvidenceGrader {
    let evidence = vec![GraderQualificationEvidenceRecord {
        evidence_ref: r("grader-qualification:evidence"),
        grader: plan.grader.clone(),
        plan_identity: plan.identity.clone(),
        requirement_ref: r("grader:qualification"),
        test_method_ref: r("method:grader-calibration"),
        test_run_ref: r("run:grader-calibration"),
        producer_ref: r("producer:grader-harness"),
        provenance_refs: refs(&["provenance:grader-calibration"]),
        observed_result_ref: r("result:grader-calibration"),
        validity_ref: r("validity:grader"),
        status: EvidenceStatus::Pass,
    }];
    qualify_evidence_grader(plan, &evidence).unwrap()
}

fn verified_grade(
    regime: SpecialistRegime,
    partition: EvaluationPartition,
    plan: &EvidenceGraderPlan,
) -> noerith_capabilities::VerifiedGradeRecord {
    let slug = regime_slug(regime);
    let partition_slug = match partition {
        EvaluationPartition::Development => "development",
        EvaluationPartition::Heldout => "heldout",
        EvaluationPartition::Adversarial => "adversarial",
    };
    let subject = GradeSubject {
        regime,
        task_ref: r(&format!("task:{slug}:{partition_slug}")),
        trial_ref: r(&format!("trial:{slug}:{partition_slug}:1")),
        output_digest: digest(&format!("sha256:output:{slug}:{partition_slug}")),
        trace_ref: r(&format!("trace:{slug}:{partition_slug}:1")),
        environment_ref: r("environment:quality-sandbox"),
        environment_version: v("env-v1"),
        evaluation_scope_refs: refs(&["scope:quality-evaluation"]),
        execution_evidence_refs: refs(&["evidence:execution-trace"]),
    };
    let request = GradeRequest {
        request_ref: r(&format!("grade-request:{slug}:{partition_slug}")),
        subject: subject.clone(),
        grader_plan_identity: plan.identity.clone(),
        mandatory_criterion_refs: plan.mandatory_criterion_refs.clone(),
    };
    let record = GradeRecord {
        grade_ref: r(&format!("grade:{slug}:{partition_slug}")),
        request_ref: request.request_ref.clone(),
        subject,
        grader: plan.grader.clone(),
        grader_plan_identity: plan.identity.clone(),
        rubric_ref: plan.rubric_ref.clone(),
        rubric_version: plan.rubric_version.clone(),
        criterion_results: vec![CriterionGrade {
            criterion_ref: r("grader:criterion"),
            status: EvidenceStatus::Pass,
            evidence_refs: refs(&["evidence:grade"]),
        }],
        provenance_refs: refs(&["provenance:grade"]),
        validity_ref: r("validity:grade"),
    };
    verify_grade_record(&qualified_grader(plan), &request, &record).unwrap()
}

fn q07_plan() -> QualityFloorPlan {
    let heldout_regime_corpus_refs: BTreeMap<_, _> = SpecialistRegime::ALL
        .into_iter()
        .map(|regime| (regime, r(&format!("corpus:{}", regime_slug(regime)))))
        .collect();
    let comparison_axis_refs = Q07ComparisonAxis::ALL
        .into_iter()
        .map(|axis| (axis, r(&format!("axis:{axis:?}"))))
        .collect();
    let evaluation_corpus_refs = heldout_regime_corpus_refs.values().cloned().collect();
    let mut plan = QualityFloorPlan {
        plan_ref: r("quality-floor:q07"),
        plan_version: v("floor-v1"),
        content_digest: digest("sha256:placeholder-floor"),
        gate: QualityGateId::Q07ModelsExperts,
        source_contract_refs: refs(&["source:master-blueprint"]),
        floor_criteria: vec![
            QualityFloorCriterion {
                kind: QualityCriterionKind::Quality,
                criterion_ref: r("criterion:quality"),
                measurement_target_ref: r("target:quality"),
                threshold_policy_ref: r("threshold:quality"),
                evidence_requirement_refs: refs(&["requirement:quality"]),
            },
            QualityFloorCriterion {
                kind: QualityCriterionKind::Privacy,
                criterion_ref: r("criterion:privacy"),
                measurement_target_ref: r("target:privacy"),
                threshold_policy_ref: r("threshold:privacy"),
                evidence_requirement_refs: refs(&["requirement:privacy"]),
            },
        ],
        profile_metrics: vec![QualityProfileMetric {
            role: QualityProfileMetricRole::Cost,
            metric_ref: r("metric:cost"),
            measurement_target_ref: r("target:cost"),
            reporting_policy_ref: r("report:cost"),
            evidence_requirement_refs: refs(&["requirement:cost"]),
        }],
        coverage: QualityGateCoverage::Q07(Q07CoverageContract {
            heldout_regime_corpus_refs,
            comparison_axis_refs,
            repeated_trial_protocol_ref: r("q07:repeated-trials"),
            candidate_configuration_manifest_ref: r("q07:candidate-configurations"),
        }),
        evaluation_corpus_refs,
        grader_plan_refs: refs(&["grader-plan:quality"]),
        environment_qualification_plan_refs: refs(&["environment-plan:quality"]),
        trial_protocol_ref: r("trial-protocol:registered"),
        statistical_model_ref: r("statistics:registered"),
        uncertainty_policy_ref: r("uncertainty:registered"),
        seed_manifest_ref: r("seeds:registered"),
        hardware_manifest_ref: r("hardware:registered"),
        confidence_target_ref: r("confidence:registered"),
        analysis_plan_ref: r("analysis:registered"),
        preregistration_evidence_ref: r("preregistration:evidence"),
        invalidation_dependency_refs: refs(&["dependency:quality-floor"]),
    };
    plan.content_digest = compute_quality_floor_plan_digest(&plan).unwrap();
    plan
}

fn coverage_for(plan: &QualityFloorPlan) -> Vec<QualityCoverageResult> {
    let QualityGateCoverage::Q07(coverage) = &plan.coverage else {
        unreachable!();
    };
    let mut result = Vec::new();
    for (regime, requirement) in &coverage.heldout_regime_corpus_refs {
        result.push(QualityCoverageResult {
            item: QualityCoverageItem::Q07Regime(*regime),
            requirement_ref: requirement.clone(),
            evidence_refs: refs(&[&format!("coverage:regime:{}", regime_slug(*regime))]),
        });
    }
    for (axis, requirement) in &coverage.comparison_axis_refs {
        result.push(QualityCoverageResult {
            item: QualityCoverageItem::Q07ComparisonAxis(*axis),
            requirement_ref: requirement.clone(),
            evidence_refs: refs(&[&format!("coverage:axis:{axis:?}")]),
        });
    }
    result.push(QualityCoverageResult {
        item: QualityCoverageItem::Q07RepeatedTrials,
        requirement_ref: coverage.repeated_trial_protocol_ref.clone(),
        evidence_refs: refs(&["coverage:repeated-trials"]),
    });
    result.push(QualityCoverageResult {
        item: QualityCoverageItem::Q07CandidateConfiguration,
        requirement_ref: coverage.candidate_configuration_manifest_ref.clone(),
        evidence_refs: refs(&["coverage:candidate-configurations"]),
    });
    result
}

fn q07_result(
    plan: &QualityFloorPlan,
    grades: &[noerith_capabilities::VerifiedGradeRecord],
    environment_evidence: &BTreeSet<Reference>,
) -> QualityFloorResultSet {
    let grade_refs: BTreeSet<Reference> = grades
        .iter()
        .map(|grade| grade.grade_ref().clone())
        .collect();
    let criterion_results = plan
        .floor_criteria
        .iter()
        .map(|criterion| QualityCriterionResult {
            result_ref: r(&format!("result:{}", criterion.criterion_ref)),
            criterion_ref: criterion.criterion_ref.clone(),
            kind: criterion.kind,
            status: EvidenceStatus::Pass,
            measurement_target_ref: criterion.measurement_target_ref.clone(),
            threshold_policy_ref: criterion.threshold_policy_ref.clone(),
            satisfied_evidence_requirement_refs: criterion.evidence_requirement_refs.clone(),
            analysis_result_ref: r(&format!("analysis-result:{}", criterion.criterion_ref)),
            trial_evidence_refs: refs(&["trial-evidence:repeated"]),
            grader_result_refs: grade_refs.clone(),
            environment_evidence_refs: environment_evidence.clone(),
            provenance_refs: refs(&["provenance:quality-result"]),
            invalidation_dependency_refs: refs(&["dependency:quality-result"]),
        })
        .collect();
    let profile_results = plan
        .profile_metrics
        .iter()
        .map(|metric| QualityProfileResult {
            result_ref: r(&format!("profile-result:{}", metric.metric_ref)),
            metric_ref: metric.metric_ref.clone(),
            role: metric.role,
            measurement_target_ref: metric.measurement_target_ref.clone(),
            reporting_policy_ref: metric.reporting_policy_ref.clone(),
            satisfied_evidence_requirement_refs: metric.evidence_requirement_refs.clone(),
            measured_result_ref: r("measured:cost"),
            evidence_refs: refs(&["evidence:cost-measurement"]),
            provenance_refs: refs(&["provenance:cost"]),
            invalidation_dependency_refs: refs(&["dependency:cost"]),
        })
        .collect();
    let mut result = QualityFloorResultSet {
        result_set_ref: r("quality-result:q07"),
        result_set_version: v("result-v1"),
        content_digest: digest("sha256:placeholder-result"),
        plan_ref: plan.plan_ref.clone(),
        plan_version: plan.plan_version.clone(),
        plan_digest: plan.content_digest.clone(),
        gate: plan.gate,
        experiment: QualityExperimentBinding {
            evaluation_corpus_refs: plan.evaluation_corpus_refs.clone(),
            grader_plan_refs: plan.grader_plan_refs.clone(),
            environment_qualification_plan_refs: plan.environment_qualification_plan_refs.clone(),
            trial_protocol_ref: plan.trial_protocol_ref.clone(),
            statistical_model_ref: plan.statistical_model_ref.clone(),
            uncertainty_policy_ref: plan.uncertainty_policy_ref.clone(),
            seed_manifest_ref: plan.seed_manifest_ref.clone(),
            hardware_manifest_ref: plan.hardware_manifest_ref.clone(),
            confidence_target_ref: plan.confidence_target_ref.clone(),
            analysis_plan_ref: plan.analysis_plan_ref.clone(),
            preregistration_evidence_ref: plan.preregistration_evidence_ref.clone(),
        },
        criterion_results,
        profile_results,
        coverage_results: coverage_for(plan),
        provenance_refs: refs(&["provenance:result-set"]),
        invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
    };
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    result
}

fn q07_bundle() -> (
    QualityFloorPlan,
    QualityFloorResultSet,
    QualityEvidenceBundle,
) {
    let plan = q07_plan();
    let grader_plan = grader_plan();
    let environment = qualified_environment();
    let corpora: Vec<QualityCorpusEvidence> = SpecialistRegime::ALL
        .into_iter()
        .map(|regime| {
            let corpus = corpus(regime);
            let verified = verify_evaluation_corpus(&corpus).unwrap();
            QualityCorpusEvidence { corpus, verified }
        })
        .collect();
    let grades: Vec<_> = SpecialistRegime::ALL
        .into_iter()
        .map(|regime| verified_grade(regime, EvaluationPartition::Heldout, &grader_plan))
        .collect();
    let result = q07_result(&plan, &grades, environment.evidence_refs());
    let bundle = QualityEvidenceBundle {
        corpus_evidence: corpora,
        grade_records: grades,
        execution_environments: vec![environment],
    };
    (plan, result, bundle)
}

#[test]
fn q07_evidence_requires_exact_verified_heldout_provenance_for_all_six_regimes() {
    let (plan, result, bundle) = q07_bundle();
    let verified = verify_quality_evidence_bundle(&plan, &result, &bundle).unwrap();
    assert_eq!(verified.gate(), QualityGateId::Q07ModelsExperts);
    assert_eq!(
        verified.heldout_regimes().len(),
        SpecialistRegime::ALL.len()
    );
    assert_eq!(verified.grade_refs().len(), SpecialistRegime::ALL.len());
    assert_eq!(verified.corpus_refs().len(), SpecialistRegime::ALL.len());
}

#[test]
fn development_grade_cannot_be_used_as_confirmatory_floor_evidence() {
    let (plan, mut result, mut bundle) = q07_bundle();
    let grader_plan = grader_plan();
    let development = verified_grade(
        SpecialistRegime::ConversationPersonalAssistant,
        EvaluationPartition::Development,
        &grader_plan,
    );
    let old = bundle.grade_records.remove(0);
    for criterion in &mut result.criterion_results {
        criterion.grader_result_refs.remove(old.grade_ref());
        criterion
            .grader_result_refs
            .insert(development.grade_ref().clone());
    }
    bundle.grade_records.push(development);
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    assert!(matches!(
        verify_quality_evidence_bundle(&plan, &result, &bundle),
        Err(QualityEvidenceError::DevelopmentEvidenceRejected(_))
            | Err(QualityEvidenceError::Q07RequiresHeldout(_))
    ));
}

#[test]
fn missing_one_regime_grade_cannot_be_hidden_by_other_heldout_results() {
    let (plan, mut result, mut bundle) = q07_bundle();
    let removed = bundle.grade_records.pop().unwrap();
    for criterion in &mut result.criterion_results {
        criterion.grader_result_refs.remove(removed.grade_ref());
    }
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    assert!(matches!(
        verify_quality_evidence_bundle(&plan, &result, &bundle),
        Err(QualityEvidenceError::MissingQ07Regime(_))
    ));
}

#[test]
fn mutated_raw_corpus_cannot_ride_on_old_verified_wrapper() {
    let (plan, result, mut bundle) = q07_bundle();
    bundle.corpus_evidence[0].corpus.sampling_policy_ref = r("sampling:changed-after-verify");
    assert!(matches!(
        verify_quality_evidence_bundle(&plan, &result, &bundle),
        Err(QualityEvidenceError::Corpus(_)) | Err(QualityEvidenceError::CorpusWrapperMismatch(_))
    ));
}

#[test]
fn grade_from_unknown_task_or_wrong_environment_cannot_be_laundered() {
    let (plan, mut result, mut bundle) = q07_bundle();
    let grader_plan = grader_plan();
    let foreign = verified_grade(
        SpecialistRegime::ConversationPersonalAssistant,
        EvaluationPartition::Heldout,
        &grader_plan,
    );
    let original = bundle.grade_records.remove(0);

    // A verified grade is immutable from outside its owning module. To create an
    // unknown-task attack, remove the corpus that owns its legitimate task.
    for criterion in &mut result.criterion_results {
        criterion.grader_result_refs.remove(original.grade_ref());
        criterion
            .grader_result_refs
            .insert(foreign.grade_ref().clone());
    }
    bundle.grade_records.push(foreign.clone());
    bundle
        .corpus_evidence
        .retain(|entry| entry.corpus.regime != SpecialistRegime::ConversationPersonalAssistant);
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    assert!(matches!(
        verify_quality_evidence_bundle(&plan, &result, &bundle),
        Err(QualityEvidenceError::UnknownGradeTask(_))
    ));

    // Keep the variable used explicitly so this test also documents that the
    // verified-grade wrapper itself cannot be field-mutated by a caller.
    assert_eq!(
        foreign.subject().environment_ref,
        r("environment:quality-sandbox")
    );
}

#[test]
fn result_experiment_cannot_change_after_preregistration() {
    let (plan, mut result, bundle) = q07_bundle();
    result.experiment.hardware_manifest_ref = r("hardware:post-hoc");
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    assert_eq!(
        verify_quality_evidence_bundle(&plan, &result, &bundle),
        Err(QualityEvidenceError::ResultExperimentMismatch)
    );
}

#[test]
fn cross_corpus_contamination_family_partition_conflict_is_rejected() {
    let (plan, result, mut bundle) = q07_bundle();
    let shared = bundle.corpus_evidence[0].corpus.tasks[0]
        .contamination_family_ref
        .clone();
    bundle.corpus_evidence[1].corpus.tasks[1].contamination_family_ref = shared;
    bundle.corpus_evidence[1].corpus.content_digest =
        compute_evaluation_corpus_digest(&bundle.corpus_evidence[1].corpus).unwrap();
    bundle.corpus_evidence[1].verified =
        verify_evaluation_corpus(&bundle.corpus_evidence[1].corpus).unwrap();
    assert!(matches!(
        verify_quality_evidence_bundle(&plan, &result, &bundle),
        Err(QualityEvidenceError::ContaminationFamilyCrossesPartitions(
            _
        ))
    ));
}
