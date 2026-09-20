// Reuse the qualified Q07 corpus/grader/environment fixtures so this seam test
// binds real owner wrappers rather than weakening the evidence path.
include!("quality_evidence.rs");

use noerith_capabilities::{
    CandidateConfiguration, CandidateConfigurationManifest, CandidateModelBinding,
    QualityTrialConfigurationError, QualityTrialRecord, QualityTrialSet,
    QualityTrialVerificationEvidence, VerifiedCandidateConfigurationManifest,
    VerifiedQualityTrialSet, compute_candidate_configuration_digest,
    compute_candidate_configuration_manifest_digest, compute_quality_trial_set_digest,
    verify_candidate_configuration_manifest, verify_q07_trial_configuration_binding,
    verify_quality_floor_plan, verify_quality_trial_set,
};

fn candidate_configuration(name: &str, alternate: bool) -> CandidateConfiguration {
    let mut configuration = CandidateConfiguration {
        configuration_ref: r(&format!("candidate-configuration:{name}")),
        configuration_version: v("configuration-v1"),
        content_digest: digest("sha256:pending-configuration"),
        model: CandidateModelBinding {
            provider_ref: r(if alternate {
                "provider:b"
            } else {
                "provider:a"
            }),
            model_ref: r(if alternate { "model:b" } else { "model:a" }),
            model_version: v(if alternate { "model-v2" } else { "model-v1" }),
            adapter_ref: r(if alternate { "adapter:b" } else { "adapter:a" }),
            adapter_version: v(if alternate {
                "adapter-v2"
            } else {
                "adapter-v1"
            }),
        },
        worker_topology_ref: r(if alternate {
            "worker-topology:cooperating-pair"
        } else {
            "worker-topology:single"
        }),
        worker_count: if alternate { 2 } else { 1 },
        worker_coordination_policy_ref: r(if alternate {
            "worker-coordination:shared-state-arbiter"
        } else {
            "worker-coordination:single-worker"
        }),
        reasoning_effort_ref: r(if alternate {
            "reasoning-effort:high"
        } else {
            "reasoning-effort:standard"
        }),
        context_strategy_ref: r(if alternate {
            "context-strategy:multi-resolution"
        } else {
            "context-strategy:focused"
        }),
        retrieval_strategy_ref: r(if alternate {
            "retrieval-strategy:hybrid"
        } else {
            "retrieval-strategy:exact-first"
        }),
        provenance_refs: refs(&[&format!("provenance:candidate:{name}")]),
        invalidation_dependency_refs: refs(&[&format!("dependency:candidate:{name}")]),
    };
    configuration.content_digest = compute_candidate_configuration_digest(&configuration).unwrap();
    configuration
}

fn candidate_manifest() -> CandidateConfigurationManifest {
    let mut manifest = CandidateConfigurationManifest {
        manifest_ref: r("candidate-configuration-manifest:q07"),
        manifest_version: v("candidate-manifest-v1"),
        content_digest: digest("sha256:pending-candidate-manifest"),
        source_contract_refs: refs(&["source:q07", "source:master-blueprint"]),
        experiment_design_ref: r("experiment-design:q07"),
        randomization_policy_ref: r("randomization:q07"),
        blocking_policy_ref: r("blocking:q07"),
        comparison_estimand_refs: Q07ComparisonAxis::ALL
            .into_iter()
            .map(|axis| (axis, r(&format!("estimand:{axis:?}"))))
            .collect(),
        configurations: vec![
            candidate_configuration("a", false),
            candidate_configuration("b", true),
        ],
        invalidation_dependency_refs: refs(&[
            "dependency:q07-floor",
            "dependency:candidate-manifest",
        ]),
    };
    manifest.content_digest = compute_candidate_configuration_manifest_digest(&manifest).unwrap();
    manifest
}

fn q07_plan_for_manifest(manifest: &CandidateConfigurationManifest) -> QualityFloorPlan {
    let mut plan = q07_plan();
    let QualityGateCoverage::Q07(coverage) = &mut plan.coverage else {
        unreachable!();
    };
    coverage.candidate_configuration_manifest_ref = manifest.content_digest.value.clone();
    plan.content_digest = digest("sha256:pending-floor");
    plan.content_digest = compute_quality_floor_plan_digest(&plan).unwrap();
    plan
}

fn trial_for(
    configuration: &CandidateConfiguration,
    corpus: &EvaluationCorpusDefinition,
    environment: &ExecutionEnvironmentProfile,
) -> QualityTrialRecord {
    let task = corpus
        .tasks
        .iter()
        .find(|task| task.partition == EvaluationPartition::Heldout)
        .unwrap();
    let slug = regime_slug(task.regime);
    let configuration_slug = if configuration.configuration_ref == r("candidate-configuration:a") {
        "a"
    } else {
        "b"
    };
    QualityTrialRecord {
        trial_ref: r(&format!("trial:{slug}:{configuration_slug}")),
        corpus_ref: corpus.corpus_ref.clone(),
        corpus_version: corpus.corpus_version.clone(),
        corpus_digest: corpus.content_digest.clone(),
        task_ref: task.task_ref.clone(),
        task_version: task.task_version.clone(),
        task_digest: task.task_content_digest.clone(),
        regime: task.regime,
        partition: task.partition,
        candidate_configuration_ref: configuration.configuration_ref.clone(),
        candidate_configuration_version: configuration.configuration_version.clone(),
        candidate_configuration_digest: configuration.content_digest.clone(),
        model_ref: configuration.model.model_ref.clone(),
        model_version: configuration.model.model_version.clone(),
        provider_ref: configuration.model.provider_ref.clone(),
        adapter_ref: configuration.model.adapter_ref.clone(),
        adapter_version: configuration.model.adapter_version.clone(),
        environment_ref: environment.environment_ref.clone(),
        environment_version: environment.environment_version.clone(),
        environment_digest: environment.content_digest.clone(),
        seed_ref: r(&format!("seed:{slug}:{configuration_slug}")),
        input_digest: digest(&format!("sha256:input:{slug}:{configuration_slug}")),
        output_digest: digest(&format!("sha256:output:{slug}:{configuration_slug}")),
        trace_ref: r(&format!("trace:{slug}:{configuration_slug}")),
        execution_evidence_refs: refs(&[&format!(
            "execution-evidence:{slug}:{configuration_slug}"
        )]),
        grader_result_refs: refs(&[&format!("grade:{slug}:{configuration_slug}")]),
        provenance_refs: refs(&[&format!("provenance:trial:{slug}:{configuration_slug}")]),
        invalidation_dependency_refs: refs(&[&format!(
            "dependency:trial:{slug}:{configuration_slug}"
        )]),
    }
}

fn grade_for_trial_with_evidence(
    plan: &EvidenceGraderPlan,
    trial: &QualityTrialRecord,
    criterion_evidence_ref: &str,
) -> noerith_capabilities::VerifiedGradeRecord {
    let grader = qualified_grader(plan);
    let subject = GradeSubject {
        regime: trial.regime,
        task_ref: trial.task_ref.clone(),
        trial_ref: trial.trial_ref.clone(),
        output_digest: trial.output_digest.clone(),
        trace_ref: trial.trace_ref.clone(),
        environment_ref: trial.environment_ref.clone(),
        environment_version: trial.environment_version.clone(),
        evaluation_scope_refs: refs(&["scope:quality-evaluation"]),
        execution_evidence_refs: trial.execution_evidence_refs.clone(),
    };
    let request = GradeRequest {
        request_ref: r(&format!("grade-request:{}", trial.trial_ref)),
        subject: subject.clone(),
        grader_plan_identity: plan.identity.clone(),
        mandatory_criterion_refs: plan.mandatory_criterion_refs.clone(),
    };
    let grade_ref = trial.grader_result_refs.iter().next().unwrap().clone();
    let record = GradeRecord {
        grade_ref,
        request_ref: request.request_ref.clone(),
        subject,
        grader: plan.grader.clone(),
        grader_plan_identity: plan.identity.clone(),
        rubric_ref: plan.rubric_ref.clone(),
        rubric_version: plan.rubric_version.clone(),
        criterion_results: vec![CriterionGrade {
            criterion_ref: r("grader:criterion"),
            status: EvidenceStatus::Pass,
            evidence_refs: refs(&[criterion_evidence_ref]),
        }],
        provenance_refs: refs(&["provenance:grade"]),
        validity_ref: r("validity:grade"),
    };
    verify_grade_record(&grader, &request, &record).unwrap()
}

fn grade_for_trial(
    plan: &EvidenceGraderPlan,
    trial: &QualityTrialRecord,
) -> noerith_capabilities::VerifiedGradeRecord {
    grade_for_trial_with_evidence(plan, trial, "evidence:grade")
}

#[derive(Clone)]
struct BindingFixture {
    plan: QualityFloorPlan,
    manifest: CandidateConfigurationManifest,
    verified_manifest: VerifiedCandidateConfigurationManifest,
    corpora: Vec<EvaluationCorpusDefinition>,
    verified_corpora: Vec<noerith_capabilities::VerifiedEvaluationCorpus>,
    environment: noerith_capabilities::VerifiedExecutionEnvironment,
    grader_plan: EvidenceGraderPlan,
    grades: Vec<noerith_capabilities::VerifiedGradeRecord>,
    trial_set: QualityTrialSet,
    verified_trial_set: VerifiedQualityTrialSet,
}

fn binding_fixture<F>(mutate_trials: F) -> BindingFixture
where
    F: FnOnce(&mut Vec<QualityTrialRecord>),
{
    let manifest = candidate_manifest();
    let verified_manifest = verify_candidate_configuration_manifest(&manifest).unwrap();
    let plan = q07_plan_for_manifest(&manifest);

    let corpora: Vec<EvaluationCorpusDefinition> =
        SpecialistRegime::ALL.into_iter().map(corpus).collect();
    let verified_corpora: Vec<_> = corpora
        .iter()
        .map(|corpus| verify_evaluation_corpus(corpus).unwrap())
        .collect();
    let environment_profile = environment_profile();
    let environment = qualified_environment();

    let mut trials = Vec::new();
    for configuration in &manifest.configurations {
        for corpus in &corpora {
            trials.push(trial_for(configuration, corpus, &environment_profile));
        }
    }
    mutate_trials(&mut trials);

    let grader_plan = grader_plan();
    let grades: Vec<_> = trials
        .iter()
        .map(|trial| grade_for_trial(&grader_plan, trial))
        .collect();

    let mut trial_set = QualityTrialSet {
        trial_set_ref: r("trial-set:q07:candidate-configurations"),
        trial_set_version: v("trial-set-v1"),
        content_digest: digest("sha256:pending-trial-set"),
        plan_ref: plan.plan_ref.clone(),
        plan_version: plan.plan_version.clone(),
        plan_digest: plan.content_digest.clone(),
        gate: plan.gate,
        trial_protocol_ref: plan.trial_protocol_ref.clone(),
        seed_manifest_ref: plan.seed_manifest_ref.clone(),
        hardware_manifest_ref: plan.hardware_manifest_ref.clone(),
        candidate_configuration_manifest_ref: Some(manifest.content_digest.value.clone()),
        preregistration_evidence_ref: plan.preregistration_evidence_ref.clone(),
        trials,
        provenance_refs: refs(&["provenance:q07-trial-set"]),
        invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
    };
    trial_set.content_digest = compute_quality_trial_set_digest(&trial_set).unwrap();

    let verified_plan = verify_quality_floor_plan(&plan).unwrap();
    let verified_trial_set = verify_quality_trial_set(
        &plan,
        &verified_plan,
        &trial_set,
        QualityTrialVerificationEvidence {
            corpora: &verified_corpora,
            grades: &grades,
            environments: core::slice::from_ref(&environment),
        },
    )
    .unwrap();

    BindingFixture {
        plan,
        manifest,
        verified_manifest,
        corpora,
        verified_corpora,
        environment,
        grader_plan,
        grades,
        trial_set,
        verified_trial_set,
    }
}

fn aliased_trial_population(
    fixture: &BindingFixture,
    alias: &str,
    distinct_execution: bool,
) -> (
    QualityTrialSet,
    Vec<noerith_capabilities::VerifiedGradeRecord>,
    VerifiedQualityTrialSet,
) {
    let mut set = fixture.trial_set.clone();
    set.trial_set_ref = r(&format!("trial-set:q07:{alias}"));
    set.provenance_refs = refs(&[&format!("provenance:q07-trial-set:{alias}")]);

    for (index, trial) in set.trials.iter_mut().enumerate() {
        trial.trial_ref = r(&format!("trial:q07:{alias}:{index}"));
        trial.grader_result_refs = refs(&[&format!("grade:q07:{alias}:{index}")]);
        trial.provenance_refs = refs(&[&format!("provenance:trial:{alias}:{index}")]);
        trial.invalidation_dependency_refs = refs(&[&format!("dependency:trial:{alias}:{index}")]);
        if distinct_execution {
            trial.seed_ref = r(&format!("seed:{alias}:{index}"));
            trial.input_digest = digest(&format!("sha256:input:{alias}:{index}"));
        }
    }
    set.content_digest = compute_quality_trial_set_digest(&set).unwrap();

    let grades: Vec<_> = set
        .trials
        .iter()
        .map(|trial| grade_for_trial(&fixture.grader_plan, trial))
        .collect();
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();
    let verified = verify_quality_trial_set(
        &fixture.plan,
        &verified_plan,
        &set,
        QualityTrialVerificationEvidence {
            corpora: &fixture.verified_corpora,
            grades: &grades,
            environments: core::slice::from_ref(&fixture.environment),
        },
    )
    .unwrap();

    (set, grades, verified)
}

fn population_evidence(
    fixture: &BindingFixture,
    extra_grades: Vec<noerith_capabilities::VerifiedGradeRecord>,
    trial_sets: &[VerifiedQualityTrialSet],
) -> (QualityFloorResultSet, QualityEvidenceBundle) {
    let mut grades = fixture.grades.clone();
    grades.extend(extra_grades);

    let mut result = q07_result(&fixture.plan, &grades, fixture.environment.evidence_refs());
    let all_trial_refs: BTreeSet<Reference> = trial_sets
        .iter()
        .map(noerith_capabilities::quality_trial_evidence_ref)
        .collect();

    for criterion in &mut result.criterion_results {
        criterion.trial_evidence_refs = all_trial_refs.clone();
    }
    for coverage in &mut result.coverage_results {
        match coverage.item {
            QualityCoverageItem::Q07Regime(regime) => {
                coverage.evidence_refs = trial_sets
                    .iter()
                    .filter(|set| set.regimes().contains(&regime))
                    .map(noerith_capabilities::quality_trial_evidence_ref)
                    .collect();
            }
            QualityCoverageItem::Q07RepeatedTrials
            | QualityCoverageItem::Q07CandidateConfiguration => {
                coverage.evidence_refs = all_trial_refs.clone();
            }
            _ => {}
        }
    }
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();

    let corpus_evidence = fixture
        .corpora
        .iter()
        .cloned()
        .zip(fixture.verified_corpora.iter().cloned())
        .map(|(corpus, verified)| QualityCorpusEvidence { corpus, verified })
        .collect();
    let bundle = QualityEvidenceBundle {
        corpus_evidence,
        grade_records: grades,
        execution_environments: vec![fixture.environment.clone()],
    };
    (result, bundle)
}

fn strong_trial_evidence_ref(fixture: &BindingFixture) -> Reference {
    noerith_capabilities::quality_trial_evidence_ref(&fixture.verified_trial_set)
}

fn verify_binding(
    fixture: &BindingFixture,
) -> Result<
    noerith_capabilities::VerifiedQualityTrialConfigurationBinding,
    QualityTrialConfigurationError,
> {
    verify_q07_trial_configuration_binding(
        &fixture.plan,
        &fixture.trial_set,
        &fixture.verified_trial_set,
        &fixture.manifest,
        &fixture.verified_manifest,
    )
}

#[test]
fn q07_binding_proves_every_preregistered_configuration_across_all_six_regimes() {
    let fixture = binding_fixture(|_| {});
    let verified = verify_binding(&fixture).unwrap();
    assert_eq!(verified.configuration_identities().len(), 2);
    assert_eq!(
        verified.configuration_regime_pairs().len(),
        2 * SpecialistRegime::ALL.len()
    );
    assert_eq!(
        verified.configuration_manifest_digest(),
        &fixture.manifest.content_digest
    );
    assert_eq!(
        strong_trial_evidence_ref(&fixture),
        fixture
            .verified_trial_set
            .verification_digest()
            .value
            .clone(),
    );
    assert_eq!(
        verified.trial_set_digest(),
        fixture.verified_trial_set.content_digest(),
    );
    assert_eq!(
        verified.trial_evidence_digest(),
        fixture.verified_trial_set.verification_digest(),
    );
}

#[test]
fn q07_trial_cannot_substitute_model_under_a_valid_configuration_identity() {
    let fixture = binding_fixture(|trials| {
        trials[0].model_ref = r("model:substituted-after-registration");
    });
    assert!(matches!(
        verify_binding(&fixture),
        Err(QualityTrialConfigurationError::ModelBindingMismatch(_))
    ));
}

#[test]
fn q07_trial_cannot_substitute_configuration_digest() {
    let fixture = binding_fixture(|trials| {
        trials[0].candidate_configuration_digest = digest("sha256:forged-configuration");
    });
    assert!(matches!(
        verify_binding(&fixture),
        Err(QualityTrialConfigurationError::ConfigurationDigestMismatch(
            _
        ))
    ));
}

#[test]
fn q07_cannot_omit_a_preregistered_candidate_after_results_are_seen() {
    let fixture = binding_fixture(|trials| {
        trials.retain(|trial| trial.candidate_configuration_ref == r("candidate-configuration:a"));
    });
    assert_eq!(
        verify_binding(&fixture),
        Err(QualityTrialConfigurationError::ConfigurationPopulationMismatch)
    );
}

#[test]
fn q07_each_candidate_configuration_must_cover_each_specialist_regime() {
    let fixture = binding_fixture(|trials| {
        trials.retain(|trial| {
            !(trial.candidate_configuration_ref == r("candidate-configuration:b")
                && trial.regime == SpecialistRegime::SoftwareEngineering)
        });
    });
    assert_eq!(
        verify_binding(&fixture),
        Err(
            QualityTrialConfigurationError::MissingConfigurationRegimeCoverage {
                configuration_ref: "candidate-configuration:b".to_string(),
                regime: SpecialistRegime::SoftwareEngineering,
            }
        )
    );
}

#[test]
fn q07_mutated_raw_trial_set_cannot_ride_on_old_verified_wrapper() {
    let mut fixture = binding_fixture(|_| {});
    fixture.trial_set.trials[0]
        .provenance_refs
        .insert(r("provenance:mutated-after-verification"));
    assert_eq!(
        verify_binding(&fixture),
        Err(QualityTrialConfigurationError::TrialSetDigestMismatch)
    );
}

#[test]
fn q07_population_rejects_duplicate_execution_identity_hidden_behind_new_trial_aliases() {
    let fixture = binding_fixture(|_| {});
    let (_, alias_grades, alias_verified) =
        aliased_trial_population(&fixture, "execution-alias", false);
    let trial_sets = vec![fixture.verified_trial_set.clone(), alias_verified];
    let (result, bundle) = population_evidence(&fixture, alias_grades, &trial_sets);

    assert_eq!(
        noerith_capabilities::verify_quality_evidence_with_trials(
            &fixture.plan,
            &result,
            &bundle,
            &trial_sets,
        ),
        Err(
            noerith_capabilities::QualityTrialEvidenceBindingError::
                DuplicatePopulationExecutionIdentity
        )
    );
}

#[test]
fn q07_population_allows_exact_corpus_environment_reuse_when_execution_identity_is_distinct() {
    let fixture = binding_fixture(|_| {});
    let (_, alias_grades, alias_verified) =
        aliased_trial_population(&fixture, "distinct-execution", true);
    let trial_sets = vec![fixture.verified_trial_set.clone(), alias_verified];
    let (result, bundle) = population_evidence(&fixture, alias_grades, &trial_sets);

    let verified = noerith_capabilities::verify_quality_evidence_with_trials(
        &fixture.plan,
        &result,
        &bundle,
        &trial_sets,
    )
    .unwrap();
    assert_eq!(verified.trial_evidence_refs().len(), 2);
}

#[test]
fn q07_same_raw_trial_set_with_changed_verified_grade_content_gets_new_evidence_identity() {
    let fixture = binding_fixture(|_| {});
    let baseline = verify_binding(&fixture).unwrap();

    let alternate_grades: Vec<_> = fixture
        .trial_set
        .trials
        .iter()
        .enumerate()
        .map(|(index, trial)| {
            if index == 0 {
                grade_for_trial_with_evidence(
                    &fixture.grader_plan,
                    trial,
                    "evidence:grade:alternate-valid-content",
                )
            } else {
                grade_for_trial(&fixture.grader_plan, trial)
            }
        })
        .collect();
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();
    let alternate_verified_trial_set = verify_quality_trial_set(
        &fixture.plan,
        &verified_plan,
        &fixture.trial_set,
        QualityTrialVerificationEvidence {
            corpora: &fixture.verified_corpora,
            grades: &alternate_grades,
            environments: core::slice::from_ref(&fixture.environment),
        },
    )
    .unwrap();

    assert_eq!(
        alternate_verified_trial_set.content_digest(),
        fixture.verified_trial_set.content_digest(),
        "raw preregistered trial identity must stay stable",
    );
    assert_ne!(
        alternate_verified_trial_set.verification_digest(),
        fixture.verified_trial_set.verification_digest(),
        "verified evidence composition must change with valid grade content",
    );

    let alternate_binding = verify_q07_trial_configuration_binding(
        &fixture.plan,
        &fixture.trial_set,
        &alternate_verified_trial_set,
        &fixture.manifest,
        &fixture.verified_manifest,
    )
    .unwrap();
    assert_eq!(
        alternate_binding.trial_set_digest(),
        baseline.trial_set_digest(),
    );
    assert_ne!(
        alternate_binding.trial_evidence_digest(),
        baseline.trial_evidence_digest(),
    );
}
