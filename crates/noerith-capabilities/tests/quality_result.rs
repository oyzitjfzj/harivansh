use noerith_capabilities::{
    ContentDigest, EvidenceStatus, OpaqueVersion, Q06CoverageContract, Q07ComparisonAxis,
    Q07CoverageContract, QualityCoverageItem, QualityCoverageResult, QualityCriterionKind,
    QualityCriterionResult, QualityExperimentBinding, QualityFloorCriterion, QualityFloorPlan,
    QualityFloorResultSet, QualityGateCoverage, QualityGateId, QualityProfileMetric,
    QualityProfileMetricRole, QualityProfileResult, QualityResultError, Reference,
    SHA256_ALGORITHM_REF, SpecialistRegime, compute_quality_floor_plan_digest,
    compute_quality_floor_result_digest, verify_quality_floor_plan, verify_quality_floor_result,
};
use std::collections::BTreeSet;

fn r(value: &str) -> Reference {
    Reference::new(value).unwrap()
}

fn refs(values: &[&str]) -> BTreeSet<Reference> {
    values.iter().map(|value| r(value)).collect()
}

fn placeholder_digest() -> ContentDigest {
    ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r("sha256:pending"),
    }
}

fn criterion(kind: QualityCriterionKind, name: &str) -> QualityFloorCriterion {
    QualityFloorCriterion {
        kind,
        criterion_ref: r(name),
        measurement_target_ref: r(&format!("target:{name}")),
        threshold_policy_ref: r(&format!("threshold:{name}")),
        evidence_requirement_refs: refs(&[&format!("requirement:{name}")]),
    }
}

fn metric(role: QualityProfileMetricRole, name: &str) -> QualityProfileMetric {
    QualityProfileMetric {
        role,
        metric_ref: r(name),
        measurement_target_ref: r(&format!("target:{name}")),
        reporting_policy_ref: r(&format!("report:{name}")),
        evidence_requirement_refs: refs(&[&format!("requirement:{name}")]),
    }
}

fn common_plan(gate: QualityGateId, coverage: QualityGateCoverage) -> QualityFloorPlan {
    QualityFloorPlan {
        plan_ref: r(match gate {
            QualityGateId::Q06MemoryContext => "floor:q06",
            QualityGateId::Q07ModelsExperts => "floor:q07",
        }),
        plan_version: OpaqueVersion::new("locked-2026-09").unwrap(),
        content_digest: placeholder_digest(),
        gate,
        source_contract_refs: refs(&["source:master", "source:build-decisions"]),
        floor_criteria: Vec::new(),
        profile_metrics: Vec::new(),
        coverage,
        evaluation_corpus_refs: refs(&["corpus:heldout:primary"]),
        grader_plan_refs: refs(&["grader-plan:qualified"]),
        environment_qualification_plan_refs: refs(&["environment-plan:qualified"]),
        trial_protocol_ref: r("trial-protocol:registered"),
        statistical_model_ref: r("statistics:registered"),
        uncertainty_policy_ref: r("uncertainty:registered"),
        seed_manifest_ref: r("seeds:registered"),
        hardware_manifest_ref: r("hardware:registered"),
        confidence_target_ref: r("confidence:registered"),
        analysis_plan_ref: r("analysis:registered"),
        preregistration_evidence_ref: r("preregistration:evidence"),
        invalidation_dependency_refs: refs(&[
            "dependency:corpus",
            "dependency:grader",
            "dependency:environment",
        ]),
    }
}

fn q06_plan() -> QualityFloorPlan {
    let coverage = QualityGateCoverage::Q06(Q06CoverageContract {
        long_history_memory_corpus_ref: r("q06:long-history"),
        multi_session_reasoning_corpus_ref: r("q06:multi-session"),
        correction_case_corpus_ref: r("q06:corrections"),
        poisoning_case_corpus_ref: r("q06:poisoning"),
        lifecycle_case_corpus_ref: r("q06:lifecycle"),
        abstention_unknown_case_corpus_ref: r("q06:abstention"),
        protected_constraint_evidence_ref: r("q06:protected-constraint"),
    });
    let mut plan = common_plan(QualityGateId::Q06MemoryContext, coverage);
    plan.floor_criteria = vec![
        criterion(QualityCriterionKind::Recall, "criterion:recall"),
        criterion(QualityCriterionKind::Fidelity, "criterion:fidelity"),
        criterion(QualityCriterionKind::Privacy, "criterion:privacy"),
        criterion(
            QualityCriterionKind::NoSilentLostConstraint,
            "criterion:no-lost-constraint",
        ),
    ];
    plan.content_digest = compute_quality_floor_plan_digest(&plan).unwrap();
    plan
}

fn q07_plan() -> QualityFloorPlan {
    let heldout_regime_corpus_refs = SpecialistRegime::ALL
        .into_iter()
        .map(|regime| (regime, r(&format!("heldout:{regime:?}"))))
        .collect();
    let comparison_axis_refs = Q07ComparisonAxis::ALL
        .into_iter()
        .map(|axis| (axis, r(&format!("axis:{axis:?}"))))
        .collect();
    let coverage = QualityGateCoverage::Q07(Q07CoverageContract {
        heldout_regime_corpus_refs,
        comparison_axis_refs,
        repeated_trial_protocol_ref: r("q07:repeated-trials"),
        candidate_configuration_manifest_ref: r("q07:candidate-configurations"),
    });
    let mut plan = common_plan(QualityGateId::Q07ModelsExperts, coverage);
    plan.floor_criteria = vec![
        criterion(QualityCriterionKind::Quality, "criterion:quality"),
        criterion(QualityCriterionKind::Privacy, "criterion:privacy"),
    ];
    plan.profile_metrics = vec![metric(QualityProfileMetricRole::Cost, "metric:cost")];
    plan.content_digest = compute_quality_floor_plan_digest(&plan).unwrap();
    plan
}

fn coverage_for(plan: &QualityFloorPlan) -> Vec<QualityCoverageResult> {
    let mut out = Vec::new();
    let mut push = |item, requirement: &Reference| {
        out.push(QualityCoverageResult {
            item,
            requirement_ref: requirement.clone(),
            evidence_refs: refs(&[&format!("coverage-evidence:{item:?}")]),
        });
    };
    match &plan.coverage {
        QualityGateCoverage::Q06(coverage) => {
            push(
                QualityCoverageItem::Q06LongHistoryMemory,
                &coverage.long_history_memory_corpus_ref,
            );
            push(
                QualityCoverageItem::Q06MultiSessionReasoning,
                &coverage.multi_session_reasoning_corpus_ref,
            );
            push(
                QualityCoverageItem::Q06Corrections,
                &coverage.correction_case_corpus_ref,
            );
            push(
                QualityCoverageItem::Q06Poisoning,
                &coverage.poisoning_case_corpus_ref,
            );
            push(
                QualityCoverageItem::Q06Lifecycle,
                &coverage.lifecycle_case_corpus_ref,
            );
            push(
                QualityCoverageItem::Q06AbstentionUnknown,
                &coverage.abstention_unknown_case_corpus_ref,
            );
            push(
                QualityCoverageItem::Q06ProtectedConstraint,
                &coverage.protected_constraint_evidence_ref,
            );
        }
        QualityGateCoverage::Q07(coverage) => {
            for (regime, requirement) in &coverage.heldout_regime_corpus_refs {
                push(QualityCoverageItem::Q07Regime(*regime), requirement);
            }
            for (axis, requirement) in &coverage.comparison_axis_refs {
                push(QualityCoverageItem::Q07ComparisonAxis(*axis), requirement);
            }
            push(
                QualityCoverageItem::Q07RepeatedTrials,
                &coverage.repeated_trial_protocol_ref,
            );
            push(
                QualityCoverageItem::Q07CandidateConfiguration,
                &coverage.candidate_configuration_manifest_ref,
            );
        }
    }
    out
}

fn result_for(plan: &QualityFloorPlan) -> QualityFloorResultSet {
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
            trial_evidence_refs: refs(&[&format!("trials:{}", criterion.criterion_ref)]),
            grader_result_refs: refs(&[&format!("grades:{}", criterion.criterion_ref)]),
            environment_evidence_refs: refs(&[&format!(
                "environment-evidence:{}",
                criterion.criterion_ref
            )]),
            provenance_refs: refs(&[&format!("provenance:{}", criterion.criterion_ref)]),
            invalidation_dependency_refs: refs(&[&format!(
                "invalidation:{}",
                criterion.criterion_ref
            )]),
        })
        .collect();

    let profile_results = plan
        .profile_metrics
        .iter()
        .map(|metric| QualityProfileResult {
            result_ref: r(&format!("result:{}", metric.metric_ref)),
            metric_ref: metric.metric_ref.clone(),
            role: metric.role,
            measurement_target_ref: metric.measurement_target_ref.clone(),
            reporting_policy_ref: metric.reporting_policy_ref.clone(),
            satisfied_evidence_requirement_refs: metric.evidence_requirement_refs.clone(),
            measured_result_ref: r(&format!("measured:{}", metric.metric_ref)),
            evidence_refs: refs(&[&format!("metric-evidence:{}", metric.metric_ref)]),
            provenance_refs: refs(&[&format!("metric-provenance:{}", metric.metric_ref)]),
            invalidation_dependency_refs: refs(&[&format!(
                "metric-invalidation:{}",
                metric.metric_ref
            )]),
        })
        .collect();

    let mut result = QualityFloorResultSet {
        result_set_ref: r(&format!("result-set:{}", plan.plan_ref)),
        result_set_version: OpaqueVersion::new("run-2026-09").unwrap(),
        content_digest: placeholder_digest(),
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
        provenance_refs: refs(&["result-set:provenance"]),
        invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
    };
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    result
}

fn redigest(result: &mut QualityFloorResultSet) {
    result.content_digest = placeholder_digest();
    result.content_digest = compute_quality_floor_result_digest(result).unwrap();
}

#[test]
fn q06_pass_requires_every_exact_preregistered_hard_result() {
    let plan = q06_plan();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();
    let result = result_for(&plan);
    let verified = verify_quality_floor_result(&plan, &verified_plan, &result).unwrap();
    assert_eq!(verified.gate(), QualityGateId::Q06MemoryContext);
    assert_eq!(verified.criterion_result_refs().len(), 4);
    assert_eq!(verified.profile_result_refs().len(), 0);
    assert_eq!(verified.coverage_evidence_refs().len(), 7);
}

#[test]
fn fail_and_indeterminate_hard_results_fail_closed_even_with_valid_result_digest() {
    for status in [EvidenceStatus::Fail, EvidenceStatus::Indeterminate] {
        let plan = q06_plan();
        let verified_plan = verify_quality_floor_plan(&plan).unwrap();
        let mut result = result_for(&plan);
        result.criterion_results[0].status = status;
        redigest(&mut result);
        let error = verify_quality_floor_result(&plan, &verified_plan, &result).unwrap_err();
        assert!(matches!(
            (status, error),
            (
                EvidenceStatus::Fail,
                QualityResultError::HardCriterionFailed(_)
            ) | (
                EvidenceStatus::Indeterminate,
                QualityResultError::HardCriterionIndeterminate(_)
            )
        ));
    }
}

#[test]
fn q07_cost_profile_cannot_compensate_for_quality_failure() {
    let plan = q07_plan();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();
    let mut result = result_for(&plan);
    let quality = result
        .criterion_results
        .iter_mut()
        .find(|item| item.kind == QualityCriterionKind::Quality)
        .unwrap();
    quality.status = EvidenceStatus::Fail;
    redigest(&mut result);
    assert!(matches!(
        verify_quality_floor_result(&plan, &verified_plan, &result),
        Err(QualityResultError::HardCriterionFailed(_))
    ));
    assert_eq!(result.profile_results.len(), 1);
}

#[test]
fn plan_or_experiment_substitution_cannot_reuse_a_passing_result() {
    let plan = q07_plan();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();

    let mut wrong_experiment = result_for(&plan);
    wrong_experiment.experiment.hardware_manifest_ref = r("hardware:post-hoc-faster-box");
    redigest(&mut wrong_experiment);
    assert_eq!(
        verify_quality_floor_result(&plan, &verified_plan, &wrong_experiment),
        Err(QualityResultError::ExperimentBindingMismatch)
    );

    let mut wrong_plan_binding = result_for(&plan);
    wrong_plan_binding.plan_version = OpaqueVersion::new("other-floor-version").unwrap();
    redigest(&mut wrong_plan_binding);
    assert_eq!(
        verify_quality_floor_result(&plan, &verified_plan, &wrong_plan_binding),
        Err(QualityResultError::PlanBindingMismatch)
    );
}

#[test]
fn mutated_raw_plan_invalidates_old_verified_plan_and_result() {
    let mut plan = q06_plan();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();
    let result = result_for(&plan);
    plan.analysis_plan_ref = r("analysis:changed-after-results");
    assert!(matches!(
        verify_quality_floor_result(&plan, &verified_plan, &result),
        Err(QualityResultError::FloorPlan(_))
    ));
}

#[test]
fn missing_hard_profile_or_coverage_evidence_is_rejected() {
    let plan = q07_plan();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();

    let mut missing_hard = result_for(&plan);
    missing_hard.criterion_results.pop();
    redigest(&mut missing_hard);
    assert_eq!(
        verify_quality_floor_result(&plan, &verified_plan, &missing_hard),
        Err(QualityResultError::CriterionSetMismatch)
    );

    let mut missing_profile = result_for(&plan);
    missing_profile.profile_results.clear();
    redigest(&mut missing_profile);
    assert_eq!(
        verify_quality_floor_result(&plan, &verified_plan, &missing_profile),
        Err(QualityResultError::ProfileSetMismatch)
    );

    let mut missing_coverage = result_for(&plan);
    missing_coverage.coverage_results.pop();
    redigest(&mut missing_coverage);
    assert_eq!(
        verify_quality_floor_result(&plan, &verified_plan, &missing_coverage),
        Err(QualityResultError::CoverageSetMismatch)
    );
}

#[test]
fn criterion_binding_cannot_change_measurement_target_or_threshold() {
    let plan = q06_plan();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();
    let mut result = result_for(&plan);
    result.criterion_results[0].threshold_policy_ref = r("threshold:post-hoc-lower");
    redigest(&mut result);
    assert!(matches!(
        verify_quality_floor_result(&plan, &verified_plan, &result),
        Err(QualityResultError::CriterionBindingMismatch(_))
    ));
}

#[test]
fn q07_requires_exact_regime_and_comparison_coverage_binding() {
    let plan = q07_plan();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();
    let mut result = result_for(&plan);
    let item = result
        .coverage_results
        .iter_mut()
        .find(|entry| {
            entry.item == QualityCoverageItem::Q07Regime(SpecialistRegime::SoftwareEngineering)
        })
        .unwrap();
    item.requirement_ref = r("heldout:wrong-regime-corpus");
    redigest(&mut result);
    assert_eq!(
        verify_quality_floor_result(&plan, &verified_plan, &result),
        Err(QualityResultError::CoverageBindingMismatch(
            QualityCoverageItem::Q07Regime(SpecialistRegime::SoftwareEngineering)
        ))
    );
}

#[test]
fn result_digest_detects_post_composition_mutation() {
    let plan = q06_plan();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();
    let mut result = result_for(&plan);
    assert!(verify_quality_floor_result(&plan, &verified_plan, &result).is_ok());
    result.criterion_results[0]
        .provenance_refs
        .insert(r("provenance:added-after-verification"));
    assert_eq!(
        verify_quality_floor_result(&plan, &verified_plan, &result),
        Err(QualityResultError::DigestMismatch)
    );
}

#[test]
fn canonical_result_digest_is_order_independent_for_semantic_sets_and_vectors() {
    let plan = q07_plan();
    let first = result_for(&plan);
    let mut second = result_for(&plan);
    second.criterion_results.reverse();
    second.profile_results.reverse();
    second.coverage_results.reverse();
    second.content_digest = placeholder_digest();

    assert_eq!(
        compute_quality_floor_result_digest(&first).unwrap(),
        compute_quality_floor_result_digest(&second).unwrap()
    );
}

#[test]
fn duplicate_coverage_item_is_rejected_even_if_evidence_names_differ() {
    let plan = q06_plan();
    let mut result = result_for(&plan);
    let mut duplicate = result.coverage_results[0].clone();
    duplicate.evidence_refs = refs(&["different-evidence"]);
    result.coverage_results.push(duplicate);
    result.content_digest = placeholder_digest();
    assert!(matches!(
        compute_quality_floor_result_digest(&result),
        Err(QualityResultError::DuplicateCoverageItem(_))
    ));
}

#[test]
fn q07_coverage_fixture_contains_all_six_regimes_and_five_experiment_axes() {
    let plan = q07_plan();
    let result = result_for(&plan);
    let regime_count = result
        .coverage_results
        .iter()
        .filter(|entry| matches!(entry.item, QualityCoverageItem::Q07Regime(_)))
        .count();
    let axis_count = result
        .coverage_results
        .iter()
        .filter(|entry| matches!(entry.item, QualityCoverageItem::Q07ComparisonAxis(_)))
        .count();
    assert_eq!(regime_count, SpecialistRegime::ALL.len());
    assert_eq!(axis_count, Q07ComparisonAxis::ALL.len());
}

#[test]
fn result_sets_remain_plain_evidence_until_the_verifier_returns_private_pass_wrapper() {
    let plan = q06_plan();
    let verified_plan = verify_quality_floor_plan(&plan).unwrap();
    let result = result_for(&plan);
    assert_eq!(result.gate, QualityGateId::Q06MemoryContext);
    let verified = verify_quality_floor_result(&plan, &verified_plan, &result).unwrap();
    assert_eq!(verified.plan_digest(), &plan.content_digest);
}
