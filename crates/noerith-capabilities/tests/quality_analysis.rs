// Reuse the strongest current Q07 trial/configuration fixture. This keeps the
// analysis seam test attached to exact verified held-out trial ownership rather
// than inventing a weaker parallel trial wrapper.
include!("quality_trial_configuration.rs");

fn result_for_analysis(
    fixture: &BindingFixture,
    trial_evidence_ref: Reference,
) -> QualityFloorResultSet {
    let plan = &fixture.plan;
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
            analysis_result_ref: r(&format!("analysis:pending:{}", criterion.criterion_ref)),
            trial_evidence_refs: BTreeSet::from([trial_evidence_ref.clone()]),
            grader_result_refs: refs(&[&format!("grade-set:{}", criterion.criterion_ref)]),
            environment_evidence_refs: refs(&[&format!(
                "environment-evidence:{}",
                criterion.criterion_ref
            )]),
            provenance_refs: refs(&["provenance:quality-result"]),
            invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
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
            measured_result_ref: r(&format!("measurement:pending:{}", metric.metric_ref)),
            evidence_refs: refs(&[&format!("measurement-evidence:{}", metric.metric_ref)]),
            provenance_refs: refs(&["provenance:profile-result"]),
            invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
        })
        .collect();

    let mut result = QualityFloorResultSet {
        result_set_ref: r("quality-result:q07:analysis-bound"),
        result_set_version: v("result-v1"),
        content_digest: digest("sha256:pending-quality-result"),
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
        provenance_refs: refs(&["provenance:quality-result-set"]),
        invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
    };
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    result
}

fn bind_analysis_records(
    plan: &QualityFloorPlan,
    result: &mut QualityFloorResultSet,
    trial_evidence_ref: Reference,
) -> noerith_capabilities::QualityAnalysisEvidenceBundle {
    let mut criterion_analyses = Vec::new();
    for criterion_result in &mut result.criterion_results {
        let mut analysis = noerith_capabilities::QualityCriterionAnalysisRecord {
            analysis_ref: r(&format!("analysis:{}", criterion_result.criterion_ref)),
            analysis_version: v("analysis-v1"),
            content_digest: digest("sha256:pending-analysis"),
            plan_ref: plan.plan_ref.clone(),
            plan_version: plan.plan_version.clone(),
            plan_digest: plan.content_digest.clone(),
            gate: plan.gate,
            criterion_ref: criterion_result.criterion_ref.clone(),
            kind: criterion_result.kind,
            status: criterion_result.status,
            measurement_target_ref: criterion_result.measurement_target_ref.clone(),
            threshold_policy_ref: criterion_result.threshold_policy_ref.clone(),
            analysis_plan_ref: plan.analysis_plan_ref.clone(),
            statistical_model_ref: plan.statistical_model_ref.clone(),
            uncertainty_policy_ref: plan.uncertainty_policy_ref.clone(),
            confidence_target_ref: plan.confidence_target_ref.clone(),
            trial_evidence_refs: BTreeSet::from([trial_evidence_ref.clone()]),
            analysis_output_ref: r(&format!(
                "analysis-output:{}",
                criterion_result.criterion_ref
            )),
            assumption_evidence_refs: refs(&["evidence:analysis-assumptions"]),
            diagnostic_evidence_refs: refs(&["evidence:analysis-diagnostics"]),
            decision_evidence_refs: refs(&["evidence:threshold-decision"]),
            provenance_refs: refs(&["provenance:analysis"]),
            invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
        };
        analysis.content_digest =
            noerith_capabilities::compute_quality_criterion_analysis_digest(&analysis).unwrap();
        criterion_result.analysis_result_ref = analysis.content_digest.value.clone();
        criterion_analyses.push(analysis);
    }

    let mut profile_measurements = Vec::new();
    for profile_result in &mut result.profile_results {
        let mut measurement = noerith_capabilities::QualityProfileMeasurementRecord {
            measurement_ref: r(&format!("measurement:{}", profile_result.metric_ref)),
            measurement_version: v("measurement-v1"),
            content_digest: digest("sha256:pending-measurement"),
            plan_ref: plan.plan_ref.clone(),
            plan_version: plan.plan_version.clone(),
            plan_digest: plan.content_digest.clone(),
            gate: plan.gate,
            metric_ref: profile_result.metric_ref.clone(),
            role: profile_result.role,
            measurement_target_ref: profile_result.measurement_target_ref.clone(),
            reporting_policy_ref: profile_result.reporting_policy_ref.clone(),
            analysis_plan_ref: plan.analysis_plan_ref.clone(),
            statistical_model_ref: plan.statistical_model_ref.clone(),
            uncertainty_policy_ref: plan.uncertainty_policy_ref.clone(),
            confidence_target_ref: plan.confidence_target_ref.clone(),
            trial_evidence_refs: BTreeSet::from([trial_evidence_ref.clone()]),
            measured_output_ref: r(&format!("measured-output:{}", profile_result.metric_ref)),
            supporting_evidence_refs: profile_result.evidence_refs.clone(),
            provenance_refs: refs(&["provenance:profile-measurement"]),
            invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
        };
        measurement.content_digest =
            noerith_capabilities::compute_quality_profile_measurement_digest(&measurement).unwrap();
        profile_result.measured_result_ref = measurement.content_digest.value.clone();
        profile_measurements.push(measurement);
    }

    result.content_digest = compute_quality_floor_result_digest(result).unwrap();
    noerith_capabilities::QualityAnalysisEvidenceBundle {
        criterion_analyses,
        profile_measurements,
    }
}

fn analysis_fixture() -> (
    BindingFixture,
    QualityFloorResultSet,
    noerith_capabilities::QualityAnalysisEvidenceBundle,
) {
    let fixture = binding_fixture(|_| {});
    let trial_evidence_ref = strong_trial_evidence_ref(&fixture);
    let mut result = result_for_analysis(&fixture, trial_evidence_ref.clone());
    let bundle = bind_analysis_records(&fixture.plan, &mut result, trial_evidence_ref);
    (fixture, result, bundle)
}

#[test]
fn q07_pass_and_cost_profile_require_exact_content_bound_analysis_evidence() {
    let (fixture, result, bundle) = analysis_fixture();
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();
    let verified = noerith_capabilities::verify_quality_analysis_evidence(
        &fixture.plan,
        &verified_plan,
        &result,
        core::slice::from_ref(&fixture.verified_trial_set),
        &bundle,
    )
    .unwrap();

    assert_eq!(
        verified.criterion_analysis_evidence_refs().len(),
        fixture.plan.floor_criteria.len()
    );
    assert_eq!(
        verified.profile_measurement_evidence_refs().len(),
        fixture.plan.profile_metrics.len()
    );
    assert_eq!(verified.trial_evidence_refs().len(), 1);
    assert_eq!(
        verified.trial_evidence_refs(),
        &BTreeSet::from([strong_trial_evidence_ref(&fixture)]),
    );
}

#[test]
fn caller_cannot_invent_analysis_reference_for_a_structurally_valid_pass() {
    let (fixture, mut result, bundle) = analysis_fixture();
    result.criterion_results[0].analysis_result_ref = r("sha256:forged-analysis-result");
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();

    assert!(matches!(
        noerith_capabilities::verify_quality_analysis_evidence(
            &fixture.plan,
            &verified_plan,
            &result,
            core::slice::from_ref(&fixture.verified_trial_set),
            &bundle,
        ),
        Err(noerith_capabilities::QualityAnalysisError::CriterionAnalysisBindingMismatch(_))
    ));
}

#[test]
fn post_hoc_statistical_model_change_cannot_be_rebound_as_the_same_pass() {
    let (fixture, mut result, mut bundle) = analysis_fixture();
    bundle.criterion_analyses[0].statistical_model_ref = r("statistics:post-hoc-model");
    bundle.criterion_analyses[0].content_digest =
        noerith_capabilities::compute_quality_criterion_analysis_digest(
            &bundle.criterion_analyses[0],
        )
        .unwrap();
    result.criterion_results[0].analysis_result_ref =
        bundle.criterion_analyses[0].content_digest.value.clone();
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();

    assert!(matches!(
        noerith_capabilities::verify_quality_analysis_evidence(
            &fixture.plan,
            &verified_plan,
            &result,
            core::slice::from_ref(&fixture.verified_trial_set),
            &bundle,
        ),
        Err(noerith_capabilities::QualityAnalysisError::CriterionAnalysisBindingMismatch(_))
    ));
}

#[test]
fn q07_cost_measurement_cannot_float_free_from_the_verified_trial_population() {
    let (fixture, mut result, mut bundle) = analysis_fixture();
    bundle.profile_measurements[0].trial_evidence_refs = refs(&["sha256:other-trial-population"]);
    bundle.profile_measurements[0].content_digest =
        noerith_capabilities::compute_quality_profile_measurement_digest(
            &bundle.profile_measurements[0],
        )
        .unwrap();
    result.profile_results[0].measured_result_ref =
        bundle.profile_measurements[0].content_digest.value.clone();
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();

    assert!(matches!(
        noerith_capabilities::verify_quality_analysis_evidence(
            &fixture.plan,
            &verified_plan,
            &result,
            core::slice::from_ref(&fixture.verified_trial_set),
            &bundle,
        ),
        Err(noerith_capabilities::QualityAnalysisError::ProfileMeasurementTrialMismatch(_))
    ));
}

#[test]
fn analysis_record_mutation_after_digest_is_detected() {
    let (fixture, result, mut bundle) = analysis_fixture();
    bundle.criterion_analyses[0]
        .diagnostic_evidence_refs
        .insert(r("evidence:added-after-digest"));
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();

    assert!(matches!(
        noerith_capabilities::verify_quality_analysis_evidence(
            &fixture.plan,
            &verified_plan,
            &result,
            core::slice::from_ref(&fixture.verified_trial_set),
            &bundle,
        ),
        Err(noerith_capabilities::QualityAnalysisError::DigestMismatch(
            _
        ))
    ));
}
