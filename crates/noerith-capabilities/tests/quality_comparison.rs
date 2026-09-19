include!("quality_trial_configuration.rs");

use noerith_capabilities::{
    Q07ComparisonAnalysisError, Q07ComparisonAnalysisRecord,
    compute_q07_comparison_analysis_digest, verify_q07_comparison_analysis_evidence,
    verify_quality_evidence_with_trials,
};

fn comparison_records(fixture: &BindingFixture) -> Vec<Q07ComparisonAnalysisRecord> {
    let QualityGateCoverage::Q07(coverage) = &fixture.plan.coverage else {
        unreachable!();
    };
    let trial_evidence_refs = BTreeSet::from([strong_trial_evidence_ref(fixture)]);
    let mut invalidation_dependency_refs = fixture.plan.invalidation_dependency_refs.clone();
    invalidation_dependency_refs.extend(
        fixture
            .manifest
            .invalidation_dependency_refs
            .iter()
            .cloned(),
    );

    Q07ComparisonAxis::ALL
        .into_iter()
        .map(|axis| {
            let mut record = Q07ComparisonAnalysisRecord {
                analysis_ref: r(&format!("comparison-analysis:{axis:?}")),
                analysis_version: v("analysis-v1"),
                content_digest: digest("sha256:pending-comparison-analysis"),
                axis,
                plan_ref: fixture.plan.plan_ref.clone(),
                plan_version: fixture.plan.plan_version.clone(),
                plan_digest: fixture.plan.content_digest.clone(),
                comparison_requirement_ref: coverage.comparison_axis_refs[&axis].clone(),
                candidate_manifest_ref: fixture.manifest.manifest_ref.clone(),
                candidate_manifest_version: fixture.manifest.manifest_version.clone(),
                candidate_manifest_digest: fixture.manifest.content_digest.clone(),
                experiment_design_ref: fixture.manifest.experiment_design_ref.clone(),
                randomization_policy_ref: fixture.manifest.randomization_policy_ref.clone(),
                blocking_policy_ref: fixture.manifest.blocking_policy_ref.clone(),
                trial_evidence_refs: trial_evidence_refs.clone(),
                comparison_estimand_ref: fixture.manifest.comparison_estimand_refs[&axis].clone(),
                analysis_plan_ref: fixture.plan.analysis_plan_ref.clone(),
                statistical_model_ref: fixture.plan.statistical_model_ref.clone(),
                uncertainty_policy_ref: fixture.plan.uncertainty_policy_ref.clone(),
                confidence_target_ref: fixture.plan.confidence_target_ref.clone(),
                analysis_output_ref: r(&format!("analysis-output:{axis:?}")),
                assumption_evidence_refs: refs(&[&format!("assumptions:{axis:?}")]),
                diagnostic_evidence_refs: refs(&[&format!("diagnostics:{axis:?}")]),
                interaction_confounding_evidence_refs: refs(&[&format!(
                    "interaction-confounding:{axis:?}"
                )]),
                decision_evidence_refs: refs(&[&format!("decision:{axis:?}")]),
                provenance_refs: refs(&[&format!("provenance:{axis:?}")]),
                invalidation_dependency_refs: invalidation_dependency_refs.clone(),
            };
            record.content_digest = compute_q07_comparison_analysis_digest(&record).unwrap();
            record
        })
        .collect()
}

fn result_for_comparison(
    fixture: &BindingFixture,
    records: &[Q07ComparisonAnalysisRecord],
) -> QualityFloorResultSet {
    let plan = &fixture.plan;
    let trial_evidence_ref = strong_trial_evidence_ref(fixture);
    let grader_result_refs: BTreeSet<Reference> = fixture
        .trial_set
        .trials
        .iter()
        .flat_map(|trial| trial.grader_result_refs.iter().cloned())
        .collect();
    let environment = qualified_environment();

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
            analysis_result_ref: r(&format!("analysis:{}", criterion.criterion_ref)),
            trial_evidence_refs: BTreeSet::from([trial_evidence_ref.clone()]),
            grader_result_refs: grader_result_refs.clone(),
            environment_evidence_refs: environment.evidence_refs().clone(),
            provenance_refs: refs(&["provenance:q07-comparison-result"]),
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
            measured_result_ref: r(&format!("measurement:{}", metric.metric_ref)),
            evidence_refs: refs(&[&format!("measurement-evidence:{}", metric.metric_ref)]),
            provenance_refs: refs(&["provenance:q07-comparison-profile"]),
            invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
        })
        .collect();

    let mut coverage_results = coverage_for(plan);
    for coverage in &mut coverage_results {
        match coverage.item {
            QualityCoverageItem::Q07Regime(_)
            | QualityCoverageItem::Q07RepeatedTrials
            | QualityCoverageItem::Q07CandidateConfiguration => {
                coverage.evidence_refs = BTreeSet::from([trial_evidence_ref.clone()]);
            }
            QualityCoverageItem::Q07ComparisonAxis(axis) => {
                let record = records.iter().find(|record| record.axis == axis);
                if let Some(record) = record {
                    coverage.evidence_refs = BTreeSet::from([record.content_digest.value.clone()]);
                }
            }
            _ => {}
        }
    }

    let mut result = QualityFloorResultSet {
        result_set_ref: r("quality-result:q07:comparison-bound"),
        result_set_version: v("result-v1"),
        content_digest: digest("sha256:pending-q07-comparison-result"),
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
        coverage_results,
        provenance_refs: refs(&["provenance:q07-comparison-result-set"]),
        invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
    };
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    result
}

fn evidence_bundle_for_comparison(fixture: &BindingFixture) -> QualityEvidenceBundle {
    let corpus_evidence = fixture
        .corpora
        .iter()
        .cloned()
        .zip(fixture.verified_corpora.iter().cloned())
        .map(|(corpus, verified)| QualityCorpusEvidence { corpus, verified })
        .collect();

    QualityEvidenceBundle {
        corpus_evidence,
        grade_records: fixture.grades.clone(),
        execution_environments: vec![fixture.environment.clone()],
    }
}

fn verified_quality_evidence(
    fixture: &BindingFixture,
    result: &QualityFloorResultSet,
) -> noerith_capabilities::VerifiedQualityEvidenceWithTrials {
    let bundle = evidence_bundle_for_comparison(fixture);
    verify_quality_evidence_with_trials(
        &fixture.plan,
        result,
        &bundle,
        core::slice::from_ref(&fixture.verified_trial_set),
    )
    .unwrap()
}

fn verify_records(
    fixture: &BindingFixture,
    records: &[Q07ComparisonAnalysisRecord],
) -> Result<noerith_capabilities::VerifiedQ07ComparisonAnalysisEvidence, Q07ComparisonAnalysisError>
{
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();
    let binding = verify_binding(fixture).unwrap();
    let result = result_for_comparison(fixture, records);
    let quality_evidence = verified_quality_evidence(fixture, &result);
    verify_q07_comparison_analysis_evidence(
        &fixture.plan,
        &verified_plan,
        &result,
        &quality_evidence,
        &fixture.manifest,
        &fixture.verified_manifest,
        core::slice::from_ref(&fixture.verified_trial_set),
        core::slice::from_ref(&binding),
        records,
    )
}

#[test]
fn q07_comparison_requires_exact_content_bound_evidence_for_all_five_axes() {
    let fixture = binding_fixture(|_| {});
    let records = comparison_records(&fixture);
    let verified = verify_records(&fixture, &records).unwrap();

    assert_eq!(
        verified.axis_evidence_refs().len(),
        Q07ComparisonAxis::ALL.len()
    );
    assert_eq!(
        verified.trial_evidence_refs(),
        &BTreeSet::from([strong_trial_evidence_ref(&fixture)])
    );
    assert_eq!(
        verified.candidate_manifest_digest(),
        &fixture.manifest.content_digest
    );
}

#[test]
fn q07_comparison_cannot_omit_or_duplicate_an_axis() {
    let fixture = binding_fixture(|_| {});
    let mut missing = comparison_records(&fixture);
    missing.retain(|record| record.axis != Q07ComparisonAxis::RetrievalStrategy);
    assert_eq!(
        verify_records(&fixture, &missing),
        Err(Q07ComparisonAnalysisError::MissingAxis(
            Q07ComparisonAxis::RetrievalStrategy
        ))
    );

    let mut duplicate = comparison_records(&fixture);
    duplicate.push(duplicate[0].clone());
    assert_eq!(
        verify_records(&fixture, &duplicate),
        Err(Q07ComparisonAnalysisError::DuplicateAxis(duplicate[0].axis))
    );
}

#[test]
fn q07_axis_cannot_be_relabelled_to_another_preregistered_requirement() {
    let fixture = binding_fixture(|_| {});
    let mut records = comparison_records(&fixture);
    let QualityGateCoverage::Q07(coverage) = &fixture.plan.coverage else {
        unreachable!();
    };
    records[0].comparison_requirement_ref =
        coverage.comparison_axis_refs[&Q07ComparisonAxis::RetrievalStrategy].clone();
    records[0].content_digest = compute_q07_comparison_analysis_digest(&records[0]).unwrap();

    assert_eq!(
        verify_records(&fixture, &records),
        Err(Q07ComparisonAnalysisError::AxisRequirementMismatch(
            records[0].axis
        ))
    );
}

#[test]
fn q07_result_axis_coverage_must_cite_exact_analysis_digest() {
    let fixture = binding_fixture(|_| {});
    let records = comparison_records(&fixture);
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();
    let binding = verify_binding(&fixture).unwrap();
    let mut result = result_for_comparison(&fixture, &records);
    let axis = Q07ComparisonAxis::CandidateModel;
    let entry = result
        .coverage_results
        .iter_mut()
        .find(|entry| entry.item == QualityCoverageItem::Q07ComparisonAxis(axis))
        .unwrap();
    entry.evidence_refs = refs(&["sha256:forged-axis-analysis"]);
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    let quality_evidence = verified_quality_evidence(&fixture, &result);

    assert_eq!(
        verify_q07_comparison_analysis_evidence(
            &fixture.plan,
            &verified_plan,
            &result,
            &quality_evidence,
            &fixture.manifest,
            &fixture.verified_manifest,
            core::slice::from_ref(&fixture.verified_trial_set),
            core::slice::from_ref(&binding),
            &records,
        ),
        Err(Q07ComparisonAnalysisError::AxisCoverageEvidenceMismatch(
            axis
        ))
    );
}

#[test]
fn q07_post_hoc_comparison_estimand_substitution_is_rejected() {
    let fixture = binding_fixture(|_| {});
    let mut records = comparison_records(&fixture);
    let axis = records[0].axis;
    records[0].comparison_estimand_ref = r("estimand:chosen-after-results");
    records[0].content_digest = compute_q07_comparison_analysis_digest(&records[0]).unwrap();

    assert_eq!(
        verify_records(&fixture, &records),
        Err(Q07ComparisonAnalysisError::ComparisonEstimandBindingMismatch(axis))
    );
}

#[test]
fn q07_comparison_cannot_use_a_favorable_trial_subset_or_unknown_trial() {
    let fixture = binding_fixture(|_| {});
    let mut records = comparison_records(&fixture);
    records[0].trial_evidence_refs = refs(&["sha256:favorable-subset-or-other-trial"]);
    records[0].content_digest = compute_q07_comparison_analysis_digest(&records[0]).unwrap();

    assert_eq!(
        verify_records(&fixture, &records),
        Err(Q07ComparisonAnalysisError::TrialPopulationMismatch(
            records[0].axis
        ))
    );
}

#[test]
fn q07_post_hoc_statistical_or_experiment_design_change_is_rejected() {
    let fixture = binding_fixture(|_| {});
    let mut records = comparison_records(&fixture);
    records[0].statistical_model_ref = r("statistics:post-hoc");
    records[0].content_digest = compute_q07_comparison_analysis_digest(&records[0]).unwrap();
    assert_eq!(
        verify_records(&fixture, &records),
        Err(Q07ComparisonAnalysisError::AnalysisPlanBindingMismatch(
            records[0].axis
        ))
    );

    let mut records = comparison_records(&fixture);
    records[0].blocking_policy_ref = r("blocking:post-hoc");
    records[0].content_digest = compute_q07_comparison_analysis_digest(&records[0]).unwrap();
    assert_eq!(
        verify_records(&fixture, &records),
        Err(Q07ComparisonAnalysisError::ExperimentDesignBindingMismatch(
            records[0].axis
        ))
    );
}

#[test]
fn q07_comparison_requires_methodological_and_interaction_evidence() {
    let fixture = binding_fixture(|_| {});
    let mut records = comparison_records(&fixture);
    records[0].interaction_confounding_evidence_refs.clear();
    assert_eq!(
        compute_q07_comparison_analysis_digest(&records[0]),
        Err(Q07ComparisonAnalysisError::MissingMethodologicalEvidence(
            records[0].axis
        ))
    );
}

#[test]
fn q07_comparison_detects_post_digest_mutation() {
    let fixture = binding_fixture(|_| {});
    let mut records = comparison_records(&fixture);
    records[0]
        .diagnostic_evidence_refs
        .insert(r("diagnostics:mutated-after-digest"));
    assert_eq!(
        verify_records(&fixture, &records),
        Err(Q07ComparisonAnalysisError::DigestMismatch(records[0].axis))
    );
}

#[test]
fn q07_comparison_record_order_does_not_change_verified_semantics() {
    let fixture = binding_fixture(|_| {});
    let first_records = comparison_records(&fixture);
    let first = verify_records(&fixture, &first_records).unwrap();

    let mut reordered = first_records;
    reordered.reverse();
    let second = verify_records(&fixture, &reordered).unwrap();
    assert_eq!(first, second);
}

#[test]
fn q07_comparison_requires_the_verified_trial_configuration_binding_population() {
    let fixture = binding_fixture(|_| {});
    let records = comparison_records(&fixture);
    let verified_plan = verify_quality_floor_plan(&fixture.plan).unwrap();
    let result = result_for_comparison(&fixture, &records);
    let quality_evidence = verified_quality_evidence(&fixture, &result);

    assert_eq!(
        verify_q07_comparison_analysis_evidence(
            &fixture.plan,
            &verified_plan,
            &result,
            &quality_evidence,
            &fixture.manifest,
            &fixture.verified_manifest,
            core::slice::from_ref(&fixture.verified_trial_set),
            &[],
            &records,
        ),
        Err(Q07ComparisonAnalysisError::MissingConfigurationBindings)
    );
}

#[test]
fn q07_old_configuration_binding_cannot_ride_on_same_raw_set_with_new_verified_grade_content() {
    let fixture = binding_fixture(|_| {});
    let baseline_binding = verify_binding(&fixture).unwrap();

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
                    "evidence:grade:q07-comparison-alternate",
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
    );
    assert_ne!(
        alternate_verified_trial_set.verification_digest(),
        fixture.verified_trial_set.verification_digest(),
    );

    let mut alternate = fixture.clone();
    alternate.grades = alternate_grades;
    alternate.verified_trial_set = alternate_verified_trial_set;
    let records = comparison_records(&alternate);
    let result = result_for_comparison(&alternate, &records);
    let quality_evidence = verified_quality_evidence(&alternate, &result);

    assert_eq!(
        verify_q07_comparison_analysis_evidence(
            &alternate.plan,
            &verified_plan,
            &result,
            &quality_evidence,
            &alternate.manifest,
            &alternate.verified_manifest,
            core::slice::from_ref(&alternate.verified_trial_set),
            core::slice::from_ref(&baseline_binding),
            &records,
        ),
        Err(Q07ComparisonAnalysisError::ConfigurationBindingTrialPopulationMismatch)
    );

    verify_records(&alternate, &records)
        .expect("fresh binding for the new verified trial identity must remain admissible");
}
