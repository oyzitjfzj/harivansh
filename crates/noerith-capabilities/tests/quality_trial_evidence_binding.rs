// Reuse the already-adversarially-developed S05 trial fixture in the same
// integration-test crate so this seam test exercises the exact owner wrappers
// rather than inventing a weaker parallel fixture.
include!("quality_trial.rs");

use noerith_capabilities::{
    QualityCorpusEvidence, QualityCoverageItem, QualityCoverageResult, QualityCriterionResult,
    QualityEvidenceBundle, QualityExperimentBinding, QualityFloorResultSet,
    QualityTrialEvidenceBindingError, compute_quality_floor_result_digest,
    quality_trial_evidence_ref, verify_quality_evidence_with_trials,
};

fn coverage_results(plan: &QualityFloorPlan) -> Vec<QualityCoverageResult> {
    let QualityGateCoverage::Q06(coverage) = &plan.coverage else {
        unreachable!("shared fixture is Q06");
    };
    [
        (
            QualityCoverageItem::Q06LongHistoryMemory,
            &coverage.long_history_memory_corpus_ref,
        ),
        (
            QualityCoverageItem::Q06MultiSessionReasoning,
            &coverage.multi_session_reasoning_corpus_ref,
        ),
        (
            QualityCoverageItem::Q06Corrections,
            &coverage.correction_case_corpus_ref,
        ),
        (
            QualityCoverageItem::Q06Poisoning,
            &coverage.poisoning_case_corpus_ref,
        ),
        (
            QualityCoverageItem::Q06Lifecycle,
            &coverage.lifecycle_case_corpus_ref,
        ),
        (
            QualityCoverageItem::Q06AbstentionUnknown,
            &coverage.abstention_unknown_case_corpus_ref,
        ),
        (
            QualityCoverageItem::Q06ProtectedConstraint,
            &coverage.protected_constraint_evidence_ref,
        ),
    ]
    .into_iter()
    .map(|(item, requirement_ref)| QualityCoverageResult {
        item,
        requirement_ref: requirement_ref.clone(),
        evidence_refs: refs(&[&format!("coverage:{item:?}")]),
    })
    .collect()
}

fn result_for_trial_and_grade(
    fixture: &Fixture,
    trial_evidence_ref: Reference,
    grade_ref: Reference,
) -> QualityFloorResultSet {
    let criterion_results = fixture
        .plan
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
            grader_result_refs: BTreeSet::from([grade_ref.clone()]),
            environment_evidence_refs: fixture.environment.evidence_refs().clone(),
            provenance_refs: refs(&["provenance:floor-result"]),
            invalidation_dependency_refs: refs(&["dependency:floor-result"]),
        })
        .collect();

    let plan = &fixture.plan;
    let mut result = QualityFloorResultSet {
        result_set_ref: r("quality-result:q06:trial-bound"),
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
        profile_results: Vec::new(),
        coverage_results: coverage_results(plan),
        provenance_refs: refs(&["provenance:result-set"]),
        invalidation_dependency_refs: plan.invalidation_dependency_refs.clone(),
    };
    result.content_digest = compute_quality_floor_result_digest(&result).unwrap();
    result
}

fn evidence_bundle(
    fixture: &Fixture,
    grade: noerith_capabilities::VerifiedGradeRecord,
) -> QualityEvidenceBundle {
    QualityEvidenceBundle {
        corpus_evidence: vec![QualityCorpusEvidence {
            corpus: corpus(),
            verified: fixture.corpus.clone(),
        }],
        grade_records: vec![grade],
        execution_environments: vec![fixture.environment.clone()],
    }
}

#[test]
fn s05_trial_evidence_composition_requires_exact_content_bound_trial_set() {
    let fixture = fixture();
    let verified_trial_set = verify_fixture(&fixture).unwrap();
    let trial_ref = quality_trial_evidence_ref(&verified_trial_set);
    assert_eq!(
        trial_ref,
        verified_trial_set.verification_digest().value.clone(),
        "quality evidence must cite the exact verified trial composition, not only the raw declaration",
    );

    let result = result_for_trial_and_grade(
        &fixture,
        trial_ref.clone(),
        fixture.grade.grade_ref().clone(),
    );
    let bundle = evidence_bundle(&fixture, fixture.grade.clone());
    let verified = verify_quality_evidence_with_trials(
        &fixture.plan,
        &result,
        &bundle,
        core::slice::from_ref(&verified_trial_set),
    )
    .unwrap();

    assert_eq!(verified.trial_evidence_refs(), &BTreeSet::from([trial_ref]));
    assert_eq!(
        verified.scope().grade_refs(),
        &BTreeSet::from([fixture.grade.grade_ref().clone()])
    );
}

#[test]
fn s05_arbitrary_trial_reference_cannot_cross_the_quality_evidence_seam() {
    let fixture = fixture();
    let verified_trial_set = verify_fixture(&fixture).unwrap();
    let forged = r("sha256:forged-trial-population");
    let result =
        result_for_trial_and_grade(&fixture, forged.clone(), fixture.grade.grade_ref().clone());
    let bundle = evidence_bundle(&fixture, fixture.grade.clone());

    assert!(matches!(
        verify_quality_evidence_with_trials(
            &fixture.plan,
            &result,
            &bundle,
            core::slice::from_ref(&verified_trial_set),
        ),
        Err(QualityTrialEvidenceBindingError::MissingCitedTrialEvidence(reference))
            if reference == forged.to_string()
    ));
}

#[test]
fn s05_scope_grades_must_equal_the_exact_verified_trial_population() {
    let fixture = fixture();
    let verified_trial_set = verify_fixture(&fixture).unwrap();
    let alternate = verified_grade(
        &grader_plan(),
        &fixture.set.trials[0],
        "grade:alternate",
        fixture.set.trials[0].output_digest.clone(),
    );
    let result = result_for_trial_and_grade(
        &fixture,
        quality_trial_evidence_ref(&verified_trial_set),
        alternate.grade_ref().clone(),
    );
    let bundle = evidence_bundle(&fixture, alternate);

    assert_eq!(
        verify_quality_evidence_with_trials(
            &fixture.plan,
            &result,
            &bundle,
            core::slice::from_ref(&verified_trial_set),
        ),
        Err(QualityTrialEvidenceBindingError::TrialGradeSetMismatch)
    );
}

#[test]
fn s05_duplicate_verified_trial_evidence_is_rejected() {
    let fixture = fixture();
    let verified_trial_set = verify_fixture(&fixture).unwrap();
    let result = result_for_trial_and_grade(
        &fixture,
        quality_trial_evidence_ref(&verified_trial_set),
        fixture.grade.grade_ref().clone(),
    );
    let bundle = evidence_bundle(&fixture, fixture.grade.clone());

    assert!(matches!(
        verify_quality_evidence_with_trials(
            &fixture.plan,
            &result,
            &bundle,
            &[verified_trial_set.clone(), verified_trial_set],
        ),
        Err(QualityTrialEvidenceBindingError::DuplicateTrialEvidence(_))
    ));
}

#[test]
fn s05_same_grade_ref_with_different_verified_content_cannot_cross_trial_scope() {
    let fixture = fixture();
    let verified_trial_set = verify_fixture(&fixture).unwrap();
    let grader_plan = grader_plan();
    let alternate_grade = verified_grade_with_evidence(
        &grader_plan,
        &fixture.set.trials[0],
        "grade:trial-1",
        fixture.set.trials[0].output_digest.clone(),
        "grade:evidence:substituted-behind-stable-ref",
    );

    assert_eq!(alternate_grade.grade_ref(), fixture.grade.grade_ref());
    assert_ne!(
        alternate_grade.verification_digest(),
        fixture.grade.verification_digest(),
        "precondition: logical grade ref is stable while exact grade evidence changes",
    );

    let result = result_for_trial_and_grade(
        &fixture,
        quality_trial_evidence_ref(&verified_trial_set),
        fixture.grade.grade_ref().clone(),
    );
    let bundle = evidence_bundle(&fixture, alternate_grade);

    assert_eq!(
        verify_quality_evidence_with_trials(
            &fixture.plan,
            &result,
            &bundle,
            core::slice::from_ref(&verified_trial_set),
        ),
        Err(QualityTrialEvidenceBindingError::TrialGradeIdentityMismatch)
    );
}

#[test]
fn s05_same_corpus_ref_and_version_with_different_content_cannot_cross_trial_scope() {
    let fixture = fixture();
    let verified_trial_set = verify_fixture(&fixture).unwrap();
    let mut alternate_corpus = corpus();
    alternate_corpus.sampling_policy_ref = r("sampling:research:substituted");
    alternate_corpus.content_digest = compute_evaluation_corpus_digest(&alternate_corpus).unwrap();
    let alternate_verified = verify_evaluation_corpus(&alternate_corpus).unwrap();

    assert_eq!(alternate_corpus.corpus_ref, r("evaluation-corpus:research"));
    assert_eq!(alternate_corpus.corpus_version, v("corpus-v1"));
    assert_ne!(
        alternate_corpus.content_digest,
        corpus().content_digest,
        "precondition: exact corpus content changes behind the same logical identity",
    );

    let result = result_for_trial_and_grade(
        &fixture,
        quality_trial_evidence_ref(&verified_trial_set),
        fixture.grade.grade_ref().clone(),
    );
    let bundle = QualityEvidenceBundle {
        corpus_evidence: vec![QualityCorpusEvidence {
            corpus: alternate_corpus,
            verified: alternate_verified,
        }],
        grade_records: vec![fixture.grade.clone()],
        execution_environments: vec![fixture.environment.clone()],
    };

    assert_eq!(
        verify_quality_evidence_with_trials(
            &fixture.plan,
            &result,
            &bundle,
            core::slice::from_ref(&verified_trial_set),
        ),
        Err(QualityTrialEvidenceBindingError::TrialCorpusIdentityMismatch)
    );
}

#[test]
fn s05_same_environment_identity_with_different_qualification_cannot_cross_trial_scope() {
    let fixture = fixture();
    let verified_trial_set = verify_fixture(&fixture).unwrap();
    let (_, alternate_environment) =
        qualified_environment_with_test_run("run:environment:substituted");

    assert_eq!(
        alternate_environment.subject(),
        fixture.environment.subject(),
        "precondition: profile identity remains stable",
    );
    assert_eq!(
        alternate_environment.evidence_refs(),
        fixture.environment.evidence_refs(),
        "precondition: logical evidence aliases remain stable",
    );
    assert_ne!(
        alternate_environment.verification_digest(),
        fixture.environment.verification_digest(),
        "precondition: exact qualification evidence changes behind stable aliases",
    );

    let result = result_for_trial_and_grade(
        &fixture,
        quality_trial_evidence_ref(&verified_trial_set),
        fixture.grade.grade_ref().clone(),
    );
    let bundle = QualityEvidenceBundle {
        corpus_evidence: vec![QualityCorpusEvidence {
            corpus: corpus(),
            verified: fixture.corpus.clone(),
        }],
        grade_records: vec![fixture.grade.clone()],
        execution_environments: vec![alternate_environment],
    };

    assert_eq!(
        verify_quality_evidence_with_trials(
            &fixture.plan,
            &result,
            &bundle,
            core::slice::from_ref(&verified_trial_set),
        ),
        Err(QualityTrialEvidenceBindingError::TrialEnvironmentIdentityMismatch)
    );
}
