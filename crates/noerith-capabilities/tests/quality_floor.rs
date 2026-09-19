use noerith_capabilities::{
    ContentDigest, OpaqueVersion, Q06CoverageContract, Q07ComparisonAxis, Q07CoverageContract,
    QualityCriterionKind, QualityFloorCriterion, QualityFloorError, QualityFloorPlan,
    QualityGateCoverage, QualityGateId, QualityProfileMetric, QualityProfileMetricRole, Reference,
    SHA256_ALGORITHM_REF, SpecialistRegime, compute_quality_floor_plan_digest,
    verify_quality_floor_plan,
};
use std::collections::{BTreeMap, BTreeSet};

fn r(value: &str) -> Reference {
    Reference::new(value).unwrap()
}

fn refs(values: &[&str]) -> BTreeSet<Reference> {
    values.iter().map(|value| r(value)).collect()
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

fn metric(role: QualityProfileMetricRole, name: &str) -> QualityProfileMetric {
    QualityProfileMetric {
        role,
        metric_ref: r(name),
        measurement_target_ref: r(&format!("target:{name}")),
        reporting_policy_ref: r(&format!("report:{name}")),
        evidence_requirement_refs: refs(&[&format!("evidence:{name}")]),
    }
}

fn placeholder_digest() -> ContentDigest {
    ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r("sha256:pending"),
    }
}

fn common_plan(gate: QualityGateId, coverage: QualityGateCoverage) -> QualityFloorPlan {
    QualityFloorPlan {
        plan_ref: r(match gate {
            QualityGateId::Q06MemoryContext => "quality-floor:q06",
            QualityGateId::Q07ModelsExperts => "quality-floor:q07",
        }),
        plan_version: OpaqueVersion::new("2026-09-locked").unwrap(),
        content_digest: placeholder_digest(),
        gate,
        source_contract_refs: refs(&["source:master-blueprint", "source:build-decisions"]),
        floor_criteria: Vec::new(),
        profile_metrics: Vec::new(),
        coverage,
        evaluation_corpus_refs: refs(&["corpus:heldout"]),
        grader_plan_refs: refs(&["grader:qualified-plan"]),
        environment_qualification_plan_refs: refs(&["environment:qualified-plan"]),
        trial_protocol_ref: r("trial:preregistered"),
        statistical_model_ref: r("statistics:preregistered"),
        uncertainty_policy_ref: r("uncertainty:preregistered"),
        seed_manifest_ref: r("seeds:preregistered"),
        hardware_manifest_ref: r("hardware:preregistered"),
        confidence_target_ref: r("confidence:preregistered"),
        analysis_plan_ref: r("analysis:preregistered"),
        preregistration_evidence_ref: r("preregistration:evidence"),
        invalidation_dependency_refs: refs(&[
            "dependency:corpus-version",
            "dependency:grader-version",
            "dependency:environment-version",
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
        abstention_unknown_case_corpus_ref: r("q06:abstention-unknown"),
        protected_constraint_evidence_ref: r("q06:protected-constraint-evidence"),
    });
    let mut plan = common_plan(QualityGateId::Q06MemoryContext, coverage);
    plan.floor_criteria = vec![
        criterion(QualityCriterionKind::Recall, "q06:recall"),
        criterion(QualityCriterionKind::Fidelity, "q06:fidelity"),
        criterion(QualityCriterionKind::Privacy, "q06:privacy"),
        criterion(
            QualityCriterionKind::NoSilentLostConstraint,
            "q06:no-silent-lost-constraint",
        ),
    ];
    plan.content_digest = compute_quality_floor_plan_digest(&plan).unwrap();
    plan
}

fn q07_coverage() -> Q07CoverageContract {
    let heldout_regime_corpus_refs = SpecialistRegime::ALL
        .into_iter()
        .map(|regime| (regime, r(&format!("q07:heldout:{regime:?}"))))
        .collect();
    let comparison_axis_refs = Q07ComparisonAxis::ALL
        .into_iter()
        .map(|axis| (axis, r(&format!("q07:axis:{axis:?}"))))
        .collect();
    Q07CoverageContract {
        heldout_regime_corpus_refs,
        comparison_axis_refs,
        repeated_trial_protocol_ref: r("q07:repeated-trial-protocol"),
        candidate_configuration_manifest_ref: r("q07:candidate-configurations"),
    }
}

fn q07_plan() -> QualityFloorPlan {
    let mut plan = common_plan(
        QualityGateId::Q07ModelsExperts,
        QualityGateCoverage::Q07(q07_coverage()),
    );
    plan.floor_criteria = vec![
        criterion(QualityCriterionKind::Quality, "q07:quality"),
        criterion(QualityCriterionKind::Privacy, "q07:privacy"),
    ];
    plan.profile_metrics = vec![metric(QualityProfileMetricRole::Cost, "q07:cost")];
    plan.content_digest = compute_quality_floor_plan_digest(&plan).unwrap();
    plan
}

#[test]
fn q06_plan_requires_all_non_compensable_memory_context_floors() {
    let plan = q06_plan();
    let verified = verify_quality_floor_plan(&plan).unwrap();
    assert_eq!(verified.gate(), QualityGateId::Q06MemoryContext);
    assert_eq!(verified.hard_criterion_refs().len(), 4);

    for missing in [
        QualityCriterionKind::Recall,
        QualityCriterionKind::Fidelity,
        QualityCriterionKind::Privacy,
        QualityCriterionKind::NoSilentLostConstraint,
    ] {
        let mut broken = q06_plan();
        broken.floor_criteria.retain(|item| item.kind != missing);
        broken.content_digest = placeholder_digest();
        assert_eq!(
            compute_quality_floor_plan_digest(&broken),
            Err(QualityFloorError::MissingQ06Criterion(missing))
        );
    }
}

#[test]
fn q07_cost_is_profile_only_and_cannot_replace_quality_or_privacy() {
    let plan = q07_plan();
    let verified = verify_quality_floor_plan(&plan).unwrap();
    assert_eq!(verified.gate(), QualityGateId::Q07ModelsExperts);
    assert_eq!(verified.hard_criterion_refs().len(), 2);
    assert_eq!(verified.profile_metric_refs().len(), 1);

    let mut no_cost = q07_plan();
    no_cost.profile_metrics.clear();
    no_cost.content_digest = placeholder_digest();
    assert_eq!(
        compute_quality_floor_plan_digest(&no_cost),
        Err(QualityFloorError::MissingQ07CostProfile)
    );

    let mut no_quality = q07_plan();
    no_quality
        .floor_criteria
        .retain(|item| item.kind != QualityCriterionKind::Quality);
    no_quality.content_digest = placeholder_digest();
    assert_eq!(
        compute_quality_floor_plan_digest(&no_quality),
        Err(QualityFloorError::MissingQ07Criterion(
            QualityCriterionKind::Quality
        ))
    );
}

#[test]
fn q07_requires_all_six_regimes_and_all_declared_comparison_axes() {
    let mut missing_regime = q07_plan();
    let QualityGateCoverage::Q07(coverage) = &mut missing_regime.coverage else {
        unreachable!();
    };
    coverage
        .heldout_regime_corpus_refs
        .remove(&SpecialistRegime::SoftwareEngineering);
    missing_regime.content_digest = placeholder_digest();
    assert_eq!(
        compute_quality_floor_plan_digest(&missing_regime),
        Err(QualityFloorError::UnexpectedQ07RegimeCount)
    );

    let mut missing_axis = q07_plan();
    let QualityGateCoverage::Q07(coverage) = &mut missing_axis.coverage else {
        unreachable!();
    };
    coverage
        .comparison_axis_refs
        .remove(&Q07ComparisonAxis::RetrievalStrategy);
    missing_axis.content_digest = placeholder_digest();
    assert_eq!(
        compute_quality_floor_plan_digest(&missing_axis),
        Err(QualityFloorError::MissingQ07ComparisonAxis(
            Q07ComparisonAxis::RetrievalStrategy
        ))
    );
}

#[test]
fn gate_cannot_be_relabelled_onto_the_other_coverage_contract() {
    let mut plan = q06_plan();
    plan.gate = QualityGateId::Q07ModelsExperts;
    plan.content_digest = placeholder_digest();
    assert_eq!(
        compute_quality_floor_plan_digest(&plan),
        Err(QualityFloorError::WrongCoverageForGate)
    );
}

#[test]
fn preregistered_plan_digest_detects_post_result_mutation() {
    let mut plan = q07_plan();
    assert!(verify_quality_floor_plan(&plan).is_ok());
    plan.analysis_plan_ref = r("analysis:changed-after-results");
    assert_eq!(
        verify_quality_floor_plan(&plan),
        Err(QualityFloorError::DigestMismatch)
    );
}

#[test]
fn criterion_cannot_be_duplicated_or_reclassified_as_profile_metric() {
    let mut duplicate = q06_plan();
    duplicate
        .floor_criteria
        .push(duplicate.floor_criteria[0].clone());
    duplicate.content_digest = placeholder_digest();
    assert!(matches!(
        compute_quality_floor_plan_digest(&duplicate),
        Err(QualityFloorError::DuplicateCriterion(_))
    ));

    let mut collision = q07_plan();
    collision.profile_metrics.push(QualityProfileMetric {
        role: QualityProfileMetricRole::Other,
        metric_ref: r("q07:quality"),
        measurement_target_ref: r("target:q07:quality-profile-copy"),
        reporting_policy_ref: r("report:q07:quality-profile-copy"),
        evidence_requirement_refs: refs(&["evidence:q07:quality-profile-copy"]),
    });
    collision.content_digest = placeholder_digest();
    assert!(matches!(
        compute_quality_floor_plan_digest(&collision),
        Err(QualityFloorError::CriterionProfileCollision(_))
    ));
}

#[test]
fn canonical_digest_is_order_independent_for_sets_maps_and_criterion_vectors() {
    let first = q07_plan();
    let mut second = q07_plan();
    second.floor_criteria.reverse();
    second.profile_metrics.reverse();

    let QualityGateCoverage::Q07(coverage) = &second.coverage else {
        unreachable!();
    };
    let rebuilt_regimes: BTreeMap<_, _> = coverage
        .heldout_regime_corpus_refs
        .iter()
        .rev()
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    let rebuilt_axes: BTreeMap<_, _> = coverage
        .comparison_axis_refs
        .iter()
        .rev()
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    if let QualityGateCoverage::Q07(coverage) = &mut second.coverage {
        coverage.heldout_regime_corpus_refs = rebuilt_regimes;
        coverage.comparison_axis_refs = rebuilt_axes;
    }

    assert_eq!(
        compute_quality_floor_plan_digest(&first).unwrap(),
        compute_quality_floor_plan_digest(&second).unwrap()
    );
}
