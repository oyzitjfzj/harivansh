use noerith_capabilities::{
    ContentDigest, EvidenceStatus, OpaqueVersion, QualityCriterionKind, QualityCriterionResult,
    QualityExperimentBinding, QualityFloorResultSet, QualityGateId, QualityProfileMetricRole,
    QualityProfileResult, QualityResultError, Reference, SHA256_ALGORITHM_REF,
    compute_quality_floor_result_digest,
};
use std::collections::BTreeSet;

fn r(value: &str) -> Reference {
    Reference::new(value).unwrap()
}

fn refs(values: &[&str]) -> BTreeSet<Reference> {
    values.iter().map(|value| r(value)).collect()
}

#[test]
fn hard_and_profile_results_cannot_reuse_one_evidence_identity() {
    let shared = r("result:shared");
    let result = QualityFloorResultSet {
        result_set_ref: r("result-set:q07"),
        result_set_version: OpaqueVersion::new("run-1").unwrap(),
        content_digest: ContentDigest {
            algorithm_ref: r(SHA256_ALGORITHM_REF),
            value: r("sha256:pending"),
        },
        plan_ref: r("plan:q07"),
        plan_version: OpaqueVersion::new("plan-1").unwrap(),
        plan_digest: ContentDigest {
            algorithm_ref: r(SHA256_ALGORITHM_REF),
            value: r("sha256:plan"),
        },
        gate: QualityGateId::Q07ModelsExperts,
        experiment: QualityExperimentBinding {
            evaluation_corpus_refs: refs(&["corpus:heldout"]),
            grader_plan_refs: refs(&["grader:plan"]),
            environment_qualification_plan_refs: refs(&["environment:plan"]),
            trial_protocol_ref: r("trial:protocol"),
            statistical_model_ref: r("statistics:model"),
            uncertainty_policy_ref: r("uncertainty:policy"),
            seed_manifest_ref: r("seeds:manifest"),
            hardware_manifest_ref: r("hardware:manifest"),
            confidence_target_ref: r("confidence:target"),
            analysis_plan_ref: r("analysis:plan"),
            preregistration_evidence_ref: r("preregistration:evidence"),
        },
        criterion_results: vec![QualityCriterionResult {
            result_ref: shared.clone(),
            criterion_ref: r("criterion:quality"),
            kind: QualityCriterionKind::Quality,
            status: EvidenceStatus::Pass,
            measurement_target_ref: r("target:quality"),
            threshold_policy_ref: r("threshold:quality"),
            satisfied_evidence_requirement_refs: refs(&["requirement:quality"]),
            analysis_result_ref: r("analysis-result:quality"),
            trial_evidence_refs: refs(&["trial:evidence"]),
            grader_result_refs: refs(&["grade:quality"]),
            environment_evidence_refs: refs(&["environment:evidence"]),
            provenance_refs: refs(&["provenance:quality"]),
            invalidation_dependency_refs: refs(&["invalidation:quality"]),
        }],
        profile_results: vec![QualityProfileResult {
            result_ref: shared.clone(),
            metric_ref: r("metric:cost"),
            role: QualityProfileMetricRole::Cost,
            measurement_target_ref: r("target:cost"),
            reporting_policy_ref: r("report:cost"),
            satisfied_evidence_requirement_refs: refs(&["requirement:cost"]),
            measured_result_ref: r("measured:cost"),
            evidence_refs: refs(&["evidence:cost"]),
            provenance_refs: refs(&["provenance:cost"]),
            invalidation_dependency_refs: refs(&["invalidation:cost"]),
        }],
        coverage_results: Vec::new(),
        provenance_refs: refs(&["provenance:result-set"]),
        invalidation_dependency_refs: refs(&["invalidation:result-set"]),
    };

    assert_eq!(
        compute_quality_floor_result_digest(&result),
        Err(QualityResultError::ResultRefCollision(shared.to_string()))
    );
}
