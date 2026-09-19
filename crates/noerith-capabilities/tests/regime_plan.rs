use noerith_capabilities::{
    ContentDigest, OpaqueVersion, QualificationPlanPopulationIdentity, Reference,
    RegimeCapabilityRequirement, RegimeEvaluationCorpus, RegimeGradingContract, RegimePipelinePlan,
    RegimePlanError, RegimeReliabilityProtocol, SHA256_ALGORITHM_REF, SixRegimeQualificationPlan,
    SpecialistRegime, compute_regime_pipeline_digest, compute_six_regime_qualification_plan_digest,
    validate_six_regime_qualification_plan,
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

fn placeholder(name: &str) -> ContentDigest {
    ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r(&format!("sha256:placeholder:{name}")),
    }
}

fn population_identity(suffix: &str) -> QualificationPlanPopulationIdentity {
    QualificationPlanPopulationIdentity {
        population_ref: r(&format!("qualification-population:{suffix}")),
        population_version: v("population-v1"),
        population_digest: placeholder(&format!("population:{suffix}")),
    }
}

fn pipeline(regime: SpecialistRegime, suffix: &str) -> RegimePipelinePlan {
    let mut pipeline = RegimePipelinePlan {
        regime,
        pipeline_ref: r(&format!("regime-pipeline:{suffix}")),
        pipeline_version: v("plan-2026-09"),
        content_digest: placeholder(suffix),
        source_contract_refs: refs(&["source:frozen-six-regime-contract"]),
        algorithm_policy_ref: r(&format!("algorithm-policy:{suffix}")),
        corpus: RegimeEvaluationCorpus {
            task_distribution_ref: r(&format!("distribution:{suffix}")),
            development_partition_ref: r(&format!("partition:{suffix}:development")),
            heldout_partition_ref: r(&format!("partition:{suffix}:heldout")),
            adversarial_partition_ref: r(&format!("partition:{suffix}:adversarial")),
            contamination_control_ref: r(&format!("contamination-control:{suffix}")),
            coverage_model_ref: r(&format!("coverage-model:{suffix}")),
            anti_gaming_review_ref: r(&format!("anti-gaming:{suffix}")),
        },
        grading: RegimeGradingContract {
            grader_refs: refs(&[&format!("grader:{suffix}:primary")]),
            grader_calibration_ref: r(&format!("grader-calibration:{suffix}")),
            grader_disagreement_policy_ref: r(&format!("grader-disagreement:{suffix}")),
            evidence_schema_refs: refs(&[&format!("evidence-schema:{suffix}")]),
        },
        reliability: RegimeReliabilityProtocol {
            trial_protocol_ref: r(&format!("trial-protocol:{suffix}")),
            statistical_model_ref: r(&format!("statistical-model:{suffix}")),
            uncertainty_reporting_ref: r(&format!("uncertainty-reporting:{suffix}")),
            regression_policy_ref: r(&format!("regression-policy:{suffix}")),
        },
        required_capabilities: vec![RegimeCapabilityRequirement {
            requirement_ref: r(&format!("capability-set:{suffix}")),
            required_operation_refs: refs(&[&format!("operation:{suffix}")]),
        }],
        required_integration_contract_refs: refs(&[&format!("integration-contract:{suffix}")]),
        quality_floor_refs: refs(&[&format!("quality-floor:{suffix}")]),
        completion_evidence_requirement_refs: refs(&[&format!("completion-evidence:{suffix}")]),
    };
    pipeline.content_digest = compute_regime_pipeline_digest(&pipeline).unwrap();
    pipeline
}

fn valid_plan() -> SixRegimeQualificationPlan {
    let mut plan = SixRegimeQualificationPlan {
        plan_ref: r("s05-six-regime-plan"),
        plan_version: v("2026-09-preregistered"),
        content_digest: placeholder("six-regime-plan"),
        source_contract_refs: refs(&["source:phase2-six-regimes", "source:master-s05-exit"]),
        q06_floor_ref: r("quality-floor:Q06"),
        q06_floor_version: v("q06-floor-v1"),
        q06_floor_digest: placeholder("q06-floor"),
        q07_floor_ref: r("quality-floor:Q07"),
        q07_floor_version: v("q07-floor-v1"),
        q07_floor_digest: placeholder("q07-floor"),
        sandbox_qualification_population: population_identity("sandbox-integrations"),
        evidence_grader_qualification_population: population_identity("evidence-graders"),
        pipelines: vec![
            pipeline(
                SpecialistRegime::ConversationPersonalAssistant,
                "conversation-personal-assistant",
            ),
            pipeline(
                SpecialistRegime::ResearchDeepResearch,
                "research-deep-research",
            ),
            pipeline(
                SpecialistRegime::SoftwareEngineering,
                "software-engineering",
            ),
            pipeline(SpecialistRegime::ActionAutomation, "action-automation"),
            pipeline(SpecialistRegime::CreationArtifact, "creation-artifact"),
            pipeline(
                SpecialistRegime::MonitoringLongRunningWork,
                "monitoring-long-running-work",
            ),
        ],
    };
    plan.content_digest = compute_six_regime_qualification_plan_digest(&plan).unwrap();
    plan
}

#[test]
fn s05_six_regime_plan_requires_exact_frozen_regime_coverage() {
    let plan = valid_plan();
    assert!(validate_six_regime_qualification_plan(&plan).is_ok());

    let mut missing = plan.clone();
    missing
        .pipelines
        .retain(|pipeline| pipeline.regime != SpecialistRegime::MonitoringLongRunningWork);
    assert_eq!(
        validate_six_regime_qualification_plan(&missing),
        Err(RegimePlanError::MissingRegime(
            SpecialistRegime::MonitoringLongRunningWork
        ))
    );

    let mut duplicate = plan;
    duplicate.pipelines[5].regime = SpecialistRegime::SoftwareEngineering;
    assert_eq!(
        validate_six_regime_qualification_plan(&duplicate),
        Err(RegimePlanError::DuplicateRegime(
            SpecialistRegime::SoftwareEngineering
        ))
    );
}

#[test]
fn s05_regime_plan_rejects_partition_leakage() {
    let mut plan = valid_plan();
    plan.pipelines[1].corpus.heldout_partition_ref =
        plan.pipelines[1].corpus.development_partition_ref.clone();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::PartitionIdentityCollision(
            SpecialistRegime::ResearchDeepResearch
        ))
    );

    let mut plan = valid_plan();
    plan.pipelines[2].corpus.adversarial_partition_ref =
        plan.pipelines[2].corpus.heldout_partition_ref.clone();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::PartitionIdentityCollision(
            SpecialistRegime::SoftwareEngineering
        ))
    );
}

#[test]
fn s05_regime_plan_rejects_duplicate_pipeline_identity() {
    let mut plan = valid_plan();
    plan.pipelines[5].pipeline_ref = plan.pipelines[0].pipeline_ref.clone();
    let expected = plan.pipelines[0].pipeline_ref.to_string();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::DuplicatePipeline(expected))
    );
}

#[test]
fn s05_each_regime_must_predeclare_measurement_and_execution_obligations() {
    let regime = SpecialistRegime::CreationArtifact;

    let mut plan = valid_plan();
    let target = plan
        .pipelines
        .iter_mut()
        .find(|pipeline| pipeline.regime == regime)
        .unwrap();
    target.grading.grader_refs.clear();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::MissingGraders(regime))
    );

    let mut plan = valid_plan();
    let target = plan
        .pipelines
        .iter_mut()
        .find(|pipeline| pipeline.regime == regime)
        .unwrap();
    target.grading.evidence_schema_refs.clear();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::MissingGraderEvidenceSchemas(regime))
    );

    let mut plan = valid_plan();
    let target = plan
        .pipelines
        .iter_mut()
        .find(|pipeline| pipeline.regime == regime)
        .unwrap();
    target.required_capabilities.clear();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::MissingCapabilities(regime))
    );

    let mut plan = valid_plan();
    let target = plan
        .pipelines
        .iter_mut()
        .find(|pipeline| pipeline.regime == regime)
        .unwrap();
    target.required_integration_contract_refs.clear();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::MissingIntegrationContracts(regime))
    );

    let mut plan = valid_plan();
    let target = plan
        .pipelines
        .iter_mut()
        .find(|pipeline| pipeline.regime == regime)
        .unwrap();
    target.quality_floor_refs.clear();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::MissingQualityFloors(regime))
    );

    let mut plan = valid_plan();
    let target = plan
        .pipelines
        .iter_mut()
        .find(|pipeline| pipeline.regime == regime)
        .unwrap();
    target.completion_evidence_requirement_refs.clear();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::MissingCompletionEvidenceRequirements(
            regime
        ))
    );
}

#[test]
fn s05_capability_requirements_must_have_unique_identity_and_operations() {
    let regime = SpecialistRegime::SoftwareEngineering;
    let mut plan = valid_plan();
    let target = plan
        .pipelines
        .iter_mut()
        .find(|pipeline| pipeline.regime == regime)
        .unwrap();
    target.required_capabilities[0]
        .required_operation_refs
        .clear();
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::EmptyCapabilityRequirementOperations(
            "capability-set:software-engineering".into()
        ))
    );

    let mut plan = valid_plan();
    let target = plan
        .pipelines
        .iter_mut()
        .find(|pipeline| pipeline.regime == regime)
        .unwrap();
    target
        .required_capabilities
        .push(target.required_capabilities[0].clone());
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::DuplicateCapabilityRequirement(
            "capability-set:software-engineering".into()
        ))
    );
}

#[test]
fn s05_capability_requirement_order_is_not_semantic_but_content_is() {
    let mut plan = valid_plan();
    {
        let target = plan
            .pipelines
            .iter_mut()
            .find(|pipeline| pipeline.regime == SpecialistRegime::SoftwareEngineering)
            .unwrap();
        target
            .required_capabilities
            .push(RegimeCapabilityRequirement {
                requirement_ref: r("capability-set:software-engineering:secondary"),
                required_operation_refs: refs(&["operation:software-engineering:secondary"]),
            });
        target.content_digest = compute_regime_pipeline_digest(target).unwrap();
    }
    plan.content_digest = compute_six_regime_qualification_plan_digest(&plan).unwrap();
    let expected = plan.content_digest.clone();

    {
        let target = plan
            .pipelines
            .iter_mut()
            .find(|pipeline| pipeline.regime == SpecialistRegime::SoftwareEngineering)
            .unwrap();
        target.required_capabilities.reverse();
        assert_eq!(
            compute_regime_pipeline_digest(target).unwrap(),
            target.content_digest
        );
    }
    assert_eq!(
        compute_six_regime_qualification_plan_digest(&plan).unwrap(),
        expected
    );

    {
        let target = plan
            .pipelines
            .iter_mut()
            .find(|pipeline| pipeline.regime == SpecialistRegime::SoftwareEngineering)
            .unwrap();
        target.required_capabilities[0]
            .required_operation_refs
            .insert(r("operation:post-registration-added"));
    }
    assert!(matches!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::PipelineDigestMismatch(
            SpecialistRegime::SoftwareEngineering
        ))
    ));
}

#[test]
fn s05_pipeline_mutation_under_old_digest_fails_closed() {
    let mut plan = valid_plan();
    let target = plan
        .pipelines
        .iter_mut()
        .find(|pipeline| pipeline.regime == SpecialistRegime::ResearchDeepResearch)
        .unwrap();
    target.corpus.task_distribution_ref = r("distribution:research-mutated-after-preregistration");

    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::PipelineDigestMismatch(
            SpecialistRegime::ResearchDeepResearch
        ))
    );
}

#[test]
fn s05_global_plan_mutation_under_old_digest_fails_closed() {
    let mut plan = valid_plan();
    plan.q07_floor_ref = r("quality-floor:Q07-mutated-after-preregistration");
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::PlanDigestMismatch)
    );
}

#[test]
fn s05_external_dependency_version_or_digest_substitution_changes_preregistration_identity() {
    let plan = valid_plan();

    let mut changed_floor = plan.clone();
    changed_floor.q07_floor_version = v("q07-floor-post-hoc-v2");
    assert_eq!(
        validate_six_regime_qualification_plan(&changed_floor),
        Err(RegimePlanError::PlanDigestMismatch)
    );

    let mut changed_sandbox = plan.clone();
    changed_sandbox
        .sandbox_qualification_population
        .population_digest = placeholder("different-sandbox-population");
    assert_eq!(
        validate_six_regime_qualification_plan(&changed_sandbox),
        Err(RegimePlanError::PlanDigestMismatch)
    );

    let mut changed_grader = plan;
    changed_grader
        .evidence_grader_qualification_population
        .population_version = v("grader-population-post-hoc-v2");
    assert_eq!(
        validate_six_regime_qualification_plan(&changed_grader),
        Err(RegimePlanError::PlanDigestMismatch)
    );
}

#[test]
fn s05_pipeline_order_does_not_change_preregistered_semantic_identity() {
    let plan = valid_plan();
    let expected = plan.content_digest.clone();
    let mut reordered = plan.clone();
    reordered.pipelines.reverse();

    assert_eq!(
        compute_six_regime_qualification_plan_digest(&reordered).unwrap(),
        expected
    );
    assert!(validate_six_regime_qualification_plan(&reordered).is_ok());
}

#[test]
fn s05_unknown_digest_algorithm_cannot_claim_preregistration_integrity() {
    let mut plan = valid_plan();
    plan.pipelines[0].content_digest.algorithm_ref = r("urn:digest:unknown");
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::UnsupportedDigestAlgorithm(
            "urn:digest:unknown".into()
        ))
    );

    let mut plan = valid_plan();
    plan.q06_floor_digest.algorithm_ref = r("urn:digest:unknown");
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::UnsupportedDigestAlgorithm(
            "urn:digest:unknown".into()
        ))
    );

    let mut plan = valid_plan();
    plan.sandbox_qualification_population
        .population_digest
        .algorithm_ref = r("urn:digest:unknown");
    assert_eq!(
        validate_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::UnsupportedDigestAlgorithm(
            "urn:digest:unknown".into()
        ))
    );
}

#[test]
fn s05_validating_a_content_bound_plan_does_not_create_a_verified_capability() {
    let plan = valid_plan();
    validate_six_regime_qualification_plan(&plan).unwrap();

    // This is preregistration integrity only: no provider/model result,
    // availability state, credential, external-effect authority or regime-pass
    // wrapper is created by this module.
    assert_eq!(plan.pipelines.len(), SpecialistRegime::ALL.len());
    assert!(
        plan.pipelines
            .iter()
            .all(|pipeline| !pipeline.quality_floor_refs.is_empty())
    );
}
