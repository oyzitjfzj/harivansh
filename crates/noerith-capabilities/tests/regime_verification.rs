include!("regime_plan.rs");

use noerith_capabilities::verify_six_regime_qualification_plan;

#[test]
fn s05_verified_plan_owns_all_six_exact_pipeline_and_external_identities() {
    let plan = valid_plan();
    let verified = verify_six_regime_qualification_plan(&plan).unwrap();

    assert_eq!(verified.plan_ref(), &plan.plan_ref);
    assert_eq!(verified.plan_version(), &plan.plan_version);
    assert_eq!(verified.content_digest(), &plan.content_digest);
    assert_eq!(verified.q06_floor_ref(), &plan.q06_floor_ref);
    assert_eq!(verified.q06_floor_version(), &plan.q06_floor_version);
    assert_eq!(verified.q06_floor_digest(), &plan.q06_floor_digest);
    assert_eq!(verified.q07_floor_ref(), &plan.q07_floor_ref);
    assert_eq!(verified.q07_floor_version(), &plan.q07_floor_version);
    assert_eq!(verified.q07_floor_digest(), &plan.q07_floor_digest);
    assert_eq!(
        verified.sandbox_qualification_population(),
        &plan.sandbox_qualification_population
    );
    assert_eq!(
        verified.evidence_grader_qualification_population(),
        &plan.evidence_grader_qualification_population
    );
    assert_eq!(verified.pipelines().count(), SpecialistRegime::ALL.len());

    for source in &plan.pipelines {
        let pipeline = verified.pipeline(source.regime).unwrap();
        assert_eq!(pipeline.regime(), source.regime);
        assert_eq!(pipeline.pipeline_ref(), &source.pipeline_ref);
        assert_eq!(pipeline.pipeline_version(), &source.pipeline_version);
        assert_eq!(pipeline.content_digest(), &source.content_digest);
    }
}

#[test]
fn s05_mutated_current_plan_cannot_produce_verified_owner_wrapper() {
    let mut plan = valid_plan();
    plan.pipelines[0].algorithm_policy_ref = r("algorithm-policy:mutated-after-registration");

    assert!(matches!(
        verify_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::PipelineDigestMismatch(_))
    ));
}

#[test]
fn s05_external_identity_substitution_cannot_reuse_verified_owner_wrapper() {
    let mut plan = valid_plan();
    plan.q06_floor_version = v("q06-floor-post-registration-v2");

    assert_eq!(
        verify_six_regime_qualification_plan(&plan),
        Err(RegimePlanError::PlanDigestMismatch)
    );
}

#[test]
fn s05_pipeline_order_does_not_change_verified_owner_identity() {
    let first_plan = valid_plan();
    let first = verify_six_regime_qualification_plan(&first_plan).unwrap();

    let mut second_plan = first_plan.clone();
    second_plan.pipelines.reverse();
    let second = verify_six_regime_qualification_plan(&second_plan).unwrap();

    assert_eq!(first, second);
}
