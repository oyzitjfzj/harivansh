mod environment_fixture {
    include!("execution_environment.rs");

    pub fn plan_named(suffix: &str) -> ExecutionEnvironmentQualificationPlan {
        let subject = profile();
        let mut qualification = plan(&subject);
        qualification.identity.plan_ref = r(&format!("qualification-plan:environment:{suffix}"));
        qualification.identity.plan_version = v(&format!("plan:{suffix}"));
        qualification.identity.plan_digest =
            compute_execution_environment_plan_digest(&qualification).unwrap();
        qualification
    }
}

mod grader_fixture {
    include!("grader.rs");

    pub fn plan_named(suffix: &str) -> EvidenceGraderPlan {
        let mut qualification = plan();
        qualification.identity.plan_ref = r(&format!("grader-plan:{suffix}"));
        qualification.identity.plan_version = v(&format!("grader-plan-version:{suffix}"));
        qualification.identity.plan_digest =
            compute_evidence_grader_plan_digest(&qualification).unwrap();
        qualification
    }
}

use noerith_capabilities::{
    ContentDigest, OpaqueVersion, QualificationPlanMemberIdentity, QualificationPlanPopulation,
    QualificationPlanPopulationError, QualificationPlanPopulationIdentity,
    QualificationPlanPopulationPurpose, Reference, SHA256_ALGORITHM_REF,
    compute_qualification_plan_population_digest, verify_evidence_grader_qualification_population,
    verify_execution_environment_qualification_population,
};
use std::collections::BTreeSet;

fn r(value: &str) -> Reference {
    Reference::new(value).unwrap()
}

fn v(value: &str) -> OpaqueVersion {
    OpaqueVersion::new(value).unwrap()
}

fn refs(values: &[&str]) -> BTreeSet<Reference> {
    values.iter().map(|value| r(value)).collect()
}

fn pending_digest() -> ContentDigest {
    ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r("sha256:pending-population"),
    }
}

fn environment_member(
    plan: &noerith_capabilities::ExecutionEnvironmentQualificationPlan,
) -> QualificationPlanMemberIdentity {
    QualificationPlanMemberIdentity {
        plan_ref: plan.identity.plan_ref.clone(),
        plan_version: plan.identity.plan_version.clone(),
        plan_digest: plan.identity.plan_digest.clone(),
    }
}

fn grader_member(
    plan: &noerith_capabilities::EvidenceGraderPlan,
) -> QualificationPlanMemberIdentity {
    QualificationPlanMemberIdentity {
        plan_ref: plan.identity.plan_ref.clone(),
        plan_version: plan.identity.plan_version.clone(),
        plan_digest: plan.identity.plan_digest.clone(),
    }
}

fn population(
    purpose: QualificationPlanPopulationPurpose,
    suffix: &str,
    members: Vec<QualificationPlanMemberIdentity>,
) -> QualificationPlanPopulation {
    let mut population = QualificationPlanPopulation {
        identity: QualificationPlanPopulationIdentity {
            population_ref: r(&format!("qualification-population:{suffix}")),
            population_version: v("population-v1"),
            population_digest: pending_digest(),
        },
        purpose,
        source_contract_refs: refs(&["source:s05-preregistered-plan-population"]),
        member_plan_identities: members,
        invalidation_dependency_refs: refs(&[
            "dependency:member-plan-content",
            "dependency:population-policy",
        ]),
    };
    population.identity.population_digest =
        compute_qualification_plan_population_digest(&population).unwrap();
    population
}

#[test]
fn s05_environment_population_requires_exact_current_member_set() {
    let first = environment_fixture::plan_named("a");
    let second = environment_fixture::plan_named("b");
    let population = population(
        QualificationPlanPopulationPurpose::ExecutionEnvironment,
        "sandbox",
        vec![environment_member(&first), environment_member(&second)],
    );

    let verified = verify_execution_environment_qualification_population(
        &population,
        &[first.clone(), second.clone()],
    )
    .unwrap();
    assert_eq!(verified.identity(), &population.identity);
    assert_eq!(verified.member_count(), 2);
    assert!(verified.contains_exact(
        &first.identity.plan_ref,
        &first.identity.plan_version,
        &first.identity.plan_digest,
    ));

    assert_eq!(
        verify_execution_environment_qualification_population(
            &population,
            std::slice::from_ref(&first)
        ),
        Err(QualificationPlanPopulationError::MemberSetMismatch)
    );

    let extra = environment_fixture::plan_named("extra");
    assert_eq!(
        verify_execution_environment_qualification_population(&population, &[first, second, extra],),
        Err(QualificationPlanPopulationError::MemberSetMismatch)
    );
}

#[test]
fn s05_member_raw_plan_mutation_cannot_ride_old_registered_digest() {
    let original = environment_fixture::plan_named("a");
    let population = population(
        QualificationPlanPopulationPurpose::ExecutionEnvironment,
        "sandbox",
        vec![environment_member(&original)],
    );

    let mut mutated = original;
    mutated
        .workload_scope_refs
        .insert(r("workload:post-registration-added"));

    assert!(matches!(
        verify_execution_environment_qualification_population(&population, &[mutated]),
        Err(QualificationPlanPopulationError::ExecutionEnvironmentPlanInvalid(_))
    ));
}

#[test]
fn s05_population_identity_is_order_independent_but_purpose_bound() {
    let first = environment_fixture::plan_named("a");
    let second = environment_fixture::plan_named("b");
    let population = population(
        QualificationPlanPopulationPurpose::ExecutionEnvironment,
        "sandbox",
        vec![environment_member(&first), environment_member(&second)],
    );

    let expected = population.identity.population_digest.clone();
    let mut reordered = population.clone();
    reordered.member_plan_identities.reverse();
    assert_eq!(
        compute_qualification_plan_population_digest(&reordered).unwrap(),
        expected
    );

    let mut wrong_purpose = population;
    wrong_purpose.purpose = QualificationPlanPopulationPurpose::EvidenceGrader;
    assert_ne!(
        compute_qualification_plan_population_digest(&wrong_purpose).unwrap(),
        expected
    );
    assert_eq!(
        verify_execution_environment_qualification_population(&wrong_purpose, &[first, second],),
        Err(QualificationPlanPopulationError::PurposeMismatch)
    );
}

#[test]
fn s05_population_rejects_duplicate_and_ref_version_digest_collision() {
    let plan = environment_fixture::plan_named("a");
    let member = environment_member(&plan);

    let duplicate = QualificationPlanPopulation {
        identity: QualificationPlanPopulationIdentity {
            population_ref: r("qualification-population:duplicate"),
            population_version: v("v1"),
            population_digest: pending_digest(),
        },
        purpose: QualificationPlanPopulationPurpose::ExecutionEnvironment,
        source_contract_refs: refs(&["source:s05"]),
        member_plan_identities: vec![member.clone(), member.clone()],
        invalidation_dependency_refs: refs(&["dependency:member"]),
    };
    assert!(matches!(
        compute_qualification_plan_population_digest(&duplicate),
        Err(QualificationPlanPopulationError::DuplicateMember(_))
    ));

    let mut conflicting = member.clone();
    conflicting.plan_digest = ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r("sha256:different-content-same-ref-version"),
    };
    let collision = QualificationPlanPopulation {
        identity: QualificationPlanPopulationIdentity {
            population_ref: r("qualification-population:collision"),
            population_version: v("v1"),
            population_digest: pending_digest(),
        },
        purpose: QualificationPlanPopulationPurpose::ExecutionEnvironment,
        source_contract_refs: refs(&["source:s05"]),
        member_plan_identities: vec![member, conflicting],
        invalidation_dependency_refs: refs(&["dependency:member"]),
    };
    assert!(matches!(
        compute_qualification_plan_population_digest(&collision),
        Err(QualificationPlanPopulationError::MemberIdentityCollision { .. })
    ));
}

#[test]
fn s05_population_detects_post_digest_mutation_and_unknown_digest_algorithm() {
    let plan = environment_fixture::plan_named("a");
    let mut registered = population(
        QualificationPlanPopulationPurpose::ExecutionEnvironment,
        "sandbox",
        vec![environment_member(&plan)],
    );
    registered
        .invalidation_dependency_refs
        .insert(r("dependency:added-after-digest"));
    assert_eq!(
        verify_execution_environment_qualification_population(
            &registered,
            std::slice::from_ref(&plan)
        ),
        Err(QualificationPlanPopulationError::PopulationDigestMismatch)
    );

    let mut unsupported = population(
        QualificationPlanPopulationPurpose::ExecutionEnvironment,
        "unsupported",
        vec![environment_member(&plan)],
    );
    unsupported.member_plan_identities[0]
        .plan_digest
        .algorithm_ref = r("digest:unknown");
    assert_eq!(
        compute_qualification_plan_population_digest(&unsupported),
        Err(QualificationPlanPopulationError::UnsupportedDigestAlgorithm("digest:unknown".into()))
    );
}

#[test]
fn s05_grader_population_revalidates_with_grader_owner_algorithm() {
    let first = grader_fixture::plan_named("a");
    let second = grader_fixture::plan_named("b");
    let population = population(
        QualificationPlanPopulationPurpose::EvidenceGrader,
        "graders",
        vec![grader_member(&first), grader_member(&second)],
    );

    let verified = verify_evidence_grader_qualification_population(
        &population,
        &[second.clone(), first.clone()],
    )
    .unwrap();
    assert_eq!(verified.member_count(), 2);
    assert!(verified.contains_exact(
        &second.identity.plan_ref,
        &second.identity.plan_version,
        &second.identity.plan_digest,
    ));

    let mut stale = first;
    stale.rubric_version = v("rubric-post-registration");
    assert!(matches!(
        verify_evidence_grader_qualification_population(&population, &[stale, second]),
        Err(QualificationPlanPopulationError::EvidenceGraderPlanInvalid(
            _
        ))
    ));
}
