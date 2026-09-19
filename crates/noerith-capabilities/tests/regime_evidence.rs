mod regime_fixture {
    include!("regime_plan.rs");

    pub fn plan() -> SixRegimeQualificationPlan {
        valid_plan()
    }
}

mod environment_fixture {
    include!("execution_environment.rs");

    pub fn qualified_with_plan(
        qualification_plan_ref: &str,
        environment_suffix: &str,
    ) -> (
        noerith_capabilities::ExecutionEnvironmentQualificationPlan,
        noerith_capabilities::VerifiedExecutionEnvironment,
    ) {
        let mut subject = profile();
        subject.environment_ref = r(&format!("environment:regime-evidence:{environment_suffix}"));
        subject.environment_version = v(&format!("env-version:{environment_suffix}"));
        subject.content_digest = compute_execution_environment_profile_digest(&subject).unwrap();
        let verified = verify_execution_environment_profile_integrity(&subject).unwrap();
        let mut qualification = plan(&subject);
        qualification.identity.plan_ref = r(qualification_plan_ref);
        qualification.identity.plan_digest =
            compute_execution_environment_plan_digest(&qualification).unwrap();
        let records = evidence(&qualification);
        let environment =
            qualify_execution_environment(&subject, &verified, &qualification, &records).unwrap();
        (qualification, environment)
    }
}

use noerith_capabilities::{
    ContentDigest, EvidenceStatus, OpaqueVersion, QualificationPlanMemberIdentity,
    QualificationPlanPopulation, QualificationPlanPopulationIdentity,
    QualificationPlanPopulationPurpose, Reference, RegimeEvidenceError, RegimeEvidenceKind,
    RegimeExecutionEvidenceBundle, RegimeObservedEvidenceRecord, SHA256_ALGORITHM_REF,
    SpecialistRegime, VerifiedQualificationPlanPopulation,
    compute_qualification_plan_population_digest, compute_regime_observed_evidence_digest,
    compute_six_regime_qualification_plan_digest,
    verify_execution_environment_qualification_population, verify_regime_execution_evidence,
    verify_six_regime_qualification_plan,
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
        value: r("sha256:pending-regime-evidence"),
    }
}

fn sandbox_population(
    qualification_plan: &noerith_capabilities::ExecutionEnvironmentQualificationPlan,
) -> (
    QualificationPlanPopulation,
    VerifiedQualificationPlanPopulation,
) {
    let member = QualificationPlanMemberIdentity {
        plan_ref: qualification_plan.identity.plan_ref.clone(),
        plan_version: qualification_plan.identity.plan_version.clone(),
        plan_digest: qualification_plan.identity.plan_digest.clone(),
    };
    let mut population = QualificationPlanPopulation {
        identity: QualificationPlanPopulationIdentity {
            population_ref: r("qualification-population:sandbox-regime-evidence"),
            population_version: v("population-v1"),
            population_digest: pending_digest(),
        },
        purpose: QualificationPlanPopulationPurpose::ExecutionEnvironment,
        source_contract_refs: refs(&["source:s05-regime-evidence-sandbox-population"]),
        member_plan_identities: vec![member],
        invalidation_dependency_refs: refs(&[
            "dependency:environment-qualification-plan",
            "dependency:sandbox-population-policy",
        ]),
    };
    population.identity.population_digest =
        compute_qualification_plan_population_digest(&population).unwrap();
    let verified = verify_execution_environment_qualification_population(
        &population,
        core::slice::from_ref(qualification_plan),
    )
    .unwrap();
    (population, verified)
}

fn records_for(
    plan: &noerith_capabilities::SixRegimeQualificationPlan,
    regime: SpecialistRegime,
    environment: &noerith_capabilities::VerifiedExecutionEnvironment,
) -> Vec<RegimeObservedEvidenceRecord> {
    let pipeline = plan
        .pipelines
        .iter()
        .find(|pipeline| pipeline.regime == regime)
        .unwrap();
    let environment_evidence = environment
        .evidence_refs()
        .iter()
        .next()
        .expect("qualified environment has evidence")
        .clone();
    let mut invalidation_dependency_refs = refs(&[
        "dependency:regime-pipeline",
        "dependency:execution-environment",
    ]);
    invalidation_dependency_refs.extend(environment.invalidation_dependency_refs().iter().cloned());

    let mut records = Vec::new();
    for (kind, requirements) in [
        (
            RegimeEvidenceKind::IntegrationContract,
            &pipeline.required_integration_contract_refs,
        ),
        (
            RegimeEvidenceKind::CompletionRequirement,
            &pipeline.completion_evidence_requirement_refs,
        ),
    ] {
        for requirement in requirements {
            let kind_slug = match kind {
                RegimeEvidenceKind::IntegrationContract => "integration",
                RegimeEvidenceKind::CompletionRequirement => "completion",
            };
            let mut record = RegimeObservedEvidenceRecord {
                evidence_ref: r(&format!(
                    "regime-evidence:{regime:?}:{kind_slug}:{requirement}"
                )),
                evidence_version: v("observed-v1"),
                content_digest: pending_digest(),
                kind,
                regime,
                pipeline_ref: pipeline.pipeline_ref.clone(),
                pipeline_version: pipeline.pipeline_version.clone(),
                pipeline_digest: pipeline.content_digest.clone(),
                requirement_ref: requirement.clone(),
                environment_ref: environment.subject().environment_ref.clone(),
                environment_version: environment.subject().environment_version.clone(),
                environment_digest: environment.subject().content_digest.clone(),
                test_method_ref: r("method:real-sandbox-regime-conformance"),
                test_run_ref: r(&format!("run:{regime:?}:{kind_slug}:{requirement}")),
                producer_ref: r("producer:independent-regime-harness"),
                observed_result_ref: r(&format!(
                    "observed-result:{regime:?}:{kind_slug}:{requirement}"
                )),
                environment_evidence_refs: BTreeSet::from([environment_evidence.clone()]),
                provenance_refs: refs(&["provenance:regime-harness-run"]),
                validity_ref: r("validity:until-pipeline-or-environment-change"),
                invalidation_dependency_refs: invalidation_dependency_refs.clone(),
                status: EvidenceStatus::Pass,
            };
            record.content_digest = compute_regime_observed_evidence_digest(&record).unwrap();
            records.push(record);
        }
    }
    records
}

fn fixture() -> (
    noerith_capabilities::SixRegimeQualificationPlan,
    noerith_capabilities::VerifiedSixRegimeQualificationPlan,
    VerifiedQualificationPlanPopulation,
    noerith_capabilities::VerifiedExecutionEnvironment,
    RegimeExecutionEvidenceBundle,
) {
    let mut plan = regime_fixture::plan();
    let (environment_plan, environment) =
        environment_fixture::qualified_with_plan("qualification-plan:sandbox-primary", "primary");
    let (population, verified_population) = sandbox_population(&environment_plan);
    plan.sandbox_qualification_population = population.identity.clone();
    plan.content_digest = compute_six_regime_qualification_plan_digest(&plan).unwrap();
    let verified_plan = verify_six_regime_qualification_plan(&plan).unwrap();
    let records = records_for(&plan, SpecialistRegime::SoftwareEngineering, &environment);
    let bundle = RegimeExecutionEvidenceBundle {
        records,
        environments: vec![environment.clone()],
    };
    (
        plan,
        verified_plan,
        verified_population,
        environment,
        bundle,
    )
}

#[test]
fn s05_regime_evidence_requires_exact_integration_and_completion_obligations() {
    let (plan, verified_plan, sandbox_population, environment, bundle) = fixture();
    let verified = verify_regime_execution_evidence(
        &plan,
        &verified_plan,
        &sandbox_population,
        SpecialistRegime::SoftwareEngineering,
        &bundle,
    )
    .unwrap();

    let pipeline = plan
        .pipelines
        .iter()
        .find(|pipeline| pipeline.regime == SpecialistRegime::SoftwareEngineering)
        .unwrap();
    assert_eq!(
        verified.integration_evidence_refs().len(),
        pipeline.required_integration_contract_refs.len()
    );
    assert_eq!(
        verified.completion_evidence_refs().len(),
        pipeline.completion_evidence_requirement_refs.len()
    );
    assert_eq!(
        verified.environments(),
        core::slice::from_ref(environment.subject())
    );
}

#[test]
fn s05_verified_regime_evidence_identity_changes_with_record_content() {
    let (plan, verified_plan, sandbox_population, _environment, mut bundle) = fixture();
    let original = verify_regime_execution_evidence(
        &plan,
        &verified_plan,
        &sandbox_population,
        SpecialistRegime::SoftwareEngineering,
        &bundle,
    )
    .unwrap();

    let index = bundle
        .records
        .iter()
        .position(|record| record.kind == RegimeEvidenceKind::IntegrationContract)
        .unwrap();
    let logical_ref = bundle.records[index].evidence_ref.clone();
    let old_digest_ref = bundle.records[index].content_digest.value.clone();
    bundle.records[index].observed_result_ref = r("observed-result:changed-but-same-logical-ref");
    bundle.records[index].content_digest =
        compute_regime_observed_evidence_digest(&bundle.records[index]).unwrap();
    let new_digest_ref = bundle.records[index].content_digest.value.clone();

    assert_eq!(bundle.records[index].evidence_ref, logical_ref);
    assert_ne!(old_digest_ref, new_digest_ref);

    let changed = verify_regime_execution_evidence(
        &plan,
        &verified_plan,
        &sandbox_population,
        SpecialistRegime::SoftwareEngineering,
        &bundle,
    )
    .unwrap();
    assert_ne!(
        original.integration_evidence_refs(),
        changed.integration_evidence_refs()
    );
    assert!(
        changed
            .integration_evidence_refs()
            .contains(&new_digest_ref)
    );
}

#[test]
fn s05_integration_evidence_cannot_be_relabelled_as_completion_evidence() {
    let (plan, verified_plan, sandbox_population, _environment, mut bundle) = fixture();
    let record = bundle
        .records
        .iter_mut()
        .find(|record| record.kind == RegimeEvidenceKind::IntegrationContract)
        .unwrap();
    record.kind = RegimeEvidenceKind::CompletionRequirement;
    record.content_digest = compute_regime_observed_evidence_digest(record).unwrap();

    assert!(matches!(
        verify_regime_execution_evidence(
            &plan,
            &verified_plan,
            &sandbox_population,
            SpecialistRegime::SoftwareEngineering,
            &bundle,
        ),
        Err(RegimeEvidenceError::UnexpectedRequirement(_))
            | Err(RegimeEvidenceError::IncompleteIntegrationCoverage)
    ));
}

#[test]
fn s05_missing_required_regime_obligation_fails_closed() {
    let (plan, verified_plan, sandbox_population, _environment, mut bundle) = fixture();
    bundle.records.pop();

    assert!(matches!(
        verify_regime_execution_evidence(
            &plan,
            &verified_plan,
            &sandbox_population,
            SpecialistRegime::SoftwareEngineering,
            &bundle,
        ),
        Err(RegimeEvidenceError::IncompleteCompletionCoverage)
            | Err(RegimeEvidenceError::IncompleteIntegrationCoverage)
    ));
}

#[test]
fn s05_failed_or_indeterminate_observation_never_satisfies_a_regime_obligation() {
    for status in [EvidenceStatus::Fail, EvidenceStatus::Indeterminate] {
        let (plan, verified_plan, sandbox_population, _environment, mut bundle) = fixture();
        bundle.records[0].status = status;
        bundle.records[0].content_digest =
            compute_regime_observed_evidence_digest(&bundle.records[0]).unwrap();

        assert!(matches!(
            verify_regime_execution_evidence(
                &plan,
                &verified_plan,
                &sandbox_population,
                SpecialistRegime::SoftwareEngineering,
                &bundle,
            ),
            Err(RegimeEvidenceError::RequirementFailed(_))
                | Err(RegimeEvidenceError::RequirementIndeterminate(_))
        ));
    }
}

#[test]
fn s05_regime_evidence_rejects_unregistered_or_substituted_sandbox_plan() {
    let (plan, verified_plan, sandbox_population, _environment, _bundle) = fixture();

    let (_wrong_plan, wrong_ref) =
        environment_fixture::qualified_with_plan("qualification-plan:other-sandbox", "wrong-plan");
    let bundle = RegimeExecutionEvidenceBundle {
        records: records_for(&plan, SpecialistRegime::SoftwareEngineering, &wrong_ref),
        environments: vec![wrong_ref],
    };
    assert!(matches!(
        verify_regime_execution_evidence(
            &plan,
            &verified_plan,
            &sandbox_population,
            SpecialistRegime::SoftwareEngineering,
            &bundle,
        ),
        Err(RegimeEvidenceError::SandboxQualificationPlanNotPreregistered(_))
    ));

    let registered_ref = sandbox_population.member_plan_identities()[0]
        .plan_ref
        .clone();
    let (_substituted_plan, substituted) = environment_fixture::qualified_with_plan(
        registered_ref.as_str(),
        "same-ref-different-subject-plan-digest",
    );
    let bundle = RegimeExecutionEvidenceBundle {
        records: records_for(&plan, SpecialistRegime::SoftwareEngineering, &substituted),
        environments: vec![substituted],
    };
    assert!(matches!(
        verify_regime_execution_evidence(
            &plan,
            &verified_plan,
            &sandbox_population,
            SpecialistRegime::SoftwareEngineering,
            &bundle,
        ),
        Err(RegimeEvidenceError::SandboxQualificationPlanNotPreregistered(_))
    ));
}

#[test]
fn s05_regime_evidence_rejects_verified_population_from_another_manifest() {
    let (plan, verified_plan, _sandbox_population, environment, bundle) = fixture();
    let (other_plan, _other_environment) =
        environment_fixture::qualified_with_plan("qualification-plan:other-population", "other");
    let (_other_population, other_verified_population) = sandbox_population(&other_plan);

    assert_eq!(
        verify_regime_execution_evidence(
            &plan,
            &verified_plan,
            &other_verified_population,
            SpecialistRegime::SoftwareEngineering,
            &bundle,
        ),
        Err(RegimeEvidenceError::SandboxQualificationPopulationMismatch)
    );
    assert!(!other_verified_population.contains_exact(
        &environment.plan_identity().plan_ref,
        &environment.plan_identity().plan_version,
        &environment.plan_identity().plan_digest,
    ));
}

#[test]
fn s05_regime_record_cannot_forge_environment_digest_or_qualification_evidence() {
    let (plan, verified_plan, sandbox_population, _environment, mut bundle) = fixture();
    bundle.records[0].environment_digest = ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r("sha256:forged-environment"),
    };
    bundle.records[0].content_digest =
        compute_regime_observed_evidence_digest(&bundle.records[0]).unwrap();
    assert!(matches!(
        verify_regime_execution_evidence(
            &plan,
            &verified_plan,
            &sandbox_population,
            SpecialistRegime::SoftwareEngineering,
            &bundle,
        ),
        Err(RegimeEvidenceError::UnknownEnvironment(_))
    ));

    let (plan, verified_plan, sandbox_population, _environment, mut bundle) = fixture();
    bundle.records[0].environment_evidence_refs = refs(&["environment-evidence:forged"]);
    bundle.records[0].content_digest =
        compute_regime_observed_evidence_digest(&bundle.records[0]).unwrap();
    assert!(matches!(
        verify_regime_execution_evidence(
            &plan,
            &verified_plan,
            &sandbox_population,
            SpecialistRegime::SoftwareEngineering,
            &bundle,
        ),
        Err(RegimeEvidenceError::MissingEnvironmentQualificationEvidence(_))
    ));
}

#[test]
fn s05_regime_record_must_carry_environment_invalidation_dependencies() {
    let (plan, verified_plan, sandbox_population, environment, mut bundle) = fixture();
    for dependency in environment.invalidation_dependency_refs() {
        bundle.records[0]
            .invalidation_dependency_refs
            .remove(dependency);
    }
    bundle.records[0].content_digest =
        compute_regime_observed_evidence_digest(&bundle.records[0]).unwrap();

    assert!(matches!(
        verify_regime_execution_evidence(
            &plan,
            &verified_plan,
            &sandbox_population,
            SpecialistRegime::SoftwareEngineering,
            &bundle,
        ),
        Err(RegimeEvidenceError::MissingEnvironmentInvalidationDependencies(_))
    ));
}

#[test]
fn s05_post_digest_regime_evidence_mutation_is_detected() {
    let (plan, verified_plan, sandbox_population, _environment, mut bundle) = fixture();
    bundle.records[0]
        .provenance_refs
        .insert(r("provenance:added-after-digest"));

    assert!(matches!(
        verify_regime_execution_evidence(
            &plan,
            &verified_plan,
            &sandbox_population,
            SpecialistRegime::SoftwareEngineering,
            &bundle,
        ),
        Err(RegimeEvidenceError::EvidenceDigestMismatch(_))
    ));
}
