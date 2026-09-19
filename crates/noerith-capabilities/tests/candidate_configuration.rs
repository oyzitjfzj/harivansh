use noerith_capabilities::{
    CandidateConfiguration, CandidateConfigurationError, CandidateConfigurationManifest,
    CandidateModelBinding, ContentDigest, OpaqueVersion, Q07ComparisonAxis, Reference,
    SHA256_ALGORITHM_REF, compute_candidate_configuration_digest,
    compute_candidate_configuration_manifest_digest, verify_candidate_configuration,
    verify_candidate_configuration_manifest,
};
use std::collections::{BTreeMap, BTreeSet};

fn r(value: &str) -> Reference {
    Reference::new(value).unwrap()
}

fn v(value: &str) -> OpaqueVersion {
    OpaqueVersion::new(value).unwrap()
}

fn refs(values: &[&str]) -> BTreeSet<Reference> {
    values.iter().map(|value| r(value)).collect()
}

fn comparison_estimands() -> BTreeMap<Q07ComparisonAxis, Reference> {
    Q07ComparisonAxis::ALL
        .into_iter()
        .map(|axis| (axis, r(&format!("estimand:{axis:?}"))))
        .collect()
}

fn placeholder_digest() -> ContentDigest {
    ContentDigest {
        algorithm_ref: r(SHA256_ALGORITHM_REF),
        value: r("sha256:pending"),
    }
}

fn configuration(name: &str, alternate: bool) -> CandidateConfiguration {
    let mut configuration = CandidateConfiguration {
        configuration_ref: r(&format!("candidate-configuration:{name}")),
        configuration_version: v("configuration-v1"),
        content_digest: placeholder_digest(),
        model: CandidateModelBinding {
            provider_ref: r(if alternate {
                "provider:b"
            } else {
                "provider:a"
            }),
            model_ref: r(if alternate { "model:b" } else { "model:a" }),
            model_version: v(if alternate { "model-v2" } else { "model-v1" }),
            adapter_ref: r(if alternate { "adapter:b" } else { "adapter:a" }),
            adapter_version: v(if alternate {
                "adapter-v2"
            } else {
                "adapter-v1"
            }),
        },
        worker_topology_ref: r(if alternate {
            "worker-topology:cooperating-pair"
        } else {
            "worker-topology:single"
        }),
        worker_count: if alternate { 2 } else { 1 },
        worker_coordination_policy_ref: r(if alternate {
            "worker-coordination:shared-state-arbiter"
        } else {
            "worker-coordination:single-worker"
        }),
        reasoning_effort_ref: r(if alternate {
            "reasoning-effort:high"
        } else {
            "reasoning-effort:standard"
        }),
        context_strategy_ref: r(if alternate {
            "context-strategy:multi-resolution"
        } else {
            "context-strategy:focused"
        }),
        retrieval_strategy_ref: r(if alternate {
            "retrieval-strategy:hybrid"
        } else {
            "retrieval-strategy:exact-first"
        }),
        provenance_refs: refs(&[&format!("provenance:{name}")]),
        invalidation_dependency_refs: refs(&[&format!("dependency:{name}")]),
    };
    configuration.content_digest = compute_candidate_configuration_digest(&configuration).unwrap();
    configuration
}

fn manifest() -> CandidateConfigurationManifest {
    let mut manifest = CandidateConfigurationManifest {
        manifest_ref: r("candidate-configuration-manifest:q07"),
        manifest_version: v("manifest-v1"),
        content_digest: placeholder_digest(),
        source_contract_refs: refs(&["source:q07", "source:master-blueprint"]),
        experiment_design_ref: r("experiment-design:q07-registered"),
        randomization_policy_ref: r("randomization:q07-registered"),
        blocking_policy_ref: r("blocking:q07-registered"),
        comparison_estimand_refs: comparison_estimands(),
        configurations: vec![configuration("a", false), configuration("b", true)],
        invalidation_dependency_refs: refs(&[
            "dependency:q07-floor",
            "dependency:model-catalog",
            "dependency:experiment-design",
        ]),
    };
    manifest.content_digest = compute_candidate_configuration_manifest_digest(&manifest).unwrap();
    manifest
}

fn redigest_configuration(configuration: &mut CandidateConfiguration) {
    configuration.content_digest = placeholder_digest();
    configuration.content_digest = compute_candidate_configuration_digest(configuration).unwrap();
}

fn redigest_manifest(manifest: &mut CandidateConfigurationManifest) {
    manifest.content_digest = placeholder_digest();
    manifest.content_digest = compute_candidate_configuration_manifest_digest(manifest).unwrap();
}

#[test]
fn q07_candidate_manifest_requires_exact_content_bound_comparison_population() {
    let manifest = manifest();
    let verified = verify_candidate_configuration_manifest(&manifest).unwrap();
    assert_eq!(
        verified.manifest_ref(),
        &r("candidate-configuration-manifest:q07")
    );
    assert_eq!(verified.content_digest(), &manifest.content_digest);
    assert_eq!(verified.configurations().count(), 2);
    assert_eq!(verified.comparison_estimand_refs(), &comparison_estimands());
    assert!(
        verified
            .configuration(&r("candidate-configuration:a"), &v("configuration-v1"))
            .is_some()
    );
}

#[test]
fn configuration_digest_detects_post_registration_model_substitution() {
    let mut configuration = configuration("a", false);
    let verified = verify_candidate_configuration(&configuration).unwrap();
    assert_eq!(verified.model().model_ref, r("model:a"));

    configuration.model.model_ref = r("model:substituted");
    assert!(matches!(
        verify_candidate_configuration(&configuration),
        Err(CandidateConfigurationError::ConfigurationDigestMismatch(_))
    ));
}

#[test]
fn manifest_digest_detects_post_registration_population_or_estimand_mutation() {
    let mut population_mutation = manifest();
    assert!(verify_candidate_configuration_manifest(&population_mutation).is_ok());
    population_mutation.randomization_policy_ref = r("randomization:changed-after-results");
    assert_eq!(
        verify_candidate_configuration_manifest(&population_mutation),
        Err(CandidateConfigurationError::ManifestDigestMismatch)
    );

    let mut estimand_mutation = manifest();
    estimand_mutation.comparison_estimand_refs.insert(
        Q07ComparisonAxis::CandidateModel,
        r("estimand:changed-after-results"),
    );
    assert_eq!(
        verify_candidate_configuration_manifest(&estimand_mutation),
        Err(CandidateConfigurationError::ManifestDigestMismatch)
    );
}

#[test]
fn manifest_requires_one_preregistered_estimand_for_every_q07_axis() {
    for axis in Q07ComparisonAxis::ALL {
        let mut manifest = manifest();
        manifest.comparison_estimand_refs.remove(&axis);
        manifest.content_digest = placeholder_digest();
        assert_eq!(
            compute_candidate_configuration_manifest_digest(&manifest),
            Err(CandidateConfigurationError::UnexpectedComparisonEstimandCount)
        );
    }
}

#[test]
fn manifest_digest_is_order_independent_but_population_bound() {
    let first = manifest();
    let mut second = manifest();
    second.configurations.reverse();
    second.content_digest = placeholder_digest();

    assert_eq!(
        compute_candidate_configuration_manifest_digest(&first).unwrap(),
        compute_candidate_configuration_manifest_digest(&second).unwrap()
    );

    second.configurations.pop();
    second.content_digest = placeholder_digest();
    assert_ne!(
        compute_candidate_configuration_manifest_digest(&first).unwrap(),
        compute_candidate_configuration_manifest_digest(&second).unwrap()
    );
}

#[test]
fn duplicate_or_conflicting_configuration_identity_fails_closed() {
    let mut duplicate = manifest();
    duplicate
        .configurations
        .push(duplicate.configurations[0].clone());
    assert!(matches!(
        compute_candidate_configuration_manifest_digest(&duplicate),
        Err(CandidateConfigurationError::DuplicateConfiguration(_))
    ));

    let mut collision = manifest();
    let mut changed = collision.configurations[0].clone();
    changed.reasoning_effort_ref = r("reasoning-effort:changed");
    redigest_configuration(&mut changed);
    collision.configurations.push(changed);
    assert!(matches!(
        compute_candidate_configuration_manifest_digest(&collision),
        Err(CandidateConfigurationError::ConfigurationVersionDigestCollision { .. })
    ));
}

#[test]
fn every_frozen_q07_comparison_axis_requires_real_registered_variation() {
    for axis in Q07ComparisonAxis::ALL {
        let mut manifest = manifest();
        let first = manifest.configurations[0].clone();
        let second = &mut manifest.configurations[1];
        match axis {
            Q07ComparisonAxis::CandidateModel => second.model = first.model,
            Q07ComparisonAxis::WorkerTopology => {
                second.worker_topology_ref = first.worker_topology_ref;
                second.worker_count = first.worker_count;
                second.worker_coordination_policy_ref = first.worker_coordination_policy_ref;
            }
            Q07ComparisonAxis::ReasoningEffort => {
                second.reasoning_effort_ref = first.reasoning_effort_ref;
            }
            Q07ComparisonAxis::ContextStrategy => {
                second.context_strategy_ref = first.context_strategy_ref;
            }
            Q07ComparisonAxis::RetrievalStrategy => {
                second.retrieval_strategy_ref = first.retrieval_strategy_ref;
            }
        }
        redigest_configuration(second);
        redigest_manifest(&mut manifest);
        assert_eq!(
            verify_candidate_configuration_manifest(&manifest),
            Err(CandidateConfigurationError::MissingComparisonAxisVariation(
                axis
            ))
        );
    }
}

#[test]
fn q07_explicitly_requires_single_and_multiple_worker_candidates() {
    let mut no_single = manifest();
    no_single.configurations[0].worker_count = 3;
    no_single.configurations[0].worker_topology_ref = r("worker-topology:independent-triple");
    redigest_configuration(&mut no_single.configurations[0]);
    redigest_manifest(&mut no_single);
    assert_eq!(
        verify_candidate_configuration_manifest(&no_single),
        Err(CandidateConfigurationError::MissingSingleWorkerConfiguration)
    );

    let mut no_multiple = manifest();
    no_multiple.configurations[1].worker_count = 1;
    no_multiple.configurations[1].worker_topology_ref = r("worker-topology:single-alternate");
    redigest_configuration(&mut no_multiple.configurations[1]);
    redigest_manifest(&mut no_multiple);
    assert_eq!(
        verify_candidate_configuration_manifest(&no_multiple),
        Err(CandidateConfigurationError::MissingMultipleWorkerConfiguration)
    );
}

#[test]
fn zero_worker_or_missing_provenance_never_becomes_a_verified_configuration() {
    let mut zero = configuration("zero", false);
    zero.worker_count = 0;
    zero.content_digest = placeholder_digest();
    assert!(matches!(
        compute_candidate_configuration_digest(&zero),
        Err(CandidateConfigurationError::InvalidWorkerCount(_))
    ));

    let mut no_provenance = configuration("no-provenance", false);
    no_provenance.provenance_refs.clear();
    no_provenance.content_digest = placeholder_digest();
    assert!(matches!(
        compute_candidate_configuration_digest(&no_provenance),
        Err(CandidateConfigurationError::MissingConfigurationProvenance(
            _
        ))
    ));
}

#[test]
fn unsupported_digest_algorithm_cannot_claim_verified_configuration_identity() {
    let mut configuration = configuration("a", false);
    configuration.content_digest.algorithm_ref = r("digest:not-sha256");
    assert!(matches!(
        verify_candidate_configuration(&configuration),
        Err(CandidateConfigurationError::UnsupportedDigestAlgorithm(_))
    ));
}
