use noerith_capabilities::{
    ContentDigest, EvaluationCorpusDefinition, EvaluationCorpusError, EvaluationExposureClass,
    EvaluationPartition, EvaluationTaskDefinition, OpaqueVersion, Reference, SpecialistRegime,
    compute_evaluation_corpus_digest, verify_evaluation_corpus,
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

fn digest(value: &str) -> ContentDigest {
    ContentDigest {
        algorithm_ref: r("digest:sha-256"),
        value: r(value),
    }
}

fn task(
    name: &str,
    partition: EvaluationPartition,
    family: &str,
    exposure: EvaluationExposureClass,
) -> EvaluationTaskDefinition {
    EvaluationTaskDefinition {
        task_ref: r(&format!("eval-task:{name}")),
        task_version: v("task-4"),
        task_content_digest: digest(&format!("sha256:task-{name}")),
        regime: SpecialistRegime::ResearchDeepResearch,
        partition,
        contamination_family_ref: r(&format!("family:{family}")),
        source_refs: refs(&[&format!("source:{name}")]),
        provenance_refs: refs(&[&format!("provenance:{name}")]),
        data_use_policy_refs: refs(&["data-use:eval-only"]),
        domain_refs: refs(&["domain:research"]),
        coverage_stratum_refs: refs(&[&format!("coverage:{name}")]),
        required_capability_refs: refs(&["capability:source-retrieval", "capability:citation"]),
        environment_requirement_refs: refs(&["environment-requirement:controlled-research"]),
        completion_contract_refs: refs(&["completion:claim-evidence-coverage"]),
        grader_criterion_refs: refs(&[
            "criterion:claim-support",
            "criterion:source-quality",
            "criterion:conflict-coverage",
        ]),
        evaluation_affordance_policy_ref: r("policy:research-eval-affordances"),
        exposure_class: exposure,
        exposure_evidence_refs: refs(&[&format!("exposure-evidence:{name}")]),
        validation_evidence_refs: refs(&[&format!("validation-evidence:{name}")]),
        invalidation_dependency_refs: refs(&[
            "dependency:task-source-version",
            "dependency:grader-rubric-version",
        ]),
    }
}

fn corpus() -> EvaluationCorpusDefinition {
    let mut corpus = EvaluationCorpusDefinition {
        corpus_ref: r("evaluation-corpus:research"),
        corpus_version: v("corpus-12"),
        content_digest: digest("sha256:placeholder-corpus"),
        regime: SpecialistRegime::ResearchDeepResearch,
        task_distribution_ref: r("distribution:research-real-work"),
        coverage_model_ref: r("coverage-model:research-domains-and-failure-modes"),
        sampling_policy_ref: r("sampling-policy:research-preregistered"),
        anti_gaming_policy_ref: r("anti-gaming:research-evals"),
        exposure_control_policy_ref: r("exposure-control:research-evals"),
        development_partition_ref: r("partition:research:development"),
        heldout_partition_ref: r("partition:research:heldout"),
        adversarial_partition_ref: r("partition:research:adversarial"),
        tasks: vec![
            task(
                "development-a",
                EvaluationPartition::Development,
                "development-a",
                EvaluationExposureClass::Public,
            ),
            task(
                "heldout-a",
                EvaluationPartition::Heldout,
                "heldout-a",
                EvaluationExposureClass::Sequestered,
            ),
            task(
                "adversarial-a",
                EvaluationPartition::Adversarial,
                "adversarial-a",
                EvaluationExposureClass::Sequestered,
            ),
        ],
        invalidation_dependency_refs: refs(&[
            "dependency:distribution-definition",
            "dependency:coverage-model",
            "dependency:partition-custody",
        ]),
    };
    corpus.content_digest = compute_evaluation_corpus_digest(&corpus).unwrap();
    corpus
}

#[test]
fn s05_corpus_is_content_bound_and_covers_all_three_partitions() {
    let corpus = corpus();
    let verified = verify_evaluation_corpus(&corpus).unwrap();
    assert_eq!(verified.regime(), SpecialistRegime::ResearchDeepResearch);
    assert_eq!(
        verified.partition_count(EvaluationPartition::Development),
        1
    );
    assert_eq!(verified.partition_count(EvaluationPartition::Heldout), 1);
    assert_eq!(
        verified.partition_count(EvaluationPartition::Adversarial),
        1
    );

    let mut changed = corpus;
    changed.tasks[1].completion_contract_refs = refs(&["completion:different-contract"]);
    assert_eq!(
        verify_evaluation_corpus(&changed),
        Err(EvaluationCorpusError::DigestMismatch)
    );
}

#[test]
fn s05_corpus_rejects_missing_or_colliding_partitions() {
    let mut missing = corpus();
    missing
        .tasks
        .retain(|task| task.partition != EvaluationPartition::Adversarial);
    assert_eq!(
        compute_evaluation_corpus_digest(&missing),
        Err(EvaluationCorpusError::MissingPartition(
            EvaluationPartition::Adversarial
        ))
    );

    let mut collided = corpus();
    collided.heldout_partition_ref = collided.development_partition_ref.clone();
    assert_eq!(
        compute_evaluation_corpus_digest(&collided),
        Err(EvaluationCorpusError::PartitionIdentityCollision)
    );
}

#[test]
fn s05_development_family_cannot_be_renamed_into_heldout_evidence() {
    let mut corpus = corpus();
    corpus.tasks[1].contamination_family_ref = corpus.tasks[0].contamination_family_ref.clone();
    let family = corpus.tasks[0].contamination_family_ref.to_string();
    assert_eq!(
        compute_evaluation_corpus_digest(&corpus),
        Err(EvaluationCorpusError::ContaminationFamilyCrossesPartitions(
            family
        ))
    );
}

#[test]
fn s05_near_duplicate_family_cannot_span_heldout_and_adversarial_partitions() {
    let mut corpus = corpus();
    corpus.tasks[2].contamination_family_ref = corpus.tasks[1].contamination_family_ref.clone();
    let family = corpus.tasks[1].contamination_family_ref.to_string();
    assert_eq!(
        compute_evaluation_corpus_digest(&corpus),
        Err(EvaluationCorpusError::ContaminationFamilyCrossesPartitions(
            family
        ))
    );
}

#[test]
fn s05_corpus_rejects_duplicate_task_or_wrong_regime() {
    let mut duplicate = corpus();
    duplicate.tasks[2].task_ref = duplicate.tasks[1].task_ref.clone();
    let task_ref = duplicate.tasks[1].task_ref.to_string();
    assert_eq!(
        compute_evaluation_corpus_digest(&duplicate),
        Err(EvaluationCorpusError::DuplicateTask(task_ref))
    );

    let mut wrong_regime = corpus();
    wrong_regime.tasks[0].regime = SpecialistRegime::SoftwareEngineering;
    let task_ref = wrong_regime.tasks[0].task_ref.to_string();
    assert_eq!(
        compute_evaluation_corpus_digest(&wrong_regime),
        Err(EvaluationCorpusError::TaskRegimeMismatch(task_ref))
    );
}

#[test]
fn s05_missing_provenance_exposure_validation_or_measurement_scope_is_not_clean_by_default() {
    for field in [
        "provenance",
        "exposure",
        "validation",
        "coverage",
        "capability",
        "environment",
        "completion",
        "grader",
    ] {
        let mut corpus = corpus();
        match field {
            "provenance" => corpus.tasks[0].provenance_refs.clear(),
            "exposure" => corpus.tasks[0].exposure_evidence_refs.clear(),
            "validation" => corpus.tasks[0].validation_evidence_refs.clear(),
            "coverage" => corpus.tasks[0].coverage_stratum_refs.clear(),
            "capability" => corpus.tasks[0].required_capability_refs.clear(),
            "environment" => corpus.tasks[0].environment_requirement_refs.clear(),
            "completion" => corpus.tasks[0].completion_contract_refs.clear(),
            "grader" => corpus.tasks[0].grader_criterion_refs.clear(),
            _ => unreachable!(),
        }
        let task_ref = corpus.tasks[0].task_ref.to_string();
        assert_eq!(
            compute_evaluation_corpus_digest(&corpus),
            Err(EvaluationCorpusError::MissingTaskEvidence(task_ref)),
            "field {field} must fail closed"
        );
    }
}

#[test]
fn s05_verified_corpus_is_integrity_evidence_not_a_regime_pass() {
    let verified = verify_evaluation_corpus(&corpus()).unwrap();
    assert!(!verified.content_digest().value.as_str().is_empty());
    assert_eq!(verified.partition_count(EvaluationPartition::Heldout), 1);
    // No provider/model/result/status exists on the verified corpus wrapper;
    // outcome qualification remains a separate evidence stage.
}
