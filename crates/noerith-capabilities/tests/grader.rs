use noerith_capabilities::{
    ContentDigest, CriterionGrade, EvidenceGraderPlan, EvidenceGraderPlanIdentity, EvidenceStatus,
    GradeRecord, GradeRequest, GradeSubject, GraderError, GraderIdentity,
    GraderQualificationEvidenceRecord, OpaqueVersion, Reference, SpecialistRegime,
    compute_evidence_grader_plan_digest, qualify_evidence_grader, verify_grade_record,
};
use std::collections::BTreeSet;

fn r(value: &str) -> Reference {
    Reference::new(value).expect("valid ref")
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

fn grader_identity() -> GraderIdentity {
    GraderIdentity {
        grader_ref: r("grader:software-behavior"),
        grader_version: v("2026-09"),
        implementation_ref: r("artifact:grader-engine"),
        implementation_version: v("build-17"),
        configuration_ref: r("config:grader-rubric-runner"),
        configuration_version: v("cfg-5"),
    }
}

fn plan() -> EvidenceGraderPlan {
    let mut plan = EvidenceGraderPlan {
        identity: EvidenceGraderPlanIdentity {
            plan_ref: r("grader-plan:software-behavior"),
            plan_version: v("plan-3"),
            plan_digest: digest("sha256:placeholder"),
        },
        grader: grader_identity(),
        rubric_ref: r("rubric:software-behavior"),
        rubric_version: v("rubric-9"),
        mandatory_criterion_refs: refs(&["criterion:behavior", "criterion:evidence"]),
        calibrated_scope_refs: refs(&["scope:software-engineering", "scope:rust-repository"]),
        qualification_requirement_refs: refs(&[
            "grader-requirement:expert-agreement",
            "grader-requirement:anti-gaming",
        ]),
        calibration_corpus_ref: r("corpus:grader-calibration-dev"),
        heldout_calibration_partition_ref: r("corpus:grader-calibration-heldout"),
        disagreement_policy_ref: r("policy:grader-disagreement"),
        abstention_policy_ref: r("policy:grader-abstain-on-missing-evidence"),
        anti_gaming_policy_ref: r("policy:grader-anti-gaming"),
        invalidation_dependency_refs: refs(&[
            "dependency:rubric-version",
            "dependency:grader-config",
            "dependency:calibration-corpus",
        ]),
    };
    plan.identity.plan_digest = compute_evidence_grader_plan_digest(&plan).unwrap();
    plan
}

fn qualification_evidence(plan: &EvidenceGraderPlan) -> Vec<GraderQualificationEvidenceRecord> {
    plan.qualification_requirement_refs
        .iter()
        .enumerate()
        .map(|(index, requirement)| GraderQualificationEvidenceRecord {
            evidence_ref: r(&format!("grader-qualification-evidence:{index}")),
            grader: plan.grader.clone(),
            plan_identity: plan.identity.clone(),
            requirement_ref: requirement.clone(),
            test_method_ref: r("method:heldout-calibration"),
            test_run_ref: r(&format!("run:grader-calibration:{index}")),
            producer_ref: r("producer:independent-eval-harness"),
            provenance_refs: refs(&["provenance:heldout-cases", "provenance:expert-reference"]),
            observed_result_ref: r(&format!("result:grader-calibration:{index}")),
            validity_ref: r("validity:until-grader-or-rubric-change"),
            status: EvidenceStatus::Pass,
        })
        .collect()
}

fn subject() -> GradeSubject {
    GradeSubject {
        regime: SpecialistRegime::SoftwareEngineering,
        task_ref: r("task:repair-repository"),
        trial_ref: r("trial:repair-repository:4"),
        output_digest: digest("sha256:output-4"),
        trace_ref: r("trace:trial-4"),
        environment_ref: r("environment:sandbox-linux"),
        environment_version: v("sandbox-22"),
        evaluation_scope_refs: refs(&["scope:software-engineering", "scope:rust-repository"]),
        execution_evidence_refs: refs(&["evidence:build", "evidence:tests", "evidence:diff"]),
    }
}

fn grade_request(plan: &EvidenceGraderPlan) -> GradeRequest {
    GradeRequest {
        request_ref: r("grade-request:trial-4"),
        subject: subject(),
        grader_plan_identity: plan.identity.clone(),
        mandatory_criterion_refs: plan.mandatory_criterion_refs.clone(),
    }
}

fn passing_record(plan: &EvidenceGraderPlan, request: &GradeRequest) -> GradeRecord {
    GradeRecord {
        grade_ref: r("grade:trial-4"),
        request_ref: request.request_ref.clone(),
        subject: request.subject.clone(),
        grader: plan.grader.clone(),
        grader_plan_identity: plan.identity.clone(),
        rubric_ref: plan.rubric_ref.clone(),
        rubric_version: plan.rubric_version.clone(),
        criterion_results: request
            .mandatory_criterion_refs
            .iter()
            .map(|criterion| CriterionGrade {
                criterion_ref: criterion.clone(),
                status: EvidenceStatus::Pass,
                evidence_refs: refs(&[&format!("criterion-evidence:{}", criterion.as_str())]),
            })
            .collect(),
        provenance_refs: refs(&["provenance:grader-run", "provenance:trial-trace"]),
        validity_ref: r("validity:grade-bound-to-trial-4"),
    }
}

#[test]
fn s05_grader_must_be_integrity_bound_and_fully_qualified() {
    let plan = plan();
    let evidence = qualification_evidence(&plan);
    let verified = qualify_evidence_grader(&plan, &evidence).expect("qualified grader");
    assert_eq!(verified.identity(), &plan.identity);
    assert_eq!(verified.grader(), &plan.grader);
    assert_eq!(verified.qualification_evidence_refs().len(), 2);

    let mut mutated = plan.clone();
    mutated.rubric_version = v("rubric-10");
    assert_eq!(
        qualify_evidence_grader(&mutated, &evidence),
        Err(GraderError::PlanDigestMismatch)
    );
}

#[test]
fn s05_grader_qualification_rejects_missing_fail_and_indeterminate_evidence() {
    let plan = plan();
    let mut evidence = qualification_evidence(&plan);
    evidence.pop();
    assert_eq!(
        qualify_evidence_grader(&plan, &evidence),
        Err(GraderError::IncompleteQualificationEvidence)
    );

    let mut evidence = qualification_evidence(&plan);
    evidence[0].status = EvidenceStatus::Fail;
    assert!(matches!(
        qualify_evidence_grader(&plan, &evidence),
        Err(GraderError::QualificationRequirementFailed(_))
    ));

    let mut evidence = qualification_evidence(&plan);
    evidence[0].status = EvidenceStatus::Indeterminate;
    assert!(matches!(
        qualify_evidence_grader(&plan, &evidence),
        Err(GraderError::QualificationRequirementIndeterminate(_))
    ));
}

#[test]
fn s05_grade_is_bound_to_exact_task_trial_output_trace_environment_and_plan() {
    let plan = plan();
    let verified = qualify_evidence_grader(&plan, &qualification_evidence(&plan)).unwrap();
    let request = grade_request(&plan);
    let record = passing_record(&plan, &request);
    let verified_grade = verify_grade_record(&verified, &request, &record).unwrap();
    assert_eq!(verified_grade.status(), EvidenceStatus::Pass);
    assert_eq!(verified_grade.subject(), &request.subject);

    let mut replay = record.clone();
    replay.subject.output_digest = digest("sha256:different-output");
    assert_eq!(
        verify_grade_record(&verified, &request, &replay),
        Err(GraderError::GradeSubjectMismatch)
    );

    let mut replay = record;
    replay.subject.trial_ref = r("trial:other");
    assert_eq!(
        verify_grade_record(&verified, &request, &replay),
        Err(GraderError::GradeSubjectMismatch)
    );
}

#[test]
fn s05_required_criterion_failure_or_unknown_cannot_be_averaged_away() {
    let plan = plan();
    let verified = qualify_evidence_grader(&plan, &qualification_evidence(&plan)).unwrap();
    let request = grade_request(&plan);

    let mut failed = passing_record(&plan, &request);
    failed.criterion_results[0].status = EvidenceStatus::Fail;
    assert_eq!(
        verify_grade_record(&verified, &request, &failed)
            .unwrap()
            .status(),
        EvidenceStatus::Fail
    );

    let mut unknown = passing_record(&plan, &request);
    unknown.criterion_results[0].status = EvidenceStatus::Indeterminate;
    assert_eq!(
        verify_grade_record(&verified, &request, &unknown)
            .unwrap()
            .status(),
        EvidenceStatus::Indeterminate
    );
}

#[test]
fn s05_grade_rejects_missing_duplicate_extra_or_evidenceless_criterion() {
    let plan = plan();
    let verified = qualify_evidence_grader(&plan, &qualification_evidence(&plan)).unwrap();
    let request = grade_request(&plan);

    let mut missing = passing_record(&plan, &request);
    missing.criterion_results.pop();
    assert_eq!(
        verify_grade_record(&verified, &request, &missing),
        Err(GraderError::IncompleteCriterionCoverage)
    );

    let mut duplicate = passing_record(&plan, &request);
    duplicate
        .criterion_results
        .push(duplicate.criterion_results[0].clone());
    assert!(matches!(
        verify_grade_record(&verified, &request, &duplicate),
        Err(GraderError::DuplicateCriterion(_))
    ));

    let mut extra = passing_record(&plan, &request);
    extra.criterion_results.push(CriterionGrade {
        criterion_ref: r("criterion:unplanned-easy-bonus"),
        status: EvidenceStatus::Pass,
        evidence_refs: refs(&["evidence:bonus"]),
    });
    assert!(matches!(
        verify_grade_record(&verified, &request, &extra),
        Err(GraderError::UnexpectedCriterion(_))
    ));

    let mut empty_evidence = passing_record(&plan, &request);
    empty_evidence.criterion_results[0].evidence_refs.clear();
    assert!(matches!(
        verify_grade_record(&verified, &request, &empty_evidence),
        Err(GraderError::CriterionEvidenceMissing(_))
    ));
}

#[test]
fn s05_grader_cannot_grade_outside_calibrated_scope() {
    let plan = plan();
    let verified = qualify_evidence_grader(&plan, &qualification_evidence(&plan)).unwrap();
    let mut request = grade_request(&plan);
    request
        .subject
        .evaluation_scope_refs
        .insert(r("scope:medical-diagnosis"));
    let record = passing_record(&plan, &request);
    assert_eq!(
        verify_grade_record(&verified, &request, &record),
        Err(GraderError::GradeOutsideCalibratedScope)
    );
}

#[test]
fn s05_grader_qualification_identity_changes_when_leaf_evidence_content_changes() {
    let plan = plan();

    let first_evidence = qualification_evidence(&plan);
    let mut second_evidence = first_evidence.clone();
    second_evidence[0].test_run_ref = r("run:grader-calibration:changed-content");
    second_evidence[0].observed_result_ref = r("result:grader-calibration:recomputed");

    let first = qualify_evidence_grader(&plan, &first_evidence).unwrap();
    let second = qualify_evidence_grader(&plan, &second_evidence).unwrap();

    assert_eq!(
        first.qualification_evidence_refs(),
        second.qualification_evidence_refs()
    );
    assert_ne!(
        first.verification_digest(),
        second.verification_digest(),
        "same logical grader-qualification refs must not hide changed calibration evidence",
    );
}

#[test]
fn s05_grade_identity_binds_record_content_and_exact_grader_qualification() {
    let plan = plan();
    let request = grade_request(&plan);

    let first_grader = qualify_evidence_grader(&plan, &qualification_evidence(&plan)).unwrap();

    let mut changed_qualification_evidence = qualification_evidence(&plan);
    changed_qualification_evidence[0].observed_result_ref =
        r("result:grader-calibration:changed-but-valid");
    let second_grader = qualify_evidence_grader(&plan, &changed_qualification_evidence).unwrap();

    let first_record = passing_record(&plan, &request);
    let first_grade = verify_grade_record(&first_grader, &request, &first_record).unwrap();
    let second_grade = verify_grade_record(&second_grader, &request, &first_record).unwrap();

    assert_eq!(first_grade.grade_ref(), second_grade.grade_ref());
    assert_ne!(
        first_grade.verification_digest(),
        second_grade.verification_digest(),
        "a grade must bind the exact qualification evidence of its measuring instrument",
    );

    let mut changed_record = first_record;
    changed_record.criterion_results[0]
        .evidence_refs
        .insert(r("criterion-evidence:changed-content"));
    changed_record
        .provenance_refs
        .insert(r("provenance:changed-grade-run"));

    let changed_grade = verify_grade_record(&first_grader, &request, &changed_record).unwrap();

    assert_eq!(first_grade.grade_ref(), changed_grade.grade_ref());
    assert_eq!(first_grade.status(), changed_grade.status());
    assert_ne!(
        first_grade.verification_digest(),
        changed_grade.verification_digest(),
        "same logical grade ref and status must not hide different grade evidence content",
    );
}
