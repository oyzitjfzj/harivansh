use noerith_cognition::*;
use std::collections::{BTreeMap, BTreeSet};

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn rev(version: u64) -> VersionedRef {
    VersionedRef {
        reference: "goal-a".into(),
        version,
    }
}

fn empty_fields() -> BTreeMap<GoalConstitutionField, BTreeSet<String>> {
    BTreeMap::from([
        (GoalConstitutionField::Reason, BTreeSet::new()),
        (GoalConstitutionField::DesiredLevel, BTreeSet::new()),
        (GoalConstitutionField::NonNegotiable, BTreeSet::new()),
        (GoalConstitutionField::AcceptedDecision, BTreeSet::new()),
        (GoalConstitutionField::RejectedDecision, BTreeSet::new()),
        (GoalConstitutionField::Correction, BTreeSet::new()),
        (GoalConstitutionField::OpenQuestion, BTreeSet::new()),
        (GoalConstitutionField::CompletionCriterion, BTreeSet::new()),
        (GoalConstitutionField::QualityRequirement, BTreeSet::new()),
        (GoalConstitutionField::PermissionBoundary, BTreeSet::new()),
    ])
}

fn snapshot(version: u64, fingerprint: &str) -> GoalConstitutionSnapshot {
    let mut fields = empty_fields();
    fields.insert(
        GoalConstitutionField::Reason,
        set(&["reason:build-user-requested-system"]),
    );
    fields.insert(
        GoalConstitutionField::QualityRequirement,
        set(&["quality:source-defined-floor"]),
    );
    fields.insert(
        GoalConstitutionField::CompletionCriterion,
        set(&["completion:verified-evidence"]),
    );
    GoalConstitutionSnapshot {
        goal_revision: rev(version),
        fingerprint_ref: fingerprint.into(),
        fingerprint_evidence_refs: set(&["canonicalization-evidence"]),
        original_goal_evidence_refs: set(&["message:user-original-goal"]),
        fields,
    }
}

fn patch(id: &str, base_version: u64, relation: GoalPatchRelation) -> GoalPatch {
    GoalPatch {
        patch_id: id.into(),
        base_goal_revision: rev(base_version),
        relation,
        proposed_delta_ref: format!("delta:{id}"),
        exact_source_refs: set(&["message:user-current"]),
        affected_work_refs: set(&["work-a"]),
        affected_plan_refs: set(&["plan-a"]),
        affected_context_refs: set(&["context-a"]),
        acceptance_evidence_refs: set(&["accepted-user-input"]),
        resulting_goal_revision: None,
    }
}

fn amendment(
    current: &GoalConstitutionSnapshot,
    id: &str,
    relation: GoalPatchRelation,
    changed_field: GoalConstitutionField,
    new_value_ref: &str,
    new_fingerprint: &str,
) -> GoalAmendmentCandidate {
    let mut resulting_fields = current.fields.clone();
    resulting_fields
        .entry(changed_field)
        .or_default()
        .insert(new_value_ref.into());
    GoalAmendmentCandidate {
        patch: patch(id, current.goal_revision.version, relation),
        base_fingerprint_ref: current.fingerprint_ref.clone(),
        resulting_fingerprint_ref: new_fingerprint.into(),
        resulting_fingerprint_evidence_refs: set(&["canonicalized-result-evidence"]),
        resulting_fields,
        changed_fields: BTreeSet::from([changed_field]),
        authorization: GoalAmendmentAuthorization {
            authorization_ref: format!("authorization:{id}"),
            principal_context_ref: "principal:user-current".into(),
            base_goal_revision: current.goal_revision.clone(),
            base_fingerprint_ref: current.fingerprint_ref.clone(),
            authorized_fields: BTreeSet::from([changed_field]),
            authority_evidence_refs: set(&["user-amendment-authority-evidence"]),
        },
    }
}

fn dependency(
    artifact_ref: &str,
    state: &GoalConstitutionSnapshot,
    scope: GoalDependencyScope,
) -> DependencyRecord {
    DependencyRecord {
        artifact_ref: artifact_ref.into(),
        depends_on: BTreeSet::from([GoalDependencyBinding {
            goal_revision: state.goal_revision.clone(),
            constitution_fingerprint_ref: state.fingerprint_ref.clone(),
            scope,
        }]),
    }
}

#[test]
fn s04_goal_amendment_creates_exact_new_state_and_precise_invalidation() {
    let initial = snapshot(4, "constitution:fp4");
    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();
    let mut dependencies = DependencyIndex::default();
    dependencies
        .register(dependency(
            "whole-plan",
            &initial,
            GoalDependencyScope::WholeConstitution,
        ))
        .unwrap();
    dependencies
        .register(dependency(
            "quality-context",
            &initial,
            GoalDependencyScope::Fields(BTreeSet::from([
                GoalConstitutionField::QualityRequirement,
            ])),
        ))
        .unwrap();
    dependencies
        .register(dependency(
            "open-question-view",
            &initial,
            GoalDependencyScope::Fields(BTreeSet::from([GoalConstitutionField::OpenQuestion])),
        ))
        .unwrap();

    let candidate = amendment(
        &initial,
        "raise-quality",
        GoalPatchRelation::Clarify,
        GoalConstitutionField::QualityRequirement,
        "quality:no-silent-degradation",
        "constitution:fp5",
    );
    let result = constitution
        .commit_amendment(candidate, &dependencies)
        .unwrap();
    let GoalCommitDisposition::Committed(commit) = result else {
        panic!("first amendment must commit");
    };

    assert_eq!(commit.prior_state, initial);
    assert_eq!(commit.current_state.goal_revision, rev(5));
    assert_eq!(commit.current_state.fingerprint_ref, "constitution:fp5");
    assert_eq!(
        commit.changed_fields,
        BTreeSet::from([GoalConstitutionField::QualityRequirement])
    );
    assert_eq!(
        commit.invalidated_dependency_refs,
        set(&["quality-context", "whole-plan"])
    );
    assert!(
        !commit
            .invalidated_dependency_refs
            .contains("open-question-view")
    );
    assert_eq!(constitution.accepted_history().len(), 1);
}

#[test]
fn s04_patch_replay_is_idempotent_even_after_later_revisions() {
    let initial = snapshot(4, "constitution:fp4");
    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();
    let first = amendment(
        &initial,
        "correction-a",
        GoalPatchRelation::Correct,
        GoalConstitutionField::Correction,
        "correction:user-a",
        "constitution:fp5",
    );
    let GoalCommitDisposition::Committed(first_commit) = constitution
        .commit_amendment(first.clone(), &DependencyIndex::default())
        .unwrap()
    else {
        panic!("first amendment must commit");
    };

    let second_base = constitution.current().clone();
    let second = amendment(
        &second_base,
        "decision-a",
        GoalPatchRelation::Add,
        GoalConstitutionField::AcceptedDecision,
        "decision:accepted-a",
        "constitution:fp6",
    );
    constitution
        .commit_amendment(second, &DependencyIndex::default())
        .unwrap();
    assert_eq!(constitution.current().goal_revision, rev(6));

    assert_eq!(
        constitution
            .commit_amendment(first, &DependencyIndex::default())
            .unwrap(),
        GoalCommitDisposition::AlreadyCommitted(first_commit)
    );
    assert_eq!(constitution.current().goal_revision, rev(6));
    assert_eq!(constitution.accepted_history().len(), 2);
}

#[test]
fn s04_same_patch_id_with_different_binding_fails_closed() {
    let initial = snapshot(4, "constitution:fp4");
    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();
    let candidate = amendment(
        &initial,
        "same-id",
        GoalPatchRelation::Correct,
        GoalConstitutionField::Correction,
        "correction:a",
        "constitution:fp5",
    );
    constitution
        .commit_amendment(candidate.clone(), &DependencyIndex::default())
        .unwrap();
    let before = constitution.current().clone();

    let mut conflicting = candidate;
    conflicting.patch.proposed_delta_ref = "delta:different".into();
    assert_eq!(
        constitution.commit_amendment(conflicting, &DependencyIndex::default()),
        Err(GoalCommitError::PatchIdentityConflict)
    );
    assert_eq!(constitution.current(), &before);
}

#[test]
fn s04_stale_revision_or_fingerprint_cannot_commit() {
    let initial = snapshot(4, "constitution:fp4");
    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();

    let mut stale_revision = amendment(
        &initial,
        "stale-revision",
        GoalPatchRelation::Correct,
        GoalConstitutionField::Correction,
        "correction:a",
        "constitution:fp5",
    );
    stale_revision.patch.base_goal_revision = rev(3);
    assert_eq!(
        constitution.commit_amendment(stale_revision, &DependencyIndex::default()),
        Err(GoalCommitError::StaleBaseRevision)
    );

    let mut stale_fingerprint = amendment(
        &initial,
        "stale-fingerprint",
        GoalPatchRelation::Correct,
        GoalConstitutionField::Correction,
        "correction:a",
        "constitution:fp5",
    );
    stale_fingerprint.base_fingerprint_ref = "constitution:wrong".into();
    assert_eq!(
        constitution.commit_amendment(stale_fingerprint, &DependencyIndex::default()),
        Err(GoalCommitError::BaseFingerprintMismatch)
    );
    assert_eq!(constitution.current(), &initial);
}

#[test]
fn s04_changed_fields_are_recomputed_and_narrow_authorization_is_exact() {
    let initial = snapshot(4, "constitution:fp4");
    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();

    let mut underdeclared = amendment(
        &initial,
        "underdeclared",
        GoalPatchRelation::Correct,
        GoalConstitutionField::Correction,
        "correction:a",
        "constitution:fp5",
    );
    underdeclared
        .resulting_fields
        .get_mut(&GoalConstitutionField::QualityRequirement)
        .unwrap()
        .insert("quality:new".into());
    assert_eq!(
        constitution.commit_amendment(underdeclared, &DependencyIndex::default()),
        Err(GoalCommitError::ChangedFieldSetMismatch)
    );

    let mut overbroad_authority = amendment(
        &initial,
        "overbroad-auth",
        GoalPatchRelation::Correct,
        GoalConstitutionField::Correction,
        "correction:a",
        "constitution:fp5",
    );
    overbroad_authority
        .authorization
        .authorized_fields
        .insert(GoalConstitutionField::PermissionBoundary);
    assert_eq!(
        constitution.commit_amendment(overbroad_authority, &DependencyIndex::default()),
        Err(GoalCommitError::AuthorizationMismatch)
    );
    assert_eq!(constitution.current(), &initial);
}

#[test]
fn s04_new_revision_requires_new_fingerprint_and_grounding_evidence() {
    let initial = snapshot(4, "constitution:fp4");
    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();
    let mut candidate = amendment(
        &initial,
        "reuse-fingerprint",
        GoalPatchRelation::Add,
        GoalConstitutionField::AcceptedDecision,
        "decision:a",
        "constitution:fp4",
    );
    assert_eq!(
        constitution.commit_amendment(candidate.clone(), &DependencyIndex::default()),
        Err(GoalCommitError::FingerprintReused)
    );

    candidate.resulting_fingerprint_ref = "constitution:fp5".into();
    candidate.resulting_fingerprint_evidence_refs.clear();
    assert_eq!(
        constitution.commit_amendment(candidate, &DependencyIndex::default()),
        Err(GoalCommitError::FingerprintInvalid)
    );
    assert_eq!(constitution.current(), &initial);
}

#[test]
fn s04_independent_work_is_a_separate_idempotent_handoff_not_a_mutation() {
    let initial = snapshot(4, "constitution:fp4");
    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();
    let independent = patch("new-independent-goal", 4, GoalPatchRelation::Independent);

    let IndependentGoalDisposition::Admitted(handoff) = constitution
        .admit_independent_goal(independent.clone())
        .unwrap()
    else {
        panic!("first independent goal must be admitted");
    };
    assert_eq!(handoff.parent_goal_revision, rev(4));
    assert_eq!(
        handoff.parent_constitution_fingerprint_ref,
        "constitution:fp4"
    );
    assert_eq!(constitution.current(), &initial);
    assert!(constitution.has_independent_handoff("new-independent-goal"));
    assert!(!constitution.has_accepted_patch("new-independent-goal"));

    assert_eq!(
        constitution.admit_independent_goal(independent).unwrap(),
        IndependentGoalDisposition::AlreadyAdmitted(handoff)
    );
    assert_eq!(constitution.accepted_history().len(), 0);
}

#[test]
fn s04_independent_handoff_can_reference_preserved_historical_parent_revision() {
    let initial = snapshot(4, "constitution:fp4");
    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();
    let amendment = amendment(
        &initial,
        "advance-current",
        GoalPatchRelation::Add,
        GoalConstitutionField::AcceptedDecision,
        "decision:a",
        "constitution:fp5",
    );
    constitution
        .commit_amendment(amendment, &DependencyIndex::default())
        .unwrap();

    let IndependentGoalDisposition::Admitted(handoff) = constitution
        .admit_independent_goal(patch(
            "independent-from-old-context",
            4,
            GoalPatchRelation::Independent,
        ))
        .unwrap()
    else {
        panic!("historical independent goal must be admitted");
    };
    assert_eq!(
        handoff.parent_constitution_fingerprint_ref,
        "constitution:fp4"
    );
    assert_eq!(constitution.current().goal_revision, rev(5));
}

#[test]
fn s04_mutation_and_independent_paths_cannot_be_confused() {
    let initial = snapshot(4, "constitution:fp4");
    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();
    let independent_candidate = GoalAmendmentCandidate {
        patch: patch("wrong-path", 4, GoalPatchRelation::Independent),
        ..amendment(
            &initial,
            "placeholder",
            GoalPatchRelation::Correct,
            GoalConstitutionField::Correction,
            "correction:a",
            "constitution:fp5",
        )
    };
    assert_eq!(
        constitution.commit_amendment(independent_candidate, &DependencyIndex::default()),
        Err(GoalCommitError::IndependentRequiresSeparateAdmission)
    );
    assert_eq!(
        constitution.admit_independent_goal(patch(
            "not-independent",
            4,
            GoalPatchRelation::Correct,
        )),
        Err(GoalCommitError::NonIndependentRequired)
    );
}

#[test]
fn s04_supersession_invalidates_every_exact_prior_head_dependency() {
    let initial = snapshot(4, "constitution:fp4");
    let mut dependencies = DependencyIndex::default();
    dependencies
        .register(dependency(
            "quality-only",
            &initial,
            GoalDependencyScope::Fields(BTreeSet::from([
                GoalConstitutionField::QualityRequirement,
            ])),
        ))
        .unwrap();
    dependencies
        .register(dependency(
            "question-only",
            &initial,
            GoalDependencyScope::Fields(BTreeSet::from([GoalConstitutionField::OpenQuestion])),
        ))
        .unwrap();

    let mut constitution = GoalConstitution::new(initial.clone()).unwrap();
    let result = constitution
        .commit_amendment(
            amendment(
                &initial,
                "supersede-a",
                GoalPatchRelation::Supersede,
                GoalConstitutionField::Reason,
                "reason:new-accepted-end",
                "constitution:fp5",
            ),
            &dependencies,
        )
        .unwrap();
    let GoalCommitDisposition::Committed(commit) = result else {
        panic!("supersession must commit");
    };
    assert_eq!(
        commit.invalidated_dependency_refs,
        set(&["quality-only", "question-only"])
    );
}

#[test]
fn s04_dependency_registration_is_single_assignment_and_multi_goal_safe() {
    let initial = snapshot(4, "constitution:fp4");
    let original = dependency("plan-a", &initial, GoalDependencyScope::WholeConstitution);
    let mut dependencies = DependencyIndex::default();
    assert_eq!(dependencies.register(original.clone()), Ok(()));
    assert_eq!(dependencies.register(original), Ok(()));

    let mut conflicting = dependency(
        "plan-a",
        &initial,
        GoalDependencyScope::Fields(BTreeSet::from([GoalConstitutionField::Reason])),
    );
    conflicting.depends_on.insert(GoalDependencyBinding {
        goal_revision: VersionedRef {
            reference: "goal-b".into(),
            version: 2,
        },
        constitution_fingerprint_ref: "goal-b:fp2".into(),
        scope: GoalDependencyScope::WholeConstitution,
    });
    assert_eq!(
        dependencies.register(conflicting),
        Err(DependencyRegistrationError::ConflictingArtifactDefinition)
    );
}

#[test]
fn s04_invalid_dependency_or_initial_constitution_never_enters_state() {
    let initial = snapshot(4, "constitution:fp4");
    let mut dependencies = DependencyIndex::default();
    assert_eq!(
        dependencies.register(DependencyRecord {
            artifact_ref: "".into(),
            depends_on: BTreeSet::from([GoalDependencyBinding {
                goal_revision: rev(4),
                constitution_fingerprint_ref: initial.fingerprint_ref.clone(),
                scope: GoalDependencyScope::WholeConstitution,
            }]),
        }),
        Err(DependencyRegistrationError::EmptyArtifactRef)
    );
    assert_eq!(
        dependencies.register(DependencyRecord {
            artifact_ref: "context-a".into(),
            depends_on: BTreeSet::new(),
        }),
        Err(DependencyRegistrationError::EmptyDependencySet)
    );
    assert_eq!(
        dependencies.register(DependencyRecord {
            artifact_ref: "context-a".into(),
            depends_on: BTreeSet::from([GoalDependencyBinding {
                goal_revision: rev(4),
                constitution_fingerprint_ref: "".into(),
                scope: GoalDependencyScope::WholeConstitution,
            }]),
        }),
        Err(DependencyRegistrationError::InvalidFingerprintRef)
    );

    let mut invalid_initial = initial;
    invalid_initial
        .fields
        .remove(&GoalConstitutionField::PermissionBoundary);
    assert_eq!(
        GoalConstitution::new(invalid_initial),
        Err(GoalCommitError::InvalidInitialState)
    );
}
