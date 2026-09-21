use noerith_policy::{
    Applicability, PolicyBundle, PolicyRequestProfile, PolicyResult, Scope, TypedObligation,
    compose_policy_decision,
};
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn obligation(kind: &str, digest: &str) -> TypedObligation {
    TypedObligation {
        obligation_type: kind.to_owned(),
        parameters_digest: digest.to_owned(),
    }
}

fn set_obligations(values: &[(&str, &str)]) -> BTreeSet<TypedObligation> {
    values
        .iter()
        .map(|(kind, digest)| obligation(kind, digest))
        .collect()
}

fn scope(ops: &[&str], targets: &[&str], audiences: &[&str]) -> Scope {
    Scope {
        operations: set(ops),
        targets: set(targets),
        audiences: set(audiences),
    }
}

fn bundle(id: &str, result: PolicyResult) -> PolicyBundle {
    PolicyBundle {
        policy_id: id.to_owned(),
        version: "1".to_owned(),
        issuer: "issuer".to_owned(),
        applicability: Applicability::Applicable,
        verified: true,
        effective_now: true,
        protected_mandatory_prohibition: false,
        result,
        obligations: Vec::new(),
        narrowed_scope: None,
        precedence_over: BTreeSet::new(),
    }
}

fn high_impact_profile(ids: &[&str]) -> PolicyRequestProfile {
    PolicyRequestProfile {
        expected_policy_ids: set(ids),
        require_complete_verified_bundle: true,
    }
}

#[test]
fn q04_missing_expired_unverified_or_unknown_policy_fails_indeterminate() {
    let profile = high_impact_profile(&["a"]);
    let missing = compose_policy_decision(&profile, &[]);
    assert_eq!(missing.result, PolicyResult::Indeterminate);

    let mut unverified = bundle("a", PolicyResult::Permit);
    unverified.verified = false;
    assert_eq!(
        compose_policy_decision(&profile, &[unverified]).result,
        PolicyResult::Indeterminate
    );

    let mut expired = bundle("a", PolicyResult::Permit);
    expired.effective_now = false;
    assert_eq!(
        compose_policy_decision(&profile, &[expired]).result,
        PolicyResult::Indeterminate
    );

    let mut unknown = bundle("a", PolicyResult::Permit);
    unknown.applicability = Applicability::Unknown;
    assert_eq!(
        compose_policy_decision(&profile, &[unknown]).result,
        PolicyResult::Indeterminate
    );
}

#[test]
fn q04_wrong_applicability_is_filtered_before_combination() {
    let profile = high_impact_profile(&["permit", "wrong-region"]);
    let mut wrong = bundle("wrong-region", PolicyResult::Deny);
    wrong.applicability = Applicability::NotApplicable;
    let decision =
        compose_policy_decision(&profile, &[bundle("permit", PolicyResult::Permit), wrong]);
    assert_eq!(decision.result, PolicyResult::Permit);
    assert_eq!(decision.applicable_policy_ids, set(&["permit"]));
}

#[test]
fn q04_protected_mandatory_prohibition_cannot_be_overridden_by_permit() {
    let profile = high_impact_profile(&["permit", "mandatory"]);
    let permit = bundle("permit", PolicyResult::Permit);
    let mut mandatory = bundle("mandatory", PolicyResult::Deny);
    mandatory.protected_mandatory_prohibition = true;
    let decision = compose_policy_decision(&profile, &[permit, mandatory]);
    assert_eq!(decision.result, PolicyResult::Deny);
}

#[test]
fn q04_incompatible_policies_without_precedence_are_conflict() {
    let profile = high_impact_profile(&["allow", "deny"]);
    let decision = compose_policy_decision(
        &profile,
        &[
            bundle("allow", PolicyResult::Permit),
            bundle("deny", PolicyResult::Deny),
        ],
    );
    assert_eq!(decision.result, PolicyResult::Conflict);
    assert!(!decision.permits_protected_commit(&BTreeSet::new()));
}

#[test]
fn q04_explicit_precedence_resolves_incompatible_policies_without_latest_wins() {
    let profile = high_impact_profile(&["org", "local"]);
    let mut org = bundle("org", PolicyResult::RequireReview);
    org.precedence_over.insert("local".to_owned());
    let local = bundle("local", PolicyResult::Permit);
    let decision = compose_policy_decision(&profile, &[org, local]);
    assert_eq!(decision.result, PolicyResult::RequireReview);
    assert!(!decision.permits_protected_commit(&BTreeSet::new()));
}

#[test]
fn q04_compatible_obligations_union_and_require_evidence() {
    let profile = high_impact_profile(&["a", "b"]);
    let mut a = bundle("a", PolicyResult::PermitWithObligations);
    a.obligations.push(obligation("audit", "v1"));
    let mut b = bundle("b", PolicyResult::PermitWithObligations);
    b.obligations.push(obligation("notify", "v1"));
    let decision = compose_policy_decision(&profile, &[a, b]);
    assert_eq!(decision.result, PolicyResult::PermitWithObligations);
    assert_eq!(decision.obligations.len(), 2);
    assert!(!decision.permits_protected_commit(&set_obligations(&[("audit", "v1")])),);
    assert!(
        decision.permits_protected_commit(&set_obligations(&[("audit", "v1"), ("notify", "v1")]))
    );
}

#[test]
fn q04_incompatible_typed_obligation_parameters_are_conflict() {
    let profile = high_impact_profile(&["a", "b"]);
    let mut a = bundle("a", PolicyResult::PermitWithObligations);
    a.obligations.push(obligation("retention", "30d"));
    let mut b = bundle("b", PolicyResult::PermitWithObligations);
    b.obligations.push(obligation("retention", "0d"));
    assert_eq!(
        compose_policy_decision(&profile, &[a, b]).result,
        PolicyResult::Conflict
    );
}

#[test]
fn q04_scope_restrictions_intersect_and_narrow_requires_new_candidate() {
    let profile = high_impact_profile(&["a", "b"]);
    let mut a = bundle("a", PolicyResult::Narrow);
    a.narrowed_scope = Some(scope(&["read", "write"], &["r1", "r2"], &["u1", "u2"]));
    let mut b = bundle("b", PolicyResult::Narrow);
    b.narrowed_scope = Some(scope(&["read"], &["r2"], &["u2"]));
    let decision = compose_policy_decision(&profile, &[a, b]);
    assert_eq!(decision.result, PolicyResult::Narrow);
    assert_eq!(
        decision.narrowed_scope,
        Some(scope(&["read"], &["r2"], &["u2"]))
    );
    assert!(!decision.permits_protected_commit(&BTreeSet::new()));
}

#[test]
fn q04_nonpermit_results_never_silently_commit() {
    for result in [
        PolicyResult::Narrow,
        PolicyResult::RequireUserAction,
        PolicyResult::RequireReview,
        PolicyResult::Deny,
        PolicyResult::Defer,
        PolicyResult::Indeterminate,
        PolicyResult::Conflict,
    ] {
        let profile = high_impact_profile(&["p"]);
        let decision = compose_policy_decision(&profile, &[bundle("p", result)]);
        assert_eq!(decision.result, result);
        assert!(!decision.permits_protected_commit(&BTreeSet::new()));
    }
}

#[test]
fn q04_duplicate_policy_identity_with_different_content_is_conflict() {
    let profile = high_impact_profile(&["p"]);
    let first = bundle("p", PolicyResult::Permit);
    let second = bundle("p", PolicyResult::Deny);
    assert_eq!(
        compose_policy_decision(&profile, &[first, second]).result,
        PolicyResult::Conflict
    );
}
