#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyResult {
    Permit,
    PermitWithObligations,
    Narrow,
    RequireUserAction,
    RequireReview,
    Deny,
    Defer,
    Indeterminate,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applicability {
    Applicable,
    NotApplicable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypedObligation {
    pub obligation_type: String,
    pub parameters_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub operations: BTreeSet<String>,
    pub targets: BTreeSet<String>,
    pub audiences: BTreeSet<String>,
}

impl Scope {
    fn intersection(&self, other: &Self) -> Self {
        Self {
            operations: self
                .operations
                .intersection(&other.operations)
                .cloned()
                .collect(),
            targets: self.targets.intersection(&other.targets).cloned().collect(),
            audiences: self
                .audiences
                .intersection(&other.audiences)
                .cloned()
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundle {
    pub policy_id: String,
    pub version: String,
    pub issuer: String,
    pub applicability: Applicability,
    pub verified: bool,
    pub effective_now: bool,
    pub protected_mandatory_prohibition: bool,
    pub result: PolicyResult,
    pub obligations: Vec<TypedObligation>,
    pub narrowed_scope: Option<Scope>,
    pub precedence_over: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequestProfile {
    pub expected_policy_ids: BTreeSet<String>,
    pub require_complete_verified_bundle: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositePolicyDecision {
    pub result: PolicyResult,
    pub applicable_policy_ids: BTreeSet<String>,
    pub obligations: BTreeSet<TypedObligation>,
    pub narrowed_scope: Option<Scope>,
    pub reason_codes: BTreeSet<String>,
}

impl CompositePolicyDecision {
    pub fn permits_protected_commit(&self, satisfied: &BTreeSet<TypedObligation>) -> bool {
        match self.result {
            PolicyResult::Permit => self.obligations.is_empty(),
            PolicyResult::PermitWithObligations => self.obligations.is_subset(satisfied),
            PolicyResult::Narrow
            | PolicyResult::RequireUserAction
            | PolicyResult::RequireReview
            | PolicyResult::Deny
            | PolicyResult::Defer
            | PolicyResult::Indeterminate
            | PolicyResult::Conflict => false,
        }
    }
}

fn decision(
    result: PolicyResult,
    applicable_policy_ids: BTreeSet<String>,
    obligations: BTreeSet<TypedObligation>,
    narrowed_scope: Option<Scope>,
    reason: &str,
) -> CompositePolicyDecision {
    CompositePolicyDecision {
        result,
        applicable_policy_ids,
        obligations,
        narrowed_scope,
        reason_codes: BTreeSet::from([reason.to_owned()]),
    }
}

fn precedence_reaches(policies: &BTreeMap<String, PolicyBundle>, from: &str, to: &str) -> bool {
    let mut queue = VecDeque::from([from.to_owned()]);
    let mut seen = BTreeSet::new();
    while let Some(current) = queue.pop_front() {
        if !seen.insert(current.clone()) {
            continue;
        }
        let Some(policy) = policies.get(&current) else {
            continue;
        };
        for next in &policy.precedence_over {
            if next == to {
                return true;
            }
            if policies.contains_key(next) {
                queue.push_back(next.clone());
            }
        }
    }
    false
}

fn safely_composable(left: PolicyResult, right: PolicyResult) -> bool {
    use PolicyResult::{Narrow, Permit, PermitWithObligations};
    let left_safe = matches!(left, Permit | PermitWithObligations | Narrow);
    let right_safe = matches!(right, Permit | PermitWithObligations | Narrow);
    (left_safe && right_safe) || left == right
}

fn merge_obligations<'a>(
    policies: impl Iterator<Item = &'a PolicyBundle>,
) -> Result<BTreeSet<TypedObligation>, ()> {
    let mut by_type = BTreeMap::<String, String>::new();
    let mut merged = BTreeSet::new();
    for policy in policies {
        for obligation in &policy.obligations {
            if let Some(existing) = by_type.get(&obligation.obligation_type) {
                if existing != &obligation.parameters_digest {
                    return Err(());
                }
            } else {
                by_type.insert(
                    obligation.obligation_type.clone(),
                    obligation.parameters_digest.clone(),
                );
            }
            merged.insert(obligation.clone());
        }
    }
    Ok(merged)
}

pub fn compose_policy_decision(
    profile: &PolicyRequestProfile,
    bundles: &[PolicyBundle],
) -> CompositePolicyDecision {
    let mut unique = BTreeMap::<String, PolicyBundle>::new();
    for bundle in bundles {
        match unique.get(&bundle.policy_id) {
            Some(existing) if existing != bundle => {
                return decision(
                    PolicyResult::Conflict,
                    BTreeSet::new(),
                    BTreeSet::new(),
                    None,
                    "DUPLICATE_POLICY_ID_CONFLICT",
                );
            }
            Some(_) => {}
            None => {
                unique.insert(bundle.policy_id.clone(), bundle.clone());
            }
        }
    }

    if profile.require_complete_verified_bundle
        && profile
            .expected_policy_ids
            .iter()
            .any(|policy_id| !unique.contains_key(policy_id))
    {
        return decision(
            PolicyResult::Indeterminate,
            BTreeSet::new(),
            BTreeSet::new(),
            None,
            "EXPECTED_POLICY_MISSING",
        );
    }

    let mut applicable = BTreeMap::<String, PolicyBundle>::new();
    for (policy_id, bundle) in unique {
        match bundle.applicability {
            Applicability::NotApplicable => continue,
            Applicability::Unknown if profile.require_complete_verified_bundle => {
                return decision(
                    PolicyResult::Indeterminate,
                    BTreeSet::new(),
                    BTreeSet::new(),
                    None,
                    "POLICY_APPLICABILITY_UNKNOWN",
                );
            }
            Applicability::Unknown => continue,
            Applicability::Applicable => {}
        }
        if profile.require_complete_verified_bundle && (!bundle.verified || !bundle.effective_now) {
            return decision(
                PolicyResult::Indeterminate,
                BTreeSet::new(),
                BTreeSet::new(),
                None,
                "POLICY_UNVERIFIED_OR_EXPIRED",
            );
        }
        if bundle.verified && bundle.effective_now {
            applicable.insert(policy_id, bundle);
        }
    }

    let applicable_ids: BTreeSet<String> = applicable.keys().cloned().collect();
    if applicable
        .values()
        .any(|bundle| bundle.protected_mandatory_prohibition)
    {
        return decision(
            PolicyResult::Deny,
            applicable_ids,
            BTreeSet::new(),
            None,
            "PROTECTED_MANDATORY_PROHIBITION",
        );
    }
    if applicable.is_empty() {
        return decision(
            PolicyResult::Indeterminate,
            applicable_ids,
            BTreeSet::new(),
            None,
            "NO_APPLICABLE_VERIFIED_POLICY",
        );
    }

    let ids: Vec<String> = applicable.keys().cloned().collect();
    let mut dominated = BTreeSet::new();
    for left_index in 0..ids.len() {
        for right_index in (left_index + 1)..ids.len() {
            let left_id = &ids[left_index];
            let right_id = &ids[right_index];
            let left = applicable.get(left_id).expect("id came from map keys");
            let right = applicable.get(right_id).expect("id came from map keys");
            if safely_composable(left.result, right.result) {
                continue;
            }
            match (
                precedence_reaches(&applicable, left_id, right_id),
                precedence_reaches(&applicable, right_id, left_id),
            ) {
                (true, false) => {
                    dominated.insert(right_id.clone());
                }
                (false, true) => {
                    dominated.insert(left_id.clone());
                }
                _ => {
                    return decision(
                        PolicyResult::Conflict,
                        applicable_ids,
                        BTreeSet::new(),
                        None,
                        "UNRESOLVED_POLICY_CONFLICT",
                    );
                }
            }
        }
    }

    let survivors: Vec<&PolicyBundle> = applicable
        .iter()
        .filter(|(policy_id, _)| !dominated.contains(*policy_id))
        .map(|(_, bundle)| bundle)
        .collect();
    if survivors.is_empty() {
        return decision(
            PolicyResult::Conflict,
            applicable_ids,
            BTreeSet::new(),
            None,
            "PRECEDENCE_CYCLE_OR_EMPTY_SURVIVOR_SET",
        );
    }

    let obligations = match merge_obligations(survivors.iter().copied()) {
        Ok(value) => value,
        Err(()) => {
            return decision(
                PolicyResult::Conflict,
                applicable_ids,
                BTreeSet::new(),
                None,
                "INCOMPATIBLE_TYPED_OBLIGATIONS",
            );
        }
    };

    let mut narrowed_scope: Option<Scope> = None;
    for bundle in &survivors {
        if let Some(candidate) = &bundle.narrowed_scope {
            narrowed_scope = Some(match narrowed_scope {
                None => candidate.clone(),
                Some(current) => current.intersection(candidate),
            });
        }
    }

    let result_set: BTreeSet<PolicyResult> = survivors.iter().map(|bundle| bundle.result).collect();
    let safe_family = result_set.iter().all(|result| {
        matches!(
            result,
            PolicyResult::Permit | PolicyResult::PermitWithObligations | PolicyResult::Narrow
        )
    });
    let result = if safe_family {
        if narrowed_scope.is_some() || result_set.contains(&PolicyResult::Narrow) {
            PolicyResult::Narrow
        } else if !obligations.is_empty()
            || result_set.contains(&PolicyResult::PermitWithObligations)
        {
            PolicyResult::PermitWithObligations
        } else {
            PolicyResult::Permit
        }
    } else if result_set.len() == 1 {
        *result_set.iter().next().expect("nonempty survivor set")
    } else {
        return decision(
            PolicyResult::Conflict,
            applicable_ids,
            BTreeSet::new(),
            None,
            "UNCOMPOSABLE_SURVIVING_RESULTS",
        );
    };

    decision(
        result,
        applicable_ids,
        obligations,
        narrowed_scope,
        "POLICY_COMPOSITION_COMPLETE",
    )
}
