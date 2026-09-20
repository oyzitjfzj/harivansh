use crate::{AdaptivePolicyRef, ContextCandidateDescriptor};
use std::collections::{BTreeMap, BTreeSet};

/// Semantic role inside a compiled context. These roles classify information;
/// none of them carries executable authority or permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContextInformationClass {
    ContentData,
    InstructionCandidate,
    Evidence,
    PrincipalAuthorityContext,
}

/// Exact label state on one side of a derived-context transition.
///
/// Trust, data-use and lifecycle live on the candidate contract; taint,
/// sensitivity, principal scope and expiry live on the delivery contract. They
/// remain separate axes, but a transition proof binds their exact combination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextDeliveryLabelSnapshot {
    pub trust_label_ref: String,
    pub data_use_label_ref: String,
    pub lifecycle_label_ref: String,
    pub taint_label_ref: String,
    pub sensitivity_label_ref: String,
    pub principal_scope_ref: Option<String>,
    pub expiry_ref: Option<String>,
}

impl ContextDeliveryLabelSnapshot {
    pub fn capture(
        candidate: &ContextCandidateDescriptor,
        boundary: &ContextDeliveryBoundary,
    ) -> Result<Self, ContextDeliveryError> {
        if candidate.identity().item_ref != boundary.item_ref {
            return Err(ContextDeliveryError::UnknownCandidate);
        }
        Ok(snapshot(candidate, boundary))
    }
}

/// Evidence that one exact derived child was allowed to cross the delivery
/// labels inherited from one exact direct parent.
///
/// The validator checks identity, before/after label state and qualification. It
/// deliberately does not invent a universal ordering for opaque trust/privacy
/// labels; the qualified policy/evidence layer owns that semantic decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextLabelTransitionEvidence {
    pub parent_item_ref: String,
    pub child_item_ref: String,
    pub parent_labels: ContextDeliveryLabelSnapshot,
    pub child_labels: ContextDeliveryLabelSnapshot,
    pub transition_policy: AdaptivePolicyRef,
    pub evidence_refs: BTreeSet<String>,
}

/// Delivery-time metadata that must survive context selection separately from
/// free-form content. Candidate source/version/trust/data-use/lifecycle fields
/// remain on `ContextCandidateDescriptor`; this record adds independent
/// taint/sensitivity/expiry and semantic-use axes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextDeliveryBoundary {
    pub item_ref: String,
    pub information_classes: BTreeSet<ContextInformationClass>,
    pub taint_label_ref: String,
    pub sensitivity_label_ref: String,
    pub principal_scope_ref: Option<String>,
    pub authority_context_evidence_ref: Option<String>,
    pub expiry_ref: Option<String>,
    pub label_transition_evidence: Vec<ContextLabelTransitionEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextDeliveryError {
    EmptyField(&'static str),
    UnknownCandidate,
    DuplicateBoundary,
    IncompleteBoundarySet,
    MissingInformationClass,
    PrincipalAuthorityContextUngrounded,
    DerivedLabelTransitionIncomplete,
    DerivedLabelTransitionDuplicateParent,
    DerivedLabelTransitionUnknownParent,
    DerivedLabelTransitionChildMismatch,
    DerivedLabelTransitionParentStateMismatch,
    DerivedLabelTransitionChildStateMismatch,
    DerivedLabelTransitionUnqualified,
    DerivedLabelTransitionEvidenceMissing,
    ExactSourceTransitionEvidenceUnexpected,
    StructuredFactTransitionEvidenceUnexpected,
}

fn optional_ref_is_empty(value: Option<&str>) -> bool {
    value.is_some_and(|reference| reference.trim().is_empty())
}

fn transition_policy_is_qualified(policy: &AdaptivePolicyRef) -> bool {
    !policy.policy_ref.trim().is_empty()
        && !policy.version.trim().is_empty()
        && !policy.qualification_evidence_refs.is_empty()
        && policy
            .qualification_evidence_refs
            .iter()
            .all(|reference| !reference.trim().is_empty())
}

/// Require one and only one delivery boundary for every candidate, then bind
/// each derived transition to the actual current parent and child label states.
/// Validation is deliberately two-pass so vector ordering cannot change the
/// result.
pub fn validate_context_delivery_boundaries(
    candidates: &[ContextCandidateDescriptor],
    boundaries: &[ContextDeliveryBoundary],
) -> Result<(), ContextDeliveryError> {
    let candidate_by_ref: BTreeMap<&str, &ContextCandidateDescriptor> = candidates
        .iter()
        .map(|candidate| (candidate.identity().item_ref.as_str(), candidate))
        .collect();
    if candidate_by_ref.len() != candidates.len() {
        return Err(ContextDeliveryError::IncompleteBoundarySet);
    }

    let mut boundary_by_ref = BTreeMap::<&str, &ContextDeliveryBoundary>::new();
    for boundary in boundaries {
        validate_boundary_shape(boundary)?;
        if !candidate_by_ref.contains_key(boundary.item_ref.as_str()) {
            return Err(ContextDeliveryError::UnknownCandidate);
        }
        if boundary_by_ref
            .insert(boundary.item_ref.as_str(), boundary)
            .is_some()
        {
            return Err(ContextDeliveryError::DuplicateBoundary);
        }
    }
    if boundary_by_ref.len() != candidate_by_ref.len() {
        return Err(ContextDeliveryError::IncompleteBoundarySet);
    }

    for boundary in boundaries {
        let candidate = candidate_by_ref
            .get(boundary.item_ref.as_str())
            .expect("total candidate map already validated");

        if boundary
            .information_classes
            .contains(&ContextInformationClass::PrincipalAuthorityContext)
            && (boundary.principal_scope_ref.is_none()
                || boundary.authority_context_evidence_ref.is_none())
        {
            return Err(ContextDeliveryError::PrincipalAuthorityContextUngrounded);
        }

        match candidate {
            ContextCandidateDescriptor::Exact(_) => {
                if !boundary.label_transition_evidence.is_empty() {
                    return Err(ContextDeliveryError::ExactSourceTransitionEvidenceUnexpected);
                }
            }
            ContextCandidateDescriptor::Structured(_) => {
                if !boundary.label_transition_evidence.is_empty() {
                    return Err(ContextDeliveryError::StructuredFactTransitionEvidenceUnexpected);
                }
            }
            ContextCandidateDescriptor::Derived(derived) => {
                let expected_child = snapshot(candidate, boundary);
                let mut transition_parents = BTreeSet::new();

                for transition in &boundary.label_transition_evidence {
                    if transition.parent_item_ref.trim().is_empty() {
                        return Err(ContextDeliveryError::EmptyField(
                            "delivery.transition.parent_item_ref",
                        ));
                    }
                    if transition.child_item_ref.trim().is_empty() {
                        return Err(ContextDeliveryError::EmptyField(
                            "delivery.transition.child_item_ref",
                        ));
                    }
                    if transition.child_item_ref != boundary.item_ref {
                        return Err(ContextDeliveryError::DerivedLabelTransitionChildMismatch);
                    }
                    if !derived
                        .parent_item_refs
                        .contains(transition.parent_item_ref.as_str())
                    {
                        return Err(ContextDeliveryError::DerivedLabelTransitionUnknownParent);
                    }
                    if !transition_parents.insert(transition.parent_item_ref.as_str()) {
                        return Err(ContextDeliveryError::DerivedLabelTransitionDuplicateParent);
                    }
                    if !transition_policy_is_qualified(&transition.transition_policy) {
                        return Err(ContextDeliveryError::DerivedLabelTransitionUnqualified);
                    }
                    if transition.evidence_refs.is_empty()
                        || transition
                            .evidence_refs
                            .iter()
                            .any(|reference| reference.trim().is_empty())
                    {
                        return Err(ContextDeliveryError::DerivedLabelTransitionEvidenceMissing);
                    }

                    let Some(parent_candidate) =
                        candidate_by_ref.get(transition.parent_item_ref.as_str())
                    else {
                        return Err(ContextDeliveryError::DerivedLabelTransitionUnknownParent);
                    };
                    let Some(parent_boundary) =
                        boundary_by_ref.get(transition.parent_item_ref.as_str())
                    else {
                        return Err(ContextDeliveryError::DerivedLabelTransitionUnknownParent);
                    };
                    let expected_parent = snapshot(parent_candidate, parent_boundary);
                    if transition.parent_labels != expected_parent {
                        return Err(
                            ContextDeliveryError::DerivedLabelTransitionParentStateMismatch,
                        );
                    }
                    if transition.child_labels != expected_child {
                        return Err(ContextDeliveryError::DerivedLabelTransitionChildStateMismatch);
                    }
                }

                let expected_parents: BTreeSet<&str> = derived
                    .parent_item_refs
                    .iter()
                    .map(String::as_str)
                    .collect();
                if transition_parents != expected_parents {
                    return Err(ContextDeliveryError::DerivedLabelTransitionIncomplete);
                }
            }
        }
    }
    Ok(())
}

fn validate_boundary_shape(boundary: &ContextDeliveryBoundary) -> Result<(), ContextDeliveryError> {
    if boundary.item_ref.trim().is_empty() {
        return Err(ContextDeliveryError::EmptyField("delivery.item_ref"));
    }
    if boundary.information_classes.is_empty() {
        return Err(ContextDeliveryError::MissingInformationClass);
    }
    if boundary.taint_label_ref.trim().is_empty() {
        return Err(ContextDeliveryError::EmptyField("delivery.taint_label_ref"));
    }
    if boundary.sensitivity_label_ref.trim().is_empty() {
        return Err(ContextDeliveryError::EmptyField(
            "delivery.sensitivity_label_ref",
        ));
    }
    if optional_ref_is_empty(boundary.principal_scope_ref.as_deref()) {
        return Err(ContextDeliveryError::EmptyField(
            "delivery.principal_scope_ref",
        ));
    }
    if optional_ref_is_empty(boundary.authority_context_evidence_ref.as_deref()) {
        return Err(ContextDeliveryError::EmptyField(
            "delivery.authority_context_evidence_ref",
        ));
    }
    if optional_ref_is_empty(boundary.expiry_ref.as_deref()) {
        return Err(ContextDeliveryError::EmptyField("delivery.expiry_ref"));
    }
    Ok(())
}

fn snapshot(
    candidate: &ContextCandidateDescriptor,
    boundary: &ContextDeliveryBoundary,
) -> ContextDeliveryLabelSnapshot {
    let labels = candidate.boundary();
    ContextDeliveryLabelSnapshot {
        trust_label_ref: labels.trust_label_ref.clone(),
        data_use_label_ref: labels.data_use_label_ref.clone(),
        lifecycle_label_ref: labels.lifecycle_label_ref.clone(),
        taint_label_ref: boundary.taint_label_ref.clone(),
        sensitivity_label_ref: boundary.sensitivity_label_ref.clone(),
        principal_scope_ref: boundary.principal_scope_ref.clone(),
        expiry_ref: boundary.expiry_ref.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ContextBoundaryLabels, ContextItemIdentity, ContextItemKind, DerivedContextProjection,
        ExactSourceProjection, StructuredFactProjection,
    };

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn policy(name: &str) -> AdaptivePolicyRef {
        AdaptivePolicyRef {
            policy_ref: name.to_owned(),
            version: "qualified-1".into(),
            qualification_evidence_refs: set(&["policy-qualification"]),
        }
    }

    fn exact(item_ref: &str, trust: &str) -> ContextCandidateDescriptor {
        ContextCandidateDescriptor::Exact(ExactSourceProjection {
            identity: ContextItemIdentity {
                tenant_ref: "tenant-a".into(),
                purpose_ref: "purpose-a".into(),
                item_ref: item_ref.into(),
                kind: ContextItemKind::ExactSourceSpan,
            },
            source_ref: format!("source-{item_ref}"),
            source_version: 1,
            span_ref: format!("span-{item_ref}"),
            content_digest: format!("digest-{item_ref}"),
            lineage_ref: format!("lineage-{item_ref}"),
            boundary: ContextBoundaryLabels {
                trust_label_ref: trust.into(),
                data_use_label_ref: "use-private".into(),
                lifecycle_label_ref: "current@4".into(),
            },
            validity_dependency_refs: set(&["frontier@4"]),
        })
    }

    fn structured() -> ContextCandidateDescriptor {
        ContextCandidateDescriptor::Structured(StructuredFactProjection {
            identity: ContextItemIdentity {
                tenant_ref: "tenant-a".into(),
                purpose_ref: "purpose-a".into(),
                item_ref: "fact-a".into(),
                kind: ContextItemKind::StructuredFact,
            },
            fact_ref: "fact:decision-a".into(),
            fact_version: 2,
            content_digest: "fact-digest-a".into(),
            provenance_refs: set(&["source-a@1"]),
            boundary: ContextBoundaryLabels {
                trust_label_ref: "trust-verified-fact".into(),
                data_use_label_ref: "use-private".into(),
                lifecycle_label_ref: "current@4".into(),
            },
            validity_dependency_refs: set(&["frontier@4"]),
        })
    }

    fn derived(item_ref: &str, parents: &[&str]) -> ContextCandidateDescriptor {
        ContextCandidateDescriptor::Derived(DerivedContextProjection {
            identity: ContextItemIdentity {
                tenant_ref: "tenant-a".into(),
                purpose_ref: "purpose-a".into(),
                item_ref: item_ref.into(),
                kind: ContextItemKind::DerivedView,
            },
            content_digest: format!("digest-{item_ref}"),
            parent_item_refs: set(parents),
            provenance_ref: format!("provenance-{item_ref}"),
            transform_policy: policy("transform"),
            boundary: ContextBoundaryLabels {
                trust_label_ref: "trust-derived".into(),
                data_use_label_ref: "use-private".into(),
                lifecycle_label_ref: "current@4".into(),
            },
            validity_dependency_refs: set(&["frontier@4"]),
        })
    }

    fn boundary(item_ref: &str) -> ContextDeliveryBoundary {
        ContextDeliveryBoundary {
            item_ref: item_ref.into(),
            information_classes: BTreeSet::from([
                ContextInformationClass::ContentData,
                ContextInformationClass::Evidence,
            ]),
            taint_label_ref: "taint-untrusted".into(),
            sensitivity_label_ref: "sensitivity-private".into(),
            principal_scope_ref: Some("principal-a".into()),
            authority_context_evidence_ref: None,
            expiry_ref: Some("expiry@4".into()),
            label_transition_evidence: Vec::new(),
        }
    }

    fn bound_transition(
        parent: &ContextCandidateDescriptor,
        parent_boundary: &ContextDeliveryBoundary,
        child: &ContextCandidateDescriptor,
        child_boundary: &ContextDeliveryBoundary,
    ) -> ContextLabelTransitionEvidence {
        ContextLabelTransitionEvidence {
            parent_item_ref: parent.identity().item_ref.clone(),
            child_item_ref: child.identity().item_ref.clone(),
            parent_labels: ContextDeliveryLabelSnapshot::capture(parent, parent_boundary).unwrap(),
            child_labels: ContextDeliveryLabelSnapshot::capture(child, child_boundary).unwrap(),
            transition_policy: policy("label-transition"),
            evidence_refs: set(&["label-flow-proof-a"]),
        }
    }

    #[test]
    fn delivery_boundaries_are_total_unique_and_order_independent() {
        let candidates = vec![exact("a", "trust-a"), exact("b", "trust-b")];
        assert!(
            validate_context_delivery_boundaries(&candidates, &[boundary("b"), boundary("a")])
                .is_ok()
        );
        assert_eq!(
            validate_context_delivery_boundaries(&candidates, &[boundary("a")]),
            Err(ContextDeliveryError::IncompleteBoundarySet)
        );
        assert_eq!(
            validate_context_delivery_boundaries(&candidates, &[boundary("a"), boundary("a")]),
            Err(ContextDeliveryError::DuplicateBoundary)
        );
    }

    #[test]
    fn principal_authority_context_requires_scope_and_independent_evidence() {
        let candidates = vec![exact("a", "trust-a")];
        let mut metadata = boundary("a");
        metadata.information_classes =
            BTreeSet::from([ContextInformationClass::PrincipalAuthorityContext]);
        metadata.authority_context_evidence_ref = None;
        assert_eq!(
            validate_context_delivery_boundaries(&candidates, &[metadata.clone()]),
            Err(ContextDeliveryError::PrincipalAuthorityContextUngrounded)
        );
        metadata.principal_scope_ref = None;
        metadata.authority_context_evidence_ref = Some("authority-proof".into());
        assert_eq!(
            validate_context_delivery_boundaries(&candidates, &[metadata.clone()]),
            Err(ContextDeliveryError::PrincipalAuthorityContextUngrounded)
        );
        metadata.principal_scope_ref = Some("principal-a".into());
        assert!(validate_context_delivery_boundaries(&candidates, &[metadata]).is_ok());
    }

    #[test]
    fn derived_transition_binds_exact_parent_and_child_label_states() {
        let parent = exact("a", "trust-user-source");
        let child = derived("derived-a", &["a"]);
        let parent_boundary = boundary("a");
        let mut child_boundary = boundary("derived-a");
        child_boundary.label_transition_evidence = vec![bound_transition(
            &parent,
            &parent_boundary,
            &child,
            &child_boundary,
        )];
        let candidates = vec![child.clone(), parent.clone()];
        assert!(
            validate_context_delivery_boundaries(
                &candidates,
                &[child_boundary.clone(), parent_boundary.clone()]
            )
            .is_ok()
        );

        let mut replayed_parent = parent.clone();
        if let ContextCandidateDescriptor::Exact(value) = &mut replayed_parent {
            value.boundary.trust_label_ref = "trust-reclassified".into();
        }
        assert_eq!(
            validate_context_delivery_boundaries(
                &[child.clone(), replayed_parent],
                &[child_boundary.clone(), parent_boundary.clone()]
            ),
            Err(ContextDeliveryError::DerivedLabelTransitionParentStateMismatch)
        );

        let mut changed_child_boundary = child_boundary.clone();
        changed_child_boundary.sensitivity_label_ref = "sensitivity-public".into();
        assert_eq!(
            validate_context_delivery_boundaries(
                &[parent.clone(), child.clone()],
                &[parent_boundary.clone(), changed_child_boundary]
            ),
            Err(ContextDeliveryError::DerivedLabelTransitionChildStateMismatch)
        );
    }

    #[test]
    fn transition_cannot_be_replayed_on_another_child() {
        let parent = exact("a", "trust-a");
        let child = derived("derived-a", &["a"]);
        let other_child = derived("derived-b", &["a"]);
        let parent_boundary = boundary("a");
        let child_boundary = boundary("derived-a");
        let mut other_boundary = boundary("derived-b");
        other_boundary.label_transition_evidence = vec![bound_transition(
            &parent,
            &parent_boundary,
            &child,
            &child_boundary,
        )];
        assert_eq!(
            validate_context_delivery_boundaries(
                &[parent, other_child],
                &[parent_boundary, other_boundary]
            ),
            Err(ContextDeliveryError::DerivedLabelTransitionChildMismatch)
        );
    }

    #[test]
    fn multi_parent_derivation_requires_exact_evidence_for_every_parent() {
        let left = exact("left", "trust-left");
        let right = exact("right", "trust-right");
        let child = derived("joined", &["left", "right"]);
        let left_boundary = boundary("left");
        let mut right_boundary = boundary("right");
        right_boundary.taint_label_ref = "taint-high".into();
        let mut child_boundary = boundary("joined");
        child_boundary.label_transition_evidence = vec![
            bound_transition(&left, &left_boundary, &child, &child_boundary),
            bound_transition(&right, &right_boundary, &child, &child_boundary),
        ];
        assert!(
            validate_context_delivery_boundaries(
                &[child, right, left],
                &[child_boundary, left_boundary, right_boundary]
            )
            .is_ok()
        );
    }

    #[test]
    fn derived_transition_rejects_missing_duplicate_unknown_or_unqualified_parent_evidence() {
        let parent = exact("a", "trust-a");
        let child = derived("derived-a", &["a"]);
        let parent_boundary = boundary("a");
        let mut child_boundary = boundary("derived-a");
        assert_eq!(
            validate_context_delivery_boundaries(
                &[parent.clone(), child.clone()],
                &[parent_boundary.clone(), child_boundary.clone()]
            ),
            Err(ContextDeliveryError::DerivedLabelTransitionIncomplete)
        );

        let transition = bound_transition(&parent, &parent_boundary, &child, &child_boundary);
        child_boundary.label_transition_evidence = vec![transition.clone(), transition.clone()];
        assert_eq!(
            validate_context_delivery_boundaries(
                &[parent.clone(), child.clone()],
                &[parent_boundary.clone(), child_boundary.clone()]
            ),
            Err(ContextDeliveryError::DerivedLabelTransitionDuplicateParent)
        );

        let mut unknown = transition.clone();
        unknown.parent_item_ref = "missing".into();
        child_boundary.label_transition_evidence = vec![unknown];
        assert_eq!(
            validate_context_delivery_boundaries(
                &[parent.clone(), child.clone()],
                &[parent_boundary.clone(), child_boundary.clone()]
            ),
            Err(ContextDeliveryError::DerivedLabelTransitionUnknownParent)
        );

        let mut unqualified = transition;
        unqualified
            .transition_policy
            .qualification_evidence_refs
            .clear();
        child_boundary.label_transition_evidence = vec![unqualified];
        assert_eq!(
            validate_context_delivery_boundaries(
                &[parent, child],
                &[parent_boundary, child_boundary]
            ),
            Err(ContextDeliveryError::DerivedLabelTransitionUnqualified)
        );
    }

    #[test]
    fn exact_and_structured_candidates_cannot_claim_derived_transition_evidence() {
        let parent = exact("a", "trust-a");
        let child = derived("derived-a", &["a"]);
        let parent_boundary = boundary("a");
        let child_boundary = boundary("derived-a");
        let transition = bound_transition(&parent, &parent_boundary, &child, &child_boundary);

        let mut exact_boundary = parent_boundary.clone();
        exact_boundary.label_transition_evidence = vec![transition.clone()];
        assert_eq!(
            validate_context_delivery_boundaries(&[parent], &[exact_boundary]),
            Err(ContextDeliveryError::ExactSourceTransitionEvidenceUnexpected)
        );

        let fact = structured();
        let mut fact_boundary = boundary("fact-a");
        let mut fact_transition = transition;
        fact_transition.child_item_ref = "fact-a".into();
        fact_boundary.label_transition_evidence = vec![fact_transition];
        assert_eq!(
            validate_context_delivery_boundaries(&[fact], &[fact_boundary]),
            Err(ContextDeliveryError::StructuredFactTransitionEvidenceUnexpected)
        );
    }
}
