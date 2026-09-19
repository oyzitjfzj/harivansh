extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use sha2::{Digest, Sha256};

use crate::{
    manifest::{ContentDigest, Reference},
    qualification::{OperatingCeiling, QualificationPlan, QualificationPlanIdentity},
};

pub const QUALIFICATION_PLAN_CANONICAL_PROFILE: &str =
    "NOERITH/QUALIFICATION-PLAN/CANONICAL-2026-09";
const DOMAIN: &[u8] = b"NOERITH\0QUALIFICATION-PLAN\0CANONICAL-2026-09\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQualificationPlan {
    identity: QualificationPlanIdentity,
    canonical_profile_ref: &'static str,
}

impl VerifiedQualificationPlan {
    pub fn identity(&self) -> &QualificationPlanIdentity {
        &self.identity
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

pub fn compute_qualification_plan_digest(
    plan: &QualificationPlan,
) -> Result<ContentDigest, QualificationPlanIntegrityError> {
    validate_plan_shape(plan)?;
    let transcript = canonical_qualification_plan_transcript(plan)?;
    let digest = Sha256::digest(&transcript);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut hex, "{byte:02x}")
            .map_err(|_| QualificationPlanIntegrityError::EncodingFailure)?;
    }
    Ok(ContentDigest {
        algorithm_ref: Reference::new(crate::SHA256_ALGORITHM_REF)
            .map_err(|_| QualificationPlanIntegrityError::EncodingFailure)?,
        value: Reference::new(alloc::format!("sha256:{hex}"))
            .map_err(|_| QualificationPlanIntegrityError::EncodingFailure)?,
    })
}

pub fn verify_qualification_plan(
    plan: &QualificationPlan,
) -> Result<VerifiedQualificationPlan, QualificationPlanIntegrityError> {
    if plan.identity.plan_digest.algorithm_ref.as_str() != crate::SHA256_ALGORITHM_REF {
        return Err(QualificationPlanIntegrityError::UnsupportedDigestAlgorithm(
            plan.identity.plan_digest.algorithm_ref.to_string(),
        ));
    }
    let computed = compute_qualification_plan_digest(plan)?;
    if computed != plan.identity.plan_digest {
        return Err(QualificationPlanIntegrityError::DigestMismatch);
    }
    Ok(VerifiedQualificationPlan {
        identity: plan.identity.clone(),
        canonical_profile_ref: QUALIFICATION_PLAN_CANONICAL_PROFILE,
    })
}

pub fn canonical_qualification_plan_transcript(
    plan: &QualificationPlan,
) -> Result<Vec<u8>, QualificationPlanIntegrityError> {
    validate_plan_shape(plan)?;
    let mut encoder = Encoder::new();
    encoder.raw(DOMAIN);

    encoder.tag(0x01);
    encoder.text(plan.identity.plan_ref.as_str())?;
    encoder.tag(0x02);
    encoder.text(plan.identity.plan_version.as_str())?;
    // `plan_digest` is the assertion over this transcript and therefore does
    // not recursively participate in its own digest.

    encoder.tag(0x10);
    encode_ref_set(&mut encoder, &plan.operation_refs)?;
    encoder.tag(0x11);
    encode_ref_set(&mut encoder, &plan.required_evidence_refs)?;
    encoder.tag(0x12);
    encode_ref_set(&mut encoder, &plan.evaluation_corpus_refs)?;
    encoder.tag(0x13);
    encode_ref_set(&mut encoder, &plan.tooling_refs)?;
    encoder.tag(0x14);
    encoder.tag(match plan.requested_ceiling {
        OperatingCeiling::E0ReadOnly => 0,
        OperatingCeiling::E1OpaqueWrite => 1,
        OperatingCeiling::E2DeduplicatedWrite => 2,
        OperatingCeiling::E3ObservableWrite => 3,
        OperatingCeiling::E4CompensatableWrite => 4,
        OperatingCeiling::E5SharedAtomic => 5,
    });
    encoder.tag(0x15);
    encode_ref_set(&mut encoder, &plan.validity_requirement_refs)?;
    encoder.tag(0x16);
    encode_ref_set(&mut encoder, &plan.invalidation_dependency_refs)?;

    Ok(encoder.finish())
}

fn validate_plan_shape(plan: &QualificationPlan) -> Result<(), QualificationPlanIntegrityError> {
    if plan.operation_refs.is_empty()
        || plan.required_evidence_refs.is_empty()
        || plan.evaluation_corpus_refs.is_empty()
        || plan.tooling_refs.is_empty()
        || plan.validity_requirement_refs.is_empty()
        || plan.invalidation_dependency_refs.is_empty()
    {
        return Err(QualificationPlanIntegrityError::InvalidPlan);
    }
    Ok(())
}

fn encode_ref_set(
    encoder: &mut Encoder,
    values: &alloc::collections::BTreeSet<Reference>,
) -> Result<(), QualificationPlanIntegrityError> {
    encoder.count(values.len())?;
    for value in values {
        encoder.text(value.as_str())?;
    }
    Ok(())
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn tag(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn count(&mut self, value: usize) -> Result<(), QualificationPlanIntegrityError> {
        let value =
            u64::try_from(value).map_err(|_| QualificationPlanIntegrityError::LengthOverflow)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), QualificationPlanIntegrityError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualificationPlanIntegrityError {
    InvalidPlan,
    UnsupportedDigestAlgorithm(String),
    DigestMismatch,
    LengthOverflow,
    EncodingFailure,
}

impl fmt::Display for QualificationPlanIntegrityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "qualification plan integrity rejected: {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{manifest::OpaqueVersion, qualification::QualificationPlan};
    use alloc::collections::BTreeSet;

    fn r(value: &str) -> Reference {
        Reference::new(value).unwrap()
    }

    fn v(value: &str) -> OpaqueVersion {
        OpaqueVersion::new(value).unwrap()
    }

    fn refs(values: &[&str]) -> BTreeSet<Reference> {
        values.iter().map(|value| r(value)).collect()
    }

    fn plan() -> QualificationPlan {
        QualificationPlan {
            identity: QualificationPlanIdentity {
                plan_ref: r("plan:send"),
                plan_version: v("opaque/plan-A"),
                plan_digest: ContentDigest {
                    algorithm_ref: r(crate::SHA256_ALGORITHM_REF),
                    value: r("sha256:placeholder"),
                },
            },
            operation_refs: refs(&["operation:send"]),
            required_evidence_refs: refs(&["evidence:schema", "evidence:effects"]),
            evaluation_corpus_refs: refs(&["eval:heldout-A"]),
            tooling_refs: refs(&["tool:conformance-A"]),
            requested_ceiling: OperatingCeiling::E3ObservableWrite,
            validity_requirement_refs: refs(&["validity:security-review"]),
            invalidation_dependency_refs: refs(&[
                "invalidate:manifest",
                "invalidate:adapter",
                "invalidate:environment",
            ]),
        }
    }

    fn finalized_plan() -> QualificationPlan {
        let mut value = plan();
        value.identity.plan_digest = compute_qualification_plan_digest(&value).unwrap();
        value
    }

    #[test]
    fn exact_plan_body_produces_private_verified_identity() {
        let value = finalized_plan();
        let verified = verify_qualification_plan(&value).unwrap();
        assert_eq!(verified.identity(), &value.identity);
        assert_eq!(
            verified.canonical_profile_ref(),
            QUALIFICATION_PLAN_CANONICAL_PROFILE
        );
    }

    #[test]
    fn ceiling_or_requirement_change_invalidates_old_plan_digest() {
        let mut value = finalized_plan();
        value.requested_ceiling = OperatingCeiling::E5SharedAtomic;
        assert_eq!(
            verify_qualification_plan(&value),
            Err(QualificationPlanIntegrityError::DigestMismatch)
        );

        let mut value = finalized_plan();
        value.required_evidence_refs.remove(&r("evidence:effects"));
        assert_eq!(
            verify_qualification_plan(&value),
            Err(QualificationPlanIntegrityError::DigestMismatch)
        );
    }

    #[test]
    fn corpus_tooling_validity_and_invalidation_are_digest_bound() {
        let mut fields = [
            ("corpus", finalized_plan()),
            ("tooling", finalized_plan()),
            ("validity", finalized_plan()),
            ("invalidation", finalized_plan()),
        ];
        fields[0].1.evaluation_corpus_refs.insert(r("eval:changed"));
        fields[1].1.tooling_refs.insert(r("tool:changed"));
        fields[2]
            .1
            .validity_requirement_refs
            .insert(r("validity:changed"));
        fields[3]
            .1
            .invalidation_dependency_refs
            .insert(r("invalidate:changed"));
        for (name, value) in fields {
            assert_eq!(
                verify_qualification_plan(&value),
                Err(QualificationPlanIntegrityError::DigestMismatch),
                "{name} must be content-bound"
            );
        }
    }

    #[test]
    fn set_insertion_order_is_not_identity() {
        let left = plan();
        let mut right = plan();
        right.required_evidence_refs = BTreeSet::new();
        right.required_evidence_refs.insert(r("evidence:effects"));
        right.required_evidence_refs.insert(r("evidence:schema"));
        assert_eq!(
            compute_qualification_plan_digest(&left).unwrap(),
            compute_qualification_plan_digest(&right).unwrap()
        );
    }

    #[test]
    fn unknown_digest_algorithm_fails_closed() {
        let mut value = finalized_plan();
        value.identity.plan_digest.algorithm_ref = r("digest:not-supported");
        assert!(matches!(
            verify_qualification_plan(&value),
            Err(QualificationPlanIntegrityError::UnsupportedDigestAlgorithm(
                _
            ))
        ));
    }
}
