extern crate alloc;

use crate::{
    manifest::{ContentDigest, OpaqueVersion, Reference},
    qualification_population::QualificationPlanPopulationIdentity,
    regime::{
        RegimePlanError, SIX_REGIME_PLAN_CANONICAL_PROFILE, SixRegimeQualificationPlan,
        SpecialistRegime, validate_six_regime_qualification_plan,
    },
};
use alloc::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegimePipelineIdentity {
    regime: SpecialistRegime,
    pipeline_ref: Reference,
    pipeline_version: OpaqueVersion,
    content_digest: ContentDigest,
}

impl VerifiedRegimePipelineIdentity {
    pub fn regime(&self) -> SpecialistRegime {
        self.regime
    }

    pub fn pipeline_ref(&self) -> &Reference {
        &self.pipeline_ref
    }

    pub fn pipeline_version(&self) -> &OpaqueVersion {
        &self.pipeline_version
    }

    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }
}

/// Owner-produced proof that the current six-regime preregistration has passed
/// structural/content validation. This type deliberately carries no quality
/// result, provider credential, execution permission, or S05-complete status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSixRegimeQualificationPlan {
    plan_ref: Reference,
    plan_version: OpaqueVersion,
    content_digest: ContentDigest,
    q06_floor_ref: Reference,
    q06_floor_version: OpaqueVersion,
    q06_floor_digest: ContentDigest,
    q07_floor_ref: Reference,
    q07_floor_version: OpaqueVersion,
    q07_floor_digest: ContentDigest,
    sandbox_qualification_population: QualificationPlanPopulationIdentity,
    evidence_grader_qualification_population: QualificationPlanPopulationIdentity,
    pipelines: BTreeMap<SpecialistRegime, VerifiedRegimePipelineIdentity>,
    canonical_profile_ref: &'static str,
}

impl VerifiedSixRegimeQualificationPlan {
    pub fn plan_ref(&self) -> &Reference {
        &self.plan_ref
    }

    pub fn plan_version(&self) -> &OpaqueVersion {
        &self.plan_version
    }

    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    pub fn q06_floor_ref(&self) -> &Reference {
        &self.q06_floor_ref
    }

    pub fn q06_floor_version(&self) -> &OpaqueVersion {
        &self.q06_floor_version
    }

    pub fn q06_floor_digest(&self) -> &ContentDigest {
        &self.q06_floor_digest
    }

    pub fn q07_floor_ref(&self) -> &Reference {
        &self.q07_floor_ref
    }

    pub fn q07_floor_version(&self) -> &OpaqueVersion {
        &self.q07_floor_version
    }

    pub fn q07_floor_digest(&self) -> &ContentDigest {
        &self.q07_floor_digest
    }

    pub fn sandbox_qualification_population(&self) -> &QualificationPlanPopulationIdentity {
        &self.sandbox_qualification_population
    }

    pub fn evidence_grader_qualification_population(&self) -> &QualificationPlanPopulationIdentity {
        &self.evidence_grader_qualification_population
    }

    pub fn pipeline(&self, regime: SpecialistRegime) -> Option<&VerifiedRegimePipelineIdentity> {
        self.pipelines.get(&regime)
    }

    pub fn pipelines(&self) -> impl Iterator<Item = &VerifiedRegimePipelineIdentity> {
        self.pipelines.values()
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

pub fn verify_six_regime_qualification_plan(
    plan: &SixRegimeQualificationPlan,
) -> Result<VerifiedSixRegimeQualificationPlan, RegimePlanError> {
    validate_six_regime_qualification_plan(plan)?;

    let pipelines = plan
        .pipelines
        .iter()
        .map(|pipeline| {
            (
                pipeline.regime,
                VerifiedRegimePipelineIdentity {
                    regime: pipeline.regime,
                    pipeline_ref: pipeline.pipeline_ref.clone(),
                    pipeline_version: pipeline.pipeline_version.clone(),
                    content_digest: pipeline.content_digest.clone(),
                },
            )
        })
        .collect();

    Ok(VerifiedSixRegimeQualificationPlan {
        plan_ref: plan.plan_ref.clone(),
        plan_version: plan.plan_version.clone(),
        content_digest: plan.content_digest.clone(),
        q06_floor_ref: plan.q06_floor_ref.clone(),
        q06_floor_version: plan.q06_floor_version.clone(),
        q06_floor_digest: plan.q06_floor_digest.clone(),
        q07_floor_ref: plan.q07_floor_ref.clone(),
        q07_floor_version: plan.q07_floor_version.clone(),
        q07_floor_digest: plan.q07_floor_digest.clone(),
        sandbox_qualification_population: plan.sandbox_qualification_population.clone(),
        evidence_grader_qualification_population: plan
            .evidence_grader_qualification_population
            .clone(),
        pipelines,
        canonical_profile_ref: SIX_REGIME_PLAN_CANONICAL_PROFILE,
    })
}
