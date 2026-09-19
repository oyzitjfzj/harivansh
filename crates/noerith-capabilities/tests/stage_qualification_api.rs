use std::collections::BTreeMap;

use noerith_capabilities::{
    Q07ComparisonAxis, Reference, S05StageQualificationError, S05StageQualificationRequest,
    SixRegimeQualificationPlan, VerifiedCapabilityCatalog, VerifiedEvidenceGrader,
    VerifiedQ07ComparisonAnalysisEvidence, VerifiedQualificationPlanPopulation,
    VerifiedQualityAnalysisEvidence, VerifiedQualityEvidenceWithTrials,
    VerifiedQualityTrialConfigurationBinding, VerifiedRegimeCapabilityConformance,
    VerifiedRegimeExecutionEvidence, VerifiedS05DomainCapabilities,
    VerifiedSixRegimeQualificationPlan, verify_s05_stage_qualification,
};

type ExpectedStageVerifier =
    fn(
        &S05StageQualificationRequest,
        &SixRegimeQualificationPlan,
        &VerifiedSixRegimeQualificationPlan,
        &VerifiedQualificationPlanPopulation,
        &VerifiedQualificationPlanPopulation,
        &[VerifiedRegimeExecutionEvidence],
        &[VerifiedRegimeCapabilityConformance],
        &VerifiedCapabilityCatalog,
        &[VerifiedEvidenceGrader],
        &VerifiedQualityEvidenceWithTrials,
        &VerifiedQualityAnalysisEvidence,
        &VerifiedQualityEvidenceWithTrials,
        &VerifiedQualityAnalysisEvidence,
        &VerifiedQ07ComparisonAnalysisEvidence,
        &[VerifiedQualityTrialConfigurationBinding],
    ) -> Result<VerifiedS05DomainCapabilities, S05StageQualificationError>;

#[test]
fn final_stage_api_requires_owner_verified_q07_comparison_evidence() {
    let _: ExpectedStageVerifier = verify_s05_stage_qualification;
}

#[test]
fn final_stage_wrapper_exposes_exact_q07_axis_analysis_evidence() {
    fn assert_api(value: &VerifiedS05DomainCapabilities) {
        let _: &BTreeMap<Q07ComparisonAxis, Reference> = value.q07_comparison_axis_evidence_refs();
    }

    let _ = assert_api as fn(&VerifiedS05DomainCapabilities);
}
