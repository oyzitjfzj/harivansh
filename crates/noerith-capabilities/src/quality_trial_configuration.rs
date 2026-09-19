extern crate alloc;

use crate::{
    candidate_configuration::{
        CandidateConfigurationError, CandidateConfigurationManifest,
        VerifiedCandidateConfigurationManifest, verify_candidate_configuration_manifest,
    },
    manifest::{ContentDigest, OpaqueVersion, Reference},
    quality_floor::{QualityFloorPlan, QualityGateCoverage, QualityGateId},
    quality_trial::{
        QualityTrialError, QualityTrialSet, VerifiedQualityTrialSet,
        compute_quality_trial_set_digest,
    },
    regime::SpecialistRegime,
};
use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
};
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQualityTrialConfigurationBinding {
    trial_set_ref: Reference,
    trial_set_digest: ContentDigest,
    configuration_manifest_ref: Reference,
    configuration_manifest_digest: ContentDigest,
    configuration_identities: BTreeSet<(Reference, OpaqueVersion)>,
    configuration_regime_pairs: BTreeSet<((Reference, OpaqueVersion), SpecialistRegime)>,
}

impl VerifiedQualityTrialConfigurationBinding {
    pub fn trial_set_ref(&self) -> &Reference {
        &self.trial_set_ref
    }

    pub fn trial_set_digest(&self) -> &ContentDigest {
        &self.trial_set_digest
    }

    pub fn configuration_manifest_ref(&self) -> &Reference {
        &self.configuration_manifest_ref
    }

    pub fn configuration_manifest_digest(&self) -> &ContentDigest {
        &self.configuration_manifest_digest
    }

    pub fn configuration_identities(&self) -> &BTreeSet<(Reference, OpaqueVersion)> {
        &self.configuration_identities
    }

    pub fn configuration_regime_pairs(
        &self,
    ) -> &BTreeSet<((Reference, OpaqueVersion), SpecialistRegime)> {
        &self.configuration_regime_pairs
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityTrialConfigurationError {
    WrongGate,
    CandidateManifest(CandidateConfigurationError),
    CandidateManifestWrapperMismatch,
    TrialSet(QualityTrialError),
    TrialSetDigestMismatch,
    TrialSetWrapperMismatch,
    TrialSetPlanMismatch,
    FloorCandidateManifestMismatch,
    TrialCandidateManifestMismatch,
    UndeclaredConfiguration(String),
    ConfigurationDigestMismatch(String),
    ModelBindingMismatch(String),
    ConfigurationPopulationMismatch,
    MissingConfigurationRegimeCoverage {
        configuration_ref: String,
        regime: SpecialistRegime,
    },
}

impl fmt::Display for QualityTrialConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "quality trial configuration binding rejected: {self:?}"
        )
    }
}

/// Bind an already-qualified Q07 repeated-trial population to the exact
/// preregistered candidate-configuration population. This proves experiment
/// subject identity only; it does not compute or authorize any quality/model
/// selection conclusion.
pub fn verify_q07_trial_configuration_binding(
    plan: &QualityFloorPlan,
    trial_set: &QualityTrialSet,
    verified_trial_set: &VerifiedQualityTrialSet,
    manifest: &CandidateConfigurationManifest,
    verified_manifest: &VerifiedCandidateConfigurationManifest,
) -> Result<VerifiedQualityTrialConfigurationBinding, QualityTrialConfigurationError> {
    if plan.gate != QualityGateId::Q07ModelsExperts {
        return Err(QualityTrialConfigurationError::WrongGate);
    }
    let QualityGateCoverage::Q07(coverage) = &plan.coverage else {
        return Err(QualityTrialConfigurationError::WrongGate);
    };

    let current_manifest = verify_candidate_configuration_manifest(manifest)
        .map_err(QualityTrialConfigurationError::CandidateManifest)?;
    if &current_manifest != verified_manifest {
        return Err(QualityTrialConfigurationError::CandidateManifestWrapperMismatch);
    }

    let current_trial_digest = compute_quality_trial_set_digest(trial_set)
        .map_err(QualityTrialConfigurationError::TrialSet)?;
    if current_trial_digest != trial_set.content_digest {
        return Err(QualityTrialConfigurationError::TrialSetDigestMismatch);
    }
    if verified_trial_set.trial_set_ref() != &trial_set.trial_set_ref
        || verified_trial_set.trial_set_version() != &trial_set.trial_set_version
        || verified_trial_set.content_digest() != &current_trial_digest
    {
        return Err(QualityTrialConfigurationError::TrialSetWrapperMismatch);
    }
    if verified_trial_set.plan_ref() != &plan.plan_ref
        || verified_trial_set.plan_version() != &plan.plan_version
        || verified_trial_set.plan_digest() != &plan.content_digest
        || verified_trial_set.gate() != plan.gate
        || trial_set.plan_ref != plan.plan_ref
        || trial_set.plan_version != plan.plan_version
        || trial_set.plan_digest != plan.content_digest
        || trial_set.gate != plan.gate
    {
        return Err(QualityTrialConfigurationError::TrialSetPlanMismatch);
    }

    let manifest_evidence_ref = verified_manifest.content_digest().value.clone();
    if coverage.candidate_configuration_manifest_ref != manifest_evidence_ref {
        return Err(QualityTrialConfigurationError::FloorCandidateManifestMismatch);
    }
    if trial_set.candidate_configuration_manifest_ref.as_ref() != Some(&manifest_evidence_ref) {
        return Err(QualityTrialConfigurationError::TrialCandidateManifestMismatch);
    }

    let mut used_configurations = BTreeSet::new();
    let mut configuration_regime_pairs = BTreeSet::new();
    for trial in &trial_set.trials {
        let Some(configuration) = verified_manifest.configuration(
            &trial.candidate_configuration_ref,
            &trial.candidate_configuration_version,
        ) else {
            return Err(QualityTrialConfigurationError::UndeclaredConfiguration(
                trial.candidate_configuration_ref.to_string(),
            ));
        };

        if configuration.content_digest() != &trial.candidate_configuration_digest {
            return Err(QualityTrialConfigurationError::ConfigurationDigestMismatch(
                trial.candidate_configuration_ref.to_string(),
            ));
        }
        let model = configuration.model();
        if trial.provider_ref != model.provider_ref
            || trial.model_ref != model.model_ref
            || trial.model_version != model.model_version
            || trial.adapter_ref != model.adapter_ref
            || trial.adapter_version != model.adapter_version
        {
            return Err(QualityTrialConfigurationError::ModelBindingMismatch(
                trial.trial_ref.to_string(),
            ));
        }

        let identity = (
            trial.candidate_configuration_ref.clone(),
            trial.candidate_configuration_version.clone(),
        );
        used_configurations.insert(identity.clone());
        configuration_regime_pairs.insert((identity, trial.regime));
    }

    let declared_configurations: BTreeSet<(Reference, OpaqueVersion)> = verified_manifest
        .configurations()
        .map(|configuration| {
            (
                configuration.configuration_ref().clone(),
                configuration.configuration_version().clone(),
            )
        })
        .collect();
    if used_configurations != declared_configurations {
        return Err(QualityTrialConfigurationError::ConfigurationPopulationMismatch);
    }

    // Q07's source contract evaluates the candidate model/topology/effort/
    // context/retrieval settings on all six specialist-regime datasets. A
    // configuration observed only in one easy regime cannot stand in for that
    // cross-regime qualification population.
    for configuration in &declared_configurations {
        for regime in SpecialistRegime::ALL {
            if !configuration_regime_pairs.contains(&(configuration.clone(), regime)) {
                return Err(
                    QualityTrialConfigurationError::MissingConfigurationRegimeCoverage {
                        configuration_ref: configuration.0.to_string(),
                        regime,
                    },
                );
            }
        }
    }

    Ok(VerifiedQualityTrialConfigurationBinding {
        trial_set_ref: trial_set.trial_set_ref.clone(),
        trial_set_digest: current_trial_digest,
        configuration_manifest_ref: verified_manifest.manifest_ref().clone(),
        configuration_manifest_digest: verified_manifest.content_digest().clone(),
        configuration_identities: used_configurations,
        configuration_regime_pairs,
    })
}
