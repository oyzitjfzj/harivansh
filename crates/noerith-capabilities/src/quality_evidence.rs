extern crate alloc;

use crate::{
    evaluation_corpus::{
        EvaluationCorpusDefinition, EvaluationCorpusError, EvaluationPartition,
        VerifiedEvaluationCorpus, verify_evaluation_corpus,
    },
    execution_environment::VerifiedExecutionEnvironment,
    grader::VerifiedGradeRecord,
    manifest::Reference,
    quality_floor::{
        QualityFloorError, QualityFloorPlan, QualityGateCoverage, QualityGateId,
        verify_quality_floor_plan,
    },
    quality_result::{
        QualityCoverageItem, QualityExperimentBinding, QualityFloorResultSet, QualityResultError,
        VerifiedQualityFloorResult, compute_quality_floor_result_digest,
        verify_quality_floor_result,
    },
    quality_trial::{
        ExactCorpusEvidenceIdentity, ExactEnvironmentEvidenceIdentity, ExactGradeEvidenceIdentity,
        ExecutionIdentity, VerifiedQualityTrialSet,
    },
    regime::SpecialistRegime,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

pub const QUALITY_EVIDENCE_CANONICAL_PROFILE: &str = "NOERITH/QUALITY-EVIDENCE/CANONICAL-2026-09";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityCorpusEvidence {
    pub corpus: EvaluationCorpusDefinition,
    pub verified: VerifiedEvaluationCorpus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityEvidenceBundle {
    pub corpus_evidence: Vec<QualityCorpusEvidence>,
    pub grade_records: Vec<VerifiedGradeRecord>,
    pub execution_environments: Vec<VerifiedExecutionEnvironment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQualityEvidenceBundle {
    gate: QualityGateId,
    corpus_refs: BTreeSet<Reference>,
    exact_corpus_identities: BTreeSet<ExactCorpusEvidenceIdentity>,
    grade_refs: BTreeSet<Reference>,
    exact_grade_identities: BTreeSet<ExactGradeEvidenceIdentity>,
    environment_refs: BTreeSet<Reference>,
    exact_environment_identities: BTreeSet<ExactEnvironmentEvidenceIdentity>,
    heldout_regimes: BTreeSet<SpecialistRegime>,
    canonical_profile_ref: &'static str,
}

impl VerifiedQualityEvidenceBundle {
    pub fn gate(&self) -> QualityGateId {
        self.gate
    }

    pub fn corpus_refs(&self) -> &BTreeSet<Reference> {
        &self.corpus_refs
    }

    pub(crate) fn exact_corpus_identities(&self) -> &BTreeSet<ExactCorpusEvidenceIdentity> {
        &self.exact_corpus_identities
    }

    pub fn grade_refs(&self) -> &BTreeSet<Reference> {
        &self.grade_refs
    }

    pub(crate) fn exact_grade_identities(&self) -> &BTreeSet<ExactGradeEvidenceIdentity> {
        &self.exact_grade_identities
    }

    pub fn environment_refs(&self) -> &BTreeSet<Reference> {
        &self.environment_refs
    }

    pub(crate) fn exact_environment_identities(
        &self,
    ) -> &BTreeSet<ExactEnvironmentEvidenceIdentity> {
        &self.exact_environment_identities
    }

    pub fn heldout_regimes(&self) -> &BTreeSet<SpecialistRegime> {
        &self.heldout_regimes
    }

    pub fn canonical_profile_ref(&self) -> &'static str {
        self.canonical_profile_ref
    }
}

/// Stronger composition wrapper that proves the exact hard-floor result and
/// the verified corpus/grader/environment scope are backed by the exact
/// content-bound repeated-trial sets cited by the result. This is still not a
/// public-release or model-lock authorization object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQualityEvidenceWithTrials {
    result: VerifiedQualityFloorResult,
    scope: VerifiedQualityEvidenceBundle,
    trial_evidence_refs: BTreeSet<Reference>,
}

impl VerifiedQualityEvidenceWithTrials {
    pub fn result(&self) -> &VerifiedQualityFloorResult {
        &self.result
    }

    pub fn scope(&self) -> &VerifiedQualityEvidenceBundle {
        &self.scope
    }

    pub fn trial_evidence_refs(&self) -> &BTreeSet<Reference> {
        &self.trial_evidence_refs
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityEvidenceError {
    FloorPlan(QualityFloorError),
    Result(QualityResultError),
    ResultDigestMismatch,
    ResultPlanMismatch,
    ResultExperimentMismatch,
    Corpus(EvaluationCorpusError),
    CorpusWrapperMismatch(String),
    UndeclaredCorpus(String),
    DuplicateCorpus(String),
    DuplicateTask(String),
    ContaminationFamilyCrossesPartitions(String),
    DuplicateGrade(String),
    MissingCitedGrade(String),
    UnreferencedGrade(String),
    UnknownGradeTask(String),
    GradeRegimeMismatch(String),
    DevelopmentEvidenceRejected(String),
    Q07RequiresHeldout(String),
    UndeclaredGraderPlan(String),
    DuplicateEnvironment(String),
    UnknownEnvironment(String),
    UndeclaredEnvironmentPlan(String),
    MissingEnvironmentEvidence(String),
    UnreferencedEnvironment(String),
    MissingQ07Regime(SpecialistRegime),
    EmptyBundle,
}

impl fmt::Display for QualityEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "quality evidence rejected: {self:?}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityTrialEvidenceBindingError {
    Scope(QualityEvidenceError),
    Result(QualityResultError),
    MissingTrialEvidence,
    DuplicateTrialEvidence(String),
    TrialPlanMismatch(String),
    MissingCitedTrialEvidence(String),
    UnreferencedTrialEvidence(String),
    TrialGradeSetMismatch,
    TrialGradeIdentityMismatch,
    TrialCorpusSetMismatch,
    TrialCorpusIdentityMismatch,
    TrialEnvironmentSetMismatch,
    TrialEnvironmentIdentityMismatch,
    DuplicatePopulationTrialRef(String),
    DuplicatePopulationExecutionIdentity,
    PopulationGradeEvidenceReused(String),
    PopulationCorpusIdentityConflict(String),
    PopulationEnvironmentIdentityConflict(String),
    Q07RegimeTrialCoverageMismatch(SpecialistRegime),
    Q07RepeatedTrialCoverageMismatch,
    Q07CandidateConfigurationCoverageMismatch,
}

impl fmt::Display for QualityTrialEvidenceBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "quality trial evidence binding rejected: {self:?}"
        )
    }
}

#[derive(Clone, Copy)]
struct TaskLocation<'a> {
    partition: EvaluationPartition,
    regime: SpecialistRegime,
    corpus_ref: &'a Reference,
}

/// Canonical content-bound reference a result uses to cite the exact verified
/// trial evidence composition. The raw trial-set digest remains a separate
/// preregistered declaration identity.
pub fn quality_trial_evidence_ref(trial_set: &VerifiedQualityTrialSet) -> Reference {
    trial_set.verification_digest().value.clone()
}

pub fn verify_quality_evidence_bundle(
    plan: &QualityFloorPlan,
    result: &QualityFloorResultSet,
    bundle: &QualityEvidenceBundle,
) -> Result<VerifiedQualityEvidenceBundle, QualityEvidenceError> {
    verify_quality_floor_plan(plan).map_err(QualityEvidenceError::FloorPlan)?;
    let computed_result =
        compute_quality_floor_result_digest(result).map_err(QualityEvidenceError::Result)?;
    if computed_result != result.content_digest {
        return Err(QualityEvidenceError::ResultDigestMismatch);
    }
    if result.plan_ref != plan.plan_ref
        || result.plan_version != plan.plan_version
        || result.plan_digest != plan.content_digest
        || result.gate != plan.gate
    {
        return Err(QualityEvidenceError::ResultPlanMismatch);
    }
    if !experiment_matches_plan(&result.experiment, plan) {
        return Err(QualityEvidenceError::ResultExperimentMismatch);
    }
    if bundle.corpus_evidence.is_empty()
        || bundle.grade_records.is_empty()
        || bundle.execution_environments.is_empty()
    {
        return Err(QualityEvidenceError::EmptyBundle);
    }

    let declared_corpora = declared_corpus_refs(plan);
    let mut corpus_refs = BTreeSet::new();
    let mut tasks = BTreeMap::<String, TaskLocation<'_>>::new();
    let mut contamination_partitions = BTreeMap::<Reference, EvaluationPartition>::new();

    for evidence in &bundle.corpus_evidence {
        let current =
            verify_evaluation_corpus(&evidence.corpus).map_err(QualityEvidenceError::Corpus)?;
        if current != evidence.verified {
            return Err(QualityEvidenceError::CorpusWrapperMismatch(
                evidence.corpus.corpus_ref.to_string(),
            ));
        }
        if !declared_corpora.contains(&evidence.corpus.corpus_ref) {
            return Err(QualityEvidenceError::UndeclaredCorpus(
                evidence.corpus.corpus_ref.to_string(),
            ));
        }
        if !corpus_refs.insert(evidence.corpus.corpus_ref.clone()) {
            return Err(QualityEvidenceError::DuplicateCorpus(
                evidence.corpus.corpus_ref.to_string(),
            ));
        }

        for task in &evidence.corpus.tasks {
            if tasks
                .insert(
                    task.task_ref.to_string(),
                    TaskLocation {
                        partition: task.partition,
                        regime: task.regime,
                        corpus_ref: &evidence.corpus.corpus_ref,
                    },
                )
                .is_some()
            {
                return Err(QualityEvidenceError::DuplicateTask(
                    task.task_ref.to_string(),
                ));
            }
            if let Some(previous) = contamination_partitions
                .insert(task.contamination_family_ref.clone(), task.partition)
                && previous != task.partition
            {
                return Err(QualityEvidenceError::ContaminationFamilyCrossesPartitions(
                    task.contamination_family_ref.to_string(),
                ));
            }
        }
    }

    let cited_grade_refs: BTreeSet<Reference> = result
        .criterion_results
        .iter()
        .flat_map(|criterion| criterion.grader_result_refs.iter().cloned())
        .collect();

    let mut grades = BTreeMap::<Reference, &VerifiedGradeRecord>::new();
    for grade in &bundle.grade_records {
        if grades.insert(grade.grade_ref().clone(), grade).is_some() {
            return Err(QualityEvidenceError::DuplicateGrade(
                grade.grade_ref().to_string(),
            ));
        }
    }
    for reference in &cited_grade_refs {
        if !grades.contains_key(reference) {
            return Err(QualityEvidenceError::MissingCitedGrade(
                reference.to_string(),
            ));
        }
    }
    for reference in grades.keys() {
        if !cited_grade_refs.contains(reference) {
            return Err(QualityEvidenceError::UnreferencedGrade(
                reference.to_string(),
            ));
        }
    }

    let mut environments = BTreeMap::<(String, String), &VerifiedExecutionEnvironment>::new();
    for environment in &bundle.execution_environments {
        let key = (
            environment.subject().environment_ref.to_string(),
            String::from(environment.subject().environment_version.as_str()),
        );
        if environments.insert(key.clone(), environment).is_some() {
            return Err(QualityEvidenceError::DuplicateEnvironment(alloc::format!(
                "{}@{}", key.0, key.1
            )));
        }
        if !plan
            .environment_qualification_plan_refs
            .contains(&environment.plan_identity().plan_ref)
        {
            return Err(QualityEvidenceError::UndeclaredEnvironmentPlan(
                environment.plan_identity().plan_ref.to_string(),
            ));
        }
    }

    let mut used_environment_keys = BTreeSet::<(String, String)>::new();
    let mut used_corpus_refs = BTreeSet::new();
    let mut heldout_regimes = BTreeSet::new();

    for grade_ref in &cited_grade_refs {
        let grade = grades
            .get(grade_ref)
            .expect("cited grade existence already verified");
        if !plan
            .grader_plan_refs
            .contains(&grade.grader_plan_identity().plan_ref)
        {
            return Err(QualityEvidenceError::UndeclaredGraderPlan(
                grade.grader_plan_identity().plan_ref.to_string(),
            ));
        }

        let task = tasks
            .get(grade.subject().task_ref.as_str())
            .ok_or_else(|| {
                QualityEvidenceError::UnknownGradeTask(grade.subject().task_ref.to_string())
            })?;
        if grade.subject().regime != task.regime {
            return Err(QualityEvidenceError::GradeRegimeMismatch(
                grade.grade_ref().to_string(),
            ));
        }
        if task.partition == EvaluationPartition::Development {
            return Err(QualityEvidenceError::DevelopmentEvidenceRejected(
                grade.grade_ref().to_string(),
            ));
        }
        if plan.gate == QualityGateId::Q07ModelsExperts
            && task.partition != EvaluationPartition::Heldout
        {
            return Err(QualityEvidenceError::Q07RequiresHeldout(
                grade.grade_ref().to_string(),
            ));
        }
        if task.partition == EvaluationPartition::Heldout {
            heldout_regimes.insert(task.regime);
        }
        used_corpus_refs.insert((*task.corpus_ref).clone());

        let environment_key = (
            grade.subject().environment_ref.to_string(),
            String::from(grade.subject().environment_version.as_str()),
        );
        let environment = environments.get(&environment_key).ok_or_else(|| {
            QualityEvidenceError::UnknownEnvironment(alloc::format!(
                "{}@{}",
                environment_key.0,
                environment_key.1
            ))
        })?;
        used_environment_keys.insert(environment_key);

        let has_environment_evidence = result.criterion_results.iter().any(|criterion| {
            criterion.grader_result_refs.contains(grade_ref)
                && !criterion
                    .environment_evidence_refs
                    .is_disjoint(environment.evidence_refs())
        });
        if !has_environment_evidence {
            return Err(QualityEvidenceError::MissingEnvironmentEvidence(
                grade_ref.to_string(),
            ));
        }
    }

    for (key, environment) in &environments {
        if !used_environment_keys.contains(key) {
            return Err(QualityEvidenceError::UnreferencedEnvironment(
                alloc::format!(
                    "{}@{}",
                    environment.subject().environment_ref,
                    environment.subject().environment_version.as_str()
                ),
            ));
        }
    }

    if plan.gate == QualityGateId::Q07ModelsExperts {
        for regime in SpecialistRegime::ALL {
            if !heldout_regimes.contains(&regime) {
                return Err(QualityEvidenceError::MissingQ07Regime(regime));
            }
        }
    }

    let environment_refs = bundle
        .execution_environments
        .iter()
        .map(|environment| environment.subject().environment_ref.clone())
        .collect();

    let exact_corpus_identities: BTreeSet<ExactCorpusEvidenceIdentity> = bundle
        .corpus_evidence
        .iter()
        .filter(|evidence| used_corpus_refs.contains(&evidence.corpus.corpus_ref))
        .map(|evidence| ExactCorpusEvidenceIdentity::from_verified(&evidence.verified))
        .collect();
    let exact_grade_identities: BTreeSet<ExactGradeEvidenceIdentity> = grades
        .values()
        .map(|grade| ExactGradeEvidenceIdentity::from_verified(grade))
        .collect();
    let exact_environment_identities: BTreeSet<ExactEnvironmentEvidenceIdentity> =
        used_environment_keys
            .iter()
            .map(|key| {
                ExactEnvironmentEvidenceIdentity::from_verified(
                    *environments
                        .get(key)
                        .expect("used environment identity came from accepted evidence"),
                )
            })
            .collect();

    Ok(VerifiedQualityEvidenceBundle {
        gate: plan.gate,
        corpus_refs: used_corpus_refs,
        exact_corpus_identities,
        grade_refs: cited_grade_refs,
        exact_grade_identities,
        environment_refs,
        exact_environment_identities,
        heldout_regimes,
        canonical_profile_ref: QUALITY_EVIDENCE_CANONICAL_PROFILE,
    })
}

/// Bind the scope proof and hard-floor result to exact verified repeated-trial
/// sets. This closes the seam where `QualityCriterionResult.trial_evidence_refs`
/// could otherwise be arbitrary non-empty references.
///
/// Q07 regime/repeated-trial/candidate-configuration coverage is also forced to
/// cite these exact content-bound trial identities. Axis-specific statistical
/// interpretation remains an external preregistered analysis obligation; this
/// gate does not pretend a trial-set digest proves that analysis by itself.
pub fn verify_quality_evidence_with_trials(
    plan: &QualityFloorPlan,
    result: &QualityFloorResultSet,
    bundle: &QualityEvidenceBundle,
    trial_sets: &[VerifiedQualityTrialSet],
) -> Result<VerifiedQualityEvidenceWithTrials, QualityTrialEvidenceBindingError> {
    let scope = verify_quality_evidence_bundle(plan, result, bundle)
        .map_err(QualityTrialEvidenceBindingError::Scope)?;
    let verified_plan = verify_quality_floor_plan(plan).map_err(|error| {
        QualityTrialEvidenceBindingError::Result(QualityResultError::FloorPlan(error))
    })?;
    let verified_result = verify_quality_floor_result(plan, &verified_plan, result)
        .map_err(QualityTrialEvidenceBindingError::Result)?;

    let cited_trial_evidence_refs: BTreeSet<Reference> = result
        .criterion_results
        .iter()
        .flat_map(|criterion| criterion.trial_evidence_refs.iter().cloned())
        .collect();
    if cited_trial_evidence_refs.is_empty() || trial_sets.is_empty() {
        return Err(QualityTrialEvidenceBindingError::MissingTrialEvidence);
    }

    let mut by_evidence_ref = BTreeMap::<Reference, &VerifiedQualityTrialSet>::new();
    for trial_set in trial_sets {
        if trial_set.plan_ref() != &plan.plan_ref
            || trial_set.plan_version() != &plan.plan_version
            || trial_set.plan_digest() != &plan.content_digest
            || trial_set.gate() != plan.gate
        {
            return Err(QualityTrialEvidenceBindingError::TrialPlanMismatch(
                trial_set.trial_set_ref().to_string(),
            ));
        }
        let evidence_ref = quality_trial_evidence_ref(trial_set);
        if by_evidence_ref
            .insert(evidence_ref.clone(), trial_set)
            .is_some()
        {
            return Err(QualityTrialEvidenceBindingError::DuplicateTrialEvidence(
                evidence_ref.to_string(),
            ));
        }
    }

    for reference in &cited_trial_evidence_refs {
        if !by_evidence_ref.contains_key(reference) {
            return Err(QualityTrialEvidenceBindingError::MissingCitedTrialEvidence(
                reference.to_string(),
            ));
        }
    }
    for reference in by_evidence_ref.keys() {
        if !cited_trial_evidence_refs.contains(reference) {
            return Err(QualityTrialEvidenceBindingError::UnreferencedTrialEvidence(
                reference.to_string(),
            ));
        }
    }

    let mut population_trial_refs = BTreeSet::<Reference>::new();
    let mut population_execution_identities = BTreeSet::<ExecutionIdentity>::new();
    let mut population_grade_refs = BTreeSet::<Reference>::new();
    let mut population_grade_identities = BTreeSet::<ExactGradeEvidenceIdentity>::new();
    let mut population_corpora =
        BTreeMap::<_, ExactCorpusEvidenceIdentity>::new();
    let mut population_environments =
        BTreeMap::<_, ExactEnvironmentEvidenceIdentity>::new();

    for trial_set in trial_sets {
        for trial_ref in trial_set.trial_refs() {
            if !population_trial_refs.insert(trial_ref.clone()) {
                return Err(QualityTrialEvidenceBindingError::DuplicatePopulationTrialRef(
                    trial_ref.to_string(),
                ));
            }
        }
        for execution_identity in trial_set.execution_identities() {
            if !population_execution_identities.insert(execution_identity.clone()) {
                return Err(
                    QualityTrialEvidenceBindingError::DuplicatePopulationExecutionIdentity,
                );
            }
        }
        for grade_ref in trial_set.grade_refs() {
            if !population_grade_refs.insert(grade_ref.clone()) {
                return Err(QualityTrialEvidenceBindingError::PopulationGradeEvidenceReused(
                    grade_ref.to_string(),
                ));
            }
        }
        population_grade_identities.extend(
            trial_set
                .exact_grade_identities()
                .iter()
                .cloned(),
        );

        for identity in trial_set.exact_corpus_identities() {
            let key = identity.logical_key();
            if let Some(previous) = population_corpora.insert(key.clone(), identity.clone())
                && previous != *identity
            {
                return Err(
                    QualityTrialEvidenceBindingError::PopulationCorpusIdentityConflict(
                        key.0.to_string(),
                    ),
                );
            }
        }
        for identity in trial_set.exact_environment_identities() {
            let key = identity.logical_key();
            if let Some(previous) = population_environments.insert(key.clone(), identity.clone())
                && previous != *identity
            {
                return Err(
                    QualityTrialEvidenceBindingError::PopulationEnvironmentIdentityConflict(
                        key.0.to_string(),
                    ),
                );
            }
        }
    }

    if &population_grade_refs != scope.grade_refs() {
        return Err(QualityTrialEvidenceBindingError::TrialGradeSetMismatch);
    }
    if &population_grade_identities != scope.exact_grade_identities() {
        return Err(QualityTrialEvidenceBindingError::TrialGradeIdentityMismatch);
    }

    let trial_corpus_refs: BTreeSet<Reference> = trial_sets
        .iter()
        .flat_map(|trial_set| trial_set.corpus_refs().iter().cloned())
        .collect();
    if &trial_corpus_refs != scope.corpus_refs() {
        return Err(QualityTrialEvidenceBindingError::TrialCorpusSetMismatch);
    }
    let population_corpus_identities: BTreeSet<ExactCorpusEvidenceIdentity> =
        population_corpora.into_values().collect();
    if &population_corpus_identities != scope.exact_corpus_identities() {
        return Err(QualityTrialEvidenceBindingError::TrialCorpusIdentityMismatch);
    }

    let trial_environment_refs: BTreeSet<Reference> = trial_sets
        .iter()
        .flat_map(|trial_set| trial_set.environment_refs().iter().cloned())
        .collect();
    if &trial_environment_refs != scope.environment_refs() {
        return Err(QualityTrialEvidenceBindingError::TrialEnvironmentSetMismatch);
    }
    let population_environment_identities: BTreeSet<ExactEnvironmentEvidenceIdentity> =
        population_environments.into_values().collect();
    if &population_environment_identities != scope.exact_environment_identities() {
        return Err(QualityTrialEvidenceBindingError::TrialEnvironmentIdentityMismatch);
    }

    if plan.gate == QualityGateId::Q07ModelsExperts {
        for regime in SpecialistRegime::ALL {
            let expected: BTreeSet<Reference> = by_evidence_ref
                .iter()
                .filter_map(|(reference, trial_set)| {
                    trial_set
                        .regimes()
                        .contains(&regime)
                        .then_some(reference.clone())
                })
                .collect();
            let observed = coverage_evidence_refs(result, QualityCoverageItem::Q07Regime(regime));
            if observed != Some(&expected) {
                return Err(
                    QualityTrialEvidenceBindingError::Q07RegimeTrialCoverageMismatch(regime),
                );
            }
        }

        let all_trial_evidence: BTreeSet<Reference> = by_evidence_ref.keys().cloned().collect();
        if coverage_evidence_refs(result, QualityCoverageItem::Q07RepeatedTrials)
            != Some(&all_trial_evidence)
        {
            return Err(QualityTrialEvidenceBindingError::Q07RepeatedTrialCoverageMismatch);
        }
        if coverage_evidence_refs(result, QualityCoverageItem::Q07CandidateConfiguration)
            != Some(&all_trial_evidence)
        {
            return Err(
                QualityTrialEvidenceBindingError::Q07CandidateConfigurationCoverageMismatch,
            );
        }
    }

    Ok(VerifiedQualityEvidenceWithTrials {
        result: verified_result,
        scope,
        trial_evidence_refs: cited_trial_evidence_refs,
    })
}

fn coverage_evidence_refs(
    result: &QualityFloorResultSet,
    item: QualityCoverageItem,
) -> Option<&BTreeSet<Reference>> {
    result
        .coverage_results
        .iter()
        .find(|entry| entry.item == item)
        .map(|entry| &entry.evidence_refs)
}

fn experiment_matches_plan(experiment: &QualityExperimentBinding, plan: &QualityFloorPlan) -> bool {
    experiment.evaluation_corpus_refs == plan.evaluation_corpus_refs
        && experiment.grader_plan_refs == plan.grader_plan_refs
        && experiment.environment_qualification_plan_refs
            == plan.environment_qualification_plan_refs
        && experiment.trial_protocol_ref == plan.trial_protocol_ref
        && experiment.statistical_model_ref == plan.statistical_model_ref
        && experiment.uncertainty_policy_ref == plan.uncertainty_policy_ref
        && experiment.seed_manifest_ref == plan.seed_manifest_ref
        && experiment.hardware_manifest_ref == plan.hardware_manifest_ref
        && experiment.confidence_target_ref == plan.confidence_target_ref
        && experiment.analysis_plan_ref == plan.analysis_plan_ref
        && experiment.preregistration_evidence_ref == plan.preregistration_evidence_ref
}

fn declared_corpus_refs(plan: &QualityFloorPlan) -> BTreeSet<Reference> {
    let mut declared = plan.evaluation_corpus_refs.clone();
    match &plan.coverage {
        QualityGateCoverage::Q06(coverage) => {
            declared.insert(coverage.long_history_memory_corpus_ref.clone());
            declared.insert(coverage.multi_session_reasoning_corpus_ref.clone());
            declared.insert(coverage.correction_case_corpus_ref.clone());
            declared.insert(coverage.poisoning_case_corpus_ref.clone());
            declared.insert(coverage.lifecycle_case_corpus_ref.clone());
            declared.insert(coverage.abstention_unknown_case_corpus_ref.clone());
        }
        QualityGateCoverage::Q07(coverage) => {
            declared.extend(coverage.heldout_regime_corpus_refs.values().cloned());
        }
    }
    declared
}
