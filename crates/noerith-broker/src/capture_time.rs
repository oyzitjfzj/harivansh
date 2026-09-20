use crate::CaptureTimeEvidence;
use noerith_effects::SynchronizationState;

/// Fresh evidence sampled only after an adapter has returned.
///
/// This type intentionally has no legacy-scalar variant: new provider-return
/// evidence cannot be created by relabelling an old naked timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostReturnTimeEvidence {
    Observed {
        unix_time_ms: u64,
        uncertainty_before_ms: u64,
        uncertainty_after_ms: u64,
        clock_source: String,
        synchronization_state: SynchronizationState,
    },
    Unavailable {
        reason: String,
        evidence_ref: String,
    },
}

impl PostReturnTimeEvidence {
    pub(crate) fn conservative_processing_time_ms(&self) -> Option<u64> {
        match self {
            Self::Observed {
                unix_time_ms,
                uncertainty_after_ms,
                synchronization_state: SynchronizationState::Synced,
                ..
            } => unix_time_ms.checked_add(*uncertainty_after_ms),
            Self::Observed { .. } | Self::Unavailable { .. } => None,
        }
    }
}

impl From<PostReturnTimeEvidence> for CaptureTimeEvidence {
    fn from(value: PostReturnTimeEvidence) -> Self {
        match value {
            PostReturnTimeEvidence::Observed {
                unix_time_ms,
                uncertainty_before_ms,
                uncertainty_after_ms,
                clock_source,
                synchronization_state,
            } => Self::Observed {
                unix_time_ms,
                uncertainty_before_ms,
                uncertainty_after_ms,
                clock_source,
                synchronization_state,
            },
            PostReturnTimeEvidence::Unavailable {
                reason,
                evidence_ref,
            } => Self::Unavailable {
                reason,
                evidence_ref,
            },
        }
    }
}

/// Qualified platform boundary for post-return evidence acquisition.
///
/// Implementations must sample after the provider call returns. Clock failure
/// is represented as `Unavailable`; it must not be surfaced as an error that
/// causes the already-returned provider result to be discarded.
pub trait PostReturnTimeSource {
    fn observe_after_return(&mut self) -> PostReturnTimeEvidence;
}
