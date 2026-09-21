use crate::effect_contract::CancelAfterAcceptance;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelState {
    None,
    Requested,
    BlockedBeforeCommit,
    ForwardedToProvider,
    ConfirmedCancelled,
    TooLate,
    CancelUnknown,
}

impl CancelState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Requested => "REQUESTED",
            Self::BlockedBeforeCommit => "BLOCKED_BEFORE_COMMIT",
            Self::ForwardedToProvider => "FORWARDED_TO_PROVIDER",
            Self::ConfirmedCancelled => "CONFIRMED_CANCELLED",
            Self::TooLate => "TOO_LATE",
            Self::CancelUnknown => "CANCEL_UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelResolution {
    ConfirmedCancelled,
    TooLate,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancellationError {
    InvalidTransition,
    MissingEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationRecord {
    state: CancelState,
    evidence_refs: Vec<String>,
}

impl Default for CancellationRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationRecord {
    pub const fn new() -> Self {
        Self {
            state: CancelState::None,
            evidence_refs: Vec::new(),
        }
    }

    pub const fn state(&self) -> CancelState {
        self.state
    }

    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }

    /// Records an authenticated cancel request after the external send boundary
    /// may have been crossed. This is deliberately not a cancellation claim.
    pub fn request_after_send(
        &mut self,
        authenticated_request_evidence: &str,
    ) -> Result<CancelState, CancellationError> {
        require_evidence(authenticated_request_evidence)?;
        if self.state != CancelState::None {
            return Err(CancellationError::InvalidTransition);
        }
        self.state = CancelState::Requested;
        self.evidence_refs
            .push(authenticated_request_evidence.to_owned());
        Ok(self.state)
    }

    /// Records proof that dispatch was prevented before the external send
    /// boundary. This is a safe terminal cancel state, distinct from provider
    /// confirmation of an already-dispatched effect.
    pub fn block_before_commit(
        &mut self,
        dispatch_prevented_evidence: &str,
    ) -> Result<CancelState, CancellationError> {
        require_evidence(dispatch_prevented_evidence)?;
        if !matches!(self.state, CancelState::None | CancelState::Requested) {
            return Err(CancellationError::InvalidTransition);
        }
        self.state = CancelState::BlockedBeforeCommit;
        self.evidence_refs
            .push(dispatch_prevented_evidence.to_owned());
        Ok(self.state)
    }

    /// After provider acceptance, a known unsupported cancellation interface is
    /// truthfully TOO_LATE. Supported/best-effort/unknown capability still starts
    /// as REQUESTED until an actual provider request/result is evidenced.
    pub fn request_after_acceptance(
        &mut self,
        capability: CancelAfterAcceptance,
        authenticated_request_evidence: &str,
    ) -> Result<CancelState, CancellationError> {
        require_evidence(authenticated_request_evidence)?;
        if self.state != CancelState::None {
            return Err(CancellationError::InvalidTransition);
        }
        self.evidence_refs
            .push(authenticated_request_evidence.to_owned());
        self.state = match capability {
            CancelAfterAcceptance::Unsupported => CancelState::TooLate,
            CancelAfterAcceptance::Supported
            | CancelAfterAcceptance::BestEffort
            | CancelAfterAcceptance::Unknown => CancelState::Requested,
        };
        Ok(self.state)
    }

    /// Provider forwarding is a separate fact from user request receipt.
    pub fn mark_forwarded_to_provider(
        &mut self,
        provider_request_evidence: &str,
    ) -> Result<CancelState, CancellationError> {
        require_evidence(provider_request_evidence)?;
        if self.state != CancelState::Requested {
            return Err(CancellationError::InvalidTransition);
        }
        self.state = CancelState::ForwardedToProvider;
        self.evidence_refs
            .push(provider_request_evidence.to_owned());
        Ok(self.state)
    }

    /// A provider result may only resolve a request that was actually forwarded.
    /// In particular REQUESTED cannot jump directly to CONFIRMED_CANCELLED.
    pub fn resolve_provider_result(
        &mut self,
        resolution: CancelResolution,
        result_evidence: &str,
    ) -> Result<CancelState, CancellationError> {
        require_evidence(result_evidence)?;
        if self.state != CancelState::ForwardedToProvider {
            return Err(CancellationError::InvalidTransition);
        }
        self.state = match resolution {
            CancelResolution::ConfirmedCancelled => CancelState::ConfirmedCancelled,
            CancelResolution::TooLate => CancelState::TooLate,
            CancelResolution::Unknown => CancelState::CancelUnknown,
        };
        self.evidence_refs.push(result_evidence.to_owned());
        Ok(self.state)
    }
}

fn require_evidence(value: &str) -> Result<(), CancellationError> {
    if value.trim().is_empty() {
        Err(CancellationError::MissingEvidence)
    } else {
        Ok(())
    }
}
