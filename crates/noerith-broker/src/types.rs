use noerith_effects::{
    DispatchAttemptBinding, DispatchLease, DispatchTicket, MonotonicDeadline, StartedAt,
    VersionedRef,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialHandle {
    pub handle_id: String,
    pub tenant_namespace: String,
    pub actor_ref: String,
    pub workload_ref: String,
    pub purpose: String,
    pub audience: String,
    pub operation_type: String,
    pub target_resources: BTreeSet<String>,
    pub target_accounts: BTreeSet<String>,
    pub target_principals: BTreeSet<String>,
    pub authority_grant_ref: String,
    pub effect_intent_id: String,
    pub capability: VersionedRef,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub revocation_epoch: u64,
    pub issuer_evidence_ref: String,
}

impl CredentialHandle {
    pub fn validate(&self) -> Result<(), BrokerError> {
        for (name, value) in [
            ("handle_id", self.handle_id.as_str()),
            ("tenant_namespace", self.tenant_namespace.as_str()),
            ("actor_ref", self.actor_ref.as_str()),
            ("workload_ref", self.workload_ref.as_str()),
            ("purpose", self.purpose.as_str()),
            ("audience", self.audience.as_str()),
            ("operation_type", self.operation_type.as_str()),
            ("authority_grant_ref", self.authority_grant_ref.as_str()),
            ("effect_intent_id", self.effect_intent_id.as_str()),
            ("capability.ref_id", self.capability.ref_id.as_str()),
            ("issuer_evidence_ref", self.issuer_evidence_ref.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(BrokerError::InvalidField(name));
            }
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(BrokerError::InvalidField("handle lifetime"));
        }
        if self.target_resources.is_empty()
            && self.target_accounts.is_empty()
            && self.target_principals.is_empty()
        {
            return Err(BrokerError::InvalidField("handle targets"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRequest {
    pub tenant_namespace: String,
    pub effect_intent_id: String,
    pub actor_ref: String,
    pub workload_ref: String,
    pub audience: String,
    pub credential_handle_ref: String,
    pub capability: VersionedRef,
    pub environment: VersionedRef,
    pub lease: DispatchLease,
    pub started_at: StartedAt,
    pub monotonic_deadline: MonotonicDeadline,
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterRequest {
    pub effect_intent_id: String,
    pub operation_type: String,
    pub target_resources: Vec<String>,
    pub target_accounts: Vec<String>,
    pub target_principals: Vec<String>,
    pub payload_ref: String,
    pub payload_digest: String,
    pub audience: String,
    pub provider_idempotency_key: Option<String>,
    pub request_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterOutcome {
    NotSentProven { evidence_ref: String },
    Accepted { receipt_ref: String },
    RejectedNoEffect { evidence_ref: String },
    ResponseLost { evidence_ref: String },
    ConnectionFailedAmbiguous { evidence_ref: String },
}

pub trait ControlledAdapter {
    fn identity(&self) -> VersionedRef;
    fn send(&mut self, request: &AdapterRequest, credential: &[u8]) -> AdapterOutcome;
}

#[derive(Clone)]
pub struct SecretMaterial(Zeroizing<Vec<u8>>);

impl SecretMaterial {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CredentialSourceError> {
        if bytes.is_empty() {
            return Err(CredentialSourceError::InvalidSecret);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretMaterial([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSourceError {
    Unavailable,
    NotFound,
    InvalidSecret,
}

impl fmt::Display for CredentialSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("credential source error")
    }
}

impl std::error::Error for CredentialSourceError {}

pub trait CredentialSource {
    fn resolve(&mut self, handle_id: &str) -> Result<SecretMaterial, CredentialSourceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseState {
    Prepared,
    Consumed,
    Finalized,
}

impl ReleaseState {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::Prepared => "PREPARED",
            Self::Consumed => "CONSUMED",
            Self::Finalized => "FINALIZED",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, BrokerError> {
        match value {
            "PREPARED" => Ok(Self::Prepared),
            "CONSUMED" => Ok(Self::Consumed),
            "FINALIZED" => Ok(Self::Finalized),
            _ => Err(BrokerError::CorruptRecord),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedReleaseBinding {
    pub release_id: String,
    pub tenant_namespace: String,
    pub ticket: PersistedTicket,
    pub attempt: DispatchAttemptBinding,
    pub actor_ref: String,
    pub workload_ref: String,
    pub audience: String,
    pub credential_handle_ref: String,
    pub capability: VersionedRef,
    pub environment: VersionedRef,
    pub dispatch_owner: String,
    pub dispatch_lease_expires_at_ms: u64,
    /// Exact adapter identity as declared by the qualified EffectIntent.
    /// Kept separately from the current numeric DispatchAttempt reference so
    /// transport evidence never reconstructs or normalizes the original token.
    pub adapter_ref: String,
    pub adapter_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PersistedTicket {
    pub tenant_namespace: String,
    pub effect_intent_id: String,
    pub attempt_number: u32,
    pub fence: u64,
    pub request_digest: String,
}

impl From<&DispatchTicket> for PersistedTicket {
    fn from(ticket: &DispatchTicket) -> Self {
        Self {
            tenant_namespace: ticket.tenant_namespace.clone(),
            effect_intent_id: ticket.effect_intent_id.clone(),
            attempt_number: ticket.attempt_number,
            fence: ticket.fence,
            request_digest: ticket.request_digest.clone(),
        }
    }
}

impl From<&PersistedTicket> for DispatchTicket {
    fn from(ticket: &PersistedTicket) -> Self {
        Self {
            tenant_namespace: ticket.tenant_namespace.clone(),
            effect_intent_id: ticket.effect_intent_id.clone(),
            attempt_number: ticket.attempt_number,
            fence: ticket.fence,
            request_digest: ticket.request_digest.clone(),
        }
    }
}

#[derive(Debug)]
pub enum BrokerError {
    InvalidField(&'static str),
    CredentialBindingMismatch(&'static str),
    HandleExpired,
    HandleRevoked,
    ReleaseReplay,
    ReleaseNotPrepared,
    AdapterMismatch,
    AttemptMismatch,
    MissingSnapshot,
    VersionNotRepresentable,
    FreshnessAuthorityUnavailable,
    /// The provider result is already durably captured, but no trustworthy
    /// post-return physical-time bound is available for downstream timed state.
    /// This must never be interpreted as permission to resend the release.
    PostReturnTimeUnavailable,
    Freshness(crate::release_freshness::ReleaseFreshnessError),
    TransportCapture(crate::transport_capture::TransportCaptureError),
    CorruptRecord,
    CredentialSource(CredentialSourceError),
    Effect(noerith_effects::EffectError),
    Attempt(noerith_effects::DispatchAttemptError),
    KeyProvider(String),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(name) => write!(f, "invalid broker field: {name}"),
            Self::CredentialBindingMismatch(name) => {
                write!(f, "credential binding mismatch: {name}")
            }
            Self::HandleExpired => f.write_str("credential handle expired"),
            Self::HandleRevoked => f.write_str("credential handle revoked"),
            Self::ReleaseReplay => f.write_str("controlled release replay rejected"),
            Self::ReleaseNotPrepared => f.write_str("controlled release not prepared"),
            Self::AdapterMismatch => f.write_str("adapter identity mismatch"),
            Self::AttemptMismatch => f.write_str("dispatch attempt binding mismatch"),
            Self::MissingSnapshot => f.write_str("decision snapshot missing"),
            Self::VersionNotRepresentable => {
                f.write_str("adapter manifest version is not numeric")
            }
            Self::FreshnessAuthorityUnavailable => {
                f.write_str("release freshness authority unavailable")
            }
            Self::PostReturnTimeUnavailable => f.write_str(
                "provider result captured; trustworthy post-return time unavailable for convergence",
            ),
            Self::Freshness(error) => write!(f, "{error}"),
            Self::TransportCapture(error) => write!(f, "transport capture error: {error}"),
            Self::CorruptRecord => f.write_str("broker record corrupt"),
            Self::CredentialSource(error) => write!(f, "{error}"),
            Self::Effect(error) => write!(f, "effect runtime error: {error}"),
            Self::Attempt(error) => write!(f, "dispatch attempt error: {error}"),
            Self::KeyProvider(error) => write!(f, "key provider error: {error}"),
            Self::Sqlite(_) => f.write_str("broker storage error"),
            Self::Json(_) => f.write_str("broker serialization error"),
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<crate::release_freshness::ReleaseFreshnessError> for BrokerError {
    fn from(value: crate::release_freshness::ReleaseFreshnessError) -> Self {
        Self::Freshness(value)
    }
}

impl From<crate::transport_capture::TransportCaptureError> for BrokerError {
    fn from(value: crate::transport_capture::TransportCaptureError) -> Self {
        Self::TransportCapture(value)
    }
}

impl From<noerith_effects::EffectError> for BrokerError {
    fn from(value: noerith_effects::EffectError) -> Self {
        Self::Effect(value)
    }
}

impl From<noerith_effects::DispatchAttemptError> for BrokerError {
    fn from(value: noerith_effects::DispatchAttemptError) -> Self {
        Self::Attempt(value)
    }
}

impl From<rusqlite::Error> for BrokerError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<serde_json::Error> for BrokerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<CredentialSourceError> for BrokerError {
    fn from(value: CredentialSourceError) -> Self {
        Self::CredentialSource(value)
    }
}
