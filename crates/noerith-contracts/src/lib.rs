#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    Json(String),
    FloatingPointNotAllowed,
    PayloadDigestMismatch,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message) => write!(f, "json error: {message}"),
            Self::FloatingPointNotAllowed => write!(
                f,
                "floating point numbers are not accepted by the bounded canonical reference"
            ),
            Self::PayloadDigestMismatch => write!(f, "payload digest mismatch"),
        }
    }
}

impl std::error::Error for ContractError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractMessage {
    pub message_id: String,
    pub tenant_namespace: String,
    pub producer_principal: String,
    pub payload: Value,
    pub payload_digest: String,
}

pub fn parse_contract_message(input: &str) -> Result<ContractMessage, ContractError> {
    serde_json::from_str(input).map_err(|error| ContractError::Json(error.to_string()))
}

pub fn canonical_reference(value: &Value) -> Result<String, ContractError> {
    fn write_value(value: &Value, out: &mut String) -> Result<(), ContractError> {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Value::Number(number) => {
                if !(number.is_i64() || number.is_u64()) {
                    return Err(ContractError::FloatingPointNotAllowed);
                }
                out.push_str(&number.to_string());
            }
            Value::String(value) => {
                let encoded = serde_json::to_string(value)
                    .map_err(|error| ContractError::Json(error.to_string()))?;
                out.push_str(&encoded);
            }
            Value::Array(values) => {
                out.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    write_value(value, out)?;
                }
                out.push(']');
            }
            Value::Object(values) => {
                let mut keys: Vec<&String> = values.keys().collect();
                keys.sort();
                out.push('{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    let encoded_key = serde_json::to_string(key)
                        .map_err(|error| ContractError::Json(error.to_string()))?;
                    out.push_str(&encoded_key);
                    out.push(':');
                    write_value(&values[key], out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }

    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

pub fn payload_digest(value: &Value) -> Result<String, ContractError> {
    let canonical = canonical_reference(value)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

pub fn validate_message(message: &ContractMessage) -> Result<(), ContractError> {
    let actual = payload_digest(&message.payload)?;
    if actual != message.payload_digest {
        return Err(ContractError::PayloadDigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &str = include_str!("../../../contracts/golden/q01-message.json");
    const CHANGED_PAYLOAD: &str =
        include_str!("../../../contracts/invalid/q01-changed-payload.json");
    const UNKNOWN_CRITICAL: &str =
        include_str!("../../../contracts/invalid/q01-unknown-critical.json");
    const DUPLICATE_KEY: &str =
        include_str!("../../../contracts/invalid/q01-duplicate-message-id.json");

    #[test]
    fn golden_message_round_trips_with_expected_digest() {
        let message = parse_contract_message(GOLDEN).expect("golden message must parse");
        validate_message(&message).expect("golden message digest must match");

        let serialized = serde_json::to_string(&message).expect("serialization must succeed");
        let reparsed = parse_contract_message(&serialized).expect("round trip must parse");
        assert_eq!(message, reparsed);
    }

    #[test]
    fn changed_payload_with_old_digest_is_rejected() {
        let message = parse_contract_message(CHANGED_PAYLOAD).expect("fixture must parse");
        assert_eq!(
            validate_message(&message),
            Err(ContractError::PayloadDigestMismatch)
        );
    }

    #[test]
    fn unknown_critical_field_fails_closed() {
        assert!(parse_contract_message(UNKNOWN_CRITICAL).is_err());
    }

    #[test]
    fn duplicate_protected_field_fails_closed() {
        assert!(parse_contract_message(DUPLICATE_KEY).is_err());
    }

    #[test]
    fn floating_point_value_is_not_silently_canonicalized() {
        let value: Value = serde_json::from_str(r#"{"amount":1.25}"#).expect("valid JSON");
        assert_eq!(
            canonical_reference(&value),
            Err(ContractError::FloatingPointNotAllowed)
        );
    }
}
