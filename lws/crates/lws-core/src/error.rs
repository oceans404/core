use serde::{Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LwsErrorCode {
    WalletNotFound,
    ChainNotSupported,
    PolicyDenied,
    InsufficientFunds,
    InvalidPassphrase,
    VaultLocked,
    BroadcastFailed,
    Timeout,
    InvalidInput,
    CaipParseError,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum LwsError {
    #[error("wallet not found: {id}")]
    WalletNotFound { id: String },

    #[error("chain not supported: {chain}")]
    ChainNotSupported { chain: String },

    #[error("policy denied: {reason}")]
    PolicyDenied { reason: String },

    #[error("insufficient funds: {message}")]
    InsufficientFunds { message: String },

    #[error("invalid passphrase")]
    InvalidPassphrase,

    #[error("vault is locked")]
    VaultLocked,

    #[error("broadcast failed: {message}")]
    BroadcastFailed { message: String },

    #[error("timeout: {message}")]
    Timeout { message: String },

    #[error("invalid input: {message}")]
    InvalidInput { message: String },

    #[error("CAIP parse error: {message}")]
    CaipParseError { message: String },
}

impl LwsError {
    pub fn code(&self) -> LwsErrorCode {
        match self {
            LwsError::WalletNotFound { .. } => LwsErrorCode::WalletNotFound,
            LwsError::ChainNotSupported { .. } => LwsErrorCode::ChainNotSupported,
            LwsError::PolicyDenied { .. } => LwsErrorCode::PolicyDenied,
            LwsError::InsufficientFunds { .. } => LwsErrorCode::InsufficientFunds,
            LwsError::InvalidPassphrase => LwsErrorCode::InvalidPassphrase,
            LwsError::VaultLocked => LwsErrorCode::VaultLocked,
            LwsError::BroadcastFailed { .. } => LwsErrorCode::BroadcastFailed,
            LwsError::Timeout { .. } => LwsErrorCode::Timeout,
            LwsError::InvalidInput { .. } => LwsErrorCode::InvalidInput,
            LwsError::CaipParseError { .. } => LwsErrorCode::CaipParseError,
        }
    }
}

#[derive(Serialize)]
struct ErrorPayload {
    code: LwsErrorCode,
    message: String,
}

impl Serialize for LwsError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let payload = ErrorPayload {
            code: self.code(),
            message: self.to_string(),
        };
        payload.serialize(serializer)
    }
}

impl fmt::Display for LwsErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", self));
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_mapping_wallet_not_found() {
        let err = LwsError::WalletNotFound {
            id: "abc".to_string(),
        };
        assert_eq!(err.code(), LwsErrorCode::WalletNotFound);
    }

    #[test]
    fn test_code_mapping_all_variants() {
        assert_eq!(
            LwsError::ChainNotSupported {
                chain: "x".into()
            }
            .code(),
            LwsErrorCode::ChainNotSupported
        );
        assert_eq!(
            LwsError::PolicyDenied {
                reason: "x".into()
            }
            .code(),
            LwsErrorCode::PolicyDenied
        );
        assert_eq!(
            LwsError::InsufficientFunds {
                message: "x".into()
            }
            .code(),
            LwsErrorCode::InsufficientFunds
        );
        assert_eq!(LwsError::InvalidPassphrase.code(), LwsErrorCode::InvalidPassphrase);
        assert_eq!(LwsError::VaultLocked.code(), LwsErrorCode::VaultLocked);
        assert_eq!(
            LwsError::BroadcastFailed {
                message: "x".into()
            }
            .code(),
            LwsErrorCode::BroadcastFailed
        );
        assert_eq!(
            LwsError::Timeout {
                message: "x".into()
            }
            .code(),
            LwsErrorCode::Timeout
        );
        assert_eq!(
            LwsError::InvalidInput {
                message: "x".into()
            }
            .code(),
            LwsErrorCode::InvalidInput
        );
        assert_eq!(
            LwsError::CaipParseError {
                message: "x".into()
            }
            .code(),
            LwsErrorCode::CaipParseError
        );
    }

    #[test]
    fn test_display_output() {
        let err = LwsError::WalletNotFound {
            id: "abc-123".to_string(),
        };
        assert_eq!(err.to_string(), "wallet not found: abc-123");
    }

    #[test]
    fn test_json_serialization_shape() {
        let err = LwsError::WalletNotFound {
            id: "abc-123".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "WALLET_NOT_FOUND");
        assert_eq!(json["message"], "wallet not found: abc-123");
    }

    #[test]
    fn test_error_code_serde() {
        let code = LwsErrorCode::PolicyDenied;
        let json = serde_json::to_value(&code).unwrap();
        assert_eq!(json, "POLICY_DENIED");
    }

    #[test]
    fn test_caip_parse_error_serialization() {
        let err = LwsError::CaipParseError {
            message: "bad format".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "CAIP_PARSE_ERROR");
        assert!(json["message"].as_str().unwrap().contains("bad format"));
    }
}
