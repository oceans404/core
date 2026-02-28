use crate::caip::{AccountId, ChainId};
use crate::chain::ChainType;
use serde::{Deserialize, Serialize};

/// Unique wallet identifier (UUID v4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletId(pub String);

impl WalletId {
    pub fn new() -> Self {
        WalletId(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for WalletId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WalletId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// High-level wallet descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletDescriptor {
    pub id: WalletId,
    pub name: String,
    pub chains: Vec<ChainType>,
    pub accounts: Vec<AccountDescriptor>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// An account derived from a wallet on a specific chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDescriptor {
    pub chain: ChainId,
    pub address: String,
    pub derivation_path: String,
    pub account_id: AccountId,
}

/// Message encoding for sign-message requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageEncoding {
    Utf8,
    Hex,
    Base64,
}

/// Status of a submitted transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}

/// Request to sign a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub wallet_id: WalletId,
    pub chain: ChainId,
    pub transaction: serde_json::Value,
    #[serde(default = "default_simulate")]
    pub simulate: bool,
}

fn default_simulate() -> bool {
    true
}

/// Result of signing a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    pub signed_transaction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation: Option<SimulationResult>,
}

/// Request to sign and broadcast a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignAndSendRequest {
    #[serde(flatten)]
    pub sign_request: SignRequest,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_confirmations")]
    pub confirmations: u32,
}

fn default_max_retries() -> u32 {
    3
}

fn default_confirmations() -> u32 {
    1
}

/// Result of sign-and-send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignAndSendResult {
    pub tx_hash: String,
    pub status: TransactionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation: Option<SimulationResult>,
}

/// Request to sign an arbitrary message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessageRequest {
    pub wallet_id: WalletId,
    pub chain: ChainId,
    pub message: String,
    #[serde(default)]
    pub encoding: Option<MessageEncoding>,
}

/// Result of signing a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessageResult {
    pub signature: String,
}

/// Simulation result for a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_estimate: Option<u64>,
    pub state_changes: Vec<StateChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A state change from simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub change_type: StateChangeType,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Type of state change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateChangeType {
    BalanceChange,
    TokenTransfer,
    Approval,
    ContractCall,
}

/// Policy action type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Allow,
    Deny,
}

/// Policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub executable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Context provided to a policy for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub wallet_id: WalletId,
    pub chain: ChainId,
    pub transaction: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
}

/// Result of policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub action: PolicyAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// API key descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub key_hash: String,
    pub scoped_wallets: Vec<WalletId>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_id_generates_uuid() {
        let id = WalletId::new();
        assert!(!id.0.is_empty());
        assert!(uuid::Uuid::parse_str(&id.0).is_ok());
    }

    #[test]
    fn test_wallet_id_serde() {
        let id = WalletId("test-id".to_string());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"test-id\"");
        let id2: WalletId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_sign_request_default_simulate() {
        let json = r#"{
            "wallet_id": "test",
            "chain": "eip155:1",
            "transaction": {}
        }"#;
        let req: SignRequest = serde_json::from_str(json).unwrap();
        assert!(req.simulate);
    }

    #[test]
    fn test_sign_and_send_defaults() {
        let json = r#"{
            "wallet_id": "test",
            "chain": "eip155:1",
            "transaction": {},
            "simulate": true
        }"#;
        let req: SignAndSendRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.max_retries, 3);
        assert_eq!(req.confirmations, 1);
    }

    #[test]
    fn test_sign_and_send_flatten() {
        let req = SignAndSendRequest {
            sign_request: SignRequest {
                wallet_id: WalletId("w1".to_string()),
                chain: "eip155:1".parse().unwrap(),
                transaction: serde_json::json!({"to": "0x123"}),
                simulate: true,
            },
            max_retries: 5,
            confirmations: 2,
        };
        let json = serde_json::to_value(&req).unwrap();
        // flatten should put wallet_id at the top level
        assert_eq!(json["wallet_id"], "w1");
        assert_eq!(json["max_retries"], 5);
        assert_eq!(json["chain"], "eip155:1");
    }

    #[test]
    fn test_sign_result_optional_simulation() {
        let result = SignResult {
            signed_transaction: "0xdeadbeef".to_string(),
            simulation: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("simulation").is_none());
    }

    #[test]
    fn test_wallet_descriptor_serde() {
        let wallet = WalletDescriptor {
            id: WalletId("w1".to_string()),
            name: "Test Wallet".to_string(),
            chains: vec![ChainType::Evm, ChainType::Solana],
            accounts: vec![],
            created_at: chrono::Utc::now(),
            updated_at: None,
        };
        let json = serde_json::to_value(&wallet).unwrap();
        assert_eq!(json["name"], "Test Wallet");
        assert!(json.get("updated_at").is_none());
    }

    #[test]
    fn test_policy_result_serde() {
        let result = PolicyResult {
            action: PolicyAction::Allow,
            reason: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["action"], "allow");
        assert!(json.get("reason").is_none());
    }

    #[test]
    fn test_policy_result_deny_with_reason() {
        let result = PolicyResult {
            action: PolicyAction::Deny,
            reason: Some("exceeds limit".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["action"], "deny");
        assert_eq!(json["reason"], "exceeds limit");
    }

    #[test]
    fn test_state_change_type_serde() {
        let t = StateChangeType::BalanceChange;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"balance_change\"");
    }

    #[test]
    fn test_message_encoding_serde() {
        let enc = MessageEncoding::Hex;
        let json = serde_json::to_string(&enc).unwrap();
        assert_eq!(json, "\"hex\"");
    }

    #[test]
    fn test_transaction_status_serde() {
        let status = TransactionStatus::Confirmed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"confirmed\"");
    }

    #[test]
    fn test_api_key_serde() {
        let key = ApiKey {
            id: "k1".to_string(),
            name: "test key".to_string(),
            key_hash: "abc123".to_string(),
            scoped_wallets: vec![WalletId("w1".to_string())],
            created_at: chrono::Utc::now(),
            expires_at: None,
        };
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json["name"], "test key");
        assert!(json.get("expires_at").is_none());
    }

    #[test]
    fn test_sign_message_request_serde() {
        let req = SignMessageRequest {
            wallet_id: WalletId("w1".to_string()),
            chain: "eip155:1".parse().unwrap(),
            message: "hello".to_string(),
            encoding: Some(MessageEncoding::Utf8),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["encoding"], "utf8");
    }

    #[test]
    fn test_simulation_result_serde() {
        let sim = SimulationResult {
            success: true,
            gas_estimate: Some(21000),
            state_changes: vec![StateChange {
                change_type: StateChangeType::BalanceChange,
                address: "0x123".to_string(),
                amount: Some("-0.01".to_string()),
                token: None,
            }],
            error: None,
        };
        let json = serde_json::to_value(&sim).unwrap();
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["gas_estimate"], 21000);
        assert!(json.get("error").is_none());
    }
}
