use crate::error::{PayError, PayErrorCode};
use ows_core::ChainType;

/// An account on any chain.
#[derive(Debug, Clone)]
pub struct Account {
    /// Address in the chain's native format (e.g. "0x..." for EVM, base58 for Solana).
    pub address: String,
}

/// Trait abstracting wallet access for payment operations.
///
/// Each method takes a CAIP-2 network identifier (e.g. `"eip155:8453"`,
/// `"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"`) to identify the chain.
///
/// The private key NEVER leaves the implementation — all signing happens
/// inside the wallet.
pub trait WalletAccess: Send + Sync {
    /// Chain families this wallet can operate on.
    fn supported_chains(&self) -> Vec<ChainType>;

    /// Get the account for a CAIP-2 network.
    fn account(&self, network: &str) -> Result<Account, PayError>;

    /// Sign a payment payload for the given scheme and network.
    ///
    /// The payload format depends on the scheme:
    /// - `"exact"`: EIP-712 typed data JSON (EVM chains)
    ///
    /// Returns the signature as a hex string with `0x` prefix.
    fn sign_payload(&self, scheme: &str, network: &str, payload: &str) -> Result<String, PayError>;

    /// Sign a Stellar Soroban auth entry preimage.
    ///
    /// `preimage_xdr` is base64-encoded XDR of the HashIdPreimage.
    /// Returns base64-encoded 64-byte Ed25519 signature.
    ///
    /// Default: returns error (not all wallets support Stellar).
    fn sign_stellar_auth(
        &self,
        network: &str,
        preimage_xdr: &str,
    ) -> Result<String, PayError> {
        let _ = (network, preimage_xdr);
        Err(PayError::new(
            PayErrorCode::UnsupportedChain,
            "stellar auth signing not supported by this wallet",
        ))
    }
}
