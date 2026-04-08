//! Shared helpers for Soroban authorization entry signing.
//!
//! These functions encapsulate the Soroban-specific data transformations that
//! are needed by any code path that signs `SorobanAuthorizationEntry` values —
//! whether the signing key is a raw `&[u8]` (as in `sign_inner_authorizations`)
//! or abstracted behind a trait (as in the x402 payment flow).
//!
//! The caller is responsible for the actual Ed25519 signing step; these helpers
//! handle everything around it: building the preimage and formatting the result.

use crate::traits::SignerError;
use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, ScMapEntry, ScVal,
    SorobanAuthorizedInvocation, WriteXdr,
};

/// Build the `HashIdPreimage::SorobanAuthorization` XDR bytes for a Soroban
/// auth entry.
///
/// Returns the raw XDR bytes of the preimage. The caller hashes these with
/// SHA-256 and signs the hash with Ed25519. Different callers may use different
/// signing mechanisms (raw private key, WalletAccess trait, HSM, etc.).
pub fn build_auth_preimage_xdr(
    network_passphrase: &str,
    nonce: i64,
    signature_expiration_ledger: u32,
    invocation: &SorobanAuthorizedInvocation,
) -> Result<Vec<u8>, SignerError> {
    let network_id = Hash(Sha256::digest(network_passphrase.as_bytes()).into());

    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id,
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });

    preimage
        .to_xdr(Limits::none())
        .map_err(|e| SignerError::SigningFailed(format!("failed to serialize auth preimage: {e}")))
}

/// Format an Ed25519 public key and signature into the `ScVal` structure that
/// Soroban's `__check_auth` expects.
///
/// Returns `ScVal::Vec([ScVal::Map({public_key: Bytes, signature: Bytes})])`,
/// ready to assign to `SorobanAddressCredentials.signature`.
pub fn format_auth_signature(
    public_key: &[u8],
    signature: &[u8],
) -> Result<ScVal, SignerError> {
    let pubkey_sc = ScVal::Bytes(
        public_key
            .to_vec()
            .try_into()
            .map_err(|_| SignerError::SigningFailed("failed to create ScBytes for public_key".into()))?,
    );
    let sig_sc = ScVal::Bytes(
        signature
            .to_vec()
            .try_into()
            .map_err(|_| SignerError::SigningFailed("failed to create ScBytes for signature".into()))?,
    );

    let sig_map = ScVal::Map(Some(
        vec![
            ScMapEntry {
                key: ScVal::Symbol(
                    "public_key"
                        .try_into()
                        .map_err(|_| SignerError::SigningFailed("failed to create ScSymbol".into()))?,
                ),
                val: pubkey_sc,
            },
            ScMapEntry {
                key: ScVal::Symbol(
                    "signature"
                        .try_into()
                        .map_err(|_| SignerError::SigningFailed("failed to create ScSymbol".into()))?,
                ),
                val: sig_sc,
            },
        ]
        .try_into()
        .map_err(|_| SignerError::SigningFailed("failed to create ScMap".into()))?,
    ));

    Ok(ScVal::Vec(Some(
        vec![sig_map]
            .try_into()
            .map_err(|_| SignerError::SigningFailed("failed to create signature ScVec".into()))?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        InvokeContractArgs, ScAddress, ScSymbol, SorobanAuthorizedInvocation,
        SorobanAuthorizedFunction,
    };

    #[test]
    fn test_build_auth_preimage_xdr_deterministic() {
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(stellar_xdr::curr::ContractId(Hash([0u8; 32]))),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: vec![].try_into().unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };

        let xdr1 = build_auth_preimage_xdr("Test SDF Network ; September 2015", 42, 1000, &invocation).unwrap();
        let xdr2 = build_auth_preimage_xdr("Test SDF Network ; September 2015", 42, 1000, &invocation).unwrap();
        assert_eq!(xdr1, xdr2);
        assert!(!xdr1.is_empty());
    }

    #[test]
    fn test_format_auth_signature_structure() {
        let pubkey = [1u8; 32];
        let signature = [2u8; 64];

        let result = format_auth_signature(&pubkey, &signature).unwrap();

        // Should be ScVal::Vec containing one ScVal::Map
        match result {
            ScVal::Vec(Some(vec)) => {
                assert_eq!(vec.len(), 1);
                match &vec[0] {
                    ScVal::Map(Some(map)) => {
                        assert_eq!(map.len(), 2);
                        // First entry: public_key
                        assert_eq!(map[0].key, ScVal::Symbol("public_key".try_into().unwrap()));
                        // Second entry: signature
                        assert_eq!(map[1].key, ScVal::Symbol("signature".try_into().unwrap()));
                    }
                    _ => panic!("expected Map"),
                }
            }
            _ => panic!("expected Vec"),
        }
    }
}
