use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use sha2::{Digest, Sha256};

/// The 5 distinct key types used in the Spark protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparkKeyType {
    /// Identity key: m/8797555'/0'/x'
    Identity,
    /// Signing key: m/8797555'/1'/x'
    Signing,
    /// Deposit key: m/8797555'/2'/x'
    Deposit,
    /// Static deposit key: m/8797555'/3'/x'
    StaticDeposit,
    /// HTLC preimage key: m/8797555'/4'/x'
    HtlcPreimage,
}

impl SparkKeyType {
    /// All key types in derivation order.
    pub const ALL: [SparkKeyType; 5] = [
        SparkKeyType::Identity,
        SparkKeyType::Signing,
        SparkKeyType::Deposit,
        SparkKeyType::StaticDeposit,
        SparkKeyType::HtlcPreimage,
    ];

    /// The BIP-44 account index for this key type.
    pub fn account_index(&self) -> u32 {
        match self {
            SparkKeyType::Identity => 0,
            SparkKeyType::Signing => 1,
            SparkKeyType::Deposit => 2,
            SparkKeyType::StaticDeposit => 3,
            SparkKeyType::HtlcPreimage => 4,
        }
    }

    /// Human-readable label for this key type.
    pub fn label(&self) -> &'static str {
        match self {
            SparkKeyType::Identity => "identity",
            SparkKeyType::Signing => "signing",
            SparkKeyType::Deposit => "deposit",
            SparkKeyType::StaticDeposit => "static-deposit",
            SparkKeyType::HtlcPreimage => "htlc-preimage",
        }
    }
}

/// Spark chain signer (Bitcoin L2, secp256k1).
pub struct SparkSigner {
    pub key_type: SparkKeyType,
}

impl SparkSigner {
    pub fn new(key_type: SparkKeyType) -> Self {
        SparkSigner { key_type }
    }

    /// Convenience: default signer uses the identity key.
    pub fn identity() -> Self {
        Self::new(SparkKeyType::Identity)
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
    }
}

impl ChainSigner for SparkSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Spark
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        8797555
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();
        let pubkey_compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();
        Ok(format!(
            "spark:{}:{}",
            self.key_type.label(),
            hex::encode(pubkey_bytes)
        ))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected 32-byte hash, got {} bytes",
                message.len()
            )));
        }

        let signing_key = Self::signing_key(private_key)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: Some(recovery_id.to_byte()),
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let hash = Sha256::digest(Sha256::digest(tx_bytes));
        self.sign(private_key, &hash)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let hash = Sha256::digest(message);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/8797555'/{}'/{}'", self.key_type.account_index(), index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> Vec<u8> {
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        privkey
    }

    #[test]
    fn test_derivation_paths_all_key_types() {
        for (key_type, expected_account) in SparkKeyType::ALL.iter().zip(0u32..5) {
            let signer = SparkSigner::new(*key_type);
            let path = signer.default_derivation_path(0);
            assert_eq!(path, format!("m/8797555'/{}'/0'", expected_account));
        }
    }

    #[test]
    fn test_derivation_path_with_index() {
        let signer = SparkSigner::new(SparkKeyType::Identity);
        assert_eq!(signer.default_derivation_path(0), "m/8797555'/0'/0'");
        assert_eq!(signer.default_derivation_path(5), "m/8797555'/0'/5'");

        let signer = SparkSigner::new(SparkKeyType::HtlcPreimage);
        assert_eq!(signer.default_derivation_path(0), "m/8797555'/4'/0'");
        assert_eq!(signer.default_derivation_path(3), "m/8797555'/4'/3'");
    }

    #[test]
    fn test_address_derivation() {
        let privkey = test_privkey();
        for key_type in &SparkKeyType::ALL {
            let signer = SparkSigner::new(*key_type);
            let address = signer.derive_address(&privkey).unwrap();
            assert!(
                address.starts_with(&format!("spark:{}:", key_type.label())),
                "address should start with spark:{}: prefix, got: {}",
                key_type.label(),
                address
            );
        }
    }

    #[test]
    fn test_different_key_types_same_key_different_addresses() {
        let privkey = test_privkey();
        // All key types produce different address prefixes from the same private key
        let addresses: Vec<String> = SparkKeyType::ALL
            .iter()
            .map(|kt| SparkSigner::new(*kt).derive_address(&privkey).unwrap())
            .collect();
        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                assert_ne!(addresses[i], addresses[j]);
            }
        }
    }

    #[test]
    fn test_deterministic() {
        let privkey = test_privkey();
        let signer = SparkSigner::identity();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_chain_properties() {
        let signer = SparkSigner::identity();
        assert_eq!(signer.chain_type(), ChainType::Spark);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 8797555);
    }

    #[test]
    fn test_sign_message() {
        let privkey = test_privkey();
        let signer = SparkSigner::identity();
        let result = signer.sign_message(&privkey, b"hello spark").unwrap();
        assert!(!result.signature.is_empty());
        assert!(result.recovery_id.is_some());
    }

    #[test]
    fn test_sign_transaction() {
        let privkey = test_privkey();
        let signer = SparkSigner::identity();
        let result = signer.sign_transaction(&privkey, b"fake tx data").unwrap();
        assert!(!result.signature.is_empty());
        assert!(result.recovery_id.is_some());
    }

    #[test]
    fn test_identity_convenience() {
        let signer = SparkSigner::identity();
        assert_eq!(signer.key_type, SparkKeyType::Identity);
    }
}
