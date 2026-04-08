use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::{
    ChainType, STELLAR_PASSPHRASE_FUTURENET, STELLAR_PASSPHRASE_PUBNET,
    STELLAR_PASSPHRASE_TESTNET,
};
use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    DecoratedSignature, Limits, OperationBody, ReadXdr, ScAddress, ScVal, Signature,
    SignatureHint, SorobanAuthorizationEntry, SorobanCredentials, TransactionEnvelope,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, VecM, WriteXdr,
};

/// Stellar chain signer (Ed25519).
///
/// Stateful struct storing the network passphrase, which is required for
/// building the `TransactionSignaturePayload` during transaction signing.
/// Follows the same pattern as `BitcoinSigner` (HRP) and `CosmosSigner` (HRP).
pub struct StellarSigner {
    network_passphrase: &'static str,
}

impl StellarSigner {
    pub fn pubnet() -> Self {
        StellarSigner {
            network_passphrase: STELLAR_PASSPHRASE_PUBNET,
        }
    }

    pub fn testnet() -> Self {
        StellarSigner {
            network_passphrase: STELLAR_PASSPHRASE_TESTNET,
        }
    }

    pub fn futurenet() -> Self {
        StellarSigner {
            network_passphrase: STELLAR_PASSPHRASE_FUTURENET,
        }
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }
}

impl ChainSigner for StellarSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Stellar
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        148
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/148'/{}'", index)
    }

    /// Derive a Stellar `G...` address from a private key.
    ///
    /// Uses Strkey encoding: `base32(versionByte + ed25519PublicKey + CRC16)`.
    /// Version byte 48 (6 << 3) produces the `G` prefix.
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let strkey =
            stellar_strkey::ed25519::PublicKey(*verifying_key.as_bytes());
        Ok(String::from(strkey.to_string().as_str()))
    }

    /// Sign raw bytes with Ed25519 (no prefixing, no hashing).
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }

    /// Sign a Stellar transaction envelope (XDR bytes).
    ///
    /// 1. Parse the `TransactionEnvelope` from XDR
    /// 2. Extract the transaction body
    /// 3. Build `TransactionSignaturePayload` with `SHA256(network_passphrase)` as networkId
    /// 4. Serialize the payload to XDR, SHA-256 hash it
    /// 5. Ed25519 sign the hash
    /// 6. Return signature + public key (needed for DecoratedSignature hint)
    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction(
                "transaction bytes must not be empty".into(),
            ));
        }

        let signing_key = Self::signing_key(private_key)?;

        // Parse the envelope to extract the transaction body
        let envelope = TransactionEnvelope::from_xdr(tx_bytes, Limits::none())
            .map_err(|e| SignerError::InvalidTransaction(format!("XDR parse failed: {e}")))?;

        // Build the tagged transaction for the signature payload
        let tagged_tx = match &envelope {
            TransactionEnvelope::TxV0(v0) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(
                    // V0 envelopes contain a TransactionV0; we need to
                    // convert to a Transaction for the payload. However,
                    // stellar-xdr doesn't provide a direct conversion.
                    // For V0, we build the payload using the Tx variant
                    // after converting the V0 inner transaction.
                    //
                    // Actually, stellar-xdr has TxV0 variant in the payload tagged transaction:
                    // Let's check... No, the XDR spec says the signature payload uses
                    // ENVELOPE_TYPE_TX or ENVELOPE_TYPE_TX_FEE_BUMP.
                    // For V0 envelopes, we still use ENVELOPE_TYPE_TX with the tx body.
                    // The stellar SDK converts V0 to V1 for signing purposes.
                    // We'll handle this by reading the V0 tx fields directly.
                    {
                        // Convert V0 to a Transaction struct for signing.
                        // V0 transactions have the source as an ed25519 key (32 bytes)
                        // while V1 uses a MuxedAccount. The signing payload should
                        // use the Transaction (V1) form.
                        use stellar_xdr::curr::{MuxedAccount, Transaction, Uint256};
                        Transaction {
                            source_account: MuxedAccount::Ed25519(Uint256(
                                v0.tx.source_account_ed25519.0,
                            )),
                            fee: v0.tx.fee,
                            seq_num: v0.tx.seq_num.clone(),
                            cond: match &v0.tx.time_bounds {
                                Some(tb) => stellar_xdr::curr::Preconditions::Time(tb.clone()),
                                None => stellar_xdr::curr::Preconditions::None,
                            },
                            memo: v0.tx.memo.clone(),
                            operations: v0.tx.operations.clone(),
                            ext: stellar_xdr::curr::TransactionExt::V0,
                        }
                    },
                )
            }
            TransactionEnvelope::Tx(v1) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone())
            }
            TransactionEnvelope::TxFeeBump(fb) => {
                TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fb.tx.clone())
            }
        };

        // Compute networkId = SHA256(passphrase)
        let network_id: [u8; 32] = Sha256::digest(self.network_passphrase.as_bytes()).into();

        let payload = TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id),
            tagged_transaction: tagged_tx,
        };

        // Serialize payload to XDR, then SHA-256 hash it
        let payload_xdr = payload
            .to_xdr(Limits::none())
            .map_err(|e| SignerError::SigningFailed(format!("XDR serialize failed: {e}")))?;
        let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        // Ed25519 sign the hash
        let signature = signing_key.sign(&hash);
        let pubkey_bytes = signing_key.verifying_key().to_bytes().to_vec();

        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(pubkey_bytes),
        })
    }

    /// Encode a signed Stellar transaction: append a DecoratedSignature to the envelope.
    ///
    /// The `SignOutput` must contain `public_key` (32 bytes) for the signature hint
    /// (last 4 bytes of the public key).
    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }

        let pubkey_bytes = signature
            .public_key
            .as_ref()
            .ok_or_else(|| {
                SignerError::InvalidTransaction(
                    "public_key required for Stellar DecoratedSignature hint".into(),
                )
            })?;

        if pubkey_bytes.len() != 32 {
            return Err(SignerError::InvalidTransaction(format!(
                "expected 32-byte public key, got {}",
                pubkey_bytes.len()
            )));
        }

        let mut envelope = TransactionEnvelope::from_xdr(tx_bytes, Limits::none())
            .map_err(|e| SignerError::InvalidTransaction(format!("XDR parse failed: {e}")))?;

        // Build the DecoratedSignature: hint (last 4 bytes of pubkey) + 64-byte sig
        let hint = SignatureHint([
            pubkey_bytes[28],
            pubkey_bytes[29],
            pubkey_bytes[30],
            pubkey_bytes[31],
        ]);

        let sig_bytes: [u8; 64] = signature.signature[..64]
            .try_into()
            .map_err(|_| SignerError::InvalidTransaction("signature must be 64 bytes".into()))?;

        let decorated = DecoratedSignature {
            hint,
            signature: Signature(sig_bytes.try_into().map_err(|_| {
                SignerError::InvalidTransaction("failed to create Signature".into())
            })?),
        };

        // Append to the envelope's signatures array.
        // VecM doesn't support push directly; convert to Vec, push, convert back.
        fn append_sig(
            sigs: &stellar_xdr::curr::VecM<DecoratedSignature, 20>,
            sig: DecoratedSignature,
        ) -> Result<stellar_xdr::curr::VecM<DecoratedSignature, 20>, SignerError> {
            let mut v = sigs.to_vec();
            v.push(sig);
            v.try_into().map_err(|_| {
                SignerError::InvalidTransaction("too many signatures (max 20)".into())
            })
        }

        match &mut envelope {
            TransactionEnvelope::TxV0(ref mut v0) => {
                v0.signatures = append_sig(&v0.signatures, decorated)?;
            }
            TransactionEnvelope::Tx(ref mut v1) => {
                v1.signatures = append_sig(&v1.signatures, decorated)?;
            }
            TransactionEnvelope::TxFeeBump(ref mut fb) => {
                fb.signatures = append_sig(&fb.signatures, decorated)?;
            }
        }

        // Re-serialize to XDR
        envelope
            .to_xdr(Limits::none())
            .map_err(|e| SignerError::InvalidTransaction(format!("XDR serialize failed: {e}")))
    }

    /// Sign Soroban authorization entries embedded in an `InvokeHostFunction` operation.
    ///
    /// For each `SorobanAuthorizationEntry` with `Address` credentials that match
    /// the public key derived from `private_key` and have not yet been signed,
    /// this builds the `HashIdPreimage::SorobanAuthorization`, signs it, and
    /// attaches the standard `__check_auth` signature map.
    ///
    /// Returns the modified transaction envelope as XDR bytes.
    fn sign_inner_authorizations(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        use stellar_xdr::curr::Operation;

        let envelope = TransactionEnvelope::from_xdr(tx_bytes, Limits::none())
            .map_err(|e| SignerError::InvalidTransaction(format!("XDR parse failed: {e}")))?;

        // Extract the operations as a Vec so we can mutate them.
        let ops: Vec<Operation> = match &envelope {
            TransactionEnvelope::TxV0(v0) => v0.tx.operations.to_vec(),
            TransactionEnvelope::Tx(v1) => v1.tx.operations.to_vec(),
            TransactionEnvelope::TxFeeBump(fb) => match &fb.tx.inner_tx {
                stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                    inner.tx.operations.to_vec()
                }
            },
        };

        // Check if any operation is InvokeHostFunction; if not, return unchanged.
        let has_invoke = ops.iter().any(|op| {
            matches!(&op.body, OperationBody::InvokeHostFunction(_))
        });
        if !has_invoke {
            return Ok(tx_bytes.to_vec());
        }

        // Derive our public key from the private key for comparison.
        let signing_key = Self::signing_key(private_key)?;
        let our_pubkey = signing_key.verifying_key().to_bytes();

        let mut modified_ops = Vec::with_capacity(ops.len());
        for mut op in ops {
            if let OperationBody::InvokeHostFunction(ref mut invoke_op) = op.body {
                let auth_entries: Vec<SorobanAuthorizationEntry> = invoke_op.auth.to_vec();
                let mut new_auth = Vec::with_capacity(auth_entries.len());

                for mut entry in auth_entries {
                    if let SorobanCredentials::Address(ref mut addr_creds) = entry.credentials {
                        // Extract the ed25519 pubkey bytes from the account address.
                        let entry_pubkey = match &addr_creds.address {
                            ScAddress::Account(account_id) => match &account_id.0 {
                                stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                                    ref uint256,
                                ) => uint256.0,
                                #[allow(unreachable_patterns)]
                                _ => {
                                    // Unsupported public key type, skip.
                                    new_auth.push(entry);
                                    continue;
                                }
                            },
                            _ => {
                                // Not an account address (e.g. Contract), skip.
                                new_auth.push(entry);
                                continue;
                            }
                        };

                        // Check if this entry belongs to our signer.
                        if entry_pubkey != our_pubkey {
                            new_auth.push(entry);
                            continue;
                        }

                        // Skip if already signed (signature is not Void).
                        if !matches!(addr_creds.signature, ScVal::Void) {
                            new_auth.push(entry);
                            continue;
                        }

                        // Build the preimage and sign it.
                        let preimage_xdr = crate::soroban_auth::build_auth_preimage_xdr(
                            self.network_passphrase,
                            addr_creds.nonce,
                            addr_creds.signature_expiration_ledger,
                            &entry.root_invocation,
                        )?;

                        let sign_output = self.sign_soroban_auth(private_key, &preimage_xdr)?;

                        // Format and assign the signature using our verified pubkey.
                        addr_creds.signature = crate::soroban_auth::format_auth_signature(
                            &our_pubkey,
                            &sign_output.signature,
                        )?;
                    }
                    // SorobanCredentials::SourceAccount — skip, nothing to sign.
                    new_auth.push(entry);
                }

                // Patch the auth entries back into the operation.
                invoke_op.auth = new_auth.try_into().map_err(|_| {
                    SignerError::SigningFailed(
                        "failed to convert auth entries back to VecM".into(),
                    )
                })?;
            }
            modified_ops.push(op);
        }

        // Convert operations back to VecM and patch into the envelope.
        let ops_vecm: VecM<Operation, 100> = modified_ops.try_into().map_err(|_| {
            SignerError::SigningFailed("failed to convert operations back to VecM".into())
        })?;

        // Only one match arm executes, so moving ops_vecm in each arm is valid.
        let envelope = match envelope {
            TransactionEnvelope::TxV0(mut v0) => {
                v0.tx.operations = ops_vecm;
                TransactionEnvelope::TxV0(v0)
            }
            TransactionEnvelope::Tx(mut v1) => {
                v1.tx.operations = ops_vecm;
                TransactionEnvelope::Tx(v1)
            }
            TransactionEnvelope::TxFeeBump(mut fb) => {
                match &mut fb.tx.inner_tx {
                    stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                        inner.tx.operations = ops_vecm;
                    }
                }
                TransactionEnvelope::TxFeeBump(fb)
            }
        };

        // Re-serialize the modified envelope to XDR.
        envelope
            .to_xdr(Limits::none())
            .map_err(|e| SignerError::InvalidTransaction(format!("XDR serialize failed: {e}")))
    }

    /// Sign a message using SEP-53: `SHA256("Stellar Signed Message:\n" + message)`.
    fn sign_message(
        &self,
        private_key: &[u8],
        message: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;

        // SEP-53 payload: prefix + message
        let mut payload = Vec::with_capacity(24 + message.len());
        payload.extend_from_slice(b"Stellar Signed Message:\n");
        payload.extend_from_slice(message);

        let hash: [u8; 32] = Sha256::digest(&payload).into();
        let signature = signing_key.sign(&hash);
        let pubkey_bytes = signing_key.verifying_key().to_bytes().to_vec();

        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(pubkey_bytes),
        })
    }
}

impl StellarSigner {
    /// Sign a Soroban authorization entry preimage.
    ///
    /// Signs a Soroban authorization entry preimage.
    ///
    /// `preimage_xdr` must be the full `HashIdPreimage::SorobanAuthorization` XDR
    /// (i.e. the output of `HashIdPreimage::SorobanAuthorization(...).to_xdr()`),
    /// which starts with the `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` discriminant and
    /// includes the network_id field.
    ///
    /// Computes: Ed25519_sign(SHA256(preimage_xdr))
    /// This matches stellar-base's `authorizeEntry` which does `hash(HashIdPreimage.toXDR())`.
    pub fn sign_soroban_auth(
        &self,
        private_key: &[u8],
        preimage_xdr: &[u8],
    ) -> Result<SignOutput, SignerError> {
        if preimage_xdr.is_empty() {
            return Err(SignerError::InvalidTransaction(
                "auth entry preimage must not be empty".into(),
            ));
        }

        let signing_key = Self::signing_key(private_key)?;
        let hash: [u8; 32] = Sha256::digest(preimage_xdr).into();
        let signature = signing_key.sign(&hash);
        let pubkey_bytes = signing_key.verifying_key().to_bytes().to_vec();

        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(pubkey_bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;
    use ed25519_dalek::Verifier;

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_privkey() -> Vec<u8> {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = StellarSigner::pubnet();
        let path = signer.default_derivation_path(0);
        HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Ed25519)
            .unwrap()
            .expose()
            .to_vec()
    }

    #[test]
    fn test_chain_properties() {
        let signer = StellarSigner::pubnet();
        assert_eq!(signer.chain_type(), ChainType::Stellar);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 148);
    }

    #[test]
    fn test_derivation_path() {
        let signer = StellarSigner::pubnet();
        assert_eq!(signer.default_derivation_path(0), "m/44'/148'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/148'/1'");
        assert_eq!(signer.default_derivation_path(5), "m/44'/148'/5'");
    }

    #[test]
    fn test_derive_address_format() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let address = signer.derive_address(&privkey).unwrap();

        assert!(
            address.starts_with('G'),
            "Stellar address must start with 'G', got: {}",
            address
        );
        assert_eq!(
            address.len(),
            56,
            "Stellar address must be 56 chars, got: {}",
            address.len()
        );
        // Second character must be A, B, C, or D
        let second = address.chars().nth(1).unwrap();
        assert!(
            "ABCD".contains(second),
            "Second char must be A/B/C/D, got: {}",
            second
        );
    }

    /// SEP-0005 known vector: "abandon..." mnemonic at m/44'/148'/0'
    /// produces address GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX
    #[test]
    fn test_derive_address_known_vector_sep0005() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert_eq!(
            address, "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX"
        );
    }

    #[test]
    fn test_derive_address_deterministic() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_derive_address_invalid_key() {
        let signer = StellarSigner::pubnet();
        assert!(signer.derive_address(&[0u8; 16]).is_err());
        assert!(signer.derive_address(&[]).is_err());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();

        let message = b"test message for stellar";
        let result = signer.sign(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());

        // Verify
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key.verify(message, &sig).expect("should verify");
    }

    #[test]
    fn test_deterministic_signature() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let message = b"hello";

        let sig1 = signer.sign(&privkey, message).unwrap();
        let sig2 = signer.sign(&privkey, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_extract_signable_bytes_passthrough() {
        let signer = StellarSigner::pubnet();
        let data = b"some envelope bytes";
        let result = signer.extract_signable_bytes(data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_sign_transaction_empty_input_errors() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        assert!(signer.sign_transaction(&privkey, b"").is_err());
    }

    #[test]
    fn test_sign_transaction_invalid_xdr_errors() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        assert!(signer.sign_transaction(&privkey, b"not valid xdr").is_err());
    }

    #[test]
    fn test_sign_transaction_invalid_privkey() {
        let signer = StellarSigner::testnet();
        // Need valid XDR for this test — we'll just verify invalid key is caught
        assert!(signer.sign_transaction(&[], b"some bytes").is_err());
        assert!(signer.sign_transaction(&[0u8; 16], b"some bytes").is_err());
    }

    /// Build a minimal valid V1 TransactionEnvelope XDR for testing.
    // NOTE: duplicated in crates/ows-lib/src/ops.rs (mnemonic_wallet_sign_tx_all_chains) — keep in sync
    fn build_test_envelope() -> Vec<u8> {
        use stellar_xdr::curr::*;

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0xAA; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Inflation,
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        envelope.to_xdr(Limits::none()).unwrap()
    }

    #[test]
    fn test_sign_transaction_produces_64_byte_sig() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let result = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_some());
        assert_eq!(result.public_key.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_sign_transaction_deterministic() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let sig1 = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        let sig2 = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_sign_transaction_equivalence() {
        // Verify that sign_transaction produces the same result as manually building
        // the TransactionSignaturePayload, SHA-256 hashing, and ed25519 signing.
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let result = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();

        // Manually compute the expected signature
        let envelope =
            TransactionEnvelope::from_xdr(&envelope_xdr, Limits::none()).unwrap();
        let tagged_tx = match &envelope {
            TransactionEnvelope::Tx(v1) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone())
            }
            _ => panic!("expected V1 envelope"),
        };

        let network_id: [u8; 32] =
            Sha256::digest(STELLAR_PASSPHRASE_TESTNET.as_bytes()).into();
        let payload = TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id),
            tagged_transaction: tagged_tx,
        };
        let payload_xdr = payload.to_xdr(Limits::none()).unwrap();
        let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let expected_sig = signing_key.sign(&hash);

        assert_eq!(
            result.signature,
            expected_sig.to_bytes().to_vec(),
            "sign_transaction must match manual TransactionSignaturePayload signing"
        );
    }

    #[test]
    fn test_encode_signed_transaction_roundtrip() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let sign_output = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        let signed = signer
            .encode_signed_transaction(&envelope_xdr, &sign_output)
            .unwrap();

        // Deserialize and verify
        let signed_envelope =
            TransactionEnvelope::from_xdr(&signed, Limits::none()).unwrap();
        match signed_envelope {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.signatures.len(), 1);
                let dec_sig = &v1.signatures[0];
                // Hint = last 4 bytes of pubkey
                let pubkey = sign_output.public_key.as_ref().unwrap();
                assert_eq!(dec_sig.hint.0, pubkey[28..32]);
                assert_eq!(dec_sig.signature.0.as_slice(), &sign_output.signature[..]);
            }
            _ => panic!("expected V1 envelope"),
        }
    }

    #[test]
    fn test_encode_signed_transaction_multi_sig() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        // First signature
        let sig1 = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        let once_signed = signer
            .encode_signed_transaction(&envelope_xdr, &sig1)
            .unwrap();

        // Second signature (same key, but tests multi-sig append)
        let sig2 = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        let twice_signed = signer
            .encode_signed_transaction(&once_signed, &sig2)
            .unwrap();

        let env = TransactionEnvelope::from_xdr(&twice_signed, Limits::none()).unwrap();
        match env {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.signatures.len(), 2, "should have 2 signatures");
            }
            _ => panic!("expected V1 envelope"),
        }
    }

    #[test]
    fn test_encode_signed_transaction_missing_pubkey_errors() {
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let bad_output = SignOutput {
            signature: vec![0u8; 64],
            recovery_id: None,
            public_key: None,
        };
        assert!(signer
            .encode_signed_transaction(&envelope_xdr, &bad_output)
            .is_err());
    }

    #[test]
    fn test_full_pipeline() {
        // extract → sign → encode → verify
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let signable = signer.extract_signable_bytes(&envelope_xdr).unwrap();
        assert_eq!(signable, &envelope_xdr[..]); // passthrough

        let output = signer.sign_transaction(&privkey, signable).unwrap();
        let signed = signer
            .encode_signed_transaction(&envelope_xdr, &output)
            .unwrap();

        // Verify signed envelope is valid XDR with 1 signature
        let env = TransactionEnvelope::from_xdr(&signed, Limits::none()).unwrap();
        match env {
            TransactionEnvelope::Tx(v1) => assert_eq!(v1.signatures.len(), 1),
            _ => panic!("expected V1 envelope"),
        }
    }

    /// SEP-53 message signing test vector.
    /// Seed: SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW
    /// Address: GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L
    /// Message: "Hello, World!"
    /// Signature (base64): fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA==
    #[test]
    fn test_sign_message_sep53_test_vector() {
        // Decode the secret key from Stellar secret format (SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW)
        let secret_strkey =
            stellar_strkey::ed25519::PrivateKey::from_string(
                "SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW",
            )
            .unwrap();
        let privkey = secret_strkey.0;

        let signer = StellarSigner::pubnet();
        let result = signer.sign_message(&privkey, b"Hello, World!").unwrap();

        // Verify signature matches the test vector
        use base64::Engine;
        let expected_sig = base64::engine::general_purpose::STANDARD
            .decode("fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA==")
            .unwrap();

        assert_eq!(
            result.signature, expected_sig,
            "SEP-53 signature must match test vector"
        );

        // Verify the public key matches the expected address
        assert!(result.public_key.is_some());
        let pubkey = result.public_key.unwrap();
        let strkey = stellar_strkey::ed25519::PublicKey(pubkey.try_into().unwrap());
        assert_eq!(
            strkey.to_string(),
            "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L"
        );
    }

    #[test]
    fn test_sign_message_sep53_prefix() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let message = b"test";

        let result = signer.sign_message(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.public_key.is_some());

        // Verify that the signature is over SHA256("Stellar Signed Message:\n" + message)
        let mut payload = Vec::new();
        payload.extend_from_slice(b"Stellar Signed Message:\n");
        payload.extend_from_slice(message);
        let hash: [u8; 32] = Sha256::digest(&payload).into();

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&hash, &sig)
            .expect("SEP-53 signature should verify against SHA256(prefix + message)");
    }

    #[test]
    fn test_sign_message_invalid_key() {
        let signer = StellarSigner::pubnet();
        assert!(signer.sign_message(&[], b"hello").is_err());
        assert!(signer.sign_message(&[0u8; 16], b"hello").is_err());
    }

    #[test]
    fn test_hd_derivation_integration() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = StellarSigner::pubnet();
        let path = signer.default_derivation_path(0);
        let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Ed25519).unwrap();
        let address = signer.derive_address(key.expose()).unwrap();

        assert!(address.starts_with('G'));
        assert_eq!(address.len(), 56);
        // Known SEP-0005 vector
        assert_eq!(address, "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX");
    }

    /// Build a minimal valid V0 TransactionEnvelope XDR for testing the V0→V1 conversion path.
    fn build_test_v0_envelope() -> Vec<u8> {
        use stellar_xdr::curr::*;

        let tx = TransactionV0 {
            source_account_ed25519: Uint256([0xBB; 32]),
            fee: 200,
            seq_num: SequenceNumber(42),
            time_bounds: Some(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(1_700_000_000),
            }),
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Inflation,
            }]
            .try_into()
            .unwrap(),
            ext: TransactionV0Ext::V0,
        };

        let envelope = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        envelope.to_xdr(Limits::none()).unwrap()
    }

    #[test]
    fn test_sign_transaction_v0_envelope() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_v0_envelope();

        // sign_transaction should succeed on a V0 envelope
        let result = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();

        // Output signature must be 64 bytes
        assert_eq!(result.signature.len(), 64, "V0 signature should be 64 bytes");
        assert!(result.public_key.is_some(), "V0 signing should return public key");

        // Verify the signature against the manually-built V1-equivalent payload
        let v0_env = match TransactionEnvelope::from_xdr(&envelope_xdr, Limits::none()).unwrap() {
            TransactionEnvelope::TxV0(v0) => v0,
            _ => panic!("expected V0 envelope"),
        };

        // Reconstruct the V1-equivalent Transaction (same logic as sign_transaction)
        use stellar_xdr::curr::{MuxedAccount, Transaction, Uint256};
        let v1_tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(
                v0_env.tx.source_account_ed25519.0,
            )),
            fee: v0_env.tx.fee,
            seq_num: v0_env.tx.seq_num.clone(),
            cond: match &v0_env.tx.time_bounds {
                Some(tb) => stellar_xdr::curr::Preconditions::Time(tb.clone()),
                None => stellar_xdr::curr::Preconditions::None,
            },
            memo: v0_env.tx.memo.clone(),
            operations: v0_env.tx.operations.clone(),
            ext: stellar_xdr::curr::TransactionExt::V0,
        };

        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(v1_tx);
        let network_id: [u8; 32] =
            Sha256::digest(STELLAR_PASSPHRASE_TESTNET.as_bytes()).into();
        let payload = TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id),
            tagged_transaction: tagged_tx,
        };
        let payload_xdr = payload.to_xdr(Limits::none()).unwrap();
        let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        // Verify the Ed25519 signature
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&hash, &sig)
            .expect("V0 envelope signature should verify against V1-equivalent payload");
    }

    #[test]
    fn test_sign_transaction_v0_envelope_no_timebounds() {
        // Test V0 envelope with time_bounds = None to exercise the None → Preconditions::None path
        use stellar_xdr::curr::*;

        let tx = TransactionV0 {
            source_account_ed25519: Uint256([0xCC; 32]),
            fee: 100,
            seq_num: SequenceNumber(1),
            time_bounds: None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Inflation,
            }]
            .try_into()
            .unwrap(),
            ext: TransactionV0Ext::V0,
        };

        let envelope = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });
        let envelope_xdr = envelope.to_xdr(Limits::none()).unwrap();

        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let result = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        assert_eq!(result.signature.len(), 64, "V0 no-timebounds signature should be 64 bytes");

        // Verify signature against manually-built payload with Preconditions::None
        let v1_tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0xCC; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Inflation,
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        };

        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(v1_tx);
        let network_id: [u8; 32] =
            Sha256::digest(STELLAR_PASSPHRASE_TESTNET.as_bytes()).into();
        let payload = TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id),
            tagged_transaction: tagged_tx,
        };
        let payload_xdr = payload.to_xdr(Limits::none()).unwrap();
        let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&hash, &sig)
            .expect("V0 no-timebounds signature should verify with Preconditions::None");
    }

    #[test]
    fn test_network_passphrase_selection() {
        let pubnet = StellarSigner::pubnet();
        assert_eq!(pubnet.network_passphrase, STELLAR_PASSPHRASE_PUBNET);

        let testnet = StellarSigner::testnet();
        assert_eq!(testnet.network_passphrase, STELLAR_PASSPHRASE_TESTNET);

        let futurenet = StellarSigner::futurenet();
        assert_eq!(futurenet.network_passphrase, STELLAR_PASSPHRASE_FUTURENET);
    }

    // --- sign_soroban_auth tests ---

    #[test]
    fn test_sign_soroban_auth_empty_input_errors() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        assert!(signer.sign_soroban_auth(&privkey, b"").is_err());
    }

    #[test]
    fn test_sign_soroban_auth_produces_64_byte_sig() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let preimage = b"fake soroban auth preimage xdr bytes";

        let result = signer.sign_soroban_auth(&privkey, preimage).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_some());
        assert_eq!(result.public_key.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_sign_soroban_auth_deterministic() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let preimage = b"deterministic test preimage";

        let sig1 = signer.sign_soroban_auth(&privkey, preimage).unwrap();
        let sig2 = signer.sign_soroban_auth(&privkey, preimage).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_sign_soroban_auth_invalid_key() {
        let signer = StellarSigner::testnet();
        assert!(signer.sign_soroban_auth(&[], b"some preimage").is_err());
        assert!(signer.sign_soroban_auth(&[0u8; 16], b"some preimage").is_err());
    }

    #[test]
    fn test_sign_soroban_auth_equivalence() {
        // Verify that sign_soroban_auth produces a correct Ed25519 signature
        // over SHA256(preimage_xdr), where preimage_xdr is the full XDR output
        // of HashIdPreimage::SorobanAuthorization (which already contains the
        // network id and discriminant internally).
        use stellar_xdr::curr::{
            ContractId, Hash, InvokeContractArgs, ScAddress, ScSymbol,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
        };

        let privkey = test_privkey();
        let signer = StellarSigner::testnet();

        // Build a real preimage using the shared helper.
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0xAB; 32]))),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: vec![].try_into().unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };

        let preimage_xdr = crate::soroban_auth::build_auth_preimage_xdr(
            STELLAR_PASSPHRASE_TESTNET,
            42,
            1000,
            &invocation,
        )
        .unwrap();

        let result = signer.sign_soroban_auth(&privkey, &preimage_xdr).unwrap();

        // Manually verify: sign_soroban_auth should have signed SHA256(preimage_xdr).
        let hash: [u8; 32] = Sha256::digest(&preimage_xdr).into();

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let expected_sig = signing_key.sign(&hash);

        assert_eq!(
            result.signature,
            expected_sig.to_bytes().to_vec(),
            "sign_soroban_auth must match manual Ed25519 signing of SHA256(preimage_xdr)"
        );

        // Also verify the signature is valid using the verifying key.
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&hash, &sig)
            .expect("soroban auth signature should verify against SHA256(preimage_xdr)");
    }

    // -----------------------------------------------------------------------
    // sign_inner_authorizations tests
    // -----------------------------------------------------------------------

    use stellar_xdr::curr::{
        ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, MuxedAccount,
        Operation, OperationBody, Preconditions, ScSymbol, SequenceNumber,
        SorobanAddressCredentials, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
        Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256,
    };

    /// Build a minimal Soroban auth entry for a given pubkey with an unsigned (Void) signature.
    fn make_unsigned_auth_entry(pubkey: [u8; 32], nonce: i64) -> SorobanAuthorizationEntry {
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0xAB; 32]))),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: vec![].try_into().unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };

        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(stellar_xdr::curr::AccountId(
                    stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(Uint256(pubkey)),
                )),
                nonce,
                signature_expiration_ledger: 1000,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        }
    }

    /// Build a signed auth entry (signature is non-Void).
    fn make_signed_auth_entry(pubkey: [u8; 32]) -> SorobanAuthorizationEntry {
        let mut entry = make_unsigned_auth_entry(pubkey, 99);
        if let SorobanCredentials::Address(ref mut creds) = entry.credentials {
            creds.signature = ScVal::Vec(Some(vec![ScVal::Void].try_into().unwrap()));
        }
        entry
    }

    /// Build a contract-address auth entry.
    fn make_contract_auth_entry() -> SorobanAuthorizationEntry {
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0xCD; 32]))),
                function_name: ScSymbol("approve".try_into().unwrap()),
                args: vec![].try_into().unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };

        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash([0xEF; 32]))),
                nonce: 0,
                signature_expiration_ledger: 500,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        }
    }

    /// Build a SourceAccount auth entry.
    fn make_source_account_auth_entry() -> SorobanAuthorizationEntry {
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0x11; 32]))),
                function_name: ScSymbol("test".try_into().unwrap()),
                args: vec![].try_into().unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };

        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: invocation,
        }
    }

    /// Wrap auth entries in a V1 InvokeHostFunction transaction envelope XDR.
    fn wrap_in_invoke_envelope(auth_entries: Vec<SorobanAuthorizationEntry>) -> Vec<u8> {
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0x00; 32]))),
                    function_name: ScSymbol("noop".try_into().unwrap()),
                    args: vec![].try_into().unwrap(),
                }),
                auth: auth_entries.try_into().unwrap(),
            }),
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: stellar_xdr::curr::Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        envelope.to_xdr(Limits::none()).unwrap()
    }

    /// Wrap an operation in a non-Soroban (e.g. Payment) envelope.
    fn wrap_non_soroban_envelope() -> Vec<u8> {
        let op = Operation {
            source_account: None,
            body: OperationBody::Inflation,
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: stellar_xdr::curr::Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        envelope.to_xdr(Limits::none()).unwrap()
    }

    /// Extract the first auth entry's signature from a signed envelope.
    fn extract_auth_signature(tx_bytes: &[u8], index: usize) -> ScVal {
        let envelope = TransactionEnvelope::from_xdr(tx_bytes, Limits::none()).unwrap();
        let ops = match &envelope {
            TransactionEnvelope::Tx(v1) => v1.tx.operations.to_vec(),
            _ => panic!("expected V1 envelope"),
        };
        match &ops[0].body {
            OperationBody::InvokeHostFunction(ihf) => {
                let entry = &ihf.auth.to_vec()[index];
                match &entry.credentials {
                    SorobanCredentials::Address(creds) => creds.signature.clone(),
                    SorobanCredentials::SourceAccount => ScVal::Void,
                }
            }
            _ => panic!("expected InvokeHostFunction"),
        }
    }

    fn our_pubkey_bytes() -> [u8; 32] {
        let privkey = test_privkey();
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        signing_key.verifying_key().to_bytes()
    }

    #[test]
    fn test_sign_inner_auth_passthrough_no_invoke() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope = wrap_non_soroban_envelope();

        let result = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();
        assert_eq!(result, envelope, "non-Soroban tx should pass through unchanged");
    }

    #[test]
    fn test_sign_inner_auth_empty_auth_entries() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope = wrap_in_invoke_envelope(vec![]);

        let result = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();

        // Should still parse correctly, with empty auth
        let env = TransactionEnvelope::from_xdr(&result, Limits::none()).unwrap();
        match &env {
            TransactionEnvelope::Tx(v1) => match &v1.tx.operations[0].body {
                OperationBody::InvokeHostFunction(ihf) => {
                    assert!(ihf.auth.is_empty());
                }
                _ => panic!("expected InvokeHostFunction"),
            },
            _ => panic!("expected V1"),
        }
    }

    #[test]
    fn test_sign_inner_auth_signs_matching_entry() {
        let privkey = test_privkey();
        let pubkey = our_pubkey_bytes();
        let signer = StellarSigner::testnet();

        let entry = make_unsigned_auth_entry(pubkey, 42);
        let envelope = wrap_in_invoke_envelope(vec![entry]);

        let result = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();

        let sig = extract_auth_signature(&result, 0);
        assert!(!matches!(sig, ScVal::Void), "auth entry should be signed");

        // Verify it's the correct format: Vec([Map({public_key, signature})])
        match sig {
            ScVal::Vec(Some(vec)) => {
                assert_eq!(vec.len(), 1);
                match &vec[0] {
                    ScVal::Map(Some(map)) => {
                        assert_eq!(map.len(), 2);
                        assert_eq!(map[0].key, ScVal::Symbol("public_key".try_into().unwrap()));
                        assert_eq!(map[1].key, ScVal::Symbol("signature".try_into().unwrap()));
                        // Verify public key matches our key
                        if let ScVal::Bytes(pk_bytes) = &map[0].val {
                            assert_eq!(pk_bytes.as_slice(), &pubkey);
                        } else {
                            panic!("expected Bytes for public_key");
                        }
                        // Verify signature is 64 bytes
                        if let ScVal::Bytes(sig_bytes) = &map[1].val {
                            assert_eq!(sig_bytes.len(), 64);
                        } else {
                            panic!("expected Bytes for signature");
                        }
                    }
                    _ => panic!("expected Map inside Vec"),
                }
            }
            _ => panic!("expected Vec"),
        }
    }

    #[test]
    fn test_sign_inner_auth_skips_non_matching_key() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let other_pubkey = [0xFFu8; 32];

        let entry = make_unsigned_auth_entry(other_pubkey, 42);
        let envelope = wrap_in_invoke_envelope(vec![entry]);

        let result = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();

        let sig = extract_auth_signature(&result, 0);
        assert!(matches!(sig, ScVal::Void), "other key's entry should remain unsigned");
    }

    #[test]
    fn test_sign_inner_auth_skips_already_signed() {
        let privkey = test_privkey();
        let pubkey = our_pubkey_bytes();
        let signer = StellarSigner::testnet();

        let entry = make_signed_auth_entry(pubkey);
        let envelope = wrap_in_invoke_envelope(vec![entry]);

        let result = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();

        let sig = extract_auth_signature(&result, 0);
        // Should still be the original non-Void signature, not re-signed
        assert!(!matches!(sig, ScVal::Void));
        // Original was Vec([Void]) — verify it's preserved, not overwritten
        match sig {
            ScVal::Vec(Some(vec)) => {
                assert_eq!(vec.len(), 1);
                assert!(matches!(vec[0], ScVal::Void), "original signature payload should be preserved");
            }
            _ => panic!("expected original Vec signature"),
        }
    }

    #[test]
    fn test_sign_inner_auth_skips_contract_address() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();

        let entry = make_contract_auth_entry();
        let envelope = wrap_in_invoke_envelope(vec![entry]);

        let result = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();

        let sig = extract_auth_signature(&result, 0);
        assert!(matches!(sig, ScVal::Void), "contract address entry should remain unsigned");
    }

    #[test]
    fn test_sign_inner_auth_skips_source_account() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();

        let entry = make_source_account_auth_entry();
        let envelope = wrap_in_invoke_envelope(vec![entry]);

        let result = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();

        let sig = extract_auth_signature(&result, 0);
        assert!(matches!(sig, ScVal::Void), "source account entry needs no auth signing");
    }

    #[test]
    fn test_sign_inner_auth_mixed_entries() {
        let privkey = test_privkey();
        let pubkey = our_pubkey_bytes();
        let other_pubkey = [0xAAu8; 32];
        let signer = StellarSigner::testnet();

        let entries = vec![
            make_unsigned_auth_entry(pubkey, 1),       // 0: ours, unsigned → SIGN
            make_unsigned_auth_entry(other_pubkey, 2),  // 1: other key → SKIP
            make_signed_auth_entry(pubkey),             // 2: ours, already signed → SKIP
            make_contract_auth_entry(),                 // 3: contract address → SKIP
            make_unsigned_auth_entry(pubkey, 3),       // 4: ours, unsigned → SIGN
        ];

        let envelope = wrap_in_invoke_envelope(entries);
        let result = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();

        // Entry 0: should be signed
        let sig0 = extract_auth_signature(&result, 0);
        assert!(!matches!(sig0, ScVal::Void), "entry 0 should be signed");

        // Entry 1: should remain unsigned
        let sig1 = extract_auth_signature(&result, 1);
        assert!(matches!(sig1, ScVal::Void), "entry 1 should remain unsigned");

        // Entry 2: should preserve original signature
        let sig2 = extract_auth_signature(&result, 2);
        match sig2 {
            ScVal::Vec(Some(vec)) => assert!(matches!(vec[0], ScVal::Void)),
            _ => panic!("entry 2 should preserve original"),
        }

        // Entry 3: contract address, should remain unsigned
        let sig3 = extract_auth_signature(&result, 3);
        assert!(matches!(sig3, ScVal::Void), "entry 3 should remain unsigned");

        // Entry 4: should be signed
        let sig4 = extract_auth_signature(&result, 4);
        assert!(!matches!(sig4, ScVal::Void), "entry 4 should be signed");

        // Entries 0 and 4 should have DIFFERENT signatures (different nonces)
        assert_ne!(sig0, sig4, "different nonces must produce different signatures");
    }

    #[test]
    fn test_sign_inner_auth_idempotent() {
        let privkey = test_privkey();
        let pubkey = our_pubkey_bytes();
        let signer = StellarSigner::testnet();

        let entry = make_unsigned_auth_entry(pubkey, 42);
        let envelope = wrap_in_invoke_envelope(vec![entry]);

        let first = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();
        let second = signer.sign_inner_authorizations(&privkey, &first).unwrap();

        assert_eq!(first, second, "signing twice should produce identical output");
    }

    #[test]
    fn test_sign_inner_auth_invalid_xdr() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();

        let result = signer.sign_inner_authorizations(&privkey, b"not valid xdr");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_inner_auth_invalid_private_key() {
        let signer = StellarSigner::testnet();
        let pubkey = [0u8; 32]; // won't match anyway
        let entry = make_unsigned_auth_entry(pubkey, 1);
        let envelope = wrap_in_invoke_envelope(vec![entry]);

        // Too-short key
        let result = signer.sign_inner_authorizations(&[0u8; 16], &envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_inner_auth_different_networks_different_sigs() {
        let privkey = test_privkey();
        let pubkey = our_pubkey_bytes();

        let entry = make_unsigned_auth_entry(pubkey, 42);
        let envelope = wrap_in_invoke_envelope(vec![entry]);

        let testnet_result = StellarSigner::testnet()
            .sign_inner_authorizations(&privkey, &envelope)
            .unwrap();
        let pubnet_result = StellarSigner::pubnet()
            .sign_inner_authorizations(&privkey, &envelope)
            .unwrap();

        assert_ne!(
            testnet_result, pubnet_result,
            "different networks must produce different signatures (replay protection)"
        );
    }

    #[test]
    fn test_sign_inner_auth_signature_verifies() {
        let privkey = test_privkey();
        let pubkey = our_pubkey_bytes();
        let signer = StellarSigner::testnet();
        let nonce = 42i64;
        let expiration = 1000u32;

        let entry = make_unsigned_auth_entry(pubkey, nonce);
        let envelope = wrap_in_invoke_envelope(vec![entry.clone()]);

        let result = signer.sign_inner_authorizations(&privkey, &envelope).unwrap();

        // Extract the signature bytes
        let sig_val = extract_auth_signature(&result, 0);
        let sig_bytes: Vec<u8> = match sig_val {
            ScVal::Vec(Some(vec)) => match &vec[0] {
                ScVal::Map(Some(map)) => match &map[1].val {
                    ScVal::Bytes(b) => b.to_vec(),
                    _ => panic!("expected Bytes"),
                },
                _ => panic!("expected Map"),
            },
            _ => panic!("expected Vec"),
        };

        // Rebuild the preimage that should have been signed
        let preimage_xdr = crate::soroban_auth::build_auth_preimage_xdr(
            STELLAR_PASSPHRASE_TESTNET,
            nonce,
            expiration,
            &entry.root_invocation,
        )
        .unwrap();

        // Verify: SHA256(preimage_xdr), then check Ed25519 signature
        let hash: [u8; 32] = Sha256::digest(&preimage_xdr).into();
        let verifying_key = VerifyingKey::from_bytes(&pubkey).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());
        verifying_key
            .verify(&hash, &sig)
            .expect("auth entry signature must verify against the correct preimage");
    }
}
