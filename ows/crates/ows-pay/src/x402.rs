use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::chains::{self, ChainMapping};
use crate::error::{PayError, PayErrorCode};
use crate::types::{
    Eip3009Authorization, Eip3009Payload, PayResult, PaymentInfo, PaymentPayload,
    PaymentRequirements, Protocol, X402Response,
};
use crate::wallet::WalletAccess;

const HEADER_PAYMENT_REQUIRED: &str = "x-payment-required";
const HEADER_PAYMENT: &str = "X-PAYMENT";

/// Handle x402 payment for a 402 response we already received.
pub(crate) async fn handle_x402(
    wallet: &dyn WalletAccess,
    url: &str,
    method: &str,
    req_body: Option<&str>,
    resp_headers: &reqwest::header::HeaderMap,
    body_402: &str,
) -> Result<PayResult, PayError> {
    let requirements = parse_requirements(resp_headers, body_402)?;
    let (req, chain) = pick_payment_option(&requirements)?;

    let account = wallet.evm_account()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let valid_after = now.saturating_sub(5);
    let valid_before = now + req.max_timeout_seconds;

    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| PayError::new(PayErrorCode::SigningFailed, format!("rng: {e}")))?;
    let nonce_hex = format!("0x{}", hex::encode(nonce_bytes));

    let token_name = req
        .extra
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("USD Coin");
    let token_version = req
        .extra
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("2");

    let chain_id_num: u64 = chain
        .caip2
        .split(':')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            PayError::new(
                PayErrorCode::ProtocolMalformed,
                format!("bad CAIP-2: {}", chain.caip2),
            )
        })?;

    let typed_data_json = serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "TransferWithAuthorization": [
                { "name": "from", "type": "address" },
                { "name": "to", "type": "address" },
                { "name": "value", "type": "uint256" },
                { "name": "validAfter", "type": "uint256" },
                { "name": "validBefore", "type": "uint256" },
                { "name": "nonce", "type": "bytes32" }
            ]
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id_num.to_string(),
            "verifyingContract": req.asset
        },
        "message": {
            "from": account.address,
            "to": req.pay_to,
            "value": req.amount,
            "validAfter": valid_after.to_string(),
            "validBefore": valid_before.to_string(),
            "nonce": nonce_hex.clone()
        }
    })
    .to_string();

    let sig = wallet.sign_typed_data(chain.ows_chain, &typed_data_json)?;

    let payload = PaymentPayload {
        x402_version: 1,
        scheme: "exact".into(),
        network: req.network.clone(),
        payload: Eip3009Payload {
            signature: sig.signature,
            authorization: Eip3009Authorization {
                from: account.address,
                to: req.pay_to.clone(),
                value: req.amount.clone(),
                valid_after: valid_after.to_string(),
                valid_before: valid_before.to_string(),
                nonce: nonce_hex,
            },
        },
    };

    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = B64.encode(payload_json.as_bytes());
    let amount_display = crate::discovery::format_usdc(&req.amount);

    let client = reqwest::Client::new();
    let retry = build_request(&client, url, method, req_body, Some(&payload_b64))?
        .send()
        .await?;

    let status = retry.status().as_u16();
    let response_body = retry.text().await.unwrap_or_default();

    Ok(PayResult {
        protocol: Protocol::X402,
        status,
        body: response_body,
        payment: Some(PaymentInfo {
            amount: amount_display,
            network: chain.name.to_string(),
            token: "USDC".to_string(),
        }),
    })
}

fn parse_requirements(
    headers: &reqwest::header::HeaderMap,
    body_text: &str,
) -> Result<Vec<PaymentRequirements>, PayError> {
    if let Some(header_val) = headers.get(HEADER_PAYMENT_REQUIRED) {
        if let Ok(header_str) = header_val.to_str() {
            if let Ok(decoded) = B64.decode(header_str) {
                if let Ok(parsed) = serde_json::from_slice::<X402Response>(&decoded) {
                    if !parsed.accepts.is_empty() {
                        return Ok(parsed.accepts);
                    }
                }
            }
        }
    }

    let parsed: X402Response = serde_json::from_str(body_text).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("failed to parse x402 402 response: {e}"),
        )
    })?;

    if parsed.accepts.is_empty() {
        return Err(PayError::new(
            PayErrorCode::ProtocolMalformed,
            "402 response has empty accepts",
        ));
    }

    Ok(parsed.accepts)
}

fn pick_payment_option(
    requirements: &[PaymentRequirements],
) -> Result<(&PaymentRequirements, &'static ChainMapping), PayError> {
    for req in requirements {
        if req.scheme != "exact" {
            continue;
        }
        if let Some(chain) =
            chains::chain_by_caip2(&req.network).or_else(|| chains::chain_by_name(&req.network))
        {
            return Ok((req, chain));
        }
    }

    let networks: Vec<_> = requirements.iter().map(|r| r.network.as_str()).collect();
    Err(PayError::new(
        PayErrorCode::UnsupportedChain,
        format!("no supported EVM chain in 402 response (networks: {networks:?})"),
    ))
}

pub(crate) fn build_request(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_header: Option<&str>,
) -> Result<reqwest::RequestBuilder, PayError> {
    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        other => {
            return Err(PayError::new(
                PayErrorCode::InvalidInput,
                format!("unsupported HTTP method: {other}"),
            ))
        }
    };

    if let Some(b) = body {
        req = req
            .header("content-type", "application/json")
            .body(b.to_string());
    }

    if let Some(payment) = payment_header {
        req = req.header(HEADER_PAYMENT, payment);
    }

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use reqwest::header::HeaderMap;

    fn base_requirement() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "base".into(),
            amount: "10000".into(),
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            pay_to: "0x1234567890abcdef1234567890abcdef12345678".into(),
            max_timeout_seconds: 60,
            extra: serde_json::json!({"name": "USD Coin", "version": "2"}),
            description: Some("test service".into()),
            resource: None,
        }
    }

    // -----------------------------------------------------------------------
    // build_request
    // -----------------------------------------------------------------------

    #[test]
    fn build_request_valid_methods() {
        let client = reqwest::Client::new();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH"] {
            let result = build_request(&client, "https://example.com", method, None, None);
            assert!(result.is_ok(), "method {method} should be valid");
        }
    }

    #[test]
    fn build_request_case_insensitive() {
        let client = reqwest::Client::new();
        for method in &["get", "Post", "pUT", "dElEtE", "patch"] {
            let result = build_request(&client, "https://example.com", method, None, None);
            assert!(
                result.is_ok(),
                "method {method} should be valid (case-insensitive)"
            );
        }
    }

    #[test]
    fn build_request_invalid_method() {
        let client = reqwest::Client::new();
        let result = build_request(&client, "https://example.com", "FOOBAR", None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, PayErrorCode::InvalidInput);
        assert!(err.message.contains("FOOBAR"));
    }

    #[test]
    fn build_request_head_is_invalid() {
        let client = reqwest::Client::new();
        let result = build_request(&client, "https://example.com", "HEAD", None, None);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // parse_requirements
    // -----------------------------------------------------------------------

    #[test]
    fn parse_requirements_from_body() {
        let headers = HeaderMap::new();
        let body = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xabc",
                "maxTimeoutSeconds": 30
            }]
        })
        .to_string();

        let reqs = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].scheme, "exact");
        assert_eq!(reqs[0].network, "base");
        assert_eq!(reqs[0].amount, "10000");
        assert_eq!(reqs[0].pay_to, "0xabc");
    }

    #[test]
    fn parse_requirements_from_header() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xdef"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("x-payment-required", encoded.parse().unwrap());

        // Body is garbage — should still parse from header.
        let reqs = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xdef");
    }

    #[test]
    fn parse_requirements_header_fallback_to_body() {
        let mut headers = HeaderMap::new();
        headers.insert("x-payment-required", "not-valid-base64!!!".parse().unwrap());

        let body = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "amount": "1000",
                "asset": "0xaaa",
                "payTo": "0xbbb"
            }]
        })
        .to_string();

        let reqs = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs[0].pay_to, "0xbbb");
    }

    #[test]
    fn parse_requirements_empty_accepts_errors() {
        let headers = HeaderMap::new();
        let body = r#"{"accepts":[]}"#;
        let err = parse_requirements(&headers, body).unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    #[test]
    fn parse_requirements_bad_json_errors() {
        let headers = HeaderMap::new();
        let err = parse_requirements(&headers, "this is not json").unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    // -----------------------------------------------------------------------
    // pick_payment_option
    // -----------------------------------------------------------------------

    #[test]
    fn pick_payment_option_base_by_name() {
        let reqs = vec![base_requirement()];
        let (req, chain) = pick_payment_option(&reqs).unwrap();
        assert_eq!(req.network, "base");
        assert_eq!(chain.name, "Base");
        assert_eq!(chain.caip2, "eip155:8453");
    }

    #[test]
    fn pick_payment_option_by_caip2() {
        let mut req = base_requirement();
        req.network = "eip155:8453".into();
        let (_, chain) = pick_payment_option(&[req]).unwrap();
        assert_eq!(chain.name, "Base");
    }

    #[test]
    fn pick_payment_option_skips_non_exact() {
        let mut req = base_requirement();
        req.scheme = "subscription".into();
        let err = pick_payment_option(&[req]).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_payment_option_unsupported_chain() {
        let mut req = base_requirement();
        req.network = "solana:mainnet".into();
        let err = pick_payment_option(&[req]).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_payment_option_prefers_first_match() {
        let mut eth = base_requirement();
        eth.network = "ethereum".into();
        eth.amount = "99999".into();
        let base = base_requirement(); // network = "base"
        let reqs = [eth, base];
        let (req, chain) = pick_payment_option(&reqs).unwrap();
        assert_eq!(chain.name, "Ethereum");
        assert_eq!(req.amount, "99999");
    }

    // -----------------------------------------------------------------------
    // handle_x402 (mock wallet, no network)
    // -----------------------------------------------------------------------

    struct MockWallet;

    impl WalletAccess for MockWallet {
        fn evm_account(&self) -> Result<crate::wallet::EvmAccount, PayError> {
            Ok(crate::wallet::EvmAccount {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            })
        }

        fn sign_typed_data(
            &self,
            _chain: &str,
            _typed_data_json: &str,
        ) -> Result<crate::wallet::TypedDataSignature, PayError> {
            Ok(crate::wallet::TypedDataSignature {
                signature: "0xdeadbeef".into(),
            })
        }
    }

    /// Verify that handle_x402 builds correct typed data and payload structure
    /// using a mock wallet (no real network call — will fail at the retry HTTP
    /// request, but we can verify everything up to that point via parse/pick).
    #[test]
    fn mock_wallet_compiles_and_satisfies_trait() {
        // This test verifies the WalletAccess trait works with just
        // evm_account + sign_typed_data (no sign_hash needed).
        let wallet = MockWallet;
        let account = wallet.evm_account().unwrap();
        assert!(account.address.starts_with("0x"));

        let sig = wallet.sign_typed_data("base", "{}").unwrap();
        assert_eq!(sig.signature, "0xdeadbeef");
    }

    #[test]
    fn parse_and_pick_roundtrip() {
        // Simulate a real 402 body and verify the full parse → pick pipeline.
        let body = serde_json::json!({
            "x402Version": 1,
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "maxAmountRequired": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x7d9d1821d15B9e0b8Ab98A058361233E255E405D",
                "maxTimeoutSeconds": 120,
                "extra": {"name": "USD Coin", "version": "2"}
            }]
        })
        .to_string();

        let headers = HeaderMap::new();
        let reqs = parse_requirements(&headers, &body).unwrap();
        let (req, chain) = pick_payment_option(&reqs).unwrap();
        assert_eq!(req.pay_to, "0x7d9d1821d15B9e0b8Ab98A058361233E255E405D");
        assert_eq!(chain.ows_chain, "base");
    }
}
