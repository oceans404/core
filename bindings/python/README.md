# open-wallet-standard

Secure signing and wallet management for every chain. One vault, one interface — keys never leave your machine.

[![PyPI](https://img.shields.io/pypi/v/open-wallet-standard)](https://pypi.org/project/open-wallet-standard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/open-wallet-standard/core/blob/main/LICENSE)

## Why OWS

- **Zero key exposure.** Private keys are encrypted at rest, decrypted only inside an isolated signing process. Agents and LLMs never see raw key material.
- **Every chain, one interface.** EVM, Solana, Bitcoin, Cosmos, Tron, TON — all first-class. CAIP-2/CAIP-10 addressing abstracts away chain-specific details.
- **Policy before signing.** A pre-signing policy engine gates every operation — spending limits, allowlists, chain restrictions — before any key is touched.
- **Built for agents.** MCP server, native SDK, and CLI. A wallet created by one tool works in every other.

## Install

```bash
pip install open-wallet-standard
```

The package is **fully self-contained** — it embeds the Rust core via native FFI. No additional dependencies required.

## Quick Start

```python
from ows import create_wallet, sign_message

wallet = create_wallet("agent-treasury")
# => accounts for EVM, Solana, BTC, Cosmos, Tron, TON

sig = sign_message("agent-treasury", "evm", "hello")
print(sig["signature"])
```

## API Reference

| Function | Description |
|----------|-------------|
| `create_wallet(name)` | Create a new wallet with addresses for all chains |
| `import_wallet_mnemonic(name, mnemonic)` | Import a wallet from a BIP-39 mnemonic |
| `import_wallet_private_key(name, chain, private_key)` | Import a wallet from a private key |
| `list_wallets()` | List all wallets in the vault |
| `get_wallet(name)` | Get details of a specific wallet |
| `delete_wallet(name)` | Delete a wallet |
| `export_wallet(name)` | Export a wallet's mnemonic |
| `rename_wallet(old_name, new_name)` | Rename a wallet |
| `sign_message(wallet, chain, message)` | Sign a message with chain-specific formatting |
| `sign_transaction(wallet, chain, tx)` | Sign a raw transaction |
| `sign_and_send(wallet, chain, tx)` | Sign and broadcast a transaction |
| `generate_mnemonic()` | Generate a BIP-39 mnemonic phrase |
| `derive_address(mnemonic, chain)` | Derive an address from a mnemonic |

## Supported Chains

| Chain | Curve | Address Format | Derivation Path |
|-------|-------|----------------|-----------------|
| EVM (Ethereum, Polygon, etc.) | secp256k1 | EIP-55 checksummed | `m/44'/60'/0'/0/0` |
| Solana | Ed25519 | base58 | `m/44'/501'/0'/0'` |
| Bitcoin | secp256k1 | BIP-84 bech32 | `m/84'/0'/0'/0/0` |
| Cosmos | secp256k1 | bech32 | `m/44'/118'/0'/0/0` |
| Tron | secp256k1 | base58check | `m/44'/195'/0'/0/0` |
| TON | Ed25519 | raw/bounceable | `m/44'/607'/0'` |

## Architecture

```
Agent / CLI / App
       │
       │  OWS Interface (MCP / SDK / CLI)
       ▼
┌─────────────────────┐
│    Access Layer      │     1. Agent calls ows.sign()
│  ┌────────────────┐  │     2. Policy engine evaluates
│  │ Policy Engine   │  │     3. Enclave decrypts key
│  │ (pre-signing)   │  │     4. Transaction signed
│  └───────┬────────┘  │     5. Key wiped from memory
│  ┌───────▼────────┐  │     6. Signature returned
│  │ Signing Enclave │  │
│  │ (isolated proc) │  │     The agent NEVER sees
│  └───────┬────────┘  │     the private key.
│  ┌───────▼────────┐  │
│  │  Wallet Vault   │  │
│  │ ~/.ows/wallets/ │  │
│  └────────────────┘  │
└─────────────────────┘
```

## Documentation

The full spec and docs are available at [openwallet.sh](https://openwallet.sh) and in the [GitHub repo](https://github.com/open-wallet-standard/core).

## License

MIT
