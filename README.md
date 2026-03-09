# Local Wallet Standard (LWS)

A specification and reference implementation for secure, local-first crypto wallet management — designed for AI agents.

## Motivation

AI agents increasingly need to interact with blockchains: signing transactions, managing accounts, and moving value across chains. Existing wallet infrastructure was built for humans clicking buttons in browser extensions, not for programmatic agents operating autonomously.

LWS addresses this gap. It defines a minimal, chain-agnostic standard for wallet operations where:

- **Private keys never leave the local machine.** Keys are stored in encrypted Ethereum Keystore v3 format with strict filesystem permissions — no remote servers, no browser extensions.
- **Agents interact through structured protocols.** The primary interface is an [MCP](https://modelcontextprotocol.io) server, giving AI agents native wallet access without custom integrations.
- **Transaction policies are enforced before signing.** A pre-signing policy engine gates every operation, so agents can be granted scoped, auditable access to wallet capabilities.
- **One interface covers all chains.** CAIP-2/CAIP-10 addressing and a unified signing interface abstract away chain-specific details across EVM, Solana, Bitcoin, Cosmos, and Tron.

## Repo Structure

```
├── docs/                        # The specification (8 documents)
│   ├── 01-storage-format.md         # Vault layout, Keystore v3, filesystem permissions
│   ├── 02-chain-agnostic-addressing.md  # CAIP-2/CAIP-10 standards
│   ├── 03-signing-interface.md      # sign, signAndSend, signMessage operations
│   ├── 04-policy-engine.md          # Pre-signing transaction policies
│   ├── 05-key-isolation.md          # HD derivation paths and key separation
│   ├── 06-agent-access-layer.md     # MCP server, native language bindings
│   ├── 07-multi-chain-support.md    # Multi-chain account management
│   └── 08-wallet-lifecycle.md       # Creation, recovery, deletion, lifecycle events
│
├── lws/                         # Rust reference implementation
│   └── crates/
│       ├── lws-core/                # Core types, CAIP parsing, config (zero crypto deps)
│       └── lws-signer/             # Signing, HD derivation, chain-specific implementations
│
└── website/                     # Documentation site (localwalletstandard.org)
```

## Getting Started

Read the spec starting with [`docs/01-storage-format.md`](docs/01-storage-format.md), or browse it at [localwalletstandard.org](https://localwalletstandard.org).

### Install everything (CLI + language bindings)

```bash
curl -fsSL https://openwallet.sh/install.sh | bash
```

This installs the `lws` CLI binary, plus Node.js and Python bindings if those runtimes are detected.

### Or install only what you need

| Method | What you get | Command |
|--------|-------------|---------|
| Install script | CLI + Node + Python bindings | `curl -fsSL https://openwallet.sh/install.sh \| bash` |
| npm | Node.js bindings only (standalone) | `npm install @local-wallet-standard/node` |
| pip | Python bindings only (standalone) | `pip install local-wallet-standard` |
| Source | Build everything from source | `cd lws && cargo build --workspace --release` |

The language bindings are **fully self-contained** — they embed the Rust core via native FFI. You do not need the CLI binary or install script to use them. `npm install` or `pip install` is all you need.

## CLI

```bash
curl -fsSL https://openwallet.sh/install.sh | bash
```

| Command | Description |
|---------|-------------|
| `lws wallet create` | Create a new wallet (generates mnemonic, derives addresses for all chains) |
| `lws wallet list` | List all saved wallets in the vault |
| `lws wallet info` | Show vault path and supported chains |
| `lws sign message` | Sign a message using a vault wallet with chain-specific formatting |
| `lws sign tx` | Sign a raw transaction using a vault wallet |
| `lws mnemonic generate` | Generate a new BIP-39 mnemonic phrase |
| `lws mnemonic derive` | Derive an address from a mnemonic (via env or stdin) |
| `lws update` | Update lws and installed bindings to the latest version |
| `lws uninstall` | Remove lws and bindings from the system |

## Language Bindings

LWS provides native bindings that embed the Rust `lws-lib` crate via FFI — no CLI, no HTTP server, no subprocess required. Install the bindings in any project and use them directly.

### Node.js

[![npm](https://img.shields.io/npm/v/@local-wallet-standard/node)](https://www.npmjs.com/package/@local-wallet-standard/node)

```bash
npm install @local-wallet-standard/node
```

```javascript
import {
  generateMnemonic,
  createWallet,
  listWallets,
  signMessage,
} from "@local-wallet-standard/node";

// Generate a 12-word mnemonic
const mnemonic = generateMnemonic(12);

// Create a universal wallet (derives addresses for all supported chains)
const wallet = createWallet("agent-treasury");
console.log(wallet.accounts);
// => [{ chainId: "eip155:1", address: "0x...", derivationPath: "m/44'/60'/0'/0/0" }, ...]

// List all wallets
const wallets = listWallets();

// Sign a message
const result = signMessage("agent-treasury", "evm", "hello");
console.log(result.signature);
```

### Python

[![PyPI](https://img.shields.io/pypi/v/local-wallet-standard)](https://pypi.org/project/local-wallet-standard/)

```bash
pip install local-wallet-standard
```

```python
from local_wallet_standard import (
    generate_mnemonic,
    create_wallet,
    list_wallets,
    sign_message,
)

mnemonic = generate_mnemonic(12)

wallet = create_wallet("agent-treasury")
print(wallet["accounts"])

wallets = list_wallets()

result = sign_message("agent-treasury", "evm", "hello")
print(result["signature"])
```

Both bindings are compiled native modules (NAPI for Node.js, PyO3 for Python). They share the same API surface: wallet management, signing, and mnemonic operations. Every wallet is universal — it derives addresses for all supported chains (EVM, Solana, Bitcoin, Cosmos, Tron) at creation time.

## Supported Chains

| Chain | Curve | Address Format | Derivation Path |
|-------|-------|----------------|-----------------|
| EVM (Ethereum, Polygon, etc.) | secp256k1 | EIP-55 checksummed | `m/44'/60'/0'/0/0` |
| Solana | Ed25519 | base58 | `m/44'/501'/0'/0'` |
| Bitcoin | secp256k1 | BIP-84 bech32 (native segwit) | `m/84'/0'/0'/0/0` |
| Cosmos | secp256k1 | bech32 | `m/44'/118'/0'/0/0` |
| Tron | secp256k1 | base58check | `m/44'/195'/0'/0/0` |

## License

MIT
