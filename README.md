# Syn Wallet

**A non-custodial, phone-first, multi-chain crypto wallet that runs entirely in the browser — your keys never leave your device.**

![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=node.js&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-5-646CFF?logo=vite&logoColor=white)
![Express](https://img.shields.io/badge/Express-4-000000?logo=express&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Web%20%2F%20PWA-silver)

Syn Wallet is a full-featured web wallet for Solana, Bitcoin, and 20+ EVM networks. Create or import a wallet from a single recovery phrase, hold and send assets across every chain, swap tokens, stake SOL, collect NFTs, trade perpetuals and prediction markets, and connect to dApps with WalletConnect — all from one mobile-first interface, with no account, no sign-up, and no server ever touching your keys.

---

## Features

**Wallet core**
- Create a wallet with a 12-word BIP39 recovery phrase (numbered backup screen + verify-by-selecting-words), or import a 12/24-word phrase or a single-chain private key
- One seed derives every chain (BIP44 / SLIP-0010): Solana, all EVM networks, Bitcoin SegWit and Taproot, plus Litecoin, Tron, XRP, Cosmos, Sui, and Aptos
- Multiple wallets and accounts in one encrypted vault, per-wallet network visibility controls, custom networks and custom tokens

**Portfolio**
- Live total balance and per-asset balances with real USD prices; honest "unavailable" states — a price or balance is never faked
- Live ticker charts (24H / 7D / 1M) with streaming price updates, an asset detail view, and multi-currency display with live FX rates
- Activity history per network and across all networks, merged with locally recorded sends, with a transaction detail sheet and depth paging

**Send & receive**
- Native sends on Solana, every EVM chain, and the UTXO family (BTC / LTC) with coin selection, fee estimation, and a review screen that always accounts for the network fee
- Receive with per-chain addresses and QR codes; address book with counterparty memory

**Swap**
- In-wallet swaps via Jupiter (Solana) and LI.FI (EVM and cross-chain), with live quotes, price-impact display, and locally signed transactions

**Invest**
- **Crypto:** trending DEX pools per network (GeckoTerminal) alongside your own holdings
- **Perpetuals:** Hyperliquid markets (crypto, stocks, commodities, pre-IPO) with an in-wallet trading key that can trade but never withdraw, live charts, and position management
- **Prediction markets:** Polymarket browsing with live streamed prices, Up-or-Down short-window markets with a real-time Chainlink price-to-beat ticker, positions, and order placement signed on-device
- **bStocks:** tokenized U.S. stocks and ETFs on BNB Chain with live DEX prices
- **Stake:** native Solana staking with validator discovery and identities

**Collectibles**
- NFT gallery across chains with collection views and on-device metadata rendering

**dApps**
- WalletConnect (Reown) pairing and request review — session proposals and signing requests queue in order and are approved or rejected on-device
- Built-in Discover directory of dApps by category

---

## Screenshots

Real captures of the running app live in the [`proof/`](proof/) directory:

| File | Screen |
| --- | --- |
| `proof/01-onboarding.png` | Onboarding |
| `proof/02-backup-blurred.png` | Recovery-phrase backup (blurred) |
| `proof/03-set-password.png` | Set password |
| `proof/04-home-orb-hero.png` | Home |
| `proof/05-asset-ticker.png` | Asset detail with live ticker chart |
| `proof/06-settings.png` | Settings |
| `proof/07-unlock.png` | Unlock |

---

## Architecture

Syn Wallet is deliberately split into a **client that holds everything** and a **server that holds nothing**.

```
Browser (all user data, all signing)            Server (stateless)
┌──────────────────────────────────┐            ┌─────────────────────────────┐
│ Encrypted vault (AES-256-GCM)    │  HTTPS     │ Static host for the client  │
│ Key derivation + tx signing      │ ─────────► │ Public-data proxies only:   │
│ Vanilla TypeScript UI (Vite)     │            │ prices, RPC pools, market   │
│ WalletConnect / swap / trade     │            │ data, history — pass-through│
│ logic, all local                 │            │ with in-memory caching      │
└──────────────────────────────────┘            └─────────────────────────────┘
```

- The **client** (`client/`) is a dependency-light vanilla TypeScript app built with Vite. It generates and stores keys, derives addresses, builds and signs every transaction, and talks to swap/trading venues with the user's own credentials.
- The **server** (`src/server.ts`, Express) exists because browsers cannot reliably reach every upstream (CORS, rate limits, bot walls). It serves the client and proxies **public market data only** — prices, charts, RPC calls, order books, history — with bounded in-memory caches. It has no database, no accounts, no sessions, and never receives, logs, or stores a seed phrase, private key, or password.
- A small set of **build-time integrity tools** (`scripts/`) stamps each build with an ID and a release manifest, and verifies the served files against it.

---

## Tech stack

| Layer | Technology |
| --- | --- |
| Language | TypeScript (client + server) |
| Client build | Vite |
| Server | Node.js, Express, `ws` (WebSocket relay) |
| Key derivation | `@scure/bip39`, `@scure/bip32`, `@scure/btc-signer`, `@scure/base`, `@noble/curves`, `@noble/hashes` |
| Chains | `@solana/web3.js`, `@solana/spl-token`, `ethers` |
| dApp protocol | WalletConnect / Reown (`@walletconnect/sign-client`) |
| Swaps | Jupiter (Solana), LI.FI (EVM / cross-chain) |
| Markets | Polymarket (Gamma, CLOB, Data API, Relayer), Hyperliquid API |
| Prices & data | CoinGecko, GeckoTerminal, DexScreener, Blockscout, Routescan, Frankfurter (FX) |
| Typography | Allo (UI), DotGothic16 (dot-matrix amounts) |
| Icons | Remix Icon (self-hosted) |

---

## Security model

- **Local-only, non-custodial.** All user data lives on the user's device: the encrypted vault, wallet metadata, and preferences in browser storage. The server stores nothing about any user — there is no cloud backup and no account to recover from. If a user loses their device and their recovery phrase, the wallet cannot be restored by anyone.
- **Vault encryption.** Secrets are encrypted at rest with **AES-256-GCM**; the encryption key is derived from the wallet password with **PBKDF2, 600,000 iterations** (WebCrypto, random salt and IV). Minimum password length is enforced; the vault auto-locks after inactivity, and revealing the recovery phrase requires password re-entry.
- **Signing stays on-device.** Every transaction — sends, swaps, Polymarket orders, Hyperliquid actions — is built and signed in the browser. Trading keys for Hyperliquid are generated on-device, stored only in the encrypted vault, and are trade-only (they cannot withdraw).
- **No tracking.** No analytics, telemetry, or error-reporting SDKs anywhere in the app; WalletConnect telemetry is explicitly disabled.
- **Constrained server surface.** Proxies are allowlisted and rate-limited; the Polymarket builder-signing helper is pinned to the single relayer operation the app performs; responses and caches are size-bounded.

---

## Getting started

Requirements: Node.js 20+ and npm.

```bash
npm ci          # install dependencies
npm run build   # build the client (Vite) and the server (tsc)
npm start       # serve the app
npm test        # run the full test suite
```

Optional operator keys can be supplied through environment variables for enhanced data sources (for example a Trust Wallet API key or RPC provider keys). The app runs without them on public endpoints; no key is ever sent to the browser.

---

## Project structure

```
client/            Browser app (vanilla TypeScript + CSS)
  main.ts          UI, screens, and flows
  style.css        Design system (dark charcoal, chrome/silver)
  lib/             Chain, wallet, market, and protocol modules
src/               Server
  server.ts        Express host + public-data proxies + WS relay
  tw.ts            Trust Wallet API client (server-side)
scripts/           Build stamping, integrity check, catalog tools
tests/             Derivation, vault, protocol, and audit test suites
proof/             Screenshots of the running app
```

---

## Credits

Syn Wallet stands on excellent open-source work and public APIs:

- **Trust Wallet** — the [Trust Wallet API](https://portal.trustwallet.com) (`tws.trustwallet.com`) is integrated server-side as an optional data source for address validation, asset status, and tickers.
- **WalletConnect / Reown** — dApp pairing and session protocol (`@walletconnect/sign-client`, `@walletconnect/utils`).
- **Jupiter** — Solana swap aggregation. **LI.FI** — EVM and cross-chain swap routing.
- **@scure** (`bip39`, `bip32`, `btc-signer`, `base`) and **@noble** (`curves`, `hashes`) — audited key-derivation and cryptography primitives.
- **Solana** (`@solana/web3.js`, `@solana/spl-token`) and **ethers** — chain clients.
- **Polymarket** — Gamma, CLOB, and Data APIs plus the Relayer for prediction markets. **Hyperliquid** — perpetuals API.
- **CoinGecko**, **GeckoTerminal**, **DexScreener**, **Blockscout**, **Routescan**, **Frankfurter**, and **validators.app** — public price, market, history, FX, and validator data.
- **Vite**, **Express**, **TypeScript**, and **ws** — build and runtime foundations.
- **Allo** typeface by Josh Puckett (allo.joshpuckett.me) — the app's UI type system. **DotGothic16** via Fontsource — dot-matrix display numerals.
- **Remix Icon** — every icon in the interface, self-hosted.
- **uimaxx.ing** — several Prediction-market card designs (mini market card, match card, event card, market detail) were adapted from its registry patterns and re-implemented natively.

The interface is hand-built in vanilla TypeScript and CSS — no UI framework — following a native-iOS design language: large-title navigation, grouped inset cards, and a frosted tab bar.

---

## License

Syn Wallet is released under the [GNU General Public License v3.0](LICENSE) (GPL-3.0).

Copyright (C) 2026 Syn — Syn Wallet.

In plain terms:

- **Copyleft.** Anyone may use, study, modify and share this software, but any distributed version — modified or not — must also be released under GPL-3.0, with its source code available.
- **Credit stays.** Copyright and license notices must be preserved; the original authors must be credited.
- **No warranty.** The software is provided "as is", without warranty of any kind (see the license text for the full terms).

See the full text in [LICENSE](LICENSE).
