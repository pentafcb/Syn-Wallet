# Syn Wallet

Syn's first public live project: a **non-custodial, phone-first, multi-chain crypto wallet** on the web — create or import a wallet like Trust Wallet, for Solana, Ethereum, Polygon, BNB Chain, Arbitrum, Base and Bitcoin.

**Live:** http://79.108.164.56:8800 (redirects) · https://79.108.164.56:8801 (self-signed cert, SAN IP:79.108.164.56)

## Security model (non-negotiable)

- **Everything is saved locally — full stop.** ALL user data lives only on the user's device/browser: the encrypted vault (seed/keys), wallet metadata and preferences in local browser storage, sensitive material encrypted. The server stores **nothing** about any user: no database, no accounts, no sessions, no cloud backup, no server-side wallet files — it is a stateless static host. The price/RPC proxy is a pure pass-through with **no persistence and no logging** of wallet addresses, request bodies or transaction data; only public market data (prices/charts) is cached, in memory. No third-party analytics/trackers anywhere. Trade-off, stated in the app: if the user clears browser data or loses the device without their recovery phrase, the wallet cannot be recovered by Syn.

- **Non-custodial, client-side only.** Seed phrases and private keys are generated, derived and used for signing **entirely in your browser**. The server is a dumb static host + price/RPC proxy and **never receives, logs or stores any seed, private key, or password**.
- **Vault:** the secret is encrypted at rest in the browser (localStorage) with **AES-GCM**; the key is derived from your wallet password via **PBKDF2 (WebCrypto, 600,000 iterations, random salt/IV)**. Auto-lock after 5 minutes of inactivity + manual Lock. Reveal-phrase requires password re-entry. Wipe removes the vault from the device.
- **No analytics or tracking** on wallet screens.

## Features (v1)

- **Create:** 12-word BIP39 mnemonic (@scure/bip39, WebCrypto RNG), numbered backup screen, verify-by-selecting-words, set password.
- **Import:** 12/24-word BIP39 (checksum validated, clear error if invalid) or private key (Solana base58 / EVM hex) as a single-chain imported account.
- **Multi-chain from one seed, BIP44:** Solana `m/44'/501'/0'/0'` (SLIP-0010 ed25519), EVM `m/44'/60'/0'/0/0`, Bitcoin SegWit `m/84'/0'/0'/0/0` (bc1q). Derivation is verified against known test vectors in `tests/`.
- **Home:** total USD balance + per-asset live balances (Solana mainnet-beta, public EVM RPCs, Blockstream for BTC) and live USD prices via CoinGecko (proxied/cached server-side 60s). Honest unavailable states — never a faked 0 or price.
- **Live Ticker Chart** (asset detail + home hero): real CoinGecko `market_chart` history via the server proxy, 24H/7D/1M ranges, live polling every 25s appending the real current price, "now" marker with pulse + LIVE indicator, gridlines with right-gutter price labels and a time axis. No fake data — if live data is unavailable the last real chart is shown without animation.
- **Receive:** per-chain address + QR + copy. **Send:** native sends on Solana and all EVM chains (local signing, confirm screen, tx hash + explorer link). Bitcoin and Litecoin also send natively via the shared UTXO stack (coin selection, local signing, broadcast with txid verification).
- **Activity:** recent transactions per chain via public APIs/RPC (Solana RPC, Blockstream, Blockscout) with explorer links; honest empty states.
- **PWA:** installable, manifest + icons from the Syn chrome "S" logo.

## Design

Syn design language: dark charcoal (#0a0c10), chrome/silver accent sampled from the Syn logo, green/red only as data colours, compact quiet text, native-iOS feel (large titles, grouped inset cards, frosted bottom tab bar), Remix Icons for every icon, never emojis. The app-wide card/row system adapts the UImaxxing auth-card pattern (lit-stroke rounded cards, 10px muted labels over 13px values, circular chrome-gradient arrow buttons, "OR" hairline dividers, circular arrow chips), the account-settings pattern for Settings (16px section headings, hairline rows, ghost pill buttons, mono ID chips), the orb-button pair for Receive/Send (chrome tilted-gradient orb + steel glow on the primary side), and the wide pill CTA shape (chrome/silver gradient, black label) for "Create wallet" and Send confirmation. All re-implemented natively in vanilla TS/CSS — no React/shadcn/Tailwind. There is deliberately **no email/social login**: a non-custodial wallet has no accounts.

## Run

```bash
npm install
npm test        # derivation vectors + vault round-trip
npm run build   # vite client -> public/, tsc server -> dist/
npm start       # HTTPS 8801 + HTTP 8800 redirect (self-signed cert auto-generated in data/tls)
```

Deploy (sober77): rsync the repo (excluding node_modules/dist/data) to `/root/syn-wallet`, `npm install && npm run build`, install `syn-wallet.service` to systemd and enable it.

## Known v1 limitations

- BTC/LTC sends ride public esplora APIs (Blockstream/mempool.space, litecoinspace) — a first real-funds send on each UTXO chain should be a tiny test amount.
- EVM activity depends on Blockscout public APIs; Solana/BTC activity on public RPC/Blockstream — any of them can rate-limit, in which case the UI shows an honest unavailable/empty state.
- HTTPS uses a self-signed certificate (same pattern as the other Syn apps) — browsers show a warning until it is trusted.
- Only native assets are shown in v1 (no SPL/ERC-20 token list yet).

## Threat model & honest limits

Implemented: CSPRNG entropy via @scure/bip39 (12 words / 128-bit, optional 24 words / 256-bit); AES-256-GCM vault, PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP), random 32-byte salt + unique IV per encryption, versioned vault format; decrypted material in memory only, wiped on lock; unlock throttling with growing delays; configurable auto-lock (1/5/15 min); app always starts locked; backup words blurred until tap-to-reveal and re-hidden when the tab loses visibility; word-by-word seed import with BIP39 autocomplete; seed clipboard copy auto-clears after ~20s; reveal-phrase is password-gated every time and auto-hides after 30s; clear-signing send confirmations (network, validated recipient, amount, estimated fee, balance after) with EIP-55/base58 validation hard-blocking bad addresses and an address-poisoning similarity warning; no dApp/message signing surface in v1; strict CSP with everything self-hosted (no CDNs), X-Frame-Options DENY / frame protection, Referrer-Policy no-referrer, Permissions-Policy locked down, HSTS, HTTPS-only (HTTP only redirects, plus an in-app HTTP warning).

Not in v1, honestly: device biometrics/WebAuthn unlock (left out — it cannot wrap the vault key without weakening the password vault); hardware-wallet support.

Out of scope for any web wallet (MetaMask states the same): a compromised device, browser or clipboard at the OS level, and physical coercion. Syn can never recover a wallet — only the recovery phrase can.
