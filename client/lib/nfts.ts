// NFT helpers (Wave 2).
// Solana: NFTs are plain SPL / Token-2022 token accounts (decimals 0,
// amount 1); their display data lives in the Metaplex metadata account
// (PDA of ["metadata", metadata program, mint]) whose name/URI are parsed
// here, then the JSON at that URI is fetched by the browser. COMPRESSED
// NFTs (cNFTs) are NOT token accounts — they live in Merkle trees and
// need a DAS indexer API (no keyless tier), so they cannot appear; the
// UI says so rather than showing a misleading empty gallery.
// EVM: Blockscout's keyless v2 API indexes ERC-721/1155 holdings for the
// chains that run an instance (eth/polygon/bnb/arbitrum/base here).

export const METADATA_PROGRAM_ID = 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s';
export const TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022_PROGRAM_ID = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';

export interface NftItem {
  /** stable local key: family:chainId:contract:tokenId */
  key: string;
  family: 'solana' | 'evm';
  chainId: string;
  /** mint (Solana) or contract address (EVM) */
  contract: string;
  tokenId: string;
  name: string;
  collection: string;
  image: string;
  description: string;
  standard: string;
  amount: number;
  /** Solana token program that owns the token account (transfer needs it) */
  tokenProgram?: string;
  /** metadata attributes, when the metadata JSON carries them */
  attributes?: { k: string; v: string }[];
  /** ordered image candidates (gateway fallbacks); image = first */
  images?: string[];
}

/** Extract a metadata JSON `attributes` array into display pairs. */
export function metadataAttributes(j: any): { k: string; v: string }[] {
  const arr = Array.isArray(j?.attributes) ? j.attributes : [];
  const out: { k: string; v: string }[] = [];
  for (const a of arr) {
    if (!a || typeof a !== 'object') continue;
    const k = typeof a.trait_type === 'string' ? a.trait_type : typeof a.traitType === 'string' ? a.traitType : '';
    const v = a.value == null ? '' : String(a.value);
    if (k && v) out.push({ k, v });
    if (out.length >= 24) break;
  }
  return out;
}

/**
 * Media-URL validation (audit H-6 / NFT media hardening, 2026-11-19):
 * an attacker-controlled URL (airdrop metadata, dApp-supplied token
 * icons) must never reach an <img>/fetch sink as anything but a plain
 * https: URL on a normal host, or an inline raster data: image.
 * Rejects javascript:/data:text/html, credentials-in-URL, whitespace,
 * quotes, parentheses, backslashes and the `|` character (which would
 * corrupt the pipe-joined data-cands candidate list).
 */
export function isSafeMediaUrl(u: string): boolean {
  const s = String(u || '').trim();
  if (!s || /[\s"'()<>\\|]/.test(s)) return false;
  if (s.startsWith('data:')) return /^data:image\/(png|gif|jpe?g|webp|avif);base64,[A-Za-z0-9+/=]+$/.test(s);
  try {
    const url = new URL(s);
    if (url.protocol !== 'https:' || url.username || url.password || !url.hostname) return false;
    // Deep audit 2026-11-22: an https URL on a private / loopback /
    // link-local host is not public media — NFT metadata pointing at
    // LAN names would otherwise make the browser probe the local
    // network (img-src permits any https host). Reject IP literals in
    // private ranges, localhost and *.local names.
    const h = url.hostname.toLowerCase();
    if (h === 'localhost' || h.endsWith('.local')) return false;
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
    if (v4) {
      const [a, b] = [Number(v4[1]), Number(v4[2])];
      if (a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return false;
    }
    if (h.includes(':')) { // IPv6 literal
      const inner = h.replace(/^\[|\]$/g, '');
      if (inner === '::1' || inner.startsWith('fe8') || inner.startsWith('fe9') || inner.startsWith('fea') || inner.startsWith('feb') || inner.startsWith('fc') || inner.startsWith('fd')) return false;
    }
    return true;
  } catch { return false; }
}

/** Validated media URL or '' — the only door media URLs take into the UI. */
export function safeMediaUrl(u: string): string {
  const s = rewriteMediaUrl(u);
  return isSafeMediaUrl(s) ? s : '';
}

/** ipfs:// and ar:// media/metadata links -> https gateways. */
export function rewriteMediaUrl(u: string): string {
  const s = String(u || '').trim();
  if (!s) return '';
  if (s.startsWith('ipfs://')) {
    const rest = s.slice(7).replace(/^ipfs\//, '');
    return 'https://ipfs.io/ipfs/' + rest;
  }
  if (s.startsWith('ar://')) return 'https://arweave.net/' + s.slice(5);
  return s;
}

/**
 * Ordered candidate URLs for one NFT media reference (Addition 7).
 * IPFS content is served by several public gateways — if one is down
 * or slow the next is tried; the UI steps through this list and falls
 * back to a designed placeholder, so a browser broken-image glyph can
 * never appear. data: URIs (inline SVG etc.) pass through untouched.
 */
export function mediaCandidates(raw: string): string[] {
  const s = String(raw || '').trim();
  if (!s) return [];
  if (s.startsWith('data:')) return isSafeMediaUrl(s) ? [s] : [];
  let cidPath = '';
  if (s.startsWith('ipfs://')) cidPath = s.slice(7).replace(/^ipfs\//, '').replace(/^\/+/, '');
  else { const m = s.match(/\/ipfs\/([A-Za-z0-9][^?#]*)/); if (m) cidPath = m[1]; }
  if (cidPath) return ['https://ipfs.io/ipfs/', 'https://cloudflare-ipfs.com/ipfs/', 'https://dweb.link/ipfs/'].map(g => g + cidPath).filter(isSafeMediaUrl);
  if (s.startsWith('ar://')) { const u = 'https://arweave.net/' + s.slice(5); return isSafeMediaUrl(u) ? [u] : []; }
  return isSafeMediaUrl(s) ? [s] : [];
}

const SPAM_WORDS = /\b(airdrop|rewards?|claim|giveaway|free\s?mint|voucher|bonus|prize|winner|congratulations|redeem)\b/i;
const SPAM_DOMAIN = /\b[a-z0-9-]+\.(com|io|lat|xyz|top|site|online|app|gg|net|org|fi|co|me|fun|live|click|link)\b/i;
const SPAM_AMOUNT = /\d+\s*(ETH|SOL|BTC|USDT|USDC)\b/i;

/**
 * Scam-airdrop heuristic (Addition 7): unsolicited "reward / airdrop /
 * claim" NFTs are the standard wallet-drainer lure. An NFT is flagged
 * when its name/collection carries a domain or URL, a gift/reward
 * lure word, a currency amount bait, or a gift emoji. Flagged items
 * are quarantined (not deleted) and the user's own "not spam" choice
 * always overrides this.
 */
export function isSpamNft(n: { name: string; collection: string }): boolean {
  const name = n.name || '';
  const text = name + ' ' + (n.collection || '');
  if (/https?:\/\//i.test(text)) return true;
  if (SPAM_DOMAIN.test(name)) return true;
  if (SPAM_WORDS.test(text)) return true;
  if (SPAM_AMOUNT.test(name)) return true;
  if (name.includes('🎁') || name.includes('🧧')) return true;
  return false;
}

function readBorshString(data: Uint8Array, off: number): { text: string; next: number } | null {
  if (off + 4 > data.length) return null;
  const len = data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24);
  if (len < 0 || len > 1024 || off + 4 + len > data.length) return null;
  const bytes = data.slice(off + 4, off + 4 + len);
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes).replace(/\0/g, '').trim();
  return { text, next: off + 4 + len };
}

/**
 * Parse a Metaplex metadata account: key(1) | updateAuthority(32) |
 * mint(32) | name(str) | symbol(str) | uri(str) | ... (borsh strings:
 * u32 length + bytes; the account is zero-padded after the struct).
 */
export function parseMetaplexMetadata(data: Uint8Array): { name: string; symbol: string; uri: string } | null {
  if (!data || data.length < 69) return null;
  const name = readBorshString(data, 65); if (!name) return null;
  const symbol = readBorshString(data, name.next); if (!symbol) return null;
  const uri = readBorshString(data, symbol.next); if (!uri) return null;
  return { name: name.text, symbol: symbol.text, uri: uri.text };
}

/** Pull display fields out of an arbitrary NFT metadata JSON document. */
export function metadataJsonFields(j: any): { name: string; image: string; collection: string; description: string } {
  const out = { name: '', image: '', collection: '', description: '' };
  if (!j || typeof j !== 'object') return out;
  if (typeof j.name === 'string') out.name = j.name.trim();
  const img = typeof j.image === 'string' ? j.image : typeof j.image_url === 'string' ? j.image_url : '';
  out.image = rewriteMediaUrl(img);
  if (typeof j.description === 'string') out.description = j.description.trim().slice(0, 600);
  const col = (j as any).collection;
  if (typeof col === 'string') out.collection = col.trim();
  else if (col && typeof col.name === 'string') out.collection = col.name.trim();
  return out;
}

/** Blockscout v2 /addresses/{addr}/nft response -> unified items. */
export function normalizeBlockscoutNfts(j: any, chainId: string): NftItem[] {
  const items = Array.isArray(j?.items) ? j.items : [];
  const out: NftItem[] = [];
  for (const it of items) {
    const contract = String(it?.token?.address_hash || it?.token?.address || '');
    if (!contract) continue;
    const tokenId = String(it?.id ?? '');
    const md = it?.metadata && typeof it.metadata === 'object' ? it.metadata : {};
    const f = metadataJsonFields(md);
    const collection = String(it?.token?.name || '');
    const rawImg = (typeof it?.image_url === 'string' ? it.image_url : '') || (typeof (md as any).image === 'string' ? (md as any).image : '') || (typeof (md as any).image_url === 'string' ? (md as any).image_url : '');
    const images = mediaCandidates(rawImg);
    const image = images[0] || safeMediaUrl(typeof it?.image_url === 'string' ? it.image_url : '') || safeMediaUrl(f.image);
    out.push({
      key: `evm:${chainId}:${contract.toLowerCase()}:${tokenId}`,
      family: 'evm', chainId, contract, tokenId,
      name: f.name || (collection ? `${collection} #${tokenId}` : `Token #${tokenId}`),
      collection, image, images,
      description: f.description,
      standard: String(it?.token_type || it?.token?.type || 'ERC-721'),
      amount: Math.max(1, Number(it?.value || 1)),
      attributes: metadataAttributes(md),
    });
  }
  return out;
}
