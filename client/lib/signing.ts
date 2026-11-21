// Message signing + sign-in request handling (EIP-4361 SIWE + Solana
// sign-in). Pure build/parse logic lives here so it is unit-testable; the
// actual signing happens in main.ts with the unlocked keys, and ONLY after
// the user reviews every field on the clear-signing screen.

export interface SignInFields {
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version: string;
  chainId?: number; // EVM (EIP-4361). Solana sign-in usually omits it.
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  resources?: string[];
}
export interface ParsedSignIn { family: 'evm' | 'solana'; fields: SignInFields; }

const EVM_HEAD = ' wants you to sign in with your Ethereum account:';
const SOL_HEAD = ' wants you to sign in with your Solana account:';

export function buildSignInMessage(family: 'evm' | 'solana', f: SignInFields): string {
  const head = `${f.domain}${family === 'evm' ? EVM_HEAD : SOL_HEAD}\n${f.address}`;
  let msg = head + '\n';
  if (f.statement) msg += `\n${f.statement}\n`;
  msg += `\nURI: ${f.uri}\nVersion: ${f.version}`;
  if (family === 'evm' && f.chainId != null) msg += `\nChain ID: ${f.chainId}`;
  msg += `\nNonce: ${f.nonce}\nIssued At: ${f.issuedAt}`;
  if (f.expirationTime) msg += `\nExpiration Time: ${f.expirationTime}`;
  if (f.notBefore) msg += `\nNot Before: ${f.notBefore}`;
  if (f.requestId) msg += `\nRequest ID: ${f.requestId}`;
  if (f.resources && f.resources.length) msg += `\nResources:${f.resources.map(r => `\n- ${r}`).join('')}`;
  return msg;
}

// Strict-enough parser for pasted sign-in requests: the header must match
// the EIP-4361 / Solana sign-in shape exactly, the address line must look
// like an address for the family, and the mandatory fields (URI, Version,
// Nonce, Issued At — plus Chain ID for EVM) must all be present. Anything
// else returns null so the UI can refuse instead of signing blind.
export function parseSignInMessage(text: string): ParsedSignIn | null {
  const norm = text.replace(/\r\n/g, '\n').trim();
  const lines = norm.split('\n');
  if (lines.length < 3) return null;
  let family: 'evm' | 'solana' | null = null;
  let domain = '';
  if (lines[0].endsWith(EVM_HEAD)) { family = 'evm'; domain = lines[0].slice(0, -EVM_HEAD.length); }
  else if (lines[0].endsWith(SOL_HEAD)) { family = 'solana'; domain = lines[0].slice(0, -SOL_HEAD.length); }
  if (!family || !domain || /\s/.test(domain)) return null;
  const address = lines[1].trim();
  if (family === 'evm' && !/^0x[0-9a-fA-F]{40}$/.test(address)) return null;
  if (family === 'solana' && !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) return null;
  // Optional statement: lines between the address and the first blank line
  // that precedes the "URI:" field block.
  const uriIdx = lines.findIndex((l, i) => i >= 2 && l.startsWith('URI: '));
  if (uriIdx < 0) return null;
  let statement: string | undefined;
  const between = lines.slice(2, uriIdx);
  const stmtLines = between.filter(l => l.trim() !== '');
  if (stmtLines.length) statement = stmtLines.join('\n').trim();
  const kv = new Map<string, string>();
  const resources: string[] = [];
  let inResources = false;
  for (let i = uriIdx; i < lines.length; i++) {
    const l = lines[i];
    if (l === 'Resources:') { inResources = true; continue; }
    if (inResources) { if (l.startsWith('- ')) { resources.push(l.slice(2)); continue; } inResources = false; }
    const m = l.match(/^([A-Za-z ]+): (.*)$/);
    if (m) kv.set(m[1], m[2].trim());
  }
  const uri = kv.get('URI'); const version = kv.get('Version'); const nonce = kv.get('Nonce'); const issuedAt = kv.get('Issued At');
  if (!uri || !version || !nonce || !issuedAt) return null;
  let chainId: number | undefined;
  if (family === 'evm') {
    const raw = kv.get('Chain ID');
    if (!raw || !/^\d+$/.test(raw)) return null;
    chainId = Number(raw);
  } else if (kv.get('Chain ID') && /^\d+$/.test(kv.get('Chain ID')!)) chainId = Number(kv.get('Chain ID'));
  const fields: SignInFields = { domain, address, uri, version, nonce, issuedAt };
  if (statement) fields.statement = statement;
  if (chainId != null) fields.chainId = chainId;
  if (kv.get('Expiration Time')) fields.expirationTime = kv.get('Expiration Time');
  if (kv.get('Not Before')) fields.notBefore = kv.get('Not Before');
  if (kv.get('Request ID')) fields.requestId = kv.get('Request ID');
  if (resources.length) fields.resources = resources;
  return { family, fields };
}

// Expiry / not-before evaluation against a clock (kept pure for tests).
export function signInTimingProblem(f: SignInFields, nowMs: number): string | null {
  if (f.expirationTime) { const t = Date.parse(f.expirationTime); if (!Number.isNaN(t) && t <= nowMs) return 'This sign-in request has expired.'; }
  if (f.notBefore) { const t = Date.parse(f.notBefore); if (!Number.isNaN(t) && t > nowMs) return 'This sign-in request is not valid yet (Not Before is in the future).'; }
  return null;
}

// Blind-signing heuristic for free-form messages: a long hex blob, a long
// base64 blob, or text full of non-printable characters is not something a
// human can verify — the UI warns hard before offering to sign it.
export function looksLikeBlindBlob(text: string): boolean {
  const t = text.trim();
  if (!t) return false;
  if (/^0x[0-9a-fA-F]{40,}$/.test(t)) return true;
  if (t.length >= 64 && /^[A-Za-z0-9+/]+={0,2}$/.test(t)) return true;
  let bad = 0;
  for (const ch of t) { const c = ch.codePointAt(0)!; if ((c < 32 && ch !== '\n' && ch !== '\t' && ch !== '\r') || c === 0xfffd) bad++; }
  return t.length > 0 && bad / t.length > 0.05;
}
