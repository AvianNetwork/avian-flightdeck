/**
 * Avian Connect envelope handling.
 *
 * Everything in this module is pure: no storage, no wallet access, no DOM. It is the only place
 * that decides whether a blob of data arriving from an untrusted page is a well-formed request,
 * and it is exercised directly by the unit tests.
 */

import {
  AVIAN_CONNECT_VERSION,
  ConnectError,
  ConnectErrorCode,
  ConnectEvent,
  ConnectEventName,
  ConnectRequest,
  ConnectResponse,
  LIMITS,
} from '@/types/avianConnect';

export interface ParseSuccess {
  ok: true;
  request: ConnectRequest;
}

export interface ParseFailure {
  ok: false;
  /** Present when the malformed request still carried a usable id to reply against. */
  id?: string;
  error: ConnectError;
}

export type ParseResult = ParseSuccess | ParseFailure;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const invalid = (message: string, id?: string): ParseFailure => ({
  ok: false,
  id,
  error: { code: 'INVALID_REQUEST', message },
});

/**
 * Validates the shape of an inbound request. Rejects anything we would otherwise have to guess
 * about — wrong version tag, missing id, non-object params, oversized strings.
 */
export function parseRequest(raw: unknown): ParseResult {
  if (!isPlainObject(raw)) {
    return invalid('Request must be a JSON object');
  }

  if (raw.avianConnect !== AVIAN_CONNECT_VERSION) {
    return invalid(`Unsupported protocol version: expected ${AVIAN_CONNECT_VERSION}`);
  }

  const { id } = raw;
  if (typeof id !== 'string' || id.length === 0 || id.length > LIMITS.id) {
    return invalid(`Request id must be a string of 1..${LIMITS.id} characters`);
  }

  const { method } = raw;
  if (typeof method !== 'string' || method.length === 0 || method.length > LIMITS.method) {
    return invalid(`Request method must be a string of 1..${LIMITS.method} characters`, id);
  }

  if (raw.params !== undefined && !isPlainObject(raw.params)) {
    return invalid('Request params must be an object when present', id);
  }

  if (raw.origin !== undefined && typeof raw.origin !== 'string') {
    return invalid('Request origin must be a string when present', id);
  }

  const request: ConnectRequest = {
    avianConnect: AVIAN_CONNECT_VERSION,
    id,
    method,
  };
  if (raw.params !== undefined) {
    request.params = raw.params as Record<string, unknown>;
  }
  if (typeof raw.origin === 'string') {
    request.origin = raw.origin;
  }

  return { ok: true, request };
}

/** Extracts and bounds-checks the `message` param of signMessage. */
export function parseSignMessageParams(
  params: Record<string, unknown> | undefined,
): { ok: true; message: string } | { ok: false; error: ConnectError } {
  const message = params?.message;
  if (typeof message !== 'string' || message.length === 0) {
    return {
      ok: false,
      error: { code: 'INVALID_REQUEST', message: 'signMessage requires a non-empty message string' },
    };
  }
  if (message.length > LIMITS.message) {
    return {
      ok: false,
      error: {
        code: 'INVALID_REQUEST',
        message: `Message exceeds the ${LIMITS.message} character limit`,
      },
    };
  }
  return { ok: true, message };
}

/** Extracts and bounds-checks the `psbt` param of signPsbt (a base64 string). */
export function parseSignPsbtParams(
  params: Record<string, unknown> | undefined,
  method: 'signPsbt' | 'signAssetListing' = 'signPsbt',
): { ok: true; psbt: string } | { ok: false; error: ConnectError } {
  const psbt = params?.psbt;
  if (typeof psbt !== 'string' || psbt.length === 0) {
    return {
      ok: false,
      error: {
        code: 'INVALID_REQUEST',
        message: `${method} requires a non-empty base64 psbt string`,
      },
    };
  }
  if (psbt.length > LIMITS.psbt) {
    return {
      ok: false,
      error: { code: 'INVALID_REQUEST', message: `PSBT exceeds the ${LIMITS.psbt} character limit` },
    };
  }
  // Standard base64 alphabet with optional padding — reject anything else before it reaches the
  // decoder so a hostile page can't probe the parser with junk.
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(psbt)) {
    return {
      ok: false,
      error: { code: 'INVALID_REQUEST', message: `${method} psbt must be valid base64` },
    };
  }
  return { ok: true, psbt };
}

export function makeResult(id: string, result: unknown): ConnectResponse {
  return { avianConnect: AVIAN_CONNECT_VERSION, id, result };
}

export function makeError(id: string, code: ConnectErrorCode, message: string): ConnectResponse {
  return { avianConnect: AVIAN_CONNECT_VERSION, id, error: { code, message } };
}

export function makeEvent(event: ConnectEventName, data: unknown): ConnectEvent {
  return { avianConnect: AVIAN_CONNECT_VERSION, event, data };
}

/** True when the value looks like a response envelope (used by dApp-side helpers and the demo). */
export function isConnectResponse(value: unknown): value is ConnectResponse {
  return isPlainObject(value) && value.avianConnect === AVIAN_CONNECT_VERSION && 'id' in value;
}

// ---------------------------------------------------------------------------
// base64url (RFC 4648 §5, unpadded) over UTF-8 JSON — used by the redirect transport
// ---------------------------------------------------------------------------

export function base64UrlEncode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(encoded: string): string {
  if (!/^[A-Za-z0-9_-]*$/.test(encoded)) {
    throw new Error('Value is not base64url');
  }
  const padded = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

export function encodeEnvelope(envelope: ConnectResponse | ConnectRequest | ConnectEvent): string {
  return base64UrlEncode(JSON.stringify(envelope));
}

/** Decodes a base64url request from the `req` query parameter. */
export function decodeRequestParam(param: string): ParseResult {
  let json: string;
  try {
    json = base64UrlDecode(param);
  } catch {
    return invalid('The req parameter is not valid base64url');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return invalid('The req parameter is not valid JSON');
  }

  return parseRequest(parsed);
}

// ---------------------------------------------------------------------------
// Origins
// ---------------------------------------------------------------------------

const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

// Extra hosts/subnets allowed to use plaintext http, for LAN development against a self-hosted
// deploy. Comma-separated NEXT_PUBLIC_CONNECT_HTTP_HOSTS, each entry an exact hostname or an IPv4
// CIDR (e.g. "10.10.30.0/24"). Empty by default, so the public build keeps the https-or-loopback
// rule; NEXT_PUBLIC_* is inlined at build time, so set it in the environment that builds the app.
const EXTRA_HTTP_HOSTS = (process.env.NEXT_PUBLIC_CONNECT_HTTP_HOSTS ?? '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

/** Parse an IPv4 dotted-quad to a 32-bit unsigned int, or null if it isn't a valid IPv4 address. */
function ipv4ToInt(host: string): number | null {
  const parts = host.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

/** True if `hostname` is an IPv4 address inside the `a.b.c.d/bits` CIDR range. */
export function ipv4InCidr(hostname: string, cidr: string): boolean {
  const [range, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ip = ipv4ToInt(hostname);
  const base = ipv4ToInt(range);
  if (ip === null || base === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ip & mask) === (base & mask);
}

/** Whether a plaintext-http origin with this hostname is permitted (loopback + configured LAN). */
function isHttpHostAllowed(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (LOCAL_HOSTS.includes(host)) return true;
  return EXTRA_HTTP_HOSTS.some((entry) =>
    entry.includes('/') ? ipv4InCidr(host, entry) : entry === host,
  );
}

/**
 * Normalises an origin or URL to `scheme://host[:port]`, lowercased and without a trailing slash.
 * Returns null for anything that is not an origin we are willing to talk to: opaque origins,
 * and plaintext http outside of local development (loopback, plus any NEXT_PUBLIC_CONNECT_HTTP_HOSTS).
 */
export function normalizeOrigin(value: string): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) {
    return null;
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return null;
  }
  if (url.protocol === 'http:' && !isHttpHostAllowed(url.hostname)) {
    return null;
  }

  const origin = url.origin;
  return origin && origin !== 'null' ? origin.toLowerCase() : null;
}

export interface RedirectCheck {
  ok: boolean;
  reason?: string;
}

/**
 * The redirect transport's core guarantee: a response may only be delivered to the origin the
 * request claims to come from.
 */
export function validateRedirectUri(redirectUri: string, requestOrigin: unknown): RedirectCheck {
  if (typeof requestOrigin !== 'string' || requestOrigin.length === 0) {
    return { ok: false, reason: 'The request is missing an origin' };
  }

  const claimed = normalizeOrigin(requestOrigin);
  if (!claimed) {
    return { ok: false, reason: `The request origin is not a usable origin: ${requestOrigin}` };
  }

  const target = normalizeOrigin(redirectUri);
  if (!target) {
    return { ok: false, reason: 'redirect_uri is not an absolute https URL' };
  }

  if (target !== claimed) {
    return {
      ok: false,
      reason: `redirect_uri origin (${target}) does not match the request origin (${claimed})`,
    };
  }

  return { ok: true };
}

/** Builds the return navigation, carrying the response in the fragment — never the query string. */
export function buildRedirectUrl(redirectUri: string, response: ConnectResponse): string {
  const url = new URL(redirectUri);
  url.hash = `avianconnect=${encodeEnvelope(response)}`;
  return url.toString();
}

/** Reads a response envelope out of a `#avianconnect=…` fragment. Used by dApps and the demo. */
export function readResponseFromFragment(hash: string): ConnectResponse | null {
  const raw = new URLSearchParams(hash.replace(/^#/, '')).get('avianconnect');
  if (!raw) return null;

  try {
    const parsed = JSON.parse(base64UrlDecode(raw));
    return isConnectResponse(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
