import { describe, expect, it } from 'vitest';

import {
  base64UrlDecode,
  base64UrlEncode,
  buildRedirectUrl,
  decodeRequestParam,
  encodeEnvelope,
  ipv4InCidr,
  isConnectResponse,
  makeError,
  makeEvent,
  makeResult,
  normalizeOrigin,
  parseRequest,
  parseSignMessageParams,
  parseSignPsbtParams,
  readResponseFromFragment,
  validateRedirectUri,
} from './protocol';
import { LIMITS } from '@/types/avianConnect';

const validRequest = {
  avianConnect: 1,
  id: 'req-1',
  method: 'signMessage',
  params: { message: 'hello' },
};

describe('parseRequest', () => {
  it('accepts a well-formed request', () => {
    const result = parseRequest(validRequest);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request.method).toBe('signMessage');
    expect(result.request.params).toEqual({ message: 'hello' });
  });

  it('drops unknown top-level fields rather than passing them through', () => {
    const result = parseRequest({ ...validRequest, evil: 'payload' });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request).not.toHaveProperty('evil');
  });

  it.each([
    ['a string', 'connect'],
    ['null', null],
    ['an array', [validRequest]],
    ['a number', 7],
  ])('rejects %s', (_label, raw) => {
    const result = parseRequest(raw);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('INVALID_REQUEST');
  });

  it('rejects a wrong or missing protocol version', () => {
    expect(parseRequest({ ...validRequest, avianConnect: 2 }).ok).toBe(false);
    expect(parseRequest({ ...validRequest, avianConnect: '1' }).ok).toBe(false);
    expect(parseRequest({ id: 'x', method: 'connect' }).ok).toBe(false);
  });

  it('rejects a missing, empty or oversized id', () => {
    expect(parseRequest({ ...validRequest, id: undefined }).ok).toBe(false);
    expect(parseRequest({ ...validRequest, id: '' }).ok).toBe(false);
    expect(parseRequest({ ...validRequest, id: 42 }).ok).toBe(false);
    expect(parseRequest({ ...validRequest, id: 'x'.repeat(LIMITS.id + 1) }).ok).toBe(false);
  });

  it('rejects a bad method but still reports the id so the dApp can match the error', () => {
    const result = parseRequest({ ...validRequest, method: '' });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.id).toBe('req-1');
  });

  it('rejects params that are not a plain object', () => {
    expect(parseRequest({ ...validRequest, params: 'hello' }).ok).toBe(false);
    expect(parseRequest({ ...validRequest, params: ['hello'] }).ok).toBe(false);
    expect(parseRequest({ ...validRequest, params: null }).ok).toBe(false);
  });

  it('allows params to be omitted', () => {
    const result = parseRequest({ avianConnect: 1, id: 'a', method: 'connect' });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request.params).toBeUndefined();
  });
});

describe('parseSignMessageParams', () => {
  it('returns the message', () => {
    expect(parseSignMessageParams({ message: 'sign me' })).toEqual({ ok: true, message: 'sign me' });
  });

  it('rejects a missing, empty or non-string message', () => {
    expect(parseSignMessageParams(undefined).ok).toBe(false);
    expect(parseSignMessageParams({}).ok).toBe(false);
    expect(parseSignMessageParams({ message: '' }).ok).toBe(false);
    expect(parseSignMessageParams({ message: 123 }).ok).toBe(false);
  });

  it('rejects an oversized message', () => {
    const result = parseSignMessageParams({ message: 'x'.repeat(LIMITS.message + 1) });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('INVALID_REQUEST');
  });

  it('accepts a message exactly at the limit', () => {
    expect(parseSignMessageParams({ message: 'x'.repeat(LIMITS.message) }).ok).toBe(true);
  });
});

describe('parseSignPsbtParams', () => {
  const PSBT = 'cHNidP8BAAoAAAAAAAAAAAAA'; // base64-charset placeholder

  it('returns the psbt, with broadcasting off unless asked for', () => {
    expect(parseSignPsbtParams({ psbt: PSBT })).toEqual({ ok: true, psbt: PSBT, broadcast: false });
    expect(parseSignPsbtParams({ psbt: PSBT, broadcast: true })).toEqual({
      ok: true,
      psbt: PSBT,
      broadcast: true,
    });
  });

  it('rejects a non-boolean broadcast flag', () => {
    expect(parseSignPsbtParams({ psbt: PSBT, broadcast: 'yes' }).ok).toBe(false);
    expect(parseSignPsbtParams({ psbt: PSBT, broadcast: 1 }).ok).toBe(false);
  });

  it('refuses to broadcast a listing, which is never a complete transaction', () => {
    const result = parseSignPsbtParams({ psbt: PSBT, broadcast: true }, 'signAssetListing');
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.error.message).toMatch(/cannot broadcast/);
  });

  it('rejects a missing, empty or non-string psbt', () => {
    expect(parseSignPsbtParams(undefined).ok).toBe(false);
    expect(parseSignPsbtParams({}).ok).toBe(false);
    expect(parseSignPsbtParams({ psbt: '' }).ok).toBe(false);
    expect(parseSignPsbtParams({ psbt: 123 }).ok).toBe(false);
  });

  it('rejects a psbt that is not base64', () => {
    const result = parseSignPsbtParams({ psbt: 'not base64 !!' });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('INVALID_REQUEST');
  });

  it('rejects an oversized psbt', () => {
    expect(parseSignPsbtParams({ psbt: 'A'.repeat(LIMITS.psbt + 1) }).ok).toBe(false);
  });

  it('accepts a psbt exactly at the limit', () => {
    expect(parseSignPsbtParams({ psbt: 'A'.repeat(LIMITS.psbt) }).ok).toBe(true);
  });
});

describe('envelope builders', () => {
  it('echoes the id and carries exactly one of result/error', () => {
    const result = makeResult('id-1', { address: 'R9' });
    expect(result).toEqual({ avianConnect: 1, id: 'id-1', result: { address: 'R9' } });
    expect(result.error).toBeUndefined();

    const error = makeError('id-1', 'USER_REJECTED', 'nope');
    expect(error.error).toEqual({ code: 'USER_REJECTED', message: 'nope' });
    expect(error.result).toBeUndefined();
  });

  it('builds events without an id', () => {
    const event = makeEvent('accountsChanged', { accounts: ['R9'] });
    expect(event).toEqual({
      avianConnect: 1,
      event: 'accountsChanged',
      data: { accounts: ['R9'] },
    });
    expect(isConnectResponse(event)).toBe(false);
  });
});

describe('base64url', () => {
  it('round-trips unicode without padding', () => {
    const text = 'sign in — nonce: ✓ 日本語';
    const encoded = base64UrlEncode(text);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(base64UrlDecode(encoded)).toBe(text);
  });

  it('round-trips an envelope', () => {
    const response = makeResult('id-1', { signature: 'H9+abc/def=' });
    const decoded = JSON.parse(base64UrlDecode(encodeEnvelope(response)));
    expect(decoded).toEqual(response);
  });

  it('rejects values that are not base64url', () => {
    expect(() => base64UrlDecode('not base64!')).toThrow();
    expect(() => base64UrlDecode('has+plus')).toThrow();
  });
});

describe('decodeRequestParam', () => {
  it('decodes a base64url request', () => {
    const result = decodeRequestParam(base64UrlEncode(JSON.stringify(validRequest)));
    expect(result.ok).toBe(true);
  });

  it('rejects malformed base64url and malformed JSON', () => {
    expect(decodeRequestParam('%%%').ok).toBe(false);
    expect(decodeRequestParam(base64UrlEncode('{not json')).ok).toBe(false);
  });

  it('still applies envelope validation to the decoded payload', () => {
    const result = decodeRequestParam(base64UrlEncode(JSON.stringify({ avianConnect: 9 })));
    expect(result.ok).toBe(false);
  });
});

describe('normalizeOrigin', () => {
  it('normalises case and strips paths', () => {
    expect(normalizeOrigin('https://Realm.Example/game?x=1#y')).toBe('https://realm.example');
    expect(normalizeOrigin('https://realm.example:8443')).toBe('https://realm.example:8443');
  });

  it('allows plaintext http only on local development hosts', () => {
    expect(normalizeOrigin('http://localhost:3000')).toBe('http://localhost:3000');
    expect(normalizeOrigin('http://127.0.0.1:3000')).toBe('http://127.0.0.1:3000');
    expect(normalizeOrigin('http://realm.example')).toBeNull();
    // A LAN address is rejected unless NEXT_PUBLIC_CONNECT_HTTP_HOSTS opts it in (unset in tests).
    expect(normalizeOrigin('http://10.10.30.5:3000')).toBeNull();
  });

  it('rejects non-http(s) and opaque origins', () => {
    expect(normalizeOrigin('file:///tmp/evil.html')).toBeNull();
    expect(normalizeOrigin('javascript:alert(1)')).toBeNull();
    expect(normalizeOrigin('data:text/html,hi')).toBeNull();
    expect(normalizeOrigin('not a url')).toBeNull();
    expect(normalizeOrigin('')).toBeNull();
  });
});

describe('ipv4InCidr', () => {
  it('matches addresses inside a /24', () => {
    expect(ipv4InCidr('10.10.30.1', '10.10.30.0/24')).toBe(true);
    expect(ipv4InCidr('10.10.30.254', '10.10.30.0/24')).toBe(true);
    // A base written with a host part still masks correctly (10.10.30.1/24 → 10.10.30.0/24).
    expect(ipv4InCidr('10.10.30.50', '10.10.30.1/24')).toBe(true);
  });

  it('rejects addresses outside the range', () => {
    expect(ipv4InCidr('10.10.31.1', '10.10.30.0/24')).toBe(false);
    expect(ipv4InCidr('192.168.1.1', '10.10.30.0/24')).toBe(false);
  });

  it('handles /32 and /0 edges', () => {
    expect(ipv4InCidr('10.10.30.7', '10.10.30.7/32')).toBe(true);
    expect(ipv4InCidr('10.10.30.8', '10.10.30.7/32')).toBe(false);
    expect(ipv4InCidr('8.8.8.8', '0.0.0.0/0')).toBe(true);
  });

  it('rejects malformed input', () => {
    expect(ipv4InCidr('not-an-ip', '10.10.30.0/24')).toBe(false);
    expect(ipv4InCidr('10.10.30.1', '10.10.30.0/33')).toBe(false);
    expect(ipv4InCidr('10.10.30.999', '10.10.30.0/24')).toBe(false);
    expect(ipv4InCidr('10.10.30.1', 'garbage')).toBe(false);
  });
});

describe('validateRedirectUri', () => {
  it('accepts a redirect_uri on the same origin as the request', () => {
    expect(validateRedirectUri('https://realm.example/callback?a=1', 'https://realm.example')).toEqual(
      { ok: true },
    );
  });

  it('rejects a redirect to a different origin', () => {
    const result = validateRedirectUri('https://evil.example/steal', 'https://realm.example');
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('does not match');
  });

  it('treats a different port or scheme as a different origin', () => {
    expect(validateRedirectUri('https://realm.example:8443/cb', 'https://realm.example').ok).toBe(
      false,
    );
    expect(validateRedirectUri('http://realm.example/cb', 'https://realm.example').ok).toBe(false);
  });

  it('rejects a missing or unusable request origin', () => {
    expect(validateRedirectUri('https://realm.example/cb', undefined).ok).toBe(false);
    expect(validateRedirectUri('https://realm.example/cb', '').ok).toBe(false);
    expect(validateRedirectUri('https://realm.example/cb', 'realm.example').ok).toBe(false);
  });

  it('rejects a redirect_uri that is not an absolute web URL', () => {
    expect(validateRedirectUri('/callback', 'https://realm.example').ok).toBe(false);
    expect(
      validateRedirectUri('javascript:alert(1)', 'https://realm.example').ok,
    ).toBe(false);
  });
});

describe('redirect payloads', () => {
  it('puts the response in the fragment and never in the query string', () => {
    const response = makeResult('id-1', { signature: 'H9abc' });
    const url = new URL(buildRedirectUrl('https://realm.example/cb?state=42', response));

    expect(url.hash).toMatch(/^#avianconnect=/);
    expect(url.search).toBe('?state=42');
    expect(url.search).not.toContain('avianconnect');
    expect(readResponseFromFragment(url.hash)).toEqual(response);
  });

  it('replaces any fragment the dApp supplied', () => {
    const url = new URL(
      buildRedirectUrl('https://realm.example/cb#stale', makeResult('id-1', null)),
    );
    expect(url.hash).not.toContain('stale');
  });

  it('returns null for a fragment that does not carry a response', () => {
    expect(readResponseFromFragment('')).toBeNull();
    expect(readResponseFromFragment('#other=1')).toBeNull();
    expect(readResponseFromFragment('#avianconnect=not-base64url!')).toBeNull();
    expect(readResponseFromFragment(`#avianconnect=${base64UrlEncode('{"a":1}')}`)).toBeNull();
  });
});
