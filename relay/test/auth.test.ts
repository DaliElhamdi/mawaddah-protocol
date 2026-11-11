// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { signingInput, TIME_WINDOW_SECONDS, verifySignedRequest } from '../src/auth';
import { toBase64Url, toHex } from '../src/encoding';
import { fromHex, loadVectors, seedOf, signHeaders, testKey } from './support/signing';

const T = 1762862400;
const nowMs = T * 1000 + 500;

async function verify(headers: Record<string, string>, o: { method?: string; path?: string; body?: string; now?: number } = {}) {
  return verifySignedRequest(
    o.method ?? 'POST',
    o.path ?? '/v1/inbox',
    new Headers(headers),
    new TextEncoder().encode(o.body ?? 'body'),
    o.now ?? nowMs,
  );
}

describe('relay_signing.json (written by the Dart package)', () => {
  for (const c of loadVectors('relay_signing')) {
    it(c.name, async () => {
      const i = c.input as { method: string; path: string; body: string; timestamp: number; nonce: string; sig_seed: string };
      const o = c.output as { signing_input: string; body_sha256: string; signature: string; headers: Record<string, string> };
      const body = fromHex(i.body);
      const nonce = toBase64Url(fromHex(i.nonce));
      const input = await signingInput(i.method, i.path, body, String(i.timestamp), nonce);
      expect(new TextDecoder().decode(input)).toBe(o.signing_input);

      // The relay accepts the Dart signature at its timestamp...
      const ok = await verifySignedRequest(i.method, i.path, new Headers(o.headers), body, i.timestamp * 1000);
      expect(ok.ok).toBe(true);
      if (ok.ok) expect(ok.request.keyText).toBe(o.headers['Maw-Key']);

      // ...and WebCrypto makes the same signature from the same seed.
      const key = await testKey(fromHex(i.sig_seed));
      expect(toHex(await key.sign(input))).toBe(o.signature);
      expect(key.keyText).toBe(o.headers['Maw-Key']);
    });
  }
});

describe('verifySignedRequest', () => {
  it('accepts a correctly signed request', async () => {
    const key = await testKey(seedOf(1));
    const r = await verify(await signHeaders(key, { method: 'POST', path: '/v1/inbox', body: 'body', timestamp: T }));
    expect(r.ok).toBe(true);
  });

  it('refuses a change to any signed line with bad_signature', async () => {
    const key = await testKey(seedOf(1));
    const h = await signHeaders(key, { method: 'PUT', path: '/v1/inbox/a?after=1', body: 'body', timestamp: T });
    const base = { method: 'PUT', path: '/v1/inbox/a?after=1' };
    expect((await verify(h, base)).ok).toBe(true);
    for (const change of [
      { method: 'POST' },
      { path: '/v1/inbox/b?after=1' },
      { path: '/v1/inbox/a?after=2' },
      { path: '/v1/inbox/a' },
      { body: 'bodY' },
      { body: '' },
    ]) {
      expect(await verify(h, { ...base, ...change })).toEqual({ ok: false, code: 'bad_signature' });
    }
    expect(await verify({ ...h, 'Maw-Timestamp': String(T + 1) }, base)).toEqual({ ok: false, code: 'bad_signature' });
    const otherNonce = toBase64Url(new Uint8Array(16));
    expect(await verify({ ...h, 'Maw-Nonce': otherNonce }, base)).toEqual({ ok: false, code: 'bad_signature' });
    const other = await testKey(seedOf(2));
    expect(await verify({ ...h, 'Maw-Key': other.keyText }, base)).toEqual({ ok: false, code: 'bad_signature' });
    const sig = Buffer.from(h['Maw-Signature'] ?? '', 'base64url');
    sig[10] = (sig[10] ?? 0) ^ 1;
    expect(await verify({ ...h, 'Maw-Signature': toBase64Url(sig) }, base)).toEqual({ ok: false, code: 'bad_signature' });
  });

  it('refuses a key that is not a curve point with bad_signature', async () => {
    const key = await testKey(seedOf(1));
    const h = await signHeaders(key, { method: 'POST', path: '/v1/inbox', body: 'body', timestamp: T });
    // y = 2 has no matching x on edwards25519.
    const notAPoint = new Uint8Array(32);
    notAPoint[0] = 2;
    expect(await verify({ ...h, 'Maw-Key': toBase64Url(notAPoint) })).toEqual({ ok: false, code: 'bad_signature' });
  });

  it('accepts timestamps up to 300 s away and refuses 301 s with clock_skew', async () => {
    const key = await testKey(seedOf(1));
    for (const offset of [-TIME_WINDOW_SECONDS, 0, TIME_WINDOW_SECONDS]) {
      const h = await signHeaders(key, { method: 'POST', path: '/v1/inbox', body: 'body', timestamp: T + offset });
      expect((await verify(h, { now: T * 1000 + 999 })).ok).toBe(true);
    }
    for (const offset of [-TIME_WINDOW_SECONDS - 1, TIME_WINDOW_SECONDS + 1, -86400, 86400 * 365]) {
      const h = await signHeaders(key, { method: 'POST', path: '/v1/inbox', body: 'body', timestamp: T + offset });
      expect(await verify(h, { now: T * 1000 })).toEqual({ ok: false, code: 'clock_skew', serverTime: T });
    }
  });

  it('refuses a request without all four headers with auth_missing', async () => {
    const key = await testKey(seedOf(1));
    const h = await signHeaders(key, { method: 'POST', path: '/v1/inbox', body: 'body', timestamp: T });
    for (const name of Object.keys(h)) {
      const partial = { ...h };
      delete partial[name];
      expect(await verify(partial)).toEqual({ ok: false, code: 'auth_missing' });
    }
    expect(await verify({})).toEqual({ ok: false, code: 'auth_missing' });
  });

  it('refuses malformed headers with auth_malformed', async () => {
    const key = await testKey(seedOf(1));
    const h = await signHeaders(key, { method: 'POST', path: '/v1/inbox', body: 'body', timestamp: T });
    const bad: Record<string, string>[] = [
      { 'Maw-Key': `${h['Maw-Key']}=` },
      { 'Maw-Key': (h['Maw-Key'] ?? '').slice(1) },
      { 'Maw-Key': (h['Maw-Key'] ?? '').replaceAll('_', '/').replaceAll('-', '+') + 'A' },
      { 'Maw-Signature': (h['Maw-Signature'] ?? '').slice(0, 85) },
      { 'Maw-Nonce': 'AAAAAAAAAAAAAAAAAAAAA' },
      { 'Maw-Nonce': 'AAAAAAAAAAAAAAAAAAAAAB' }, // non-canonical: unused bits set
      { 'Maw-Timestamp': `0${T}` },
      { 'Maw-Timestamp': `${T}.0` },
      { 'Maw-Timestamp': `-${T}` },
      { 'Maw-Timestamp': `+${T}` },
      { 'Maw-Timestamp': '1e9' },
      { 'Maw-Timestamp': '' },
      { 'Maw-Timestamp': '9999999999999999' },
    ];
    for (const change of bad) {
      expect(await verify({ ...h, ...change }), JSON.stringify(change)).toEqual({ ok: false, code: 'auth_malformed' });
    }
    expect(await verify(h, { method: 'post' })).toEqual({ ok: false, code: 'auth_malformed' });
  });
});
