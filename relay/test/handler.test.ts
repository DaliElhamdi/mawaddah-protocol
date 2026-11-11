// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NONCE_MEMORY_MS } from '../src/auth';
import { inboxIdFor } from '../src/encoding';
import { handleRequest, MAX_REGISTRATION_BODY, parseRegistration, type RelayDeps } from '../src/handler';
import { REGISTRATION_WINDOW_MS } from '../src/rate_limit';
import { FakeRelay } from './support/fake_relay';
import { freshNonce, registrationBody, seedOf, signHeaders, type TestKey, testKey } from './support/signing';

const t0 = 1762862400000;
let relay: FakeRelay;
let consoleCalls: unknown[];

beforeEach(() => {
  relay = new FakeRelay(t0);
  consoleCalls = [];
  for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, m).mockImplementation((...args) => void consoleCalls.push(args));
  }
});
afterEach(() => {
  relay.close();
  vi.restoreAllMocks();
  // Spec 4.5: no request logging.
  expect(consoleCalls).toEqual([]);
});

interface Sent {
  method?: string;
  path?: string;
  body?: string;
  ip?: string;
  nonce?: string;
  timestamp?: number;
  headers?: Record<string, string>;
}

async function send(key: TestKey, o: Sent = {}, deps: RelayDeps = relay): Promise<Response> {
  const method = o.method ?? 'POST';
  const path = o.path ?? '/v1/inbox';
  const body = o.body ?? registrationBody(key);
  const signed = await signHeaders(key, {
    method,
    path,
    body,
    timestamp: o.timestamp ?? Math.floor(relay.nowMs / 1000),
    nonce: o.nonce ?? freshNonce(),
  });
  return handleRequest(
    new Request(`https://relay.test${path}`, {
      method,
      body: method === 'GET' || method === 'HEAD' ? undefined : body,
      headers: { ...signed, 'cf-connecting-ip': o.ip ?? '203.0.113.7', ...o.headers },
    }),
    deps,
  );
}

async function json(res: Response): Promise<unknown> {
  expect(res.headers.get('content-type')).toBe('application/json');
  expect(res.headers.get('cache-control')).toBe('no-store');
  return res.json();
}

describe('POST /v1/inbox', () => {
  it('registers the inbox whose ID is derived from the key', async () => {
    const key = await testKey(seedOf(1));
    const res = await send(key);
    expect(res.status).toBe(201);
    const inboxId = await inboxIdFor(key.publicKey);
    expect(await json(res)).toEqual({ inbox_id: inboxId });
    expect(relay.devices.get(inboxId)?.registration()).toEqual({
      signingKey: key.keyText,
      pushToken: 'test-fcm-token',
      platform: 'android',
    });
  });

  it('answers a repeat with the same ID and updates the token, without counting it', async () => {
    const key = await testKey(seedOf(1));
    expect((await send(key)).status).toBe(201);
    for (let i = 0; i < 10; i++) {
      const res = await send(key, { body: registrationBody(key, `token-${i}`) });
      expect(res.status).toBe(200);
      expect(await json(res)).toEqual({ inbox_id: await inboxIdFor(key.publicKey) });
    }
    expect(relay.devices.get(await inboxIdFor(key.publicKey))?.registration()?.pushToken).toBe('token-9');
    // Only the first registration counted against the IP.
    for (let i = 2; i <= 5; i++) expect((await send(await testKey(seedOf(i)))).status).toBe(201);
  });

  it('accepts a null push token', async () => {
    const key = await testKey(seedOf(1));
    expect((await send(key, { body: registrationBody(key, null) })).status).toBe(201);
  });

  it('refuses the sixth new inbox from one IP within an hour with 429', async () => {
    for (let i = 1; i <= 5; i++) {
      relay.nowMs = t0 + i * 60_000;
      expect((await send(await testKey(seedOf(i)))).status).toBe(201);
    }
    relay.nowMs = t0 + 30 * 60_000;
    const refused = await send(await testKey(seedOf(6)));
    expect(refused.status).toBe(429);
    expect(refused.headers.get('retry-after')).toBe(String(31 * 60));
    expect(await json(refused)).toEqual({ error: 'rate_limited', retry_after: 31 * 60 });
    // The refused key got no inbox.
    expect(relay.devices.get(await inboxIdFor((await testKey(seedOf(6))).publicKey))?.registration()).toBeNull();
    // Another IP is not affected.
    expect((await send(await testKey(seedOf(7)), { ip: '198.51.100.1' })).status).toBe(201);
    // An hour after the first one, a place is free again.
    relay.nowMs = t0 + 60_000 + REGISTRATION_WINDOW_MS;
    expect((await send(await testKey(seedOf(6)))).status).toBe(201);
  });

  it('counts IPv6 addresses of one /64 together', async () => {
    for (let i = 1; i <= 5; i++) {
      expect((await send(await testKey(seedOf(i)), { ip: `2001:db8:1:2::${i}` })).status).toBe(201);
    }
    expect((await send(await testKey(seedOf(6)), { ip: '2001:db8:1:2:ffff::9' })).status).toBe(429);
    expect((await send(await testKey(seedOf(7)), { ip: '2001:db8:1:3::1' })).status).toBe(201);
  });

  it('refuses a reused nonce with nonce_reused while its timestamp is accepted', async () => {
    const key = await testKey(seedOf(1));
    const nonce = freshNonce();
    expect((await send(key, { nonce })).status).toBe(201);
    const replay = await send(key, { nonce });
    expect(replay.status).toBe(401);
    expect(await json(replay)).toEqual({ error: 'nonce_reused' });
    // The same nonce stays refused until its timestamp is outside the window.
    relay.nowMs = t0 + NONCE_MEMORY_MS - 1;
    expect(await json(await send(key, { nonce, timestamp: Math.floor(t0 / 1000) }))).toEqual({ error: 'clock_skew', server_time: Math.floor(relay.nowMs / 1000) });
    expect(await json(await send(key, { nonce }))).toEqual({ error: 'nonce_reused' });
  });

  it('refuses a byte-for-byte replay of a captured request', async () => {
    const key = await testKey(seedOf(1));
    const body = registrationBody(key);
    const headers = await signHeaders(key, { method: 'POST', path: '/v1/inbox', body, timestamp: Math.floor(t0 / 1000) });
    const make = () => new Request('https://relay.test/v1/inbox', { method: 'POST', body, headers });
    expect((await handleRequest(make(), relay)).status).toBe(201);
    for (const later of [0, 1000, 299_000]) {
      relay.nowMs = t0 + later;
      const res = await handleRequest(make(), relay);
      expect(res.status).toBe(401);
      expect(await json(res)).toEqual({ error: 'nonce_reused' });
    }
    relay.nowMs = t0 + 301_000;
    expect(await json(await handleRequest(make(), relay))).toMatchObject({ error: 'clock_skew' });
  });

  it('refuses a bad signature, an old or future timestamp and missing headers with 401', async () => {
    const key = await testKey(seedOf(1));
    const bad = await send(key, { headers: { 'Maw-Signature': 'A'.repeat(86) } });
    expect(bad.status).toBe(401);
    expect(await json(bad)).toEqual({ error: 'bad_signature' });
    const nowS = Math.floor(t0 / 1000);
    for (const timestamp of [nowS - 301, nowS + 301]) {
      const res = await send(key, { timestamp });
      expect(res.status).toBe(401);
      expect(await json(res)).toEqual({ error: 'clock_skew', server_time: nowS });
    }
    const missing = await handleRequest(
      new Request('https://relay.test/v1/inbox', { method: 'POST', body: registrationBody(key) }),
      relay,
    );
    expect(missing.status).toBe(401);
    expect(await json(missing)).toEqual({ error: 'auth_missing' });
    expect(relay.devices.size).toBe(0);
  });

  it('signs the path with the query as sent', async () => {
    const key = await testKey(seedOf(1));
    const body = registrationBody(key);
    const headers = await signHeaders(key, { method: 'POST', path: '/v1/inbox', body, timestamp: Math.floor(t0 / 1000) });
    const res = await handleRequest(new Request('https://relay.test/v1/inbox?x=1', { method: 'POST', body, headers }), relay);
    expect(await json(res)).toEqual({ error: 'bad_signature' });
  });

  it('refuses a body that names another key with key_mismatch', async () => {
    const key = await testKey(seedOf(1));
    const other = await testKey(seedOf(2));
    const res = await send(key, { body: registrationBody(other) });
    expect(res.status).toBe(400);
    expect(await json(res)).toEqual({ error: 'key_mismatch' });
    expect(relay.devices.get(await inboxIdFor(other.publicKey))).toBeUndefined();
  });

  it('refuses malformed bodies with malformed_request', async () => {
    const key = await testKey(seedOf(1));
    const bodies = [
      '',
      'null',
      '[]',
      '{',
      JSON.stringify({ signing_key: key.keyText, platform: 'android' }),
      JSON.stringify({ signing_key: key.keyText, push_token: 'x', platform: 'windows' }),
      JSON.stringify({ signing_key: `${key.keyText}=`, push_token: 'x', platform: 'android' }),
      JSON.stringify({ signing_key: key.keyText, push_token: 5, platform: 'android' }),
      JSON.stringify({ signing_key: key.keyText, push_token: 'a b', platform: 'android' }),
      JSON.stringify({ signing_key: key.keyText, push_token: '', platform: 'android' }),
      JSON.stringify({ signing_key: key.keyText, push_token: 'x'.repeat(4097), platform: 'android' }),
    ];
    for (const body of bodies) {
      const res = await send(key, { body });
      expect(res.status, body.slice(0, 80)).toBe(400);
      expect(await json(res)).toEqual({ error: 'malformed_request' });
    }
    const invalidUtf8 = new Uint8Array([0x7b, 0xff, 0x7d]);
    expect(parseRegistration(invalidUtf8)).toBeNull();
    // Unknown fields are ignored.
    const extra = JSON.stringify({ ...JSON.parse(registrationBody(key)), name: 'ignored' });
    expect((await send(key, { body: extra })).status).toBe(201);
    expect(JSON.stringify(relay.devices.get(await inboxIdFor(key.publicKey))?.registration())).not.toContain('ignored');
  });

  it('refuses a body over 8 KiB with 413 before checking anything else', async () => {
    const key = await testKey(seedOf(1));
    const res = await send(key, { body: ' '.repeat(MAX_REGISTRATION_BODY + 1) });
    expect(res.status).toBe(413);
    expect(await json(res)).toEqual({ error: 'body_too_large' });
    // A body without a declared length is cut off while reading.
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        for (let i = 0; i < 9; i++) c.enqueue(new Uint8Array(1024));
        c.close();
      },
    });
    const streamed = await handleRequest(
      new Request('https://relay.test/v1/inbox', { method: 'POST', body: stream, duplex: 'half' } as RequestInit),
      relay,
    );
    expect(streamed.status).toBe(413);
  });

  it('answers other methods with 405', async () => {
    const key = await testKey(seedOf(1));
    const res = await send(key, { method: 'GET' });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('POST');
    expect(await json(res)).toEqual({ error: 'method_not_allowed' });
  });

  it('answers 409 when another key holds the inbox ID', async () => {
    const key = await testKey(seedOf(1));
    const inboxId = await inboxIdFor(key.publicKey);
    await relay.device(inboxId).register({ signingKey: 'x'.repeat(43), pushToken: null, platform: 'ios' });
    const res = await send(key);
    expect(res.status).toBe(409);
    expect(await json(res)).toEqual({ error: 'inbox_conflict' });
  });
});

describe('errors', () => {
  it('returns internal_error and nothing about the failure', async () => {
    const key = await testKey(seedOf(1));
    const broken: RelayDeps = {
      device: () => {
        throw new Error('secret detail at /srv/relay.ts:42');
      },
      registrationLimiter: (bucket) => relay.registrationLimiter(bucket),
      lookupLimiter: (bucket) => relay.lookupLimiter(bucket),
      pairingSlots: () => relay.pairingSlots(),
      push: null,
      background: (task) => relay.background(task),
      now: () => t0,
    };
    const res = await send(key, {}, broken);
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ error: 'internal_error' });
    expect(text).not.toContain('secret');
  });

  it('every error body is exactly {"error": code} plus documented fields', async () => {
    const key = await testKey(seedOf(1));
    const res = await send(key, { headers: { 'Maw-Nonce': 'bad' } });
    expect(Object.keys((await json(res)) as object)).toEqual(['error']);
  });
});
