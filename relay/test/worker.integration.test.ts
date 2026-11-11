// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Runs the real Worker with its SQLite-backed Durable Objects in wrangler's
// local runtime (workerd), and talks to it over HTTP. Time-dependent cases
// (nonce expiry, the rate-limit hour, alarms) are in the unit tests, which
// control the clock.

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { unstable_startWorker } from 'wrangler';
import { inboxIdFor } from '../src/encoding';
import { freshNonce, registrationBody, seedOf, signHeaders, type TestKey, testKey } from './support/signing';

type Worker = Awaited<ReturnType<typeof unstable_startWorker>>;
let worker: Worker;

beforeAll(async () => {
  process.env.WRANGLER_SEND_METRICS = 'false';
  worker = await unstable_startWorker({
    config: new URL('../wrangler.toml', import.meta.url).pathname,
    dev: { server: { hostname: '127.0.0.1', port: 0 }, inspector: false, persist: false, logLevel: 'none' },
  });
  await worker.ready;
}, 120_000);

afterAll(async () => {
  await worker?.dispose();
});

async function register(key: TestKey, o: { nonce?: string; ip?: string; signature?: string } = {}) {
  const body = registrationBody(key);
  const headers = await signHeaders(key, {
    method: 'POST',
    path: '/v1/inbox',
    body,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: o.nonce ?? freshNonce(),
  });
  if (o.signature !== undefined) headers['Maw-Signature'] = o.signature;
  const res = await worker.fetch('http://relay.test/v1/inbox', {
    method: 'POST',
    body,
    headers: { ...headers, 'cf-connecting-ip': o.ip ?? '192.0.2.10' },
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe('relay Worker (local runtime)', () => {
  it('serves /health', async () => {
    const res = await worker.fetch('http://relay.test/health');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it('registers an inbox, answers a repeat with the same ID and refuses a replay', async () => {
    const key = await testKey(seedOf(101));
    const nonce = freshNonce();
    expect(await register(key, { nonce, ip: '192.0.2.1' })).toEqual({
      status: 201,
      body: { inbox_id: await inboxIdFor(key.publicKey) },
    });
    expect(await register(key, { ip: '192.0.2.1' })).toEqual({
      status: 200,
      body: { inbox_id: await inboxIdFor(key.publicKey) },
    });
    expect(await register(key, { nonce, ip: '192.0.2.1' })).toEqual({ status: 401, body: { error: 'nonce_reused' } });
  });

  it('refuses a bad signature and an unsigned request with 401', async () => {
    const key = await testKey(seedOf(102));
    expect(await register(key, { signature: 'A'.repeat(86), ip: '192.0.2.2' })).toEqual({
      status: 401,
      body: { error: 'bad_signature' },
    });
    const res = await worker.fetch('http://relay.test/v1/inbox', { method: 'POST', body: '{}' });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'auth_missing' });
  });

  it('allows 5 new inboxes per IP and refuses the sixth with 429', async () => {
    const ip = '192.0.2.3';
    for (let i = 0; i < 5; i++) {
      expect((await register(await testKey(seedOf(200 + i)), { ip })).status).toBe(201);
    }
    const refused = await register(await testKey(seedOf(205)), { ip });
    expect(refused.status).toBe(429);
    expect(refused.body.error).toBe('rate_limited');
    expect(refused.body.retry_after).toBeGreaterThan(3500);
    expect((await register(await testKey(seedOf(206)), { ip: '192.0.2.4' })).status).toBe(201);
  });

  it('returns JSON errors with stable codes elsewhere', async () => {
    const res = await worker.fetch('http://relay.test/v1/nothing');
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'not_found' });
    const get = await worker.fetch('http://relay.test/v1/inbox');
    expect(get.status).toBe(405);
    expect(await get.json()).toEqual({ error: 'method_not_allowed' });
  });
});
