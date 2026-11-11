// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Runs the real Worker with its SQLite-backed Durable Objects in wrangler's
// local runtime (workerd), and talks to it over HTTP. Time-dependent cases
// (nonce expiry, the rate-limit hour, alarms) are in the unit tests, which
// control the clock.

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { unstable_startWorker } from 'wrangler';
import { inboxIdFor } from '../src/encoding';
import { wakeMessage } from '../src/fcm';
import { FakeGoogle, testServiceAccount } from './support/fake_google';
import {
  freshNonce,
  fromHex,
  loadVectors,
  registrationBody,
  seedOf,
  signHeaders,
  type TestKey,
  testKey,
} from './support/signing';

type Worker = Awaited<ReturnType<typeof unstable_startWorker>>;
let worker: Worker;
/** Google as the Worker sees it: every outbound `fetch` of the Worker goes here, nowhere else. */
let google: FakeGoogle;

beforeAll(async () => {
  process.env.WRANGLER_SEND_METRICS = 'false';
  // A throwaway service account, set as the secret the way `wrangler secret put` would.
  const { account, json, publicKey } = await testServiceAccount();
  google = new FakeGoogle(publicKey, account);
  const outboundService = async (request: Request): Promise<Response> =>
    google.fetch(request.url, {
      method: request.method,
      headers: Object.fromEntries(request.headers),
      body: await request.text(),
    });
  worker = await unstable_startWorker({
    config: new URL('../wrangler.toml', import.meta.url).pathname,
    bindings: { FCM_SERVICE_ACCOUNT: { type: 'secret_text', value: json } },
    dev: {
      server: { hostname: '127.0.0.1', port: 0 },
      inspector: false,
      persist: false,
      logLevel: 'none',
      // Not in wrangler's types, but passed to Miniflare: intercepts the Worker's outbound fetch.
      ...({ outboundService } as object),
    },
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

/** Waits (up to 10 s) for [check], which runs after the Worker's `waitUntil` work. */
async function until(check: () => boolean | Promise<boolean>): Promise<void> {
  const end = Date.now() + 10_000;
  while (!(await check())) {
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
}

async function signed(
  key: TestKey,
  method: string,
  path: string,
  body: string | Uint8Array,
  ip: string,
  extra: Record<string, string> = {},
) {
  const headers = await signHeaders(key, { method, path, body, timestamp: Math.floor(Date.now() / 1000) });
  const res = await worker.fetch(`http://relay.test${path}`, {
    method,
    body: method === 'GET' || method === 'DELETE' ? undefined : body,
    headers: { ...headers, 'cf-connecting-ip': ip, ...extra },
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

  it('pairs through a slot: create, look up by code, reply once, read the reply', async () => {
    const c = loadVectors('pairing').find((v) => v.name === 'code path');
    if (c === undefined) throw new Error('no vector');
    const seed = (side: string) => fromHex((c.input[side] as Record<string, string>).sig_seed ?? '');
    const initiator = await testKey(seed('initiator'));
    const joiner = await testKey(seed('joiner'));
    const ip = '192.0.2.20';
    expect((await register(initiator, { ip })).status).toBe(201);
    expect((await register(joiner, { ip })).status).toBe(201);

    const created = await signed(initiator, 'POST', '/v1/pairing-slot', JSON.stringify(c.output.bundle), ip);
    expect(created.status).toBe(201);
    const slot = created.body as { slot_id: string; code: string };
    const found = await worker.fetch(`http://relay.test/v1/pairing-slot/${slot.code}`, {
      headers: { 'cf-connecting-ip': ip },
    });
    expect(found.status).toBe(200);
    expect(await found.json()).toEqual({ slot_id: slot.slot_id, bundle: c.output.bundle });

    const replyPath = `/v1/pairing-slot/${slot.slot_id}/reply`;
    expect(await signed(initiator, 'GET', replyPath, '', ip)).toEqual({ status: 200, body: { reply: null } });
    expect((await signed(joiner, 'POST', replyPath, JSON.stringify(c.output.reply), ip)).status).toBe(201);
    const thief = await testKey(seedOf(300));
    expect((await register(thief, { ip: '192.0.2.21' })).status).toBe(201);
    const second = await signed(thief, 'POST', replyPath, JSON.stringify({ ...(c.output.reply as object), sig_pub: thief.keyText }), '192.0.2.21');
    expect(second).toEqual({ status: 409, body: { error: 'slot_used' } });
    expect(await signed(initiator, 'GET', replyPath, '', ip)).toEqual({ status: 200, body: { reply: c.output.reply } });
    expect(await signed(initiator, 'GET', replyPath, '', ip)).toEqual({ status: 409, body: { error: 'slot_used' } });
  });

  it('refuses the sixth failed code lookup from one IP with 429', async () => {
    const lookup = async () =>
      worker.fetch('http://relay.test/v1/pairing-slot/999999', { headers: { 'cf-connecting-ip': '192.0.2.30' } });
    for (let i = 0; i < 5; i++) expect((await lookup()).status).toBe(404);
    const refused = await lookup();
    expect(refused.status).toBe(429);
    expect(refused.headers.get('retry-after')).not.toBeNull();
    expect(((await refused.json()) as Record<string, unknown>).error).toBe('rate_limited');
  });

  it('carries envelopes: allow, deposit, fetch in order, ACK deletes, delete the inbox', async () => {
    const owner = await testKey(seedOf(400));
    const partner = await testKey(seedOf(401));
    const stranger = await testKey(seedOf(402));
    const ip = '192.0.2.40';
    for (const k of [owner, partner, stranger]) expect((await register(k, { ip })).status).toBe(201);
    const inbox = await inboxIdFor(owner.publicKey);
    const base = `/v1/inbox/${inbox}`;
    const wake = { 'maw-wake': '1' };

    expect(await signed(owner, 'POST', `${base}/allow`, JSON.stringify({ sender_key: partner.keyText }), ip)).toEqual({
      status: 201,
      body: {},
    });
    // Bytes of every value, including zeros, and the largest envelope.
    const bodies = [new Uint8Array(426), Uint8Array.from({ length: 65_536 }, (_, i) => i % 251), new Uint8Array([0, 255, 1])];
    for (const b of bodies) {
      expect(await signed(partner, 'PUT', `${base}/envelopes`, b, ip, wake)).toEqual({ status: 201, body: {} });
    }
    expect(await signed(stranger, 'PUT', `${base}/envelopes`, bodies[0] ?? new Uint8Array(1), ip, wake)).toEqual({
      status: 403,
      body: { error: 'sender_not_allowed' },
    });
    expect((await signed(partner, 'PUT', `${base}/envelopes`, new Uint8Array(65_537), ip, wake)).status).toBe(413);
    expect(await signed(partner, 'GET', `${base}/envelopes`, '', ip)).toEqual({
      status: 403,
      body: { error: 'not_inbox_owner' },
    });

    const fetched = await signed(owner, 'GET', `${base}/envelopes`, '', ip);
    expect(fetched.status).toBe(200);
    const page = fetched.body as { envelopes: { cursor: string; body: string }[]; more: boolean };
    expect(page.more).toBe(false);
    expect(page.envelopes.map((e) => new Uint8Array(Buffer.from(e.body, 'base64url')))).toEqual(bodies);
    const cursors = page.envelopes.map((e) => e.cursor);

    expect(await signed(owner, 'POST', `${base}/ack`, JSON.stringify({ cursor: cursors[1] }), ip)).toEqual({
      status: 200,
      body: {},
    });
    const rest = await signed(owner, 'GET', `${base}/envelopes?after=0`, '', ip);
    expect((rest.body as { envelopes: { cursor: string }[] }).envelopes.map((e) => e.cursor)).toEqual([cursors[2]]);

    // After everything is acknowledged, a new envelope still gets a later cursor.
    await signed(owner, 'POST', `${base}/ack`, JSON.stringify({ cursor: cursors[2] }), ip);
    await signed(partner, 'PUT', `${base}/envelopes`, new Uint8Array([9]), ip, { 'maw-wake': '0' });
    const later = await signed(owner, 'GET', `${base}/envelopes?after=${cursors[2]}`, '', ip);
    expect((later.body as { envelopes: unknown[] }).envelopes.length).toBe(1);
    // A cursor the relay never handed out is refused (sqlite_sequence in the real runtime).
    expect(await signed(owner, 'GET', `${base}/envelopes?after=999`, '', ip)).toEqual({
      status: 400,
      body: { error: 'invalid_cursor' },
    });

    expect(await signed(owner, 'POST', `${base}/push-token`, JSON.stringify({ push_token: 'fcm-new' }), ip)).toEqual({
      status: 200,
      body: {},
    });
    expect(await signed(owner, 'DELETE', base, '', ip)).toEqual({ status: 200, body: {} });
    expect(await signed(partner, 'PUT', `${base}/envelopes`, new Uint8Array([1]), ip, wake)).toEqual({
      status: 404,
      body: { error: 'inbox_not_found' },
    });
    expect(await signed(owner, 'GET', `${base}/envelopes`, '', ip)).toEqual({
      status: 404,
      body: { error: 'inbox_not_found' },
    });
  });

  it('carries a blob in 1 MiB chunks: upload, download byte for byte, delete', async () => {
    const owner = await testKey(seedOf(410));
    const partner = await testKey(seedOf(411));
    const ip = '192.0.2.41';
    for (const k of [owner, partner]) expect((await register(k, { ip })).status).toBe(201);
    const inbox = await inboxIdFor(owner.publicKey);
    const blob = `/v1/inbox/${inbox}/blobs/${'AQIDBAUGBwgJCgsMDQ4PEA'}`;
    await signed(owner, 'POST', `/v1/inbox/${inbox}/allow`, JSON.stringify({ sender_key: partner.keyText }), ip);

    // A full 1 MiB chunk is one SQLite value in the real runtime (limit 2 MB); every byte value.
    const size = 1024 * 1024 + 3;
    const whole = Uint8Array.from({ length: size }, (_, i) => (i * 7) % 256);
    const parts = [whole.slice(0, 1024 * 1024), whole.slice(1024 * 1024)];
    for (const [i, part] of parts.entries()) {
      expect(await signed(partner, 'PUT', `${blob}?size=${size}&chunk=${i}`, part, ip)).toEqual({ status: 201, body: {} });
    }
    expect((await signed(partner, 'PUT', `${blob}?size=${10 * 1024 * 1024 + 1}&chunk=0`, parts[0] ?? '', ip)).body).toEqual({
      error: 'blob_too_large',
    });

    const got: Uint8Array[] = [];
    for (let i = 0; i < parts.length; i++) {
      const path = `${blob}?chunk=${i}`;
      const headers = await signHeaders(owner, { method: 'GET', path, timestamp: Math.floor(Date.now() / 1000) });
      const res = await worker.fetch(`http://relay.test${path}`, { headers: { ...headers, 'cf-connecting-ip': ip } });
      expect([res.status, res.headers.get('maw-blob-size')]).toEqual([200, String(size)]);
      got.push(new Uint8Array(await res.arrayBuffer()));
    }
    expect(got).toEqual(parts);

    expect(await signed(owner, 'DELETE', blob, '', ip)).toEqual({ status: 200, body: {} });
    expect(await signed(owner, 'GET', `${blob}?chunk=0`, '', ip)).toEqual({
      status: 404,
      body: { error: 'blob_not_found' },
    });
  });

  it('sends a content-free FCM wake-up for Maw-Wake: 1, and forgets an unregistered token', async () => {
    const owner = await testKey(seedOf(600));
    const partner = await testKey(seedOf(601));
    const ip = '192.0.2.60';
    for (const k of [owner, partner]) expect((await register(k, { ip })).status).toBe(201);
    const inbox = await inboxIdFor(owner.publicKey);
    const base = `/v1/inbox/${inbox}`;
    const token = 'wake-test-token';
    await signed(owner, 'POST', `${base}/push-token`, JSON.stringify({ push_token: token }), ip);
    await signed(owner, 'POST', `${base}/allow`, JSON.stringify({ sender_key: partner.keyText }), ip);
    const sendsTo = () => google.sends.filter((s) => s.body === wakeMessage(token));
    const envelope = new Uint8Array(426).fill(0x5a);

    // Maw-Wake: 0 sends nothing; Maw-Wake: 1 sends exactly one message, after the answer.
    for (const wake of ['0', '1']) {
      expect(await signed(partner, 'PUT', `${base}/envelopes`, envelope, ip, { 'maw-wake': wake })).toEqual({
        status: 201,
        body: {},
      });
    }
    await until(() => sendsTo().length === 1);
    const [send] = sendsTo();
    expect(send?.url).toBe('https://fcm.googleapis.com/v1/projects/mawaddah-test/messages:send');
    expect(JSON.parse(send?.body ?? '')).toStrictEqual({
      message: { token, data: { t: 's' }, android: { priority: 'HIGH', collapse_key: 's' } },
    });
    // The Worker signed its own assertion; the fake Google checked it with the public key.
    expect(google.assertions.length).toBeGreaterThan(0);
    for (const secret of [inbox, partner.keyText, Buffer.from(envelope).toString('base64')]) {
      expect(JSON.stringify(google.requests)).not.toContain(secret);
    }

    // FCM says the token is gone: the relay forgets it and sends no more wake-ups.
    google.fcmAnswers.push({
      status: 404,
      body: {
        error: {
          code: 404,
          status: 'NOT_FOUND',
          details: [{ '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError', errorCode: 'UNREGISTERED' }],
        },
      },
    });
    await signed(partner, 'PUT', `${base}/envelopes`, envelope, ip, { 'maw-wake': '1' });
    await until(() => sendsTo().length === 2);
    // The clear happens after FCM's answer: give it a moment, then show no third send.
    await until(async () => {
      await signed(partner, 'PUT', `${base}/envelopes`, envelope, ip, { 'maw-wake': '1' });
      await new Promise((r) => setTimeout(r, 100));
      const before = sendsTo().length;
      await signed(partner, 'PUT', `${base}/envelopes`, envelope, ip, { 'maw-wake': '1' });
      await new Promise((r) => setTimeout(r, 200));
      return sendsTo().length === before;
    });
    // A new token from the phone brings the wake-ups back.
    await signed(owner, 'POST', `${base}/push-token`, JSON.stringify({ push_token: 'wake-test-token-2' }), ip);
    await signed(partner, 'PUT', `${base}/envelopes`, envelope, ip, { 'maw-wake': '1' });
    await until(() => google.sends.some((s) => s.body === wakeMessage('wake-test-token-2')));
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
