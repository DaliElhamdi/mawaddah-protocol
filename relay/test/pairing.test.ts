// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Pairing-slot routes (spec 4.5, PROTOCOL.md section 4.5), with the bundles
// and replies of `pairing.json` made by the Dart package.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleRequest, MAX_PAIRING_BODY } from '../src/handler';
import { LOOKUP_FAILURE_WINDOW_MS } from '../src/rate_limit';
import { SLOT_LIFETIME_MS } from '../src/pairing_slots';
import { FakeRelay } from './support/fake_relay';
import {
  fromHex,
  loadVectors,
  registrationBody,
  seedOf,
  signHeaders,
  type TestKey,
  testKey,
  type VectorCase,
} from './support/signing';

const t0 = 1762862400000;
const minute = 60 * 1000;
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

const vectors = loadVectors('pairing');
const vector = (name: string): VectorCase => {
  const c = vectors.find((v) => v.name === name);
  if (c === undefined) throw new Error(`no vector ${name}`);
  return c;
};

interface Party {
  key: TestKey;
  ip: string;
}

/** The initiator and joiner of a vector case, with their real signing keys. */
async function parties(c: VectorCase): Promise<{ initiator: Party; joiner: Party; bundle: object; reply: object }> {
  const seed = (side: string) => fromHex((c.input[side] as Record<string, string>).sig_seed ?? '');
  return {
    initiator: { key: await testKey(seed('initiator')), ip: '203.0.113.1' },
    joiner: { key: await testKey(seed('joiner')), ip: '198.51.100.2' },
    bundle: c.output.bundle as object,
    reply: c.output.reply as object,
  };
}

async function signed(p: Party, method: string, path: string, body = ''): Promise<Response> {
  const headers = await signHeaders(p.key, { method, path, body, timestamp: Math.floor(relay.nowMs / 1000) });
  return handleRequest(
    new Request(`https://relay.test${path}`, {
      method,
      body: method === 'GET' ? undefined : body,
      headers: { ...headers, 'cf-connecting-ip': p.ip },
    }),
    relay,
  );
}

function lookup(handle: string, ip = '198.51.100.2'): Promise<Response> {
  return handleRequest(
    new Request(`https://relay.test/v1/pairing-slot/${handle}`, { headers: { 'cf-connecting-ip': ip } }),
    relay,
  );
}

async function register(p: Party): Promise<void> {
  expect((await signed(p, 'POST', '/v1/inbox', registrationBody(p.key))).status).toBe(201);
}

async function json(res: Response): Promise<Record<string, unknown>> {
  expect(res.headers.get('content-type')).toBe('application/json');
  expect(res.headers.get('cache-control')).toBe('no-store');
  return (await res.json()) as Record<string, unknown>;
}

async function openSlot(p: Party, bundle: object): Promise<{ slot_id: string; code: string; expires_at: number }> {
  const res = await signed(p, 'POST', '/v1/pairing-slot', JSON.stringify(bundle));
  expect(res.status).toBe(201);
  return (await json(res)) as { slot_id: string; code: string; expires_at: number };
}

/** A registered party whose key is not in any vector (keys from [n]). */
async function anotherInitiator(n: number, ip: string): Promise<Party> {
  const p = { key: await testKey(seedOf(n)), ip };
  await register(p);
  return p;
}

describe('pairing with the Dart vectors', () => {
  for (const name of ['qr path', 'code path']) {
    it(`${name}: slot, lookup, reply, and the initiator reads exactly the joiner's reply`, async () => {
      const { initiator, joiner, bundle, reply } = await parties(vector(name));
      await register(initiator);
      const slot = await openSlot(initiator, bundle);
      expect(slot.slot_id).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(slot.code).toMatch(/^[0-9]{6}$/);
      expect(slot.expires_at).toBe(Math.floor((t0 + SLOT_LIFETIME_MS) / 1000));

      // The joiner reads the bundle, unsigned, by code or by slot ID: byte-identical JSON.
      for (const handle of [slot.code, slot.slot_id]) {
        const res = await lookup(handle);
        expect(res.status).toBe(200);
        expect(await json(res)).toEqual({ slot_id: slot.slot_id, bundle });
      }

      expect(await json(await signed(initiator, 'GET', `/v1/pairing-slot/${slot.slot_id}/reply`))).toEqual({
        reply: null,
      });
      await register(joiner);
      const posted = await signed(joiner, 'POST', `/v1/pairing-slot/${slot.slot_id}/reply`, JSON.stringify(reply));
      expect(posted.status).toBe(201);
      expect(await json(posted)).toEqual({});

      const read = await signed(initiator, 'GET', `/v1/pairing-slot/${slot.slot_id}/reply`);
      expect(read.status).toBe(200);
      expect(await json(read)).toEqual({ reply });
      // The relay kept no bundle or reply after that.
      expect(relay.slotSql?.('SELECT bundle, reply, state FROM slots')).toEqual([
        { bundle: null, reply: null, state: 'closed' },
      ]);
    });
  }

  it('refuses a bundle whose signature was changed by one bit', async () => {
    const c = vector('code path: bundle signature changed by one bit');
    const initiator = { key: await testKey(fromHex((c.input.initiator as Record<string, string>).sig_seed ?? '')), ip: '203.0.113.1' };
    await register(initiator);
    const res = await signed(initiator, 'POST', '/v1/pairing-slot', JSON.stringify(c.input.bundle));
    expect(res.status).toBe(400);
    expect(await json(res)).toEqual({ error: 'malformed_request' });
    expect(relay.slotState.count()).toBe(0);
  });
});

describe('POST /v1/pairing-slot', () => {
  it('gives the same slot to a retry; a changed bundle fails its signature', async () => {
    const { initiator, bundle } = await parties(vector('qr path'));
    await register(initiator);
    const slot = await openSlot(initiator, bundle);
    const again = await signed(initiator, 'POST', '/v1/pairing-slot', JSON.stringify({ ...bundle, extra: 1 }));
    expect(again.status).toBe(200);
    expect(await json(again)).toEqual(slot);
    const changed = { ...bundle, ek_pub: (vector('code path').output.bundle as Record<string, string>).ek_pub };
    const conflict = await signed(initiator, 'POST', '/v1/pairing-slot', JSON.stringify(changed));
    // The changed key breaks the bundle signature first.
    expect(await json(conflict)).toEqual({ error: 'malformed_request' });
  });

  it('stores only the known bundle fields', async () => {
    const { initiator, bundle } = await parties(vector('qr path'));
    await register(initiator);
    const slot = await openSlot(initiator, { ...bundle, name: 'Amina', note: 'x'.repeat(100) });
    expect(await json(await lookup(slot.code))).toEqual({ slot_id: slot.slot_id, bundle });
    expect(JSON.stringify(relay.slotSql?.('SELECT * FROM slots'))).not.toContain('Amina');
  });

  it('needs an inbox for the signing key', async () => {
    const { initiator, bundle } = await parties(vector('qr path'));
    const res = await signed(initiator, 'POST', '/v1/pairing-slot', JSON.stringify(bundle));
    expect(res.status).toBe(403);
    expect(await json(res)).toEqual({ error: 'inbox_required' });
    expect(relay.slotState.count()).toBe(0);
  });

  it('refuses a bundle of another key with key_mismatch', async () => {
    const { bundle } = await parties(vector('qr path'));
    const other = await anotherInitiator(1, '203.0.113.9');
    const res = await signed(other, 'POST', '/v1/pairing-slot', JSON.stringify(bundle));
    expect(res.status).toBe(400);
    expect(await json(res)).toEqual({ error: 'key_mismatch' });
  });

  it('refuses malformed bundles', async () => {
    const { initiator, bundle } = await parties(vector('qr path'));
    await register(initiator);
    const b = bundle as Record<string, unknown>;
    const bodies = [
      '',
      '[]',
      'null',
      JSON.stringify({ ...b, v: 2 }),
      JSON.stringify({ ...b, v: '1' }),
      JSON.stringify({ ...b, dh_pub: undefined }),
      JSON.stringify({ ...b, ek_pub: `${String(b.ek_pub)}A` }),
      JSON.stringify({ ...b, sig: 5 }),
    ];
    for (const body of bodies) {
      const res = await signed(initiator, 'POST', '/v1/pairing-slot', body);
      expect(res.status, body.slice(0, 60)).toBe(400);
      expect(await json(res)).toEqual({ error: 'malformed_request' });
    }
  });

  it('refuses an unsigned request and a body over 4 KiB', async () => {
    const { initiator, bundle } = await parties(vector('qr path'));
    await register(initiator);
    const unsigned = await handleRequest(
      new Request('https://relay.test/v1/pairing-slot', { method: 'POST', body: JSON.stringify(bundle) }),
      relay,
    );
    expect(await json(unsigned)).toEqual({ error: 'auth_missing' });
    const big = await signed(initiator, 'POST', '/v1/pairing-slot', ' '.repeat(MAX_PAIRING_BODY + 1));
    expect(big.status).toBe(413);
  });

  it('answers 405 for other methods', async () => {
    const res = await handleRequest(new Request('https://relay.test/v1/pairing-slot'), relay);
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('POST');
  });
});

describe('GET /v1/pairing-slot/{slot_id or code}', () => {
  it('refuses the sixth failed code lookup within 10 minutes with 429, even for a valid code', async () => {
    const { initiator, bundle } = await parties(vector('code path'));
    await register(initiator);
    const slot = await openSlot(initiator, bundle);
    const wrong = slot.code === '000000' ? '000001' : '000000';
    const ip = '192.0.2.50';
    for (let i = 0; i < 5; i++) {
      relay.nowMs = t0 + i * minute;
      const res = await lookup(wrong, ip);
      expect(res.status).toBe(404);
      expect(await json(res)).toEqual({ error: 'slot_not_found' });
    }
    relay.nowMs = t0 + 5 * minute;
    const sixth = await lookup(wrong, ip);
    expect(sixth.status).toBe(429);
    expect(sixth.headers.get('retry-after')).toBe('300');
    expect(await json(sixth)).toEqual({ error: 'rate_limited', retry_after: 300 });
    // The right code is refused too while the limit holds: guessing learns nothing.
    expect((await lookup(slot.code, ip)).status).toBe(429);
    // Refused attempts are not counted, so they do not extend the wait.
    expect(relay.lookupBuckets.get('v4:192.0.2.50')?.check(relay.nowMs)).toEqual({
      allowed: false,
      retryAfterSeconds: 300,
    });
    // Another address is not affected, and an IPv6 /64 counts as one.
    expect((await lookup(slot.code, '192.0.2.51')).status).toBe(200);
    // Ten minutes after the first failure, one more try is allowed (the slot
    // has expired by then too), and then the limit holds again.
    relay.nowMs = t0 + LOOKUP_FAILURE_WINDOW_MS;
    expect((await lookup(slot.code, ip)).status).toBe(404);
    expect((await lookup(slot.code, ip)).status).toBe(429);
  });

  it('counts the IPv6 addresses of one /64 together', async () => {
    for (let i = 1; i <= 5; i++) expect((await lookup('999999', `2001:db8:5:6::${i}`)).status).toBe(404);
    expect((await lookup('999999', '2001:db8:5:6:ffff::1')).status).toBe(429);
    expect((await lookup('999999', '2001:db8:5:7::1')).status).toBe(404);
  });

  it('does not count successful lookups, used slots, slot IDs or malformed handles', async () => {
    const { initiator, joiner, bundle, reply } = await parties(vector('code path'));
    await register(initiator);
    const slot = await openSlot(initiator, bundle);
    const ip = '192.0.2.60';
    for (let i = 0; i < 10; i++) expect((await lookup(slot.code, ip)).status).toBe(200);
    for (let i = 0; i < 10; i++) expect((await lookup('AAAAAAAAAAAAAAAAAAAAAA', ip)).status).toBe(404);
    for (const h of ['12345', '1234567', '12345a', 'AAAAAAAAAAAAAAAAAAAAAB', 'x'.repeat(23)]) {
      const res = await lookup(h, ip);
      expect(res.status, h).toBe(404);
      expect(await json(res)).toEqual({ error: 'slot_not_found' });
    }
    await register(joiner);
    await signed(joiner, 'POST', `/v1/pairing-slot/${slot.slot_id}/reply`, JSON.stringify(reply));
    for (let i = 0; i < 10; i++) {
      const used = await lookup(slot.code, ip);
      expect(used.status).toBe(409);
      expect(await json(used)).toEqual({ error: 'slot_used' });
    }
    // No failure was stored for this address.
    expect(relay.lookupBuckets.get('v4:192.0.2.60')?.prune(relay.nowMs)).toBeNull();
  });

  it('does not serve an expired slot, which is deleted', async () => {
    const { initiator, joiner, bundle, reply } = await parties(vector('code path'));
    await register(initiator);
    await register(joiner);
    const slot = await openSlot(initiator, bundle);
    relay.nowMs = t0 + SLOT_LIFETIME_MS - 1000;
    expect((await lookup(slot.code)).status).toBe(200);
    relay.nowMs = t0 + SLOT_LIFETIME_MS;
    for (const res of [
      await lookup(slot.code),
      await lookup(slot.slot_id),
      await signed(joiner, 'POST', `/v1/pairing-slot/${slot.slot_id}/reply`, JSON.stringify(reply)),
      await signed(initiator, 'GET', `/v1/pairing-slot/${slot.slot_id}/reply`),
    ]) {
      expect(res.status).toBe(404);
      expect(await json(res)).toEqual({ error: 'slot_not_found' });
    }
    expect(relay.slotSql?.('SELECT * FROM slots')).toEqual([]);
  });

  it('answers 405 for other methods', async () => {
    const res = await handleRequest(new Request('https://relay.test/v1/pairing-slot/123456', { method: 'DELETE' }), relay);
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET');
  });
});

describe('POST /v1/pairing-slot/{slot_id}/reply', () => {
  it('takes the first reply and refuses a second one (the pair is locked)', async () => {
    const { initiator, joiner, bundle, reply } = await parties(vector('qr path'));
    await register(initiator);
    await register(joiner);
    const slot = await openSlot(initiator, bundle);
    const path = `/v1/pairing-slot/${slot.slot_id}/reply`;
    expect((await signed(joiner, 'POST', path, JSON.stringify(reply))).status).toBe(201);

    // A third device, with its own valid reply, is refused.
    const other = await parties(vector('code path'));
    await register(other.joiner);
    const second = await signed(other.joiner, 'POST', path, JSON.stringify(other.reply));
    expect(second.status).toBe(409);
    expect(await json(second)).toEqual({ error: 'slot_used' });
    // The same joiner retrying (lost answer) is told it worked.
    const retry = await signed(joiner, 'POST', path, JSON.stringify(reply));
    expect(retry.status).toBe(200);
    // The initiator gets the first reply.
    expect(await json(await signed(initiator, 'GET', path))).toEqual({ reply });
    // After it is read, a late reply still gets slot_used, and a second read too.
    expect((await signed(other.joiner, 'POST', path, JSON.stringify(other.reply))).status).toBe(409);
    expect(await json(await signed(initiator, 'GET', path))).toEqual({ error: 'slot_used' });
  });

  it('refuses a reply to a code, an unknown slot or a reply of another key', async () => {
    const { initiator, joiner, bundle, reply } = await parties(vector('qr path'));
    await register(initiator);
    await register(joiner);
    const slot = await openSlot(initiator, bundle);
    for (const handle of [slot.code, 'AAAAAAAAAAAAAAAAAAAAAA', 'not-an-id']) {
      const res = await signed(joiner, 'POST', `/v1/pairing-slot/${handle}/reply`, JSON.stringify(reply));
      expect(res.status, handle).toBe(404);
      expect(await json(res)).toEqual({ error: 'slot_not_found' });
    }
    const other = await anotherInitiator(2, '203.0.113.20');
    const mismatch = await signed(other, 'POST', `/v1/pairing-slot/${slot.slot_id}/reply`, JSON.stringify(reply));
    expect(await json(mismatch)).toEqual({ error: 'key_mismatch' });
    expect((await lookup(slot.slot_id)).status).toBe(200);
  });

  it('needs an inbox and a well-formed reply', async () => {
    const { initiator, joiner, bundle, reply } = await parties(vector('qr path'));
    await register(initiator);
    const slot = await openSlot(initiator, bundle);
    const path = `/v1/pairing-slot/${slot.slot_id}/reply`;
    const noInbox = await signed(joiner, 'POST', path, JSON.stringify(reply));
    expect(noInbox.status).toBe(403);
    expect(await json(noInbox)).toEqual({ error: 'inbox_required' });
    await register(joiner);
    const r = reply as Record<string, unknown>;
    for (const body of [
      '{',
      JSON.stringify({ ...r, path: 'nfc' }),
      JSON.stringify({ ...r, v: 2 }),
      JSON.stringify({ ...r, confirm: undefined }),
      JSON.stringify({ ...r, sig: String(r.sig).slice(1) }),
    ]) {
      const res = await signed(joiner, 'POST', path, body);
      expect(res.status, body.slice(0, 60)).toBe(400);
      expect(await json(res)).toEqual({ error: 'malformed_request' });
    }
    // Nothing was accepted, so the slot is still open.
    expect((await lookup(slot.slot_id)).status).toBe(200);
  });
});

describe('GET /v1/pairing-slot/{slot_id}/reply', () => {
  it('answers only the key that opened the slot', async () => {
    const { initiator, joiner, bundle, reply } = await parties(vector('qr path'));
    await register(initiator);
    await register(joiner);
    const slot = await openSlot(initiator, bundle);
    const path = `/v1/pairing-slot/${slot.slot_id}/reply`;
    await signed(joiner, 'POST', path, JSON.stringify(reply));
    const res = await signed(joiner, 'GET', path);
    expect(res.status).toBe(404);
    expect(await json(res)).toEqual({ error: 'slot_not_found' });
    const unsigned = await handleRequest(new Request(`https://relay.test${path}`), relay);
    expect(await json(unsigned)).toEqual({ error: 'auth_missing' });
    // The reply is still there for the initiator.
    expect(await json(await signed(initiator, 'GET', path))).toEqual({ reply });
  });

  it('answers 405 for other methods', async () => {
    const res = await handleRequest(
      new Request('https://relay.test/v1/pairing-slot/AAAAAAAAAAAAAAAAAAAAAA/reply', { method: 'PUT' }),
      relay,
    );
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET, POST');
  });
});
