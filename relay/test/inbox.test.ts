// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// The inbox routes (spec 4.5): allow-list, deposit, fetch, ACK, push token
// and delete, through the handler with the real state over in-memory SQLite.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MAX_ENVELOPE_BYTES, PAGE_MAX_ENVELOPES } from '../src/device_state';
import { fromBase64Url, inboxIdFor } from '../src/encoding';
import { handleRequest } from '../src/handler';
import { FakeRelay } from './support/fake_relay';
import { freshNonce, registrationBody, seedOf, signHeaders, type TestKey, testKey } from './support/signing';

const t0 = 1762862400000;
let relay: FakeRelay;
let consoleCalls: unknown[];

/** The owner of the inbox under test, its partner and a third key. */
let owner: TestKey;
let partner: TestKey;
let stranger: TestKey;
let inbox: string;

beforeEach(async () => {
  relay = new FakeRelay(t0);
  consoleCalls = [];
  for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, m).mockImplementation((...args) => void consoleCalls.push(args));
  }
  owner = await testKey(seedOf(1));
  partner = await testKey(seedOf(2));
  stranger = await testKey(seedOf(3));
  inbox = await inboxIdFor(owner.publicKey);
});
afterEach(() => {
  relay.close();
  vi.restoreAllMocks();
  // Spec 4.5: no request logging.
  expect(consoleCalls).toEqual([]);
});

interface Sent {
  body?: Uint8Array | string;
  nonce?: string;
  headers?: Record<string, string>;
  unsigned?: boolean;
}

async function send(key: TestKey, method: string, path: string, o: Sent = {}): Promise<Response> {
  const body = o.body ?? '';
  const signed = o.unsigned
    ? {}
    : await signHeaders(key, {
        method,
        path,
        body,
        timestamp: Math.floor(relay.nowMs / 1000),
        nonce: o.nonce ?? freshNonce(),
      });
  return handleRequest(
    new Request(`https://relay.test${path}`, {
      method,
      body: method === 'GET' || method === 'HEAD' ? undefined : body,
      headers: { ...signed, 'cf-connecting-ip': '203.0.113.7', ...o.headers },
    }),
    relay,
  );
}

async function json(res: Response): Promise<unknown> {
  expect(res.headers.get('content-type')).toBe('application/json');
  expect(res.headers.get('cache-control')).toBe('no-store');
  return res.json();
}

async function expectError(res: Response, status: number, error: string): Promise<void> {
  expect({ status: res.status, body: await json(res) }).toEqual({ status, body: { error } });
}

async function register(key: TestKey): Promise<void> {
  expect((await send(key, 'POST', '/v1/inbox', { body: registrationBody(key) })).status).toBe(201);
}

function allow(sender: TestKey, key = owner, id = inbox): Promise<Response> {
  return send(key, 'POST', `/v1/inbox/${id}/allow`, { body: JSON.stringify({ sender_key: sender.keyText }) });
}

function deposit(body: Uint8Array, key = partner, o: Sent = {}): Promise<Response> {
  return send(key, 'PUT', `/v1/inbox/${inbox}/envelopes`, { body, ...o, headers: { 'maw-wake': '1', ...o.headers } });
}

function fetchPage(query = '', key = owner): Promise<Response> {
  return send(key, 'GET', `/v1/inbox/${inbox}/envelopes${query}`);
}

function ack(cursor: unknown, key = owner): Promise<Response> {
  return send(key, 'POST', `/v1/inbox/${inbox}/ack`, { body: JSON.stringify({ cursor }) });
}

/** An envelope-sized body whose bytes show its number. */
function envelope(n: number, size = 426): Uint8Array {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) out[i] = (n * 31 + i) & 0xff;
  return out;
}

interface Page {
  envelopes: { cursor: string; body: string }[];
  more: boolean;
}

async function page(res: Response): Promise<Page> {
  expect(res.status).toBe(200);
  return (await json(res)) as Page;
}

/** The envelope rows the relay stores for the inbox under test. */
function storedRows(): unknown[] {
  return relay.deviceSql.get(inbox)?.('SELECT seq FROM envelopes ORDER BY seq') ?? [];
}

/** Owner and partner registered, partner allowed on the owner's inbox. */
async function paired(): Promise<void> {
  await register(owner);
  await register(partner);
  expect((await allow(partner)).status).toBe(201);
}

describe('POST /v1/inbox/{id}/allow', () => {
  it('allows one sender key; the same key again is fine, another one conflicts', async () => {
    await register(owner);
    const first = await allow(partner);
    expect({ status: first.status, body: await json(first) }).toEqual({ status: 201, body: {} });
    const again = await allow(partner);
    expect({ status: again.status, body: await json(again) }).toEqual({ status: 200, body: {} });
    await expectError(await allow(stranger), 409, 'allow_conflict');
    expect(relay.devices.get(inbox)?.allowedSender()).toBe(partner.keyText);
  });

  it('is for the owner only', async () => {
    await register(owner);
    await register(stranger);
    await expectError(await allow(stranger, stranger), 403, 'not_inbox_owner');
    expect(relay.devices.get(inbox)?.allowedSender()).toBeNull();
  });

  it('needs an inbox and a well-formed key', async () => {
    await expectError(await allow(partner), 404, 'inbox_not_found');
    await register(owner);
    for (const body of ['{}', '{"sender_key": 7}', `{"sender_key": "${partner.keyText}x"}`, 'not json']) {
      await expectError(await send(owner, 'POST', `/v1/inbox/${inbox}/allow`, { body }), 400, 'malformed_request');
    }
  });
});

describe('PUT /v1/inbox/{id}/envelopes', () => {
  it('stores an envelope from the allowed sender', async () => {
    await paired();
    const res = await deposit(envelope(1));
    expect({ status: res.status, body: await json(res) }).toEqual({ status: 201, body: {} });
    expect(storedRows()).toEqual([{ seq: 1 }]);
  });

  it('refuses any other key with 403, before and after the allow', async () => {
    await register(owner);
    await register(partner);
    await register(stranger);
    await expectError(await deposit(envelope(1)), 403, 'sender_not_allowed');
    await allow(partner);
    await expectError(await deposit(envelope(1), stranger), 403, 'sender_not_allowed');
    // The owner is not its own sender either.
    await expectError(await deposit(envelope(1), owner), 403, 'sender_not_allowed');
    expect(storedRows()).toEqual([]);
  });

  it('takes 65,536 bytes and refuses 65,537 with 413', async () => {
    await paired();
    expect((await deposit(envelope(1, MAX_ENVELOPE_BYTES))).status).toBe(201);
    await expectError(await deposit(envelope(2, MAX_ENVELOPE_BYTES + 1)), 413, 'body_too_large');
    expect(storedRows()).toEqual([{ seq: 1 }]);
  });

  it('needs the Maw-Wake header (0 or 1) and a non-empty body', async () => {
    await paired();
    expect((await deposit(envelope(1), partner, { headers: { 'maw-wake': '0' } })).status).toBe(201);
    for (const wake of ['', '2', 'true', '01']) {
      await expectError(await deposit(envelope(1), partner, { headers: { 'maw-wake': wake } }), 400, 'malformed_request');
    }
    const headerless = await send(partner, 'PUT', `/v1/inbox/${inbox}/envelopes`, { body: envelope(1) });
    await expectError(headerless, 400, 'malformed_request');
    await expectError(await deposit(new Uint8Array(0)), 400, 'malformed_request');
    expect(storedRows()).toEqual([{ seq: 1 }]);
  });

  it('refuses an unsigned or replayed deposit', async () => {
    await paired();
    await expectError(await deposit(envelope(1), partner, { unsigned: true }), 401, 'auth_missing');
    const nonce = freshNonce();
    expect((await deposit(envelope(1), partner, { nonce })).status).toBe(201);
    await expectError(await deposit(envelope(1), partner, { nonce }), 401, 'nonce_reused');
    expect(storedRows()).toEqual([{ seq: 1 }]);
  });

  it('answers inbox_not_found for a missing inbox or a bad ID', async () => {
    await register(partner);
    await expectError(await deposit(envelope(1)), 404, 'inbox_not_found');
    const bad = await send(partner, 'PUT', '/v1/inbox/AAAA/envelopes', {
      body: envelope(1),
      headers: { 'maw-wake': '0' },
    });
    await expectError(bad, 404, 'inbox_not_found');
  });

  it('answers inbox_full when 100 MiB are waiting', async () => {
    await paired();
    const state = relay.devices.get(inbox);
    if (state === undefined) throw new Error('no state');
    for (let i = 0; i < 1600; i++) state.deposit(partner.keyText, envelope(i, MAX_ENVELOPE_BYTES), t0);
    await expectError(await deposit(envelope(1)), 409, 'inbox_full');
  });
});

describe('GET /v1/inbox/{id}/envelopes', () => {
  it('returns envelopes in deposit order with opaque cursors, byte for byte', async () => {
    await paired();
    const bodies = [envelope(1), envelope(2, 698), envelope(3, MAX_ENVELOPE_BYTES)];
    for (const b of bodies) expect((await deposit(b)).status).toBe(201);
    const all = await page(await fetchPage());
    expect(all.more).toBe(false);
    expect(all.envelopes.map((e) => fromBase64Url(e.body, Math.floor((e.body.length * 3) / 4)))).toEqual(bodies);
    const cursors = all.envelopes.map((e) => e.cursor);
    expect(new Set(cursors).size).toBe(3);
    const rest = await page(await fetchPage(`?after=${cursors[0]}`));
    expect(rest.envelopes.map((e) => e.cursor)).toEqual(cursors.slice(1));
    expect(await page(await fetchPage(`?after=${cursors[2]}`))).toEqual({ envelopes: [], more: false });
  });

  it('pages and says when more are waiting', async () => {
    await paired();
    for (let i = 0; i < PAGE_MAX_ENVELOPES + 2; i++) expect((await deposit(envelope(i, 300))).status).toBe(201);
    const first = await page(await fetchPage());
    expect(first.envelopes.length).toBe(PAGE_MAX_ENVELOPES);
    expect(first.more).toBe(true);
    const second = await page(await fetchPage(`?after=${first.envelopes.at(-1)?.cursor}`));
    expect(second.envelopes.length).toBe(2);
    expect(second.more).toBe(false);
  });

  it('is for the owner only', async () => {
    await paired();
    await deposit(envelope(1));
    await expectError(await fetchPage('', partner), 403, 'not_inbox_owner');
    await expectError(await fetchPage('', stranger), 403, 'not_inbox_owner');
  });

  it('refuses a malformed query', async () => {
    await paired();
    for (const q of ['?after=', '?after=01', '?after=-1', '?after=x', '?after=1&after=2', '?other=1', '?after=99999999999999999']) {
      await expectError(await fetchPage(q), 400, 'malformed_request');
    }
    expect((await fetchPage('?after=0')).status).toBe(200);
  });

  it('answers inbox_not_found before registration', async () => {
    await expectError(await fetchPage(), 404, 'inbox_not_found');
  });
});

describe('POST /v1/inbox/{id}/ack', () => {
  it('deletes every envelope up to and including the cursor, from storage', async () => {
    await paired();
    for (let i = 1; i <= 4; i++) await deposit(envelope(i));
    const cursors = (await page(await fetchPage())).envelopes.map((e) => e.cursor);
    const res = await ack(cursors[1]);
    expect({ status: res.status, body: await json(res) }).toEqual({ status: 200, body: {} });
    expect(storedRows()).toEqual([{ seq: 3 }, { seq: 4 }]);
    expect((await page(await fetchPage())).envelopes.map((e) => e.cursor)).toEqual(cursors.slice(2));
    // Repeating an ACK (a lost answer) is harmless.
    expect((await ack(cursors[1])).status).toBe(200);
    expect((await ack(cursors[3])).status).toBe(200);
    expect(storedRows()).toEqual([]);
    expect(relay.deviceSql.get(inbox)?.('SELECT body FROM envelopes')).toEqual([]);
  });

  it('keeps cursors increasing after everything was acknowledged', async () => {
    await paired();
    await deposit(envelope(1));
    const [first] = (await page(await fetchPage())).envelopes;
    await ack(first?.cursor);
    await deposit(envelope(2));
    const after = await page(await fetchPage(`?after=${first?.cursor}`));
    expect(after.envelopes.length).toBe(1);
  });

  it('is for the owner only and needs a cursor string', async () => {
    await paired();
    await deposit(envelope(1));
    await expectError(await ack('1', partner), 403, 'not_inbox_owner');
    for (const cursor of [1, '', '01', null, '1.5']) await expectError(await ack(cursor), 400, 'malformed_request');
    expect(storedRows()).toEqual([{ seq: 1 }]);
  });
});

describe('POST /v1/inbox/{id}/push-token', () => {
  function setToken(token: unknown, key = owner): Promise<Response> {
    return send(key, 'POST', `/v1/inbox/${inbox}/push-token`, { body: JSON.stringify({ push_token: token }) });
  }

  it('replaces the token, also with null', async () => {
    await register(owner);
    expect((await setToken('fcm-2')).status).toBe(200);
    expect(relay.devices.get(inbox)?.registration()?.pushToken).toBe('fcm-2');
    expect((await setToken(null)).status).toBe(200);
    expect(relay.devices.get(inbox)?.registration()?.pushToken).toBeNull();
  });

  it('is for the owner only, with a valid token', async () => {
    await register(owner);
    await register(stranger);
    await expectError(await setToken('x', stranger), 403, 'not_inbox_owner');
    for (const t of ['', 'has space', 5, 'x'.repeat(4097)]) await expectError(await setToken(t), 400, 'malformed_request');
    await expectError(await send(owner, 'POST', `/v1/inbox/${inbox}/push-token`, { body: '{}' }), 400, 'malformed_request');
    expect(relay.devices.get(inbox)?.registration()?.pushToken).toBe('test-fcm-token');
  });

  it('answers inbox_not_found before registration', async () => {
    await expectError(await setToken('x'), 404, 'inbox_not_found');
  });
});

describe('DELETE /v1/inbox/{id}', () => {
  it('deletes the inbox, the allow-list and the envelopes', async () => {
    await paired();
    await deposit(envelope(1));
    const res = await send(owner, 'DELETE', `/v1/inbox/${inbox}`);
    expect({ status: res.status, body: await json(res) }).toEqual({ status: 200, body: {} });
    const sql = relay.deviceSql.get(inbox);
    expect(sql?.('SELECT * FROM inbox')).toEqual([]);
    expect(sql?.('SELECT * FROM allowed_sender')).toEqual([]);
    expect(sql?.('SELECT * FROM envelopes')).toEqual([]);
    await expectError(await deposit(envelope(2)), 404, 'inbox_not_found');
    await expectError(await fetchPage(), 404, 'inbox_not_found');
    // A retry after a lost answer succeeds.
    expect((await send(owner, 'DELETE', `/v1/inbox/${inbox}`)).status).toBe(200);
  });

  it('is for the owner only', async () => {
    await paired();
    await deposit(envelope(1));
    await expectError(await send(partner, 'DELETE', `/v1/inbox/${inbox}`), 403, 'not_inbox_owner');
    expect(storedRows()).toEqual([{ seq: 1 }]);
  });

  it('does not let a captured request recreate the inbox within the nonce memory', async () => {
    const nonce = freshNonce();
    const body = registrationBody(owner);
    expect((await send(owner, 'POST', '/v1/inbox', { body, nonce })).status).toBe(201);
    expect((await send(owner, 'DELETE', `/v1/inbox/${inbox}`)).status).toBe(200);
    await expectError(await send(owner, 'POST', '/v1/inbox', { body, nonce }), 401, 'nonce_reused');
    expect(relay.devices.get(inbox)?.registration()).toBeNull();
  });
});

describe('inbox routes', () => {
  it('answer 405 with the allowed methods', async () => {
    const cases: [string, string, string][] = [
      ['GET', `/v1/inbox/${inbox}`, 'DELETE'],
      ['GET', `/v1/inbox/${inbox}/allow`, 'POST'],
      ['POST', `/v1/inbox/${inbox}/envelopes`, 'GET, PUT'],
      ['GET', `/v1/inbox/${inbox}/ack`, 'POST'],
      ['PUT', `/v1/inbox/${inbox}/push-token`, 'POST'],
    ];
    for (const [method, path, allowHeader] of cases) {
      const res = await send(owner, method, path);
      await expectError(res, 405, 'method_not_allowed');
      expect(res.headers.get('allow')).toBe(allowHeader);
    }
  });

  it('answer not_found for unknown sub-paths', async () => {
    await expectError(await send(owner, 'GET', `/v1/inbox/${inbox}/other`), 404, 'not_found');
  });

  it('answer inbox_not_found for a badly formed inbox ID', async () => {
    await register(owner);
    await expectError(await send(owner, 'DELETE', `/v1/inbox/${inbox}x`), 404, 'inbox_not_found');
    await expectError(await send(owner, 'GET', '/v1/inbox/AAAAAAAAAAAAAAAAAAAAAB/envelopes'), 404, 'inbox_not_found');
  });

  it('check the signature before the owner', async () => {
    await register(owner);
    await expectError(await send(owner, 'DELETE', `/v1/inbox/${inbox}`, { unsigned: true }), 401, 'auth_missing');
    expect(relay.devices.get(inbox)?.registration()).not.toBeNull();
  });
});
