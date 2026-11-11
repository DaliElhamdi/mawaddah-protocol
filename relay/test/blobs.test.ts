// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// The blob routes (spec 4.5, PROTOCOL.md section 12) and the 30-day delete,
// through the handler with the real state over in-memory SQLite and a fake
// clock.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  BLOB_CHUNK_BYTES,
  chunkCount,
  chunkLength,
  MAX_BLOB_BYTES,
  MAX_PENDING_BLOB_BYTES,
  RETENTION_MS,
} from '../src/device_state';
import { inboxIdFor, toBase64Url } from '../src/encoding';
import { handleRequest } from '../src/handler';
import { FakeRelay } from './support/fake_relay';
import { freshNonce, registrationBody, seedOf, signHeaders, type TestKey, testKey } from './support/signing';

const t0 = 1762862400000;
let relay: FakeRelay;
let consoleCalls: unknown[];

let owner: TestKey;
let partner: TestKey;
let stranger: TestKey;
let inbox: string;

const blobA = toBase64Url(new Uint8Array(16).fill(0xa1));
const blobB = toBase64Url(new Uint8Array(16).fill(0xb2));

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
  await register(owner);
  await register(partner);
  await register(stranger);
  const allowed = await send(owner, 'POST', `/v1/inbox/${inbox}/allow`, {
    body: JSON.stringify({ sender_key: partner.keyText }),
  });
  expect(allowed.status).toBe(201);
});
afterEach(() => {
  relay.close();
  vi.restoreAllMocks();
  // Spec 4.5: no request logging.
  expect(consoleCalls).toEqual([]);
});

async function send(key: TestKey, method: string, path: string, o: { body?: Uint8Array | string } = {}) {
  const body = o.body ?? '';
  const signed = await signHeaders(key, {
    method,
    path,
    body,
    timestamp: Math.floor(relay.nowMs / 1000),
    nonce: freshNonce(),
  });
  return handleRequest(
    new Request(`https://relay.test${path}`, {
      method,
      body: method === 'GET' || method === 'HEAD' ? undefined : body,
      headers: { ...signed, 'cf-connecting-ip': '203.0.113.7' },
    }),
    relay,
  );
}

async function register(key: TestKey): Promise<void> {
  expect((await send(key, 'POST', '/v1/inbox', { body: registrationBody(key) })).status).toBe(201);
}

async function result(res: Response): Promise<{ status: number; body: unknown }> {
  expect(res.headers.get('content-type')).toBe('application/json');
  expect(res.headers.get('cache-control')).toBe('no-store');
  return { status: res.status, body: await res.json() };
}

async function expectError(res: Response, status: number, error: string, extra: object = {}): Promise<void> {
  expect(await result(res)).toEqual({ status, body: { error, ...extra } });
}

/** Chunk [index] of a blob of [size] bytes whose bytes show [n]. */
function chunk(size: number, index: number, n = 1): Uint8Array {
  const out = new Uint8Array(chunkLength(size, index));
  for (let i = 0; i < out.length; i++) out[i] = (n * 37 + index * 11 + i) & 0xff;
  return out;
}

function put(size: number, index: number, body = chunk(size, index), o: { key?: TestKey; blob?: string } = {}) {
  const path = `/v1/inbox/${inbox}/blobs/${o.blob ?? blobA}?size=${size}&chunk=${index}`;
  return send(o.key ?? partner, 'PUT', path, { body });
}

function get(index: number, o: { key?: TestKey; blob?: string } = {}) {
  return send(o.key ?? owner, 'GET', `/v1/inbox/${inbox}/blobs/${o.blob ?? blobA}?chunk=${index}`);
}

function del(o: { key?: TestKey; blob?: string } = {}) {
  return send(o.key ?? owner, 'DELETE', `/v1/inbox/${inbox}/blobs/${o.blob ?? blobA}`);
}

async function upload(size: number, blob = blobA): Promise<void> {
  for (let i = 0; i < chunkCount(size); i++) expect((await put(size, i, chunk(size, i), { blob })).status).toBe(201);
}

async function bytesOf(res: Response): Promise<Uint8Array> {
  expect(res.status).toBe(200);
  expect(res.headers.get('content-type')).toBe('application/octet-stream');
  expect(res.headers.get('cache-control')).toBe('no-store');
  return new Uint8Array(await res.arrayBuffer());
}

describe('PUT and GET /v1/inbox/{id}/blobs/{blob_id}', () => {
  it('uploads a blob in chunks and downloads it byte for byte', async () => {
    const size = 2 * BLOB_CHUNK_BYTES + 100;
    expect(await result(await put(size, 0))).toEqual({ status: 201, body: {} });
    await expectError(await get(0), 409, 'blob_incomplete');
    expect((await put(size, 1)).status).toBe(201);
    expect((await put(size, 2)).status).toBe(201);
    for (let i = 0; i < 3; i++) {
      const res = await get(i);
      expect(res.headers.get('maw-blob-size')).toBe(String(size));
      expect(await bytesOf(res)).toEqual(chunk(size, i));
    }
    await expectError(await get(3), 400, 'malformed_request');
  });

  it('takes a 10 MiB blob and refuses 10 MiB + 1 byte', async () => {
    await upload(MAX_BLOB_BYTES);
    expect((await bytesOf(await get(9))).byteLength).toBe(BLOB_CHUNK_BYTES);
    await expectError(await put(MAX_BLOB_BYTES + 1, 0, chunk(MAX_BLOB_BYTES, 0), { blob: blobB }), 413, 'blob_too_large');
    expect(relay.deviceSql.get(inbox)?.(`SELECT blob_id FROM blobs`)).toEqual([{ blob_id: blobA }]);
  });

  it('refuses a chunk body over 1 MiB before reading the rest', async () => {
    const big = new Uint8Array(BLOB_CHUNK_BYTES + 1);
    await expectError(await put(MAX_BLOB_BYTES, 0, big), 413, 'body_too_large');
  });

  it('refuses a chunk of the wrong length, index or query', async () => {
    const size = BLOB_CHUNK_BYTES + 10;
    await expectError(await put(size, 0, new Uint8Array(BLOB_CHUNK_BYTES - 1)), 400, 'malformed_request');
    await expectError(await put(size, 1, new Uint8Array(11)), 400, 'malformed_request');
    await expectError(await put(size, 2, new Uint8Array(0)), 400, 'malformed_request');
    await expectError(await put(0, 0, new Uint8Array(0)), 400, 'malformed_request');
    for (const query of ['', '?chunk=0&size=10', '?size=10', '?size=010&chunk=0', '?size=10&chunk=0&x=1', '?size=10&chunk=-1', '?x=10&chunk=0', '?size=10&index=0']) {
      const res = await send(partner, 'PUT', `/v1/inbox/${inbox}/blobs/${blobA}${query}`, { body: new Uint8Array(10) });
      await expectError(res, 400, 'malformed_request');
    }
    for (const query of ['', '?chunk=', '?chunk=0&x=1', '?size=1&chunk=0', '?index=0']) {
      await expectError(await send(owner, 'GET', `/v1/inbox/${inbox}/blobs/${blobA}${query}`), 400, 'malformed_request');
    }
  });

  it('says which chunk comes next when one is out of order', async () => {
    const size = 3 * BLOB_CHUNK_BYTES;
    await expectError(await put(size, 1), 409, 'chunk_out_of_order', { next_chunk: 0 });
    await put(size, 0);
    await expectError(await put(size, 2), 409, 'chunk_out_of_order', { next_chunk: 1 });
  });

  it('answers a repeated chunk with 200 and refuses a changed one', async () => {
    const size = BLOB_CHUNK_BYTES + 1;
    await upload(size);
    expect(await result(await put(size, 1))).toEqual({ status: 200, body: {} });
    await expectError(await put(size, 1, chunk(size, 1, 9)), 409, 'blob_conflict');
    await expectError(await put(size + 1, 0, chunk(size + 1, 0)), 409, 'blob_conflict');
  });

  it('takes chunks only from the allowed sender and gives them only to the owner', async () => {
    await expectError(await put(10, 0, chunk(10, 0), { key: stranger }), 403, 'sender_not_allowed');
    await expectError(await put(10, 0, chunk(10, 0), { key: owner }), 403, 'sender_not_allowed');
    await upload(10);
    await expectError(await get(0, { key: partner }), 403, 'not_inbox_owner');
    await expectError(await get(0, { key: stranger }), 403, 'not_inbox_owner');
  });

  it('refuses badly formed blob IDs and unknown blobs or inboxes', async () => {
    for (const id of ['short', `${blobA}A`, 'AAAAAAAAAAAAAAAAAAAAAB']) {
      const res = await send(partner, 'PUT', `/v1/inbox/${inbox}/blobs/${id}?size=1&chunk=0`, { body: new Uint8Array(1) });
      await expectError(res, 404, 'blob_not_found');
      await expectError(await get(0, { blob: id }), 404, 'blob_not_found');
      await expectError(await del({ blob: id }), 404, 'blob_not_found');
    }
    await expectError(await get(0), 404, 'blob_not_found');
    const gone = await inboxIdFor((await testKey(seedOf(9))).publicKey);
    const res = await send(partner, 'PUT', `/v1/inbox/${gone}/blobs/${blobA}?size=1&chunk=0`, { body: new Uint8Array(1) });
    await expectError(res, 404, 'inbox_not_found');
  });

  it('refuses a new blob past the 100 MiB quota with 413', async () => {
    const count = MAX_PENDING_BLOB_BYTES / MAX_BLOB_BYTES;
    for (let i = 0; i < count; i++) {
      const id = toBase64Url(new Uint8Array(16).fill(i));
      expect((await put(MAX_BLOB_BYTES, 0, chunk(MAX_BLOB_BYTES, 0), { blob: id })).status).toBe(201);
    }
    await expectError(await put(1, 0, chunk(1, 0)), 413, 'blob_quota_exceeded');
    expect((await del({ blob: toBase64Url(new Uint8Array(16).fill(0)) })).status).toBe(200);
    expect((await put(1, 0, chunk(1, 0))).status).toBe(201);
  });

  it('allows only PUT, GET and DELETE', async () => {
    const res = await send(owner, 'POST', `/v1/inbox/${inbox}/blobs/${blobA}`);
    await expectError(res, 405, 'method_not_allowed');
    expect(res.headers.get('allow')).toBe('DELETE, GET, PUT');
  });
});

describe('DELETE /v1/inbox/{id}/blobs/{blob_id}', () => {
  it('deletes for the owner (the ACK) and answers 200 again when it is gone', async () => {
    await upload(BLOB_CHUNK_BYTES + 1);
    expect(await result(await del())).toEqual({ status: 200, body: {} });
    expect(relay.deviceSql.get(inbox)?.('SELECT * FROM blob_chunks')).toEqual([]);
    expect((await del()).status).toBe(200);
    await expectError(await get(0), 404, 'blob_not_found');
  });

  it('lets the allowed sender delete an upload it gave up, and nobody else', async () => {
    await put(2 * BLOB_CHUNK_BYTES, 0);
    await expectError(await del({ key: stranger }), 403, 'sender_not_allowed');
    expect((await del({ key: partner })).status).toBe(200);
    expect(relay.deviceSql.get(inbox)?.('SELECT * FROM blobs')).toEqual([]);
  });

  it('goes with the inbox', async () => {
    await upload(5);
    expect((await send(owner, 'DELETE', `/v1/inbox/${inbox}`)).status).toBe(200);
    expect(relay.deviceSql.get(inbox)?.('SELECT * FROM blobs')).toEqual([]);
    expect(relay.deviceSql.get(inbox)?.('SELECT * FROM blob_chunks')).toEqual([]);
    await expectError(await del(), 404, 'inbox_not_found');
    await expectError(await get(0), 404, 'inbox_not_found');
  });
});

describe('the 30-day delete', () => {
  it('removes envelopes and blobs nobody fetched, 30 days after they were stored', async () => {
    const path = `/v1/inbox/${inbox}/envelopes`;
    const body = new Uint8Array(300);
    const headers = await signHeaders(partner, { method: 'PUT', path, body, timestamp: Math.floor(t0 / 1000) });
    const stored = await handleRequest(
      new Request(`https://relay.test${path}`, { method: 'PUT', body, headers: { ...headers, 'maw-wake': '0' } }),
      relay,
    );
    expect(stored.status).toBe(201);
    await upload(10);

    relay.nowMs = t0 + RETENTION_MS - 1000;
    expect((await result(await send(owner, 'GET', `/v1/inbox/${inbox}/envelopes`))).body).toMatchObject({
      envelopes: [{ cursor: '1' }],
    });
    expect((await get(0)).status).toBe(200);

    relay.nowMs = t0 + RETENTION_MS;
    expect(await result(await send(owner, 'GET', `/v1/inbox/${inbox}/envelopes`))).toEqual({
      status: 200,
      body: { envelopes: [], more: false },
    });
    await expectError(await get(0), 404, 'blob_not_found');
    const rows = relay.deviceSql.get(inbox);
    expect([rows?.('SELECT * FROM envelopes'), rows?.('SELECT * FROM blobs'), rows?.('SELECT * FROM blob_chunks')]).toEqual([
      [],
      [],
      [],
    ]);
  });
});
