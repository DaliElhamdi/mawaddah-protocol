// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from 'vitest';
import { NONCE_MEMORY_MS } from '../src/auth';
import {
  alarmToSet,
  BLOB_CHUNK_BYTES,
  chunkCount,
  chunkLength,
  DeviceState,
  type EnvelopePage,
  type FetchResult,
  MAX_BLOB_BYTES,
  MAX_ENVELOPE_BYTES,
  MAX_PENDING_BLOB_BYTES,
  MAX_PENDING_BYTES,
  PAGE_MAX_BYTES,
  PAGE_MAX_ENVELOPES,
  type Registration,
  RETENTION_MS,
} from '../src/device_state';
import { memorySql } from './support/sqlite';

const t0 = 1762862400000;
const reg: Registration = { signingKey: 'k'.repeat(43), pushToken: 'token-1', platform: 'android' };

const closers: (() => void)[] = [];
function fresh(): { state: DeviceState; rows: (q: string) => unknown[] } {
  const sql = memorySql();
  closers.push(sql.close);
  return { state: new DeviceState(sql), rows: (q) => sql.exec(q) };
}
afterEach(() => {
  for (const c of closers.splice(0)) c();
});

describe('DeviceState nonces', () => {
  it('refuses a nonce used again within 15 minutes', () => {
    const { state } = fresh();
    expect(state.useNonce('n1', t0)).toBe(true);
    expect(state.useNonce('n1', t0)).toBe(false);
    expect(state.useNonce('n1', t0 + NONCE_MEMORY_MS - 1)).toBe(false);
    expect(state.useNonce('n2', t0)).toBe(true);
  });

  it('forgets a nonce after 15 minutes', () => {
    const { state, rows } = fresh();
    state.useNonce('n1', t0);
    state.useNonce('n2', t0 + 1000);
    expect(state.pruneNonces(t0)).toBe(t0 + NONCE_MEMORY_MS);
    expect(state.pruneNonces(t0 + NONCE_MEMORY_MS)).toBe(t0 + 1000 + NONCE_MEMORY_MS);
    expect(rows('SELECT nonce FROM nonces')).toEqual([{ nonce: 'n2' }]);
    expect(state.useNonce('n1', t0 + NONCE_MEMORY_MS)).toBe(true);
    expect(state.pruneNonces(t0 + 2 * NONCE_MEMORY_MS + 1000)).toBeNull();
  });
});

describe('DeviceState registration', () => {
  it('creates, then updates the token for the same key', () => {
    const { state } = fresh();
    expect(state.registration()).toBeNull();
    expect(state.register(reg)).toBe('created');
    expect(state.registration()).toEqual(reg);
    const again = { ...reg, pushToken: null, platform: 'ios' as const };
    expect(state.register(again)).toBe('updated');
    expect(state.registration()).toEqual(again);
  });

  it('refuses a different key for the same inbox', () => {
    const { state } = fresh();
    state.register(reg);
    expect(state.register({ ...reg, signingKey: 'j'.repeat(43) })).toBe('conflict');
    expect(state.registration()).toEqual(reg);
  });

  it('stores only the key, the push token and the platform', () => {
    const { state, rows } = fresh();
    state.register(reg);
    expect(rows('SELECT * FROM inbox')).toEqual([
      { id: 1, signing_key: reg.signingKey, push_token: reg.pushToken, platform: reg.platform },
    ]);
  });

  it('is empty only with no registration and no live nonce', () => {
    const { state } = fresh();
    expect(state.isEmpty(t0)).toBe(true);
    state.useNonce('n1', t0);
    expect(state.isEmpty(t0)).toBe(false);
    expect(state.isEmpty(t0 + NONCE_MEMORY_MS)).toBe(true);
    state.register(reg);
    expect(state.isEmpty(t0 + NONCE_MEMORY_MS)).toBe(false);
  });
});

const partner = 'p'.repeat(43);
const stranger = 's'.repeat(43);

function registered(): { state: DeviceState; rows: (q: string) => unknown[] } {
  const f = fresh();
  f.state.register(reg);
  return f;
}

function pageOf(result: FetchResult): EnvelopePage {
  if (typeof result === 'string') throw new Error(`no page: ${result}`);
  return result;
}

function bytes(n: number, fill = 7): Uint8Array {
  return new Uint8Array(n).fill(fill);
}

describe('DeviceState allow-list', () => {
  it('allows exactly one sender key', () => {
    const { state } = registered();
    expect(state.allow(partner)).toBe('allowed');
    expect(state.allow(partner)).toBe('repeat');
    expect(state.allow(stranger)).toBe('conflict');
    expect(state.allowedSender()).toBe(partner);
  });

  it('needs an inbox', () => {
    const { state } = fresh();
    expect(state.allow(partner)).toBe('no_inbox');
    expect(state.allowedSender()).toBeNull();
  });
});

describe('DeviceState envelopes', () => {
  it('refuses deposits until a sender is allowed, and from any other key', () => {
    const { state, rows } = registered();
    expect(state.deposit(partner, bytes(10), t0)).toEqual({ kind: 'not_allowed' });
    state.allow(partner);
    expect(state.deposit(stranger, bytes(10), t0)).toEqual({ kind: 'not_allowed' });
    expect(rows('SELECT seq FROM envelopes')).toEqual([]);
  });

  it('refuses deposits into a missing inbox', () => {
    const { state } = fresh();
    expect(state.deposit(partner, bytes(10), t0)).toEqual({ kind: 'no_inbox' });
    expect(state.fetchEnvelopes(null, t0)).toBe('no_inbox');
    expect(state.ack(1)).toBe('no_inbox');
    expect(state.setPushToken('t')).toBe(false);
  });

  it('returns envelopes in deposit order, after the cursor, byte for byte', () => {
    const { state } = registered();
    state.allow(partner);
    const bodies = [bytes(3, 1), bytes(5, 2), bytes(1, 3)];
    const cursors = bodies.map((b) => state.deposit(partner, b, t0));
    expect(cursors).toEqual([1, 2, 3].map((c) => ({ kind: 'stored', cursor: c })));
    expect(state.fetchEnvelopes(null, t0)).toEqual({
      envelopes: bodies.map((body, i) => ({ cursor: i + 1, body })),
      more: false,
    });
    expect(pageOf(state.fetchEnvelopes(1, t0)).envelopes.map((e) => e.cursor)).toEqual([2, 3]);
    expect(state.fetchEnvelopes(3, t0)).toEqual({ envelopes: [], more: false });
  });

  it('stores the body, its size and the deposit time only', () => {
    const { state, rows } = registered();
    state.allow(partner);
    state.deposit(partner, bytes(4, 9), t0);
    expect(rows('SELECT * FROM envelopes')).toEqual([{ seq: 1, size: 4, deposited_at: t0, body: bytes(4, 9) }]);
  });

  it('pages at 100 envelopes and at 1 MiB, with at least one envelope', () => {
    const { state } = registered();
    state.allow(partner);
    for (let i = 0; i < PAGE_MAX_ENVELOPES + 1; i++) state.deposit(partner, bytes(1), t0);
    const first = pageOf(state.fetchEnvelopes(null, t0));
    expect(first.envelopes.length).toBe(PAGE_MAX_ENVELOPES);
    expect(first.more).toBe(true);
    expect(state.fetchEnvelopes(PAGE_MAX_ENVELOPES, t0)).toEqual({
      envelopes: [{ cursor: PAGE_MAX_ENVELOPES + 1, body: bytes(1) }],
      more: false,
    });

    const big = registered().state;
    big.allow(partner);
    const per = Math.floor(PAGE_MAX_BYTES / MAX_ENVELOPE_BYTES); // 16 full envelopes fill a page exactly
    for (let i = 0; i < per + 1; i++) big.deposit(partner, bytes(MAX_ENVELOPE_BYTES), t0);
    const page = pageOf(big.fetchEnvelopes(null, t0));
    expect(page.envelopes.length).toBe(per);
    expect(page.more).toBe(true);
    expect(pageOf(big.fetchEnvelopes(per, t0)).envelopes.length).toBe(1);
  });

  it('ACK deletes every envelope up to and including the cursor', () => {
    const { state, rows } = registered();
    state.allow(partner);
    for (let i = 0; i < 5; i++) state.deposit(partner, bytes(2), t0);
    expect(state.ack(3)).toBe(3);
    expect(rows('SELECT seq FROM envelopes')).toEqual([{ seq: 4 }, { seq: 5 }]);
    expect(state.ack(3)).toBe(0);
    expect(state.ack(5)).toBe(2);
    expect(rows('SELECT seq FROM envelopes')).toEqual([]);
  });

  it('refuses an ACK or a fetch after a cursor it never handed out', () => {
    const { state, rows } = registered();
    state.allow(partner);
    expect(state.ack(1)).toBe('ahead');
    expect(state.fetchEnvelopes(1, t0)).toBe('ahead');
    expect(state.fetchEnvelopes(0, t0)).toEqual({ envelopes: [], more: false });
    for (let i = 0; i < 3; i++) state.deposit(partner, bytes(2), t0);
    expect(state.ack(4)).toBe('ahead');
    expect(state.fetchEnvelopes(4, t0)).toBe('ahead');
    expect(rows('SELECT seq FROM envelopes')).toEqual([{ seq: 1 }, { seq: 2 }, { seq: 3 }]);
    // After everything is acknowledged the last cursor still counts.
    expect(state.ack(3)).toBe(3);
    expect(state.lastCursor()).toBe(3);
    expect(state.fetchEnvelopes(3, t0)).toEqual({ envelopes: [], more: false });
  });

  it('never hands out a cursor twice, also after everything was acknowledged', () => {
    const { state } = registered();
    state.allow(partner);
    state.deposit(partner, bytes(1), t0);
    state.deposit(partner, bytes(1), t0);
    state.ack(2);
    expect(state.deposit(partner, bytes(1, 5), t0)).toEqual({ kind: 'stored', cursor: 3 });
    expect(pageOf(state.fetchEnvelopes(2, t0)).envelopes).toEqual([{ cursor: 3, body: bytes(1, 5) }]);
  });

  it('refuses a deposit that would pass 100 MiB pending, and takes it again after an ACK', () => {
    const { state } = registered();
    state.allow(partner);
    const count = MAX_PENDING_BYTES / MAX_ENVELOPE_BYTES; // 1,600
    for (let i = 0; i < count; i++) expect(state.deposit(partner, bytes(MAX_ENVELOPE_BYTES), t0).kind).toBe('stored');
    expect(state.pendingBytes()).toBe(MAX_PENDING_BYTES);
    expect(state.deposit(partner, bytes(1), t0)).toEqual({ kind: 'full' });
    state.ack(1);
    expect(state.deposit(partner, bytes(1), t0).kind).toBe('stored');
  });
});

describe('DeviceState push token and delete', () => {
  it('replaces the push token, also with null', () => {
    const { state } = registered();
    expect(state.setPushToken('token-2')).toBe(true);
    expect(state.registration()?.pushToken).toBe('token-2');
    expect(state.setPushToken(null)).toBe(true);
    expect(state.registration()).toEqual({ ...reg, pushToken: null });
  });

  it('deletes the inbox, the allowed sender, the envelopes and the blobs, and keeps the nonces', () => {
    const { state, rows } = registered();
    state.useNonce('n1', t0);
    state.allow(partner);
    state.deposit(partner, bytes(3), t0);
    state.putBlobChunk(partner, blobA, 3, 0, bytes(3), t0);
    state.putBlobChunk(partner, blobB, BLOB_CHUNK_BYTES + 1, 0, bytes(BLOB_CHUNK_BYTES), t0);
    state.deleteInbox();
    expect(rows('SELECT * FROM inbox')).toEqual([]);
    expect(rows('SELECT * FROM allowed_sender')).toEqual([]);
    expect(rows('SELECT * FROM envelopes')).toEqual([]);
    expect(rows('SELECT * FROM blobs')).toEqual([]);
    expect(rows('SELECT * FROM blob_chunks')).toEqual([]);
    expect(rows('SELECT * FROM sqlite_sequence')).toEqual([]);
    expect(state.useNonce('n1', t0 + 1)).toBe(false);
    expect(state.isEmpty(t0)).toBe(false);
    expect(state.isEmpty(t0 + NONCE_MEMORY_MS)).toBe(true);
    // A new registration starts with no allowed sender.
    state.register(reg);
    expect(state.deposit(partner, bytes(3), t0)).toEqual({ kind: 'not_allowed' });
  });

  it('is not empty while an envelope or allowed sender is stored', () => {
    const { state } = registered();
    state.allow(partner);
    state.deposit(partner, bytes(3), t0);
    // Not reachable through the routes (the inbox row goes with them), checked anyway.
    state['sql'].exec('DELETE FROM inbox');
    expect(state.isEmpty(t0)).toBe(false);
    state['sql'].exec('DELETE FROM allowed_sender');
    expect(state.isEmpty(t0)).toBe(false); // the envelope alone
    state['sql'].exec('INSERT INTO allowed_sender (id, sender_key) VALUES (1, ?)', partner);
    state['sql'].exec('DELETE FROM envelopes');
    expect(state.isEmpty(t0)).toBe(false); // the allowed sender alone
    state['sql'].exec('DELETE FROM allowed_sender');
    expect(state.isEmpty(t0)).toBe(true);
    state['sql'].exec("INSERT INTO blobs (blob_id, size, chunks, created_at) VALUES ('b', 1, 0, 0)");
    expect(state.isEmpty(t0)).toBe(false); // a blob alone
  });
});

const blobA = 'AAAAAAAAAAAAAAAAAAAAAA';
const blobB = 'BBBBBBBBBBBBBBBBBBBBBA';

/** Chunk [index] of a blob of [size] bytes whose bytes show [n]. */
function chunk(size: number, index: number, n = 1): Uint8Array {
  const out = new Uint8Array(chunkLength(size, index));
  for (let i = 0; i < out.length; i++) out[i] = (n * 37 + index * 11 + i) & 0xff;
  return out;
}

/** A paired inbox (partner allowed). */
function pairedState(): { state: DeviceState; rows: (q: string) => unknown[] } {
  const f = registered();
  f.state.allow(partner);
  return f;
}

/** Uploads every chunk of a blob of [size] bytes. */
function upload(state: DeviceState, blobId: string, size: number, at = t0, n = 1): void {
  for (let i = 0; i < chunkCount(size); i++) {
    expect(state.putBlobChunk(partner, blobId, size, i, chunk(size, i, n), at).kind).toBe('stored');
  }
}

describe('DeviceState blobs', () => {
  it('uses the limits of spec 4.5: 30 days, 10 MiB per blob, 100 MiB per inbox, 1 MiB chunks', () => {
    expect(RETENTION_MS).toBe(2_592_000_000);
    expect([BLOB_CHUNK_BYTES, MAX_BLOB_BYTES, MAX_PENDING_BLOB_BYTES]).toEqual([1_048_576, 10_485_760, 104_857_600]);
  });

  it('splits sizes into 1 MiB chunks, the last one shorter', () => {
    expect([chunkCount(1), chunkCount(BLOB_CHUNK_BYTES), chunkCount(BLOB_CHUNK_BYTES + 1)]).toEqual([1, 1, 2]);
    expect(chunkCount(MAX_BLOB_BYTES)).toBe(10);
    expect([chunkLength(BLOB_CHUNK_BYTES + 5, 0), chunkLength(BLOB_CHUNK_BYTES + 5, 1)]).toEqual([
      BLOB_CHUNK_BYTES,
      5,
    ]);
    expect(chunkLength(5, 1)).toBe(0);
  });

  it('stores the chunks in order and returns them byte for byte once complete', () => {
    const { state } = pairedState();
    const size = 2 * BLOB_CHUNK_BYTES + 3;
    expect(state.putBlobChunk(partner, blobA, size, 0, chunk(size, 0), t0)).toEqual({ kind: 'stored' });
    expect(state.getBlobChunk(blobA, 0, t0)).toEqual({ kind: 'incomplete' });
    expect(state.putBlobChunk(partner, blobA, size, 1, chunk(size, 1), t0)).toEqual({ kind: 'stored' });
    expect(state.putBlobChunk(partner, blobA, size, 2, chunk(size, 2), t0)).toEqual({ kind: 'stored' });
    for (let i = 0; i < 3; i++) {
      expect(state.getBlobChunk(blobA, i, t0)).toEqual({ kind: 'chunk', size, body: chunk(size, i) });
    }
    expect(state.getBlobChunk(blobA, 3, t0)).toEqual({ kind: 'no_chunk' });
    expect(state.getBlobChunk(blobB, 0, t0)).toEqual({ kind: 'not_found' });
  });

  it('takes the largest blob, 10 MiB', () => {
    const { state } = pairedState();
    upload(state, blobA, MAX_BLOB_BYTES);
    const last = state.getBlobChunk(blobA, 9, t0);
    expect(last.kind === 'chunk' && last.body.byteLength).toBe(BLOB_CHUNK_BYTES);
  });

  it('refuses a chunk out of order and says which one comes next', () => {
    const { state, rows } = pairedState();
    const size = 3 * BLOB_CHUNK_BYTES;
    expect(state.putBlobChunk(partner, blobA, size, 1, chunk(size, 1), t0)).toEqual({ kind: 'out_of_order', next: 0 });
    expect(rows('SELECT * FROM blobs')).toEqual([]);
    state.putBlobChunk(partner, blobA, size, 0, chunk(size, 0), t0);
    expect(state.putBlobChunk(partner, blobA, size, 2, chunk(size, 2), t0)).toEqual({ kind: 'out_of_order', next: 1 });
  });

  it('accepts a stored chunk again with the same bytes, and refuses changes', () => {
    const { state } = pairedState();
    const size = BLOB_CHUNK_BYTES + 10;
    upload(state, blobA, size);
    expect(state.putBlobChunk(partner, blobA, size, 0, chunk(size, 0), t0)).toEqual({ kind: 'repeat' });
    expect(state.putBlobChunk(partner, blobA, size, 1, chunk(size, 1), t0)).toEqual({ kind: 'repeat' });
    expect(state.putBlobChunk(partner, blobA, size, 1, chunk(size, 1, 2), t0)).toEqual({ kind: 'conflict' });
    expect(state.putBlobChunk(partner, blobA, size + 1, 0, chunk(size + 1, 0), t0)).toEqual({ kind: 'conflict' });
    expect(state.getBlobChunk(blobA, 1, t0)).toEqual({ kind: 'chunk', size, body: chunk(size, 1) });
  });

  it('takes chunks only from the allowed sender, into an existing inbox', () => {
    const { state, rows } = registered();
    expect(state.putBlobChunk(partner, blobA, 3, 0, chunk(3, 0), t0)).toEqual({ kind: 'not_allowed' });
    state.allow(partner);
    expect(state.putBlobChunk(stranger, blobA, 3, 0, chunk(3, 0), t0)).toEqual({ kind: 'not_allowed' });
    expect(rows('SELECT * FROM blob_chunks')).toEqual([]);
    const { state: none } = fresh();
    expect(none.putBlobChunk(partner, blobA, 3, 0, chunk(3, 0), t0)).toEqual({ kind: 'no_inbox' });
    expect(none.getBlobChunk(blobA, 0, t0)).toEqual({ kind: 'no_inbox' });
    expect(none.deleteBlob(blobA, null)).toBe('no_inbox');
  });

  it('stores only the blob ID, its size, the chunk count, the time and the chunk bytes', () => {
    const { state, rows } = pairedState();
    state.putBlobChunk(partner, blobA, 4, 0, bytes(4, 9), t0);
    expect(rows('SELECT * FROM blobs')).toEqual([{ blob_id: blobA, size: 4, chunks: 1, created_at: t0 }]);
    expect(rows('SELECT * FROM blob_chunks')).toEqual([{ blob_id: blobA, idx: 0, body: bytes(4, 9) }]);
  });

  it('reserves the whole size at the first chunk and refuses past 100 MiB, until a blob is deleted', () => {
    const { state } = pairedState();
    const ids = Array.from({ length: MAX_PENDING_BLOB_BYTES / MAX_BLOB_BYTES }, (_, i) => `blob${i}`);
    for (const id of ids) {
      expect(state.putBlobChunk(partner, id, MAX_BLOB_BYTES, 0, chunk(MAX_BLOB_BYTES, 0), t0).kind).toBe('stored');
    }
    expect(state.pendingBlobBytes()).toBe(MAX_PENDING_BLOB_BYTES);
    expect(state.putBlobChunk(partner, blobA, 1, 0, chunk(1, 0), t0)).toEqual({ kind: 'quota' });
    // A reserved blob still takes its next chunks.
    expect(state.putBlobChunk(partner, 'blob0', MAX_BLOB_BYTES, 1, chunk(MAX_BLOB_BYTES, 1), t0).kind).toBe('stored');
    expect(state.deleteBlob('blob3', partner)).toBe('deleted');
    expect(state.putBlobChunk(partner, blobA, MAX_BLOB_BYTES, 0, chunk(MAX_BLOB_BYTES, 0), t0).kind).toBe('stored');
    expect(state.putBlobChunk(partner, blobB, 1, 0, chunk(1, 0), t0)).toEqual({ kind: 'quota' });
  });

  it('keeps the blob quota apart from the envelope quota', () => {
    const { state } = pairedState();
    upload(state, blobA, MAX_BLOB_BYTES);
    expect(state.pendingBytes()).toBe(0);
    state.deposit(partner, bytes(10), t0);
    expect(state.pendingBlobBytes()).toBe(MAX_BLOB_BYTES);
  });

  it('deletes a blob for the owner or the allowed sender, and nobody else', () => {
    const { state, rows } = pairedState();
    upload(state, blobA, 5);
    upload(state, blobB, 5);
    expect(state.deleteBlob(blobA, stranger)).toBe('not_allowed');
    expect(state.deleteBlob(blobA, null)).toBe('deleted');
    expect(state.deleteBlob(blobA, null)).toBe('absent');
    expect(state.deleteBlob(blobB, partner)).toBe('deleted');
    expect(rows('SELECT * FROM blobs')).toEqual([]);
    expect(rows('SELECT * FROM blob_chunks')).toEqual([]);
    expect(state.getBlobChunk(blobA, 0, t0)).toEqual({ kind: 'not_found' });
    // A deleted ID can be used again (the sender's choice; IDs are random).
    expect(state.putBlobChunk(partner, blobA, 5, 0, chunk(5, 0), t0)).toEqual({ kind: 'stored' });
  });
});

describe('DeviceState 30-day delete', () => {
  it('deletes envelopes and blobs exactly 30 days after they were stored, fetched or not', () => {
    const { state, rows } = pairedState();
    state.deposit(partner, bytes(3, 1), t0);
    state.deposit(partner, bytes(3, 2), t0 + 1000);
    upload(state, blobA, BLOB_CHUNK_BYTES + 1, t0);
    upload(state, blobB, 3, t0 + 1000);
    state.expire(t0 + RETENTION_MS - 1);
    expect(rows('SELECT seq FROM envelopes')).toEqual([{ seq: 1 }, { seq: 2 }]);
    expect(rows('SELECT blob_id FROM blobs ORDER BY blob_id')).toEqual([{ blob_id: blobA }, { blob_id: blobB }]);
    state.expire(t0 + RETENTION_MS);
    expect(rows('SELECT seq FROM envelopes')).toEqual([{ seq: 2 }]);
    expect(rows('SELECT blob_id FROM blobs')).toEqual([{ blob_id: blobB }]);
    expect(rows('SELECT blob_id, idx FROM blob_chunks')).toEqual([{ blob_id: blobB, idx: 0 }]);
    state.expire(t0 + 1000 + RETENTION_MS);
    expect(rows('SELECT * FROM envelopes')).toEqual([]);
    expect(rows('SELECT * FROM blobs')).toEqual([]);
    expect(rows('SELECT * FROM blob_chunks')).toEqual([]);
    // The inbox, its sender and the cursor count stay.
    expect(state.registration()).toEqual(reg);
    expect(state.deposit(partner, bytes(1), t0 + 2000 + RETENTION_MS)).toEqual({ kind: 'stored', cursor: 3 });
  });

  it('counts a blob from its first chunk, also when it never completed', () => {
    const { state, rows } = pairedState();
    const size = 2 * BLOB_CHUNK_BYTES;
    state.putBlobChunk(partner, blobA, size, 0, chunk(size, 0), t0);
    state.putBlobChunk(partner, blobA, size, 1, chunk(size, 1), t0 + RETENTION_MS - 1);
    state.expire(t0 + RETENTION_MS);
    expect(rows('SELECT * FROM blobs')).toEqual([]);
    expect(rows('SELECT * FROM blob_chunks')).toEqual([]);
  });

  it('never hands out an expired item, even before the alarm ran', () => {
    const late = t0 + RETENTION_MS;
    const { state: envelopes } = pairedState();
    envelopes.deposit(partner, bytes(3), t0);
    expect(envelopes.fetchEnvelopes(null, late)).toEqual({ envelopes: [], more: false });
    const { state: blobs } = pairedState();
    upload(blobs, blobA, 3, t0);
    expect(blobs.getBlobChunk(blobA, 0, late)).toEqual({ kind: 'not_found' });
  });

  it('frees the quotas of expired items before counting a new one', () => {
    const end = t0 + RETENTION_MS;
    const { state: envelopes } = pairedState();
    for (let i = 0; i < MAX_PENDING_BYTES / MAX_ENVELOPE_BYTES; i++) envelopes.deposit(partner, bytes(MAX_ENVELOPE_BYTES), t0);
    expect(envelopes.deposit(partner, bytes(1), end - 1)).toEqual({ kind: 'full' });
    expect(envelopes.deposit(partner, bytes(1), end).kind).toBe('stored');
    const { state: blobs } = pairedState();
    for (let i = 0; i < 10; i++) blobs.putBlobChunk(partner, `b${i}`, MAX_BLOB_BYTES, 0, chunk(MAX_BLOB_BYTES, 0), t0);
    expect(blobs.putBlobChunk(partner, blobA, 1, 0, chunk(1, 0), end - 1)).toEqual({ kind: 'quota' });
    expect(blobs.putBlobChunk(partner, blobA, 1, 0, chunk(1, 0), end)).toEqual({ kind: 'stored' });
  });

  it('gives the next alarm time: the first nonce, envelope or blob to expire', () => {
    const { state } = pairedState();
    expect(state.cleanUp(t0)).toBeNull();
    state.deposit(partner, bytes(3), t0 + 5000);
    expect(state.cleanUp(t0 + 5000)).toBe(t0 + 5000 + RETENTION_MS);
    upload(state, blobA, 3, t0 + 2000);
    expect(state.cleanUp(t0 + 5000)).toBe(t0 + 2000 + RETENTION_MS);
    state.useNonce('n1', t0 + 6000);
    expect(state.cleanUp(t0 + 6000)).toBe(t0 + 6000 + NONCE_MEMORY_MS);
    // After the nonce: the blob, then the envelope, then nothing.
    expect(state.cleanUp(t0 + 6000 + NONCE_MEMORY_MS)).toBe(t0 + 2000 + RETENTION_MS);
    expect(state.cleanUp(t0 + 2000 + RETENTION_MS)).toBe(t0 + 5000 + RETENTION_MS);
    expect(state.cleanUp(t0 + 5000 + RETENTION_MS)).toBeNull();
    expect(state.isEmpty(t0 + 5000 + RETENTION_MS)).toBe(false); // the inbox stays
  });

  it('moves the alarm only earlier: first deposit, first chunk, and under a pending nonce alarm', () => {
    // How DeviceObject uses it: alarmToSet(current alarm, cleanUp(now)).
    const { state } = pairedState();
    let alarm: number | null = null;
    const store = (now: number) => {
      alarm = alarmToSet(alarm, state.cleanUp(now)) ?? alarm;
    };
    state.deposit(partner, bytes(3), t0);
    store(t0); // first deposit, no alarm yet
    expect(alarm).toBe(t0 + RETENTION_MS);
    state.useNonce('n1', t0 + 10);
    store(t0 + 10); // a request's nonce comes first
    expect(alarm).toBe(t0 + 10 + NONCE_MEMORY_MS);
    state.putBlobChunk(partner, blobA, 3, 0, chunk(3, 0), t0 + 20);
    store(t0 + 20); // a blob under a pending nonce alarm leaves it
    expect(alarm).toBe(t0 + 10 + NONCE_MEMORY_MS);
    const { state: other } = pairedState();
    other.putBlobChunk(partner, blobA, 3, 0, chunk(3, 0), t0);
    expect(alarmToSet(null, other.cleanUp(t0))).toBe(t0 + RETENTION_MS); // first chunk, no alarm yet
    expect(alarmToSet(t0 + 5, t0 + 9)).toBeNull();
    expect(alarmToSet(t0 + 9, null)).toBeNull();
  });

  it('drops a blob whose upload is still running at 30 days, frees its quota and starts again at chunk 0', () => {
    const { state } = pairedState();
    for (let i = 0; i < 10; i++) state.putBlobChunk(partner, `b${i}`, MAX_BLOB_BYTES, 0, chunk(MAX_BLOB_BYTES, 0), t0);
    const end = t0 + RETENTION_MS;
    expect(state.putBlobChunk(partner, 'b0', MAX_BLOB_BYTES, 1, chunk(MAX_BLOB_BYTES, 1), end - 1).kind).toBe('stored');
    expect(state.putBlobChunk(partner, 'b0', MAX_BLOB_BYTES, 2, chunk(MAX_BLOB_BYTES, 2), end)).toEqual({
      kind: 'out_of_order',
      next: 0,
    });
    expect(state.pendingBlobBytes()).toBe(0);
  });

  it('hands out envelopes and blobs until the last millisecond before 30 days', () => {
    const { state } = pairedState();
    state.deposit(partner, bytes(3), t0);
    upload(state, blobA, 3, t0);
    const last = t0 + RETENTION_MS - 1;
    expect(pageOf(state.fetchEnvelopes(null, last)).envelopes.length).toBe(1);
    expect(state.getBlobChunk(blobA, 0, last).kind).toBe('chunk');
  });

  it('leaves nothing behind for an object whose inbox is gone', () => {
    const { state } = pairedState();
    state.deposit(partner, bytes(3), t0);
    upload(state, blobA, 3, t0);
    // Not reachable through the routes (DELETE takes all of it); the alarm path anyway.
    state['sql'].exec('DELETE FROM inbox');
    state['sql'].exec('DELETE FROM allowed_sender');
    expect(state.isEmpty(t0)).toBe(false);
    expect(state.cleanUp(t0 + RETENTION_MS)).toBeNull();
    expect(state.isEmpty(t0 + RETENTION_MS)).toBe(true);
  });
});
