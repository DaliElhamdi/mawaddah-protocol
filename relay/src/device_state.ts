// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// State kept for one device, in the Durable Object named by its inbox ID
// (which is derived from its signing key, so every key has exactly one):
// - the nonces of its recent signed requests (15 minutes);
// - its inbox registration: signing key, push token, platform;
// - the one sender key allowed to deposit into the inbox (after pairing);
// - the sealed envelopes waiting for the device, until it acknowledges them;
// - the encrypted blobs (attachments) waiting for it, until it deletes them.
// Envelopes and blobs are hard-deleted 30 days after they were stored, also
// when nobody fetched them (spec 4.5). Nothing else: no names, profile data or
// IP addresses.

import { NONCE_MEMORY_MS } from './auth';
import type { Sql } from './sql';

export type Platform = 'android' | 'ios';

export interface Registration {
  /** `IKsig`, base64url. */
  readonly signingKey: string;
  /** FCM token, or null when the phone has none yet. */
  readonly pushToken: string | null;
  readonly platform: Platform;
}

export type RegisterResult = 'created' | 'updated' | 'conflict';

export type AllowResult = 'allowed' | 'repeat' | 'conflict' | 'no_inbox';

export type DepositResult =
  | {
      readonly kind: 'stored';
      readonly cursor: number;
      /** The inbox's push token at the time of the deposit (for the wake-up), or null. */
      readonly pushToken: string | null;
    }
  | { readonly kind: 'no_inbox' | 'not_allowed' | 'full' };

export interface StoredEnvelope {
  /** Position in the inbox: increasing, never reused (`AUTOINCREMENT`). */
  readonly cursor: number;
  readonly body: Uint8Array;
}

export type FetchResult = EnvelopePage | 'no_inbox' | 'ahead';

export type PutChunkResult =
  | { readonly kind: 'stored' | 'repeat' }
  | { readonly kind: 'no_inbox' | 'not_allowed' | 'quota' | 'conflict' }
  /** Chunks go in order: [next] is the one the relay expects. */
  | { readonly kind: 'out_of_order'; readonly next: number };

export type GetChunkResult =
  | { readonly kind: 'chunk'; readonly size: number; readonly body: Uint8Array }
  | { readonly kind: 'no_inbox' | 'not_found' | 'incomplete' | 'no_chunk' };

export type DeleteBlobResult = 'deleted' | 'absent' | 'no_inbox' | 'not_allowed';

/** How many envelopes an ACK deleted, or why it was refused. */
export type AckResult = number | 'no_inbox' | 'ahead';

export interface EnvelopePage {
  readonly envelopes: readonly StoredEnvelope[];
  /** True when more envelopes wait after the last one of this page. */
  readonly more: boolean;
}

/** Largest accepted envelope (PROTOCOL.md section 7). */
export const MAX_ENVELOPE_BYTES = 65_536;

/** Most bytes of envelopes one inbox holds before deposits are refused (`inbox_full`). */
export const MAX_PENDING_BYTES = 100 * 1024 * 1024;

/** At most this many envelopes per fetched page... */
export const PAGE_MAX_ENVELOPES = 100;

/** ...and at most this many envelope bytes (a page always has at least one envelope). */
export const PAGE_MAX_BYTES = 1024 * 1024;

/** Envelopes and blobs are hard-deleted this long after they were stored (spec 4.5: 30 days). */
export const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/** A blob travels in chunks of this size (the last one shorter); a Durable Object SQLite value holds at most 2 MB. */
export const BLOB_CHUNK_BYTES = 1024 * 1024;

/** Largest accepted blob (spec 4.5: 10 MB), so at most 10 chunks. */
export const MAX_BLOB_BYTES = 10 * 1024 * 1024;

/** Most bytes of blobs one inbox holds, counted from each blob's first chunk (spec 4.5: 100 MB). */
export const MAX_PENDING_BLOB_BYTES = 100 * 1024 * 1024;

/**
 * The alarm to set when [current] is the object's alarm (null: none) and
 * [next] is when its first item expires (null: nothing will): [next] when it
 * comes earlier, otherwise null (keep the alarm as it is). An object has one
 * alarm; a later one is never set, so a nonce's 15 minutes are not pushed
 * back by a 30-day envelope, and an alarm that comes too early just sets the
 * next one when it runs.
 */
export function alarmToSet(current: number | null, next: number | null): number | null {
  if (next === null) return null;
  return current === null || current > next ? next : null;
}

/** How many chunks a blob of [size] bytes has. */
export function chunkCount(size: number): number {
  return Math.ceil(size / BLOB_CHUNK_BYTES);
}

/** The exact length of chunk [index] of a blob of [size] bytes (0 when there is no such chunk). */
export function chunkLength(size: number, index: number): number {
  return Math.max(0, Math.min(BLOB_CHUNK_BYTES, size - index * BLOB_CHUNK_BYTES));
}

export class DeviceState {
  constructor(private readonly sql: Sql) {
    sql.exec('CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL) WITHOUT ROWID');
    sql.exec(
      'CREATE TABLE IF NOT EXISTS inbox (' +
        'id INTEGER PRIMARY KEY CHECK (id = 1), ' +
        'signing_key TEXT NOT NULL, push_token TEXT, platform TEXT NOT NULL)',
    );
    sql.exec(
      'CREATE TABLE IF NOT EXISTS allowed_sender (id INTEGER PRIMARY KEY CHECK (id = 1), sender_key TEXT NOT NULL)',
    );
    // AUTOINCREMENT: a cursor is never handed out twice, even after every
    // envelope up to it was acknowledged and deleted (plain rowids restart
    // after the largest one is deleted, which would hide new envelopes from a
    // client that resumes after its stored cursor).
    // `body` is the last column: SQLite then reads `size` and `deposited_at`
    // without following the body's overflow pages (SUM, and the 30-day delete).
    sql.exec(
      'CREATE TABLE IF NOT EXISTS envelopes (' +
        'seq INTEGER PRIMARY KEY AUTOINCREMENT, size INTEGER NOT NULL, ' +
        'deposited_at INTEGER NOT NULL, body BLOB NOT NULL)',
    );
    // The 30-day delete and the next alarm look envelopes and blobs up by age.
    sql.exec('CREATE INDEX IF NOT EXISTS envelopes_by_age ON envelopes (deposited_at)');
    // One row per blob: its ID (chosen by the sender), its declared size, how
    // many chunks are stored so far and when the first one was. The chunks
    // are separate rows (a value holds at most 2 MB), body last as above.
    sql.exec(
      'CREATE TABLE IF NOT EXISTS blobs (' +
        'blob_id TEXT PRIMARY KEY, size INTEGER NOT NULL, chunks INTEGER NOT NULL, created_at INTEGER NOT NULL)',
    );
    sql.exec('CREATE INDEX IF NOT EXISTS blobs_by_age ON blobs (created_at)');
    sql.exec(
      'CREATE TABLE IF NOT EXISTS blob_chunks (' +
        'blob_id TEXT NOT NULL, idx INTEGER NOT NULL, body BLOB NOT NULL, PRIMARY KEY (blob_id, idx))',
    );
  }

  /**
   * Records [nonce] at [nowMs]. False when it was already used within the
   * nonce memory (a replay).
   */
  useNonce(nonce: string, nowMs: number): boolean {
    this.pruneNonces(nowMs);
    if (this.sql.exec('SELECT 1 AS hit FROM nonces WHERE nonce = ?', nonce).length > 0) return false;
    this.sql.exec('INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)', nonce, nowMs + NONCE_MEMORY_MS);
    return true;
  }

  /** Forgets expired nonces. Returns when the next one expires (ms), or null. */
  pruneNonces(nowMs: number): number | null {
    this.sql.exec('DELETE FROM nonces WHERE expires_at <= ?', nowMs);
    const next = this.sql.exec('SELECT MIN(expires_at) AS next FROM nonces')[0]?.next;
    return typeof next === 'number' ? next : null;
  }

  /**
   * Hard-deletes the envelopes and blobs stored 30 days ago or earlier
   * (spec 4.5), whether or not they were fetched.
   */
  expire(nowMs: number): void {
    const cutoff = nowMs - RETENTION_MS;
    this.sql.exec('DELETE FROM envelopes WHERE deposited_at <= ?', cutoff);
    this.sql.exec(
      'DELETE FROM blob_chunks WHERE blob_id IN (SELECT blob_id FROM blobs WHERE created_at <= ?)',
      cutoff,
    );
    this.sql.exec('DELETE FROM blobs WHERE created_at <= ?', cutoff);
  }

  /**
   * Deletes what has expired (nonces, and envelopes and blobs older than
   * 30 days). Returns when the next item expires (ms), or null when nothing
   * left will: the time for the object's alarm.
   */
  cleanUp(nowMs: number): number | null {
    this.expire(nowMs);
    const nonce = this.pruneNonces(nowMs);
    const envelope = this.sql.exec('SELECT MIN(deposited_at) AS t FROM envelopes')[0]?.t;
    const blob = this.sql.exec('SELECT MIN(created_at) AS t FROM blobs')[0]?.t;
    const times = [
      nonce,
      typeof envelope === 'number' ? envelope + RETENTION_MS : null,
      typeof blob === 'number' ? blob + RETENTION_MS : null,
    ].filter((t): t is number => t !== null);
    return times.length === 0 ? null : Math.min(...times);
  }

  registration(): Registration | null {
    const row = this.sql.exec('SELECT signing_key, push_token, platform FROM inbox WHERE id = 1')[0];
    if (row === undefined) return null;
    return {
      signingKey: row.signing_key as string,
      pushToken: row.push_token as string | null,
      platform: row.platform as Platform,
    };
  }

  /**
   * Registers the inbox, or updates the push token and platform when the same
   * key registers again (a retry after a lost answer). `conflict` means a
   * different key already owns this inbox ID; with 128-bit IDs derived from
   * the key this does not happen by chance.
   */
  register(registration: Registration): RegisterResult {
    const existing = this.registration();
    if (existing === null) {
      this.sql.exec(
        'INSERT INTO inbox (id, signing_key, push_token, platform) VALUES (1, ?, ?, ?)',
        registration.signingKey,
        registration.pushToken,
        registration.platform,
      );
      return 'created';
    }
    if (existing.signingKey !== registration.signingKey) return 'conflict';
    this.sql.exec(
      'UPDATE inbox SET push_token = ?, platform = ? WHERE id = 1',
      registration.pushToken,
      registration.platform,
    );
    return 'updated';
  }

  /**
   * Allows exactly one sender key to deposit into this inbox (spec 4.5). The
   * same key again is a `repeat` (a retry after a lost answer); any other key
   * is a `conflict`: the pair is fixed until the inbox is deleted.
   */
  allow(senderKey: string): AllowResult {
    if (this.registration() === null) return 'no_inbox';
    const existing = this.allowedSender();
    if (existing === null) {
      this.sql.exec('INSERT INTO allowed_sender (id, sender_key) VALUES (1, ?)', senderKey);
      return 'allowed';
    }
    return existing === senderKey ? 'repeat' : 'conflict';
  }

  allowedSender(): string | null {
    const row = this.sql.exec('SELECT sender_key FROM allowed_sender WHERE id = 1')[0];
    return row === undefined ? null : (row.sender_key as string);
  }

  /**
   * Stores one sealed envelope from [senderKey], which must be the allowed
   * sender. The relay does not look inside [body].
   */
  deposit(senderKey: string, body: Uint8Array, nowMs: number): DepositResult {
    this.expire(nowMs);
    const registration = this.registration();
    if (registration === null) return { kind: 'no_inbox' };
    if (this.allowedSender() !== senderKey) return { kind: 'not_allowed' };
    if (this.pendingBytes() + body.byteLength > MAX_PENDING_BYTES) return { kind: 'full' };
    const row = this.sql.exec(
      'INSERT INTO envelopes (size, deposited_at, body) VALUES (?, ?, ?) RETURNING seq',
      body.byteLength,
      nowMs,
      body,
    )[0];
    return { kind: 'stored', cursor: row?.seq as number, pushToken: registration.pushToken };
  }

  /** Total size of the envelopes waiting in this inbox. */
  pendingBytes(): number {
    const total = this.sql.exec('SELECT COALESCE(SUM(size), 0) AS total FROM envelopes')[0]?.total;
    return typeof total === 'number' ? total : 0;
  }

  /**
   * The highest cursor handed out in this inbox (0 before the first
   * deposit). AUTOINCREMENT keeps it in `sqlite_sequence`, also after the
   * envelopes were deleted.
   */
  lastCursor(): number {
    const seq = this.sql.exec("SELECT seq FROM sqlite_sequence WHERE name = 'envelopes'")[0]?.seq;
    return typeof seq === 'number' ? seq : 0;
  }

  /**
   * The envelopes after [after] (from the start when null), in deposit
   * order, at most `PAGE_MAX_ENVELOPES` and `PAGE_MAX_BYTES` (but always at
   * least one when any is waiting). `no_inbox` when there is no inbox;
   * `ahead` when [after] was never handed out (resuming there would skip
   * the envelopes deposited up to it). Envelopes 30 days old are deleted
   * first, so none is returned even when the alarm is late.
   */
  fetchEnvelopes(after: number | null, nowMs: number): FetchResult {
    this.expire(nowMs);
    if (this.registration() === null) return 'no_inbox';
    if (after !== null && after > this.lastCursor()) return 'ahead';
    // Sizes first, so only the bodies of the envelopes kept are read.
    const rows = this.sql.exec(
      'SELECT seq, size FROM envelopes WHERE seq > ? ORDER BY seq LIMIT ?',
      after ?? 0,
      PAGE_MAX_ENVELOPES + 1,
    );
    let kept = 0;
    let bytes = 0;
    for (const row of rows) {
      const size = row.size as number;
      if (kept === PAGE_MAX_ENVELOPES) break;
      if (kept > 0 && bytes + size > PAGE_MAX_BYTES) break;
      bytes += size;
      kept++;
    }
    const last = rows[kept - 1]?.seq;
    const envelopes: StoredEnvelope[] =
      last === undefined
        ? []
        : this.sql
            .exec('SELECT seq, body FROM envelopes WHERE seq > ? AND seq <= ? ORDER BY seq', after ?? 0, last)
            .map((row) => ({ cursor: row.seq as number, body: row.body as Uint8Array }));
    return { envelopes, more: rows.length > kept };
  }

  /**
   * Deletes every envelope up to and including [cursor] (the ACK is
   * cumulative, PROTOCOL.md section 17). Returns how many were deleted;
   * `no_inbox` when there is no inbox; `ahead` when [cursor] was never
   * handed out (it would delete envelopes the device has not seen).
   */
  ack(cursor: number): AckResult {
    if (this.registration() === null) return 'no_inbox';
    if (cursor > this.lastCursor()) return 'ahead';
    return this.sql.exec('DELETE FROM envelopes WHERE seq <= ? RETURNING seq', cursor).length;
  }

  /**
   * Stores chunk [index] of the blob [blobId] (declared [size] bytes) from
   * [senderKey], which must be the allowed sender. The caller has checked
   * that [size] is 1 to `MAX_BLOB_BYTES` and that [body] is exactly
   * `chunkLength(size, index)` bytes. Chunks go in order from 0; chunk 0
   * creates the blob and counts its whole size against the quota. Sending a
   * stored chunk again with the same bytes is a `repeat` (a retry after a
   * lost answer); different bytes or another size are a `conflict` (a blob
   * never changes).
   */
  putBlobChunk(
    senderKey: string,
    blobId: string,
    size: number,
    index: number,
    body: Uint8Array,
    nowMs: number,
  ): PutChunkResult {
    this.expire(nowMs);
    if (this.registration() === null) return { kind: 'no_inbox' };
    if (this.allowedSender() !== senderKey) return { kind: 'not_allowed' };
    const blob = this.sql.exec('SELECT size, chunks FROM blobs WHERE blob_id = ?', blobId)[0];
    if (blob === undefined) {
      if (index !== 0) return { kind: 'out_of_order', next: 0 };
      if (this.pendingBlobBytes() + size > MAX_PENDING_BLOB_BYTES) return { kind: 'quota' };
      this.sql.exec(
        'INSERT INTO blobs (blob_id, size, chunks, created_at) VALUES (?, ?, 1, ?)',
        blobId,
        size,
        nowMs,
      );
      this.sql.exec('INSERT INTO blob_chunks (blob_id, idx, body) VALUES (?, 0, ?)', blobId, body);
      return { kind: 'stored' };
    }
    if (blob.size !== size) return { kind: 'conflict' };
    const stored = blob.chunks as number;
    if (index < stored) {
      const old = this.sql.exec('SELECT body FROM blob_chunks WHERE blob_id = ? AND idx = ?', blobId, index)[0]
        ?.body as Uint8Array;
      return { kind: sameBytes(old, body) ? 'repeat' : 'conflict' };
    }
    if (index > stored) return { kind: 'out_of_order', next: stored };
    this.sql.exec('INSERT INTO blob_chunks (blob_id, idx, body) VALUES (?, ?, ?)', blobId, index, body);
    this.sql.exec('UPDATE blobs SET chunks = ? WHERE blob_id = ?', stored + 1, blobId);
    return { kind: 'stored' };
  }

  /** Total declared size of the blobs in this inbox, complete or not. */
  pendingBlobBytes(): number {
    const total = this.sql.exec('SELECT COALESCE(SUM(size), 0) AS total FROM blobs')[0]?.total;
    return typeof total === 'number' ? total : 0;
  }

  /**
   * Chunk [index] of the blob [blobId], once every chunk is stored
   * (`incomplete` before). `no_chunk` when the blob has no chunk [index].
   */
  getBlobChunk(blobId: string, index: number, nowMs: number): GetChunkResult {
    this.expire(nowMs);
    if (this.registration() === null) return { kind: 'no_inbox' };
    const blob = this.sql.exec('SELECT size, chunks FROM blobs WHERE blob_id = ?', blobId)[0];
    if (blob === undefined) return { kind: 'not_found' };
    const size = blob.size as number;
    if ((blob.chunks as number) < chunkCount(size)) return { kind: 'incomplete' };
    if (index >= chunkCount(size)) return { kind: 'no_chunk' };
    const row = this.sql.exec('SELECT body FROM blob_chunks WHERE blob_id = ? AND idx = ?', blobId, index)[0];
    return { kind: 'chunk', size, body: row?.body as Uint8Array };
  }

  /**
   * Deletes the blob [blobId] and its chunks: by the owner once it has the
   * file (the blob's ACK), or by the allowed sender (an upload it gave up).
   * [senderKey] is null for the owner. `absent` when there was no such blob
   * (a retry after a lost answer).
   */
  deleteBlob(blobId: string, senderKey: string | null): DeleteBlobResult {
    if (this.registration() === null) return 'no_inbox';
    if (senderKey !== null && this.allowedSender() !== senderKey) return 'not_allowed';
    this.sql.exec('DELETE FROM blob_chunks WHERE blob_id = ?', blobId);
    return this.sql.exec('DELETE FROM blobs WHERE blob_id = ? RETURNING blob_id', blobId).length > 0
      ? 'deleted'
      : 'absent';
  }

  /** Replaces the push token. False when there is no inbox. */
  setPushToken(pushToken: string | null): boolean {
    if (this.registration() === null) return false;
    this.sql.exec('UPDATE inbox SET push_token = ? WHERE id = 1', pushToken);
    return true;
  }

  /**
   * Forgets the push token [pushToken] after FCM called it unregistered. A
   * token the device has replaced since that wake-up was sent is kept.
   * True when it was removed.
   */
  clearPushToken(pushToken: string): boolean {
    const cleared = this.sql.exec(
      'UPDATE inbox SET push_token = NULL WHERE id = 1 AND push_token = ? RETURNING id',
      pushToken,
    );
    return cleared.length === 1;
  }

  /**
   * Deletes the inbox, its allowed sender, its envelopes, its blobs and the
   * count of cursors handed out (spec 4.5). The nonces stay
   * until they expire, so a request captured before the delete cannot be
   * replayed to recreate the inbox.
   */
  deleteInbox(): void {
    this.sql.exec('DELETE FROM envelopes');
    this.sql.exec('DELETE FROM blob_chunks');
    this.sql.exec('DELETE FROM blobs');
    this.sql.exec("DELETE FROM sqlite_sequence WHERE name = 'envelopes'");
    this.sql.exec('DELETE FROM allowed_sender');
    this.sql.exec('DELETE FROM inbox');
  }

  /** True when nothing is stored: no registration, envelope, blob, allowed sender or live nonce. */
  isEmpty(nowMs: number): boolean {
    return (
      this.pruneNonces(nowMs) === null &&
      this.registration() === null &&
      this.allowedSender() === null &&
      this.sql.exec('SELECT 1 AS hit FROM envelopes LIMIT 1').length === 0 &&
      this.sql.exec('SELECT 1 AS hit FROM blobs LIMIT 1').length === 0
    );
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}
