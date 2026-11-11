// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// State kept for one device, in the Durable Object named by its inbox ID
// (which is derived from its signing key, so every key has exactly one):
// - the nonces of its recent signed requests (15 minutes);
// - its inbox registration: signing key, push token, platform;
// - the one sender key allowed to deposit into the inbox (after pairing);
// - the sealed envelopes waiting for the device, until it acknowledges them.
// Nothing else: no names, profile data or IP addresses. Blobs come with #22.

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
  | { readonly kind: 'stored'; readonly cursor: number }
  | { readonly kind: 'no_inbox' | 'not_allowed' | 'full' };

export interface StoredEnvelope {
  /** Position in the inbox: increasing, never reused (`AUTOINCREMENT`). */
  readonly cursor: number;
  readonly body: Uint8Array;
}

export type FetchResult = EnvelopePage | 'no_inbox' | 'ahead';

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
    if (this.registration() === null) return { kind: 'no_inbox' };
    if (this.allowedSender() !== senderKey) return { kind: 'not_allowed' };
    if (this.pendingBytes() + body.byteLength > MAX_PENDING_BYTES) return { kind: 'full' };
    const row = this.sql.exec(
      'INSERT INTO envelopes (size, deposited_at, body) VALUES (?, ?, ?) RETURNING seq',
      body.byteLength,
      nowMs,
      body,
    )[0];
    return { kind: 'stored', cursor: row?.seq as number };
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
   * the envelopes deposited up to it).
   */
  fetchEnvelopes(after: number | null): FetchResult {
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

  /** Replaces the push token. False when there is no inbox. */
  setPushToken(pushToken: string | null): boolean {
    if (this.registration() === null) return false;
    this.sql.exec('UPDATE inbox SET push_token = ? WHERE id = 1', pushToken);
    return true;
  }

  /**
   * Deletes the inbox, its allowed sender, its envelopes and the count of
   * cursors handed out (spec 4.5; blobs come with #22). The nonces stay
   * until they expire, so a request captured before the delete cannot be
   * replayed to recreate the inbox.
   */
  deleteInbox(): void {
    this.sql.exec('DELETE FROM envelopes');
    this.sql.exec("DELETE FROM sqlite_sequence WHERE name = 'envelopes'");
    this.sql.exec('DELETE FROM allowed_sender');
    this.sql.exec('DELETE FROM inbox');
  }

  /** True when nothing is stored: no registration, no envelope, no allowed sender and no live nonce. */
  isEmpty(nowMs: number): boolean {
    return (
      this.pruneNonces(nowMs) === null &&
      this.registration() === null &&
      this.allowedSender() === null &&
      this.sql.exec('SELECT 1 AS hit FROM envelopes LIMIT 1').length === 0
    );
  }
}
