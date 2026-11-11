// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Pairing slots (spec 4.5, PROTOCOL.md section 4.5). All live slots are kept
// in one Durable Object, so a 6-digit code is unique among them by a UNIQUE
// index. A slot holds only public keys: the initiator's bundle, and later the
// joiner's reply. Its life:
//
//   open --reply--> replied --initiator reads the reply--> closed --10 min--> gone
//
// Reading the reply erases the bundle and the reply at once. The closed row
// keeps the slot ID, the code and the two signing keys until the slot's
// 10 minutes are over, so a late lookup or a second reply gets "used" instead
// of "not found", and a code is never handed out again while someone may
// still type it. An expired row is deleted whole and is never served.

import { toBase64Url } from './encoding';
import type { Sql } from './sql';

/** Slot lifetime (PROTOCOL.md section 14). */
export const SLOT_LIFETIME_MS = 10 * 60 * 1000;

/**
 * Most slots alive at once: 10% of the 10^6 codes. Guessing a code then hits
 * a live slot at most once in 10 tries, and a random new code is free at
 * least 9 times in 10.
 */
export const MAX_LIVE_SLOTS = 100_000;

/** Random codes tried before giving up (each is free with probability >= 0.9). */
const CODE_ATTEMPTS = 32;

const CODE_SPACE = 1_000_000;
/** Largest multiple of 10^6 below 2^32: draws at or above it are redrawn (no modulo bias). */
const CODE_DRAW_LIMIT = Math.floor(0x1_0000_0000 / CODE_SPACE) * CODE_SPACE;

export type RandomBytes = (length: number) => Uint8Array;

export const secureRandomBytes: RandomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));

export interface SlotCreated {
  readonly slotId: string;
  readonly code: string;
  /** Unix milliseconds. */
  readonly expiresAt: number;
}

export type CreateResult =
  | ({ readonly kind: 'created' | 'repeat' } & SlotCreated)
  /** This key already has a slot with another bundle (or one already used). */
  | { readonly kind: 'conflict' }
  /** [MAX_LIVE_SLOTS] reached, or no free code found. */
  | { readonly kind: 'full' };

export type LookupResult =
  | { readonly kind: 'found'; readonly slotId: string; readonly bundle: string }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'used' };

export type ReplyResult = { readonly kind: 'accepted' | 'repeat' | 'not_found' | 'used' };

export type ReadReplyResult =
  | { readonly kind: 'reply'; readonly reply: string }
  | { readonly kind: 'waiting' }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'used' };

type SlotState = 'open' | 'replied' | 'closed';

interface SlotRow {
  readonly slotId: string;
  readonly code: string;
  readonly creator: string;
  readonly bundle: string | null;
  readonly replier: string | null;
  readonly reply: string | null;
  readonly state: SlotState;
  readonly expiresAt: number;
}

export class PairingSlots {
  constructor(
    private readonly sql: Sql,
    private readonly random: RandomBytes = secureRandomBytes,
    private readonly maxLiveSlots: number = MAX_LIVE_SLOTS,
  ) {
    sql.exec(
      'CREATE TABLE IF NOT EXISTS slots (' +
        'slot_id TEXT PRIMARY KEY, ' +
        'code TEXT NOT NULL UNIQUE, ' +
        'creator TEXT NOT NULL UNIQUE, ' +
        'bundle TEXT, replier TEXT, reply TEXT, ' +
        "state TEXT NOT NULL CHECK (state IN ('open', 'replied', 'closed')), " +
        'expires_at INTEGER NOT NULL) WITHOUT ROWID',
    );
    sql.exec('CREATE INDEX IF NOT EXISTS slots_expiry ON slots (expires_at)');
  }

  /**
   * Opens a slot for [creator] (the initiator's signing key, base64url) with
   * the canonical bundle JSON [bundle]. One slot per key: the same key with
   * the same bundle gets its slot again (a retry after a lost answer).
   */
  create(creator: string, bundle: string, nowMs: number): CreateResult {
    this.prune(nowMs);
    const existing = this.rowWhere('creator = ?', creator);
    if (existing !== null) {
      if (existing.state === 'open' && existing.bundle === bundle) {
        return { kind: 'repeat', slotId: existing.slotId, code: existing.code, expiresAt: existing.expiresAt };
      }
      return { kind: 'conflict' };
    }
    if (this.count() >= this.maxLiveSlots) return { kind: 'full' };
    for (let i = 0; i < CODE_ATTEMPTS; i++) {
      const code = this.randomCode();
      if (code === null || this.rowWhere('code = ?', code) !== null) continue;
      const slotId = toBase64Url(this.random(16));
      if (this.rowWhere('slot_id = ?', slotId) !== null) continue; // 128-bit IDs: not by chance
      const expiresAt = nowMs + SLOT_LIFETIME_MS;
      this.sql.exec(
        "INSERT INTO slots (slot_id, code, creator, bundle, state, expires_at) VALUES (?, ?, ?, ?, 'open', ?)",
        slotId,
        code,
        creator,
        bundle,
        expiresAt,
      );
      return { kind: 'created', slotId, code, expiresAt };
    }
    return { kind: 'full' };
  }

  /** The bundle of the slot with this ID or code, while nobody has replied. */
  lookup(handle: { readonly slotId: string } | { readonly code: string }, nowMs: number): LookupResult {
    this.prune(nowMs);
    const row = 'slotId' in handle ? this.rowWhere('slot_id = ?', handle.slotId) : this.rowWhere('code = ?', handle.code);
    if (row === null) return { kind: 'not_found' };
    if (row.state !== 'open' || row.bundle === null) return { kind: 'used' };
    return { kind: 'found', slotId: row.slotId, bundle: row.bundle };
  }

  /**
   * Stores the joiner's reply. The first reply wins (PROTOCOL.md section 4.5);
   * the same joiner sending the same reply again gets `repeat`.
   */
  reply(slotId: string, replier: string, reply: string, nowMs: number): ReplyResult {
    this.prune(nowMs);
    const row = this.rowWhere('slot_id = ?', slotId);
    if (row === null) return { kind: 'not_found' };
    if (row.state === 'open') {
      this.sql.exec("UPDATE slots SET replier = ?, reply = ?, state = 'replied' WHERE slot_id = ?", replier, reply, slotId);
      return { kind: 'accepted' };
    }
    if (row.replier !== replier) return { kind: 'used' };
    // The same joiner again: once the reply was read it is erased, so only the key can be compared.
    if (row.state === 'closed' || row.reply === reply) return { kind: 'repeat' };
    return { kind: 'used' };
  }

  /**
   * The reply, for the slot's creator only. Reading it closes the slot and
   * erases the bundle and the reply. Another key gets `not_found`, so it
   * learns nothing about the slot.
   */
  readReply(slotId: string, creator: string, nowMs: number): ReadReplyResult {
    this.prune(nowMs);
    const row = this.rowWhere('slot_id = ?', slotId);
    if (row === null || row.creator !== creator) return { kind: 'not_found' };
    if (row.state === 'open') return { kind: 'waiting' };
    if (row.state === 'closed' || row.reply === null) return { kind: 'used' };
    this.sql.exec("UPDATE slots SET bundle = NULL, reply = NULL, state = 'closed' WHERE slot_id = ?", slotId);
    return { kind: 'reply', reply: row.reply };
  }

  /** Deletes expired slots. Returns when the next one expires (ms), or null if none is left. */
  prune(nowMs: number): number | null {
    this.sql.exec('DELETE FROM slots WHERE expires_at <= ?', nowMs);
    const next = this.sql.exec('SELECT MIN(expires_at) AS next FROM slots')[0]?.next;
    return typeof next === 'number' ? next : null;
  }

  /** Number of slots stored (live ones, after a prune). */
  count(): number {
    return Number(this.sql.exec('SELECT COUNT(*) AS n FROM slots')[0]?.n ?? 0);
  }

  /**
   * A uniformly random 6-digit code, leading zeros kept. A draw is redrawn
   * with probability below 0.1%; null after 8 redraws in a row (never with a
   * working random source).
   */
  private randomCode(): string | null {
    for (let i = 0; i < 8; i++) {
      const bytes = this.random(4);
      const draw = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0);
      if (draw < CODE_DRAW_LIMIT) return String(draw % CODE_SPACE).padStart(6, '0');
    }
    return null;
  }

  private rowWhere(condition: string, value: string): SlotRow | null {
    const row = this.sql.exec(
      `SELECT slot_id, code, creator, bundle, replier, reply, state, expires_at FROM slots WHERE ${condition}`,
      value,
    )[0];
    if (row === undefined) return null;
    return {
      slotId: row.slot_id as string,
      code: row.code as string,
      creator: row.creator as string,
      bundle: row.bundle as string | null,
      replier: row.replier as string | null,
      reply: row.reply as string | null,
      state: row.state as SlotState,
      expiresAt: row.expires_at as number,
    };
  }
}
