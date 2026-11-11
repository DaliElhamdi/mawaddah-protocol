// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// State kept for one device, in the Durable Object named by its inbox ID
// (which is derived from its signing key, so every key has exactly one):
// - the nonces of its recent signed requests (15 minutes);
// - its inbox registration: signing key, push token, platform. Nothing else:
//   no names, profile data or IP addresses.
// Envelopes and the allow-list (#21) and blobs (#22) are added later.

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

export class DeviceState {
  constructor(private readonly sql: Sql) {
    sql.exec('CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL) WITHOUT ROWID');
    sql.exec(
      'CREATE TABLE IF NOT EXISTS inbox (' +
        'id INTEGER PRIMARY KEY CHECK (id = 1), ' +
        'signing_key TEXT NOT NULL, push_token TEXT, platform TEXT NOT NULL)',
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

  /** True when nothing is stored: no registration and no live nonce. */
  isEmpty(nowMs: number): boolean {
    return this.pruneNonces(nowMs) === null && this.registration() === null;
  }
}
