// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Inbox registrations per IP (spec 4.5: 5 per IP per hour). One Durable
// Object per IP bucket, named by a hash of the bucket. It stores only the
// times of accepted registrations; when the last one is an hour old the
// object deletes all its storage (an alarm does it), so nothing about an IP
// is kept longer than one hour.

import { sha256, toHex } from './encoding';
import type { Sql } from './sql';

export const REGISTRATION_LIMIT = 5;
export const REGISTRATION_WINDOW_MS = 60 * 60 * 1000;

export type RateLimitResult =
  | { readonly allowed: true; readonly clearAt: number }
  | { readonly allowed: false; readonly retryAfterSeconds: number };

export class RegistrationCounter {
  constructor(private readonly sql: Sql) {
    sql.exec('CREATE TABLE IF NOT EXISTS hits (at INTEGER NOT NULL)');
  }

  /**
   * Counts one registration at [nowMs] if the bucket is under the limit.
   * A refused attempt is not counted, so it does not extend the wait.
   * `clearAt` is when every stored time will have expired.
   */
  hit(nowMs: number): RateLimitResult {
    this.prune(nowMs);
    const rows = this.sql.exec('SELECT COUNT(*) AS n, MIN(at) AS oldest FROM hits')[0];
    const count = Number(rows?.n ?? 0);
    if (count >= REGISTRATION_LIMIT) {
      const oldest = Number(rows?.oldest);
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((oldest + REGISTRATION_WINDOW_MS - nowMs) / 1000)) };
    }
    this.sql.exec('INSERT INTO hits (at) VALUES (?)', nowMs);
    return { allowed: true, clearAt: this.clearAt() ?? nowMs + REGISTRATION_WINDOW_MS };
  }

  /** Drops expired times. Returns when the rest expire (ms), or null if none is left. */
  prune(nowMs: number): number | null {
    this.sql.exec('DELETE FROM hits WHERE at <= ?', nowMs - REGISTRATION_WINDOW_MS);
    return this.clearAt();
  }

  private clearAt(): number | null {
    const latest = this.sql.exec('SELECT MAX(at) AS latest FROM hits')[0]?.latest;
    return typeof latest === 'number' ? latest + REGISTRATION_WINDOW_MS : null;
  }
}

/**
 * The rate-limit bucket of a client address: the whole IPv4 address, or the
 * /64 prefix of an IPv6 address (one home or phone network usually gets a
 * whole /64, so counting single IPv6 addresses would be easy to dodge).
 * An IPv4-mapped IPv6 address counts as its IPv4 address. A missing or
 * unreadable address shares one bucket.
 */
export function ipBucket(address: string | null): string {
  if (address === null) return 'unknown';
  const a = address.trim().toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) return `v4:${a}`;
  const groups = expandIpv6(a);
  if (groups === null) return 'unknown';
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const [hi, lo] = [groups[6] ?? 0, groups[7] ?? 0];
    return `v4:${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  }
  return `v6:${groups
    .slice(0, 4)
    .map((g) => g.toString(16))
    .join(':')}::/64`;
}

/** The eight 16-bit groups of an IPv6 address, or null if it is not one. */
function expandIpv6(address: string): number[] | null {
  let text = address;
  // A dotted IPv4 tail (`::ffff:1.2.3.4`) stands for the last two groups.
  const v4 = /:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4 !== null) {
    const [a, b, c, d] = v4.slice(1).map(Number) as [number, number, number, number];
    if ([a, b, c, d].some((p) => p > 255)) return null;
    text = `${text.slice(0, v4.index)}:${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parse = (s: string): number[] | null => {
    if (s === '') return [];
    const out: number[] = [];
    for (const g of s.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parse(halves[0] ?? '');
  const rest = halves.length === 2 ? parse(halves[1] ?? '') : [];
  if (head === null || rest === null) return null;
  const known = head.length + rest.length;
  if (halves.length === 2) {
    if (known > 7) return null;
    return [...head, ...new Array<number>(8 - known).fill(0), ...rest];
  }
  return known === 8 ? head : null;
}

/** The Durable Object name of a bucket: a hash, so the raw address is not used as a name. */
export async function bucketObjectName(bucket: string): Promise<string> {
  return toHex(await sha256(new TextEncoder().encode(`mawaddah/v1/rate-limit\n${bucket}`)));
}
