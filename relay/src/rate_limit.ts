// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Per-IP limits (spec 4.5), one Durable Object per IP bucket, named by a
// hash of the bucket:
// - inbox registrations: 5 per IP per hour;
// - failed pairing-code lookups: 5 per IP per 10 minutes.
// Each object stores only the times of counted events; when the last one has
// left the window the object deletes all its storage (an alarm does it), so
// nothing about an IP is kept longer than its window.

import { sha256, toHex } from './encoding';
import type { Sql } from './sql';

export const REGISTRATION_LIMIT = 5;
export const REGISTRATION_WINDOW_MS = 60 * 60 * 1000;

export const LOOKUP_FAILURE_LIMIT = 5;
export const LOOKUP_FAILURE_WINDOW_MS = 10 * 60 * 1000;

export type RateLimitResult =
  | { readonly allowed: true; readonly clearAt: number }
  | { readonly allowed: false; readonly retryAfterSeconds: number };

/** At most [limit] counted events in any sliding window of [windowMs]. */
export class WindowCounter {
  constructor(
    private readonly sql: Sql,
    readonly limit: number,
    readonly windowMs: number,
  ) {
    sql.exec('CREATE TABLE IF NOT EXISTS hits (at INTEGER NOT NULL)');
  }

  /**
   * Whether one more event at [nowMs] is under the limit, without counting it.
   * When allowed, `clearAt` is when the stored times expire (now, if none).
   */
  check(nowMs: number): RateLimitResult {
    this.prune(nowMs);
    const rows = this.sql.exec('SELECT COUNT(*) AS n, MIN(at) AS oldest FROM hits')[0];
    const count = Number(rows?.n ?? 0);
    if (count >= this.limit) {
      const oldest = Number(rows?.oldest);
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((oldest + this.windowMs - nowMs) / 1000)) };
    }
    return { allowed: true, clearAt: this.clearAt() ?? nowMs };
  }

  /**
   * Counts one event at [nowMs] if the bucket is under the limit. A refused
   * attempt is not counted, so it does not extend the wait. `clearAt` is when
   * every stored time will have expired.
   */
  hit(nowMs: number): RateLimitResult {
    const result = this.check(nowMs);
    if (!result.allowed) return result;
    this.sql.exec('INSERT INTO hits (at) VALUES (?)', nowMs);
    return { allowed: true, clearAt: this.clearAt() ?? nowMs + this.windowMs };
  }

  /** Drops expired times. Returns when the rest expire (ms), or null if none is left. */
  prune(nowMs: number): number | null {
    this.sql.exec('DELETE FROM hits WHERE at <= ?', nowMs - this.windowMs);
    return this.clearAt();
  }

  private clearAt(): number | null {
    const latest = this.sql.exec('SELECT MAX(at) AS latest FROM hits')[0]?.latest;
    return typeof latest === 'number' ? latest + this.windowMs : null;
  }
}

/** New inboxes from one IP bucket: 5 per sliding hour. */
export class RegistrationCounter extends WindowCounter {
  constructor(sql: Sql) {
    super(sql, REGISTRATION_LIMIT, REGISTRATION_WINDOW_MS);
  }
}

/** Failed pairing-code lookups from one IP bucket: 5 per sliding 10 minutes. */
export class LookupFailureCounter extends WindowCounter {
  constructor(sql: Sql) {
    super(sql, LOOKUP_FAILURE_LIMIT, LOOKUP_FAILURE_WINDOW_MS);
  }
}

/**
 * The rate-limit bucket of a client address: the whole IPv4 address, or the
 * /64 prefix of an IPv6 address (one home or phone network usually gets a
 * whole /64, so counting single IPv6 addresses would be easy to dodge).
 * An IPv4-mapped IPv6 address counts as its IPv4 address (NAT64 and 6to4
 * addresses are not folded). A missing or unreadable address, including one
 * with a zone (`fe80::1%eth0`), shares the one bucket `unknown`: this fails
 * closed. Behind Cloudflare `cf-connecting-ip` is always set.
 */
export function ipBucket(address: string | null): string {
  if (address === null) return 'unknown';
  const a = address.trim().toLowerCase();
  if (a.includes('.') && !a.includes(':')) return isIpv4(a) ? `v4:${a}` : 'unknown';
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

/** A dotted IPv4 address in its one canonical spelling (no leading zeros, each part at most 255). */
function isIpv4(text: string): boolean {
  const parts = text.split('.');
  return parts.length === 4 && parts.every((p) => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255);
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
