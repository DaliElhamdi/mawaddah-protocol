// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from 'vitest';
import { bucketObjectName, ipBucket, REGISTRATION_LIMIT, REGISTRATION_WINDOW_MS, RegistrationCounter } from '../src/rate_limit';
import { memorySql } from './support/sqlite';

const t0 = 1762862400000;
const minute = 60 * 1000;

let close: () => void = () => {};
function counter(): { c: RegistrationCounter; rows: () => unknown[] } {
  const sql = memorySql();
  close = sql.close;
  return { c: new RegistrationCounter(sql), rows: () => sql.exec('SELECT at FROM hits ORDER BY at') };
}
afterEach(() => close());

describe('RegistrationCounter', () => {
  it('allows 5 registrations per hour, then says when to retry', () => {
    const { c } = counter();
    expect(REGISTRATION_LIMIT).toBe(5);
    for (let i = 0; i < 5; i++) {
      expect(c.hit(t0 + i * minute)).toEqual({ allowed: true, clearAt: t0 + i * minute + REGISTRATION_WINDOW_MS });
    }
    expect(c.hit(t0 + 10 * minute)).toEqual({ allowed: false, retryAfterSeconds: 50 * 60 });
    expect(c.hit(t0 + REGISTRATION_WINDOW_MS - 1)).toEqual({ allowed: false, retryAfterSeconds: 1 });
  });

  it('does not count refused attempts, and the window slides', () => {
    const { c, rows } = counter();
    for (let i = 0; i < 5; i++) c.hit(t0 + i * minute);
    for (let i = 0; i < 20; i++) c.hit(t0 + 30 * minute);
    expect(rows()).toHaveLength(5);
    // The first one expires exactly an hour later: one place frees up.
    expect(c.hit(t0 + REGISTRATION_WINDOW_MS).allowed).toBe(true);
    expect(c.hit(t0 + REGISTRATION_WINDOW_MS).allowed).toBe(false);
    expect(c.hit(t0 + REGISTRATION_WINDOW_MS + minute).allowed).toBe(true);
  });

  it('keeps nothing once the last registration is an hour old', () => {
    const { c, rows } = counter();
    c.hit(t0);
    c.hit(t0 + 5 * minute);
    expect(c.prune(t0 + REGISTRATION_WINDOW_MS)).toBe(t0 + 5 * minute + REGISTRATION_WINDOW_MS);
    expect(c.prune(t0 + 5 * minute + REGISTRATION_WINDOW_MS)).toBeNull();
    expect(rows()).toEqual([]);
  });
});

describe('ipBucket', () => {
  it('uses the whole IPv4 address', () => {
    expect(ipBucket('203.0.113.7')).toBe('v4:203.0.113.7');
    expect(ipBucket(' 203.0.113.7 ')).toBe('v4:203.0.113.7');
  });
  it('uses the /64 prefix of an IPv6 address, however it is written', () => {
    const a = ipBucket('2001:db8:1:2:aaaa:bbbb:cccc:dddd');
    expect(a).toBe('v6:2001:db8:1:2::/64');
    expect(ipBucket('2001:0DB8:0001:0002::1')).toBe(a);
    expect(ipBucket('2001:db8:1:2::')).toBe(a);
    expect(ipBucket('2001:db8:1:3::1')).not.toBe(a);
    expect(ipBucket('::1')).toBe('v6:0:0:0:0::/64');
    expect(ipBucket('2001:db8::')).toBe('v6:2001:db8:0:0::/64');
  });
  it('treats an IPv4-mapped IPv6 address as IPv4', () => {
    expect(ipBucket('::ffff:203.0.113.7')).toBe('v4:203.0.113.7');
    expect(ipBucket('::ffff:cb00:7107')).toBe('v4:203.0.113.7');
  });
  it('puts a missing or unreadable address in one shared bucket', () => {
    for (const bad of [
      null,
      '',
      'relay.test',
      '999.1.1.1',
      '203.0.113.07',
      '1.2.3',
      '1.2.3.4.5',
      '1:2:3:4:5:6:7:8:9',
      '1::2::3',
      '::ffff:300.1.1.1',
      '12345::',
      'fe80::1%eth0',
    ]) {
      expect(ipBucket(bad), String(bad)).toBe('unknown');
    }
  });
  it('names the object by a hash, not by the address', async () => {
    const name = await bucketObjectName('v4:203.0.113.7');
    expect(name).toMatch(/^[0-9a-f]{64}$/);
    expect(name).not.toContain('203');
    expect(await bucketObjectName('v4:203.0.113.8')).not.toBe(name);
  });
});
