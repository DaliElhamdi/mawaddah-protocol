// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from 'vitest';
import { NONCE_MEMORY_MS } from '../src/auth';
import {
  DeviceState,
  MAX_ENVELOPE_BYTES,
  MAX_PENDING_BYTES,
  PAGE_MAX_BYTES,
  PAGE_MAX_ENVELOPES,
  type Registration,
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
    expect(state.fetchEnvelopes(null)).toBeNull();
    expect(state.ack(1)).toBeNull();
    expect(state.setPushToken('t')).toBe(false);
  });

  it('returns envelopes in deposit order, after the cursor, byte for byte', () => {
    const { state } = registered();
    state.allow(partner);
    const bodies = [bytes(3, 1), bytes(5, 2), bytes(1, 3)];
    const cursors = bodies.map((b) => state.deposit(partner, b, t0));
    expect(cursors).toEqual([1, 2, 3].map((c) => ({ kind: 'stored', cursor: c })));
    expect(state.fetchEnvelopes(null)).toEqual({
      envelopes: bodies.map((body, i) => ({ cursor: i + 1, body })),
      more: false,
    });
    expect(state.fetchEnvelopes(1)?.envelopes.map((e) => e.cursor)).toEqual([2, 3]);
    expect(state.fetchEnvelopes(3)).toEqual({ envelopes: [], more: false });
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
    const first = state.fetchEnvelopes(null);
    expect(first?.envelopes.length).toBe(PAGE_MAX_ENVELOPES);
    expect(first?.more).toBe(true);
    expect(state.fetchEnvelopes(PAGE_MAX_ENVELOPES)).toEqual({
      envelopes: [{ cursor: PAGE_MAX_ENVELOPES + 1, body: bytes(1) }],
      more: false,
    });

    const big = registered().state;
    big.allow(partner);
    const per = Math.floor(PAGE_MAX_BYTES / MAX_ENVELOPE_BYTES); // 16 full envelopes fill a page exactly
    for (let i = 0; i < per + 1; i++) big.deposit(partner, bytes(MAX_ENVELOPE_BYTES), t0);
    const page = big.fetchEnvelopes(null);
    expect(page?.envelopes.length).toBe(per);
    expect(page?.more).toBe(true);
    expect(big.fetchEnvelopes(per)?.envelopes.length).toBe(1);
  });

  it('ACK deletes every envelope up to and including the cursor', () => {
    const { state, rows } = registered();
    state.allow(partner);
    for (let i = 0; i < 5; i++) state.deposit(partner, bytes(2), t0);
    expect(state.ack(3)).toBe(3);
    expect(rows('SELECT seq FROM envelopes')).toEqual([{ seq: 4 }, { seq: 5 }]);
    expect(state.ack(3)).toBe(0);
    expect(state.ack(99)).toBe(2);
    expect(rows('SELECT seq FROM envelopes')).toEqual([]);
  });

  it('never hands out a cursor twice, also after everything was acknowledged', () => {
    const { state } = registered();
    state.allow(partner);
    state.deposit(partner, bytes(1), t0);
    state.deposit(partner, bytes(1), t0);
    state.ack(2);
    expect(state.deposit(partner, bytes(1, 5), t0)).toEqual({ kind: 'stored', cursor: 3 });
    expect(state.fetchEnvelopes(2)?.envelopes).toEqual([{ cursor: 3, body: bytes(1, 5) }]);
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

  it('deletes the inbox, the allowed sender and the envelopes, and keeps the nonces', () => {
    const { state, rows } = registered();
    state.useNonce('n1', t0);
    state.allow(partner);
    state.deposit(partner, bytes(3), t0);
    state.deleteInbox();
    expect(rows('SELECT * FROM inbox')).toEqual([]);
    expect(rows('SELECT * FROM allowed_sender')).toEqual([]);
    expect(rows('SELECT * FROM envelopes')).toEqual([]);
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
    state['sql'].exec('DELETE FROM envelopes');
    expect(state.isEmpty(t0)).toBe(false);
    state['sql'].exec('DELETE FROM allowed_sender');
    expect(state.isEmpty(t0)).toBe(true);
  });
});
