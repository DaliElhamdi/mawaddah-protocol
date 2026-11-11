// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from 'vitest';
import { NONCE_MEMORY_MS } from '../src/auth';
import { DeviceState, type Registration } from '../src/device_state';
import { memorySql } from './support/sqlite';

const t0 = 1762862400000;
const reg: Registration = { signingKey: 'k'.repeat(43), pushToken: 'token-1', platform: 'android' };

let close: () => void = () => {};
function fresh(): { state: DeviceState; rows: (q: string) => unknown[] } {
  const sql = memorySql();
  close = sql.close;
  return { state: new DeviceState(sql), rows: (q) => sql.exec(q) };
}
afterEach(() => close());

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
