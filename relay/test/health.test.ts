// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { handleRequest, type RelayDeps } from '../src/handler';

const noState: RelayDeps = {
  device: () => {
    throw new Error('not used');
  },
  registrationLimiter: () => {
    throw new Error('not used');
  },
  lookupLimiter: () => {
    throw new Error('not used');
  },
  pairingSlots: () => {
    throw new Error('not used');
  },
  push: null,
  background: () => {
    throw new Error('not used');
  },
  now: () => 0,
};

const get = (path: string, method = 'GET') => handleRequest(new Request(`https://relay.test${path}`, { method }), noState);

describe('health route', () => {
  it('answers GET /health with ok', async () => {
    const res = await get('/health');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(res.headers.get('cache-control')).toBe('no-store');
  });
  it('answers HEAD /health without a body', async () => {
    const res = await get('/health', 'HEAD');
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('');
  });
  it('rejects other methods on /health', async () => {
    const res = await get('/health', 'POST');
    expect(res.status).toBe(405);
    expect(await res.json()).toEqual({ error: 'method_not_allowed' });
  });
  it('returns 404 elsewhere', async () => {
    const res = await get('/other');
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'not_found' });
  });
});
