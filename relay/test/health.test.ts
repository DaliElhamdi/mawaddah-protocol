// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { handleRequest } from '../src/index';

describe('health route', () => {
  it('answers GET /health with ok', async () => {
    const res = handleRequest(new Request('https://relay.test/health'));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(res.headers.get('cache-control')).toBe('no-store');
  });
  it('rejects other methods on /health', () => {
    const res = handleRequest(new Request('https://relay.test/health', { method: 'POST' }));
    expect(res.status).toBe(405);
  });
  it('returns 404 elsewhere', async () => {
    const res = handleRequest(new Request('https://relay.test/other'));
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'not_found' });
  });
});
