// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { fromBase64Url, inboxIdFor, toBase64Url } from '../src/encoding';
import { fromHex, loadVectors } from './support/signing';

describe('base64url', () => {
  it('round-trips every length without padding', () => {
    for (let n = 0; n < 40; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      const text = toBase64Url(bytes);
      expect(text).not.toMatch(/[=+/]/);
      expect(fromBase64Url(text, n)).toEqual(bytes);
    }
  });

  it('accepts only the one canonical spelling of the right length', () => {
    const sixteen = toBase64Url(new Uint8Array(16).fill(0xff));
    expect(sixteen).toBe('_____________________w');
    expect(fromBase64Url(sixteen, 16)).not.toBeNull();
    expect(fromBase64Url('_____________________x', 16)).toBeNull(); // unused bits set
    expect(fromBase64Url(`${sixteen}==`, 16)).toBeNull();
    expect(fromBase64Url(sixteen, 15)).toBeNull();
    expect(fromBase64Url('/////////////////////w', 16)).toBeNull(); // standard alphabet
    expect(fromBase64Url('', 0)).toEqual(new Uint8Array(0));
  });
});

describe('inboxIdFor', () => {
  it('matches the device IDs of identity.json', async () => {
    for (const c of loadVectors('identity')) {
      const o = c.output as { sig_pub: string; device_id: string };
      expect(await inboxIdFor(fromHex(o.sig_pub))).toBe(toBase64Url(fromHex(o.device_id)));
    }
  });
  it('matches the inbox IDs of relay_signing.json', async () => {
    for (const c of loadVectors('relay_signing')) {
      const o = c.output as { inbox_id: string; headers: Record<string, string> };
      const key = fromBase64Url(o.headers['Maw-Key'] ?? '', 32);
      expect(key).not.toBeNull();
      expect(await inboxIdFor(key ?? new Uint8Array(0))).toBe(o.inbox_id);
    }
  });
});
