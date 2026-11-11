// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Test-side request signing (PROTOCOL.md section 13) with WebCrypto, and the
// shared vector files written by the Dart package.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { signingInput } from '../../src/auth';
import { toBase64Url } from '../../src/encoding';

export interface VectorCase {
  name: string;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
}

/** Cases of `packages/mawaddah_protocol/test/vectors/<file>.json`. */
export function loadVectors(file: string): VectorCase[] {
  const url = new URL(`../../../packages/mawaddah_protocol/test/vectors/${file}.json`, import.meta.url);
  const json = JSON.parse(readFileSync(fileURLToPath(url), 'utf8')) as { file: string; cases: VectorCase[] };
  if (json.file !== file || json.cases.length === 0) throw new Error(`${file}: bad vector file`);
  return json.cases;
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** An Ed25519 test key made from a 32-byte seed. */
export interface TestKey {
  readonly publicKey: Uint8Array;
  readonly keyText: string;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export async function testKey(seed: Uint8Array): Promise<TestKey> {
  // WebCrypto imports an Ed25519 seed through PKCS#8: a fixed 16-byte prefix.
  const pkcs8 = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...seed,
  ]);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  const publicKey = new Uint8Array(Buffer.from(jwk.x ?? '', 'base64url'));
  return {
    publicKey,
    keyText: toBase64Url(publicKey),
    sign: async (message) => new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, message)),
  };
}

/** A key from a small number, for tests that need many different keys. */
export function seedOf(n: number): Uint8Array {
  const seed = new Uint8Array(32);
  new DataView(seed.buffer).setUint32(28, n);
  seed[0] = 0x6d;
  return seed;
}

let nonceCounter = 0;

/** A fresh, unique nonce (22 base64url characters). */
export function freshNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  new DataView(bytes.buffer).setUint32(0, ++nonceCounter);
  return toBase64Url(bytes);
}

export interface SignOptions {
  method: string;
  path: string;
  body?: Uint8Array | string;
  /** Unix seconds. */
  timestamp: number;
  nonce?: string;
}

/** The four signing headers for a request. */
export async function signHeaders(key: TestKey, o: SignOptions): Promise<Record<string, string>> {
  const body = typeof o.body === 'string' ? new TextEncoder().encode(o.body) : (o.body ?? new Uint8Array(0));
  const nonce = o.nonce ?? freshNonce();
  const input = await signingInput(o.method, o.path, body, String(o.timestamp), nonce);
  return {
    'Maw-Key': key.keyText,
    'Maw-Timestamp': String(o.timestamp),
    'Maw-Nonce': nonce,
    'Maw-Signature': toBase64Url(await key.sign(input)),
  };
}

/** The body of `POST /v1/inbox` for [key]. */
export function registrationBody(key: TestKey, pushToken: string | null = 'test-fcm-token'): string {
  return JSON.stringify({ signing_key: key.keyText, push_token: pushToken, platform: 'android' });
}
