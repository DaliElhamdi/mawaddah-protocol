// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Request signing (PROTOCOL.md section 13). This module does the stateless
// checks: header format, clock window and Ed25519 signature. The nonce check
// needs storage and is done by the caller in the signer's Durable Object.

import { fromBase64Url, sha256, toHex } from './encoding';
import type { ErrorCode } from './errors';

export const SIGNING_LABEL = 'MAWADDAH-RELAY-V1';

/** Accepted distance between the request timestamp and the relay clock. */
export const TIME_WINDOW_SECONDS = 300;

/**
 * How long a nonce is remembered. Longer than the 10 minutes of timestamps
 * the window accepts, so a request can never be replayed while its timestamp
 * is still accepted (PROTOCOL.md section 13).
 */
export const NONCE_MEMORY_MS = 15 * 60 * 1000;

export const HEADER_KEY = 'maw-key';
export const HEADER_TIMESTAMP = 'maw-timestamp';
export const HEADER_NONCE = 'maw-nonce';
export const HEADER_SIGNATURE = 'maw-signature';

const TIMESTAMP = /^(0|[1-9][0-9]{0,14})$/;
const METHOD = /^[A-Z]+$/;

/** A request whose signature and timestamp checked out. */
export interface SignedRequest {
  /** The signer's Ed25519 public key (`IKsig`). */
  readonly key: Uint8Array;
  /** The same key as sent, base64url. */
  readonly keyText: string;
  /** The nonce as sent, base64url (22 characters). */
  readonly nonce: string;
}

export type AuthResult =
  | { readonly ok: true; readonly request: SignedRequest }
  | { readonly ok: false; readonly code: ErrorCode; readonly serverTime?: number };

/** The six lines that are signed, joined by `\n`, with no final newline. */
export async function signingInput(
  method: string,
  pathAndQuery: string,
  body: Uint8Array,
  timestamp: string,
  nonce: string,
): Promise<Uint8Array> {
  const text = [SIGNING_LABEL, method, pathAndQuery, toHex(await sha256(body)), timestamp, nonce].join('\n');
  return new TextEncoder().encode(text);
}

/**
 * Checks the signing headers of a request.
 *
 * [pathAndQuery] is the path and query of the request URL as the runtime
 * parsed it; [nowMs] is the relay clock.
 */
export async function verifySignedRequest(
  method: string,
  pathAndQuery: string,
  headers: Headers,
  body: Uint8Array,
  nowMs: number,
): Promise<AuthResult> {
  const keyText = headers.get(HEADER_KEY);
  const timestamp = headers.get(HEADER_TIMESTAMP);
  const nonce = headers.get(HEADER_NONCE);
  const signatureText = headers.get(HEADER_SIGNATURE);
  if (keyText === null || timestamp === null || nonce === null || signatureText === null) {
    return { ok: false, code: 'auth_missing' };
  }
  const key = fromBase64Url(keyText, 32);
  const signature = fromBase64Url(signatureText, 64);
  if (
    key === null ||
    signature === null ||
    fromBase64Url(nonce, 16) === null ||
    !TIMESTAMP.test(timestamp) ||
    !METHOD.test(method)
  ) {
    return { ok: false, code: 'auth_malformed' };
  }
  const nowSeconds = Math.floor(nowMs / 1000);
  if (Math.abs(Number(timestamp) - nowSeconds) > TIME_WINDOW_SECONDS) {
    return { ok: false, code: 'clock_skew', serverTime: nowSeconds };
  }
  const input = await signingInput(method, pathAndQuery, body, timestamp, nonce);
  if (!(await verifyEd25519(key, signature, input))) {
    return { ok: false, code: 'bad_signature' };
  }
  return { ok: true, request: { key, keyText, nonce } };
}

/** Ed25519 verification with WebCrypto; false for a key or signature it cannot parse. */
export async function verifyEd25519(key: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  try {
    const publicKey = await crypto.subtle.importKey('raw', key, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, publicKey, signature, message);
  } catch {
    // Not a valid curve point, or a signature the runtime cannot parse.
    return false;
  }
}
