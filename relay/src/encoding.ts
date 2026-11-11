// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Byte encodings used on the wire (PROTOCOL.md section 1): base64url without
// padding, and lowercase hex for hashes.

const B64URL = /^[A-Za-z0-9_-]*$/;

/** Base64url without padding. */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/**
 * Decodes base64url without padding into exactly [length] bytes. Returns
 * null for any other text, including a non-canonical spelling of the same
 * bytes (unused low bits set), so each value has exactly one accepted form.
 */
export function fromBase64Url(text: string, length: number): Uint8Array | null {
  if (text.length !== Math.ceil((length * 4) / 3) || !B64URL.test(text)) return null;
  const padded = text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (text.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return null;
  }
  if (binary.length !== length) return null;
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) bytes[i] = binary.charCodeAt(i);
  return toBase64Url(bytes) === text ? bytes : null;
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

/** The relay inbox ID of a signing key: SHA-256("mawaddah/v1/inbox" || key)[0..16] (PROTOCOL.md section 3). */
export async function inboxIdFor(signingKey: Uint8Array): Promise<string> {
  const label = new TextEncoder().encode('mawaddah/v1/inbox');
  const input = new Uint8Array(label.length + signingKey.length);
  input.set(label);
  input.set(signingKey, label.length);
  return toBase64Url((await sha256(input)).subarray(0, 16));
}
