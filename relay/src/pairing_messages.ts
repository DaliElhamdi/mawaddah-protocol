// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// The pairing bundle and reply as the relay checks and stores them
// (PROTOCOL.md sections 4.1 and 4.3). The relay keeps only the known fields,
// re-encoded in one fixed form, so a slot cannot carry anything else.
// It verifies the bundle signature (it needs only the bundle's own keys);
// the reply signature covers the transcript hash, which needs BLAKE2b, so
// the initiator checks it (section 4.5 step 3).

import { verifyEd25519 } from './auth';
import { fromBase64Url, jsonObject } from './encoding';

export const PAIRING_FORMAT_VERSION = 1;

const BUNDLE_LABEL = 'mawaddah/v1/bundle';

export interface Bundle {
  readonly sigPub: string;
  /** The canonical JSON stored in the slot and returned to the joiner. */
  readonly json: string;
}

export interface Reply {
  readonly sigPub: string;
  /** The canonical JSON stored in the slot and returned to the initiator. */
  readonly json: string;
}

/** The pairing bundle of `POST /v1/pairing-slot`, or null if it is not a valid one. */
export async function parseBundle(body: Uint8Array): Promise<Bundle | null> {
  const fields = jsonObject(body);
  if (fields === null || fields.v !== PAIRING_FORMAT_VERSION) return null;
  const sigPub = bytesField(fields, 'sig_pub', 32);
  const dhPub = bytesField(fields, 'dh_pub', 32);
  const ekPub = bytesField(fields, 'ek_pub', 32);
  const sig = bytesField(fields, 'sig', 64);
  if (sigPub === null || dhPub === null || ekPub === null || sig === null) return null;
  const label = new TextEncoder().encode(BUNDLE_LABEL);
  const signed = new Uint8Array([...label, PAIRING_FORMAT_VERSION, ...sigPub, ...dhPub, ...ekPub]);
  if (!(await verifyEd25519(sigPub, sig, signed))) return null;
  const { sig_pub, dh_pub, ek_pub, sig: sigText } = fields as Record<string, string>;
  return {
    sigPub: sig_pub as string,
    json: JSON.stringify({ v: PAIRING_FORMAT_VERSION, sig_pub, dh_pub, ek_pub, sig: sigText }),
  };
}

/** The joiner reply of `POST /v1/pairing-slot/{slot_id}/reply`, or null if it is malformed. */
export function parseReply(body: Uint8Array): Reply | null {
  const fields = jsonObject(body);
  if (fields === null || fields.v !== PAIRING_FORMAT_VERSION) return null;
  if (fields.path !== 'qr' && fields.path !== 'code') return null;
  const sizes: [string, number][] = [
    ['sig_pub', 32],
    ['dh_pub', 32],
    ['ek_pub', 32],
    ['confirm', 32],
    ['sig', 64],
  ];
  if (sizes.some(([name, size]) => bytesField(fields, name, size) === null)) return null;
  const f = fields as Record<string, string>;
  return {
    sigPub: f.sig_pub as string,
    json: JSON.stringify({
      v: PAIRING_FORMAT_VERSION,
      path: f.path,
      sig_pub: f.sig_pub,
      dh_pub: f.dh_pub,
      ek_pub: f.ek_pub,
      confirm: f.confirm,
      sig: f.sig,
    }),
  };
}

function bytesField(fields: Record<string, unknown>, name: string, size: number): Uint8Array | null {
  const value = fields[name];
  return typeof value === 'string' ? fromBase64Url(value, size) : null;
}
