// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Every error is JSON `{"error": "<code>"}` with a stable code (relay/README.md
// lists them). Nothing else about the failure is returned: no stack traces,
// no internal messages.

export const JSON_HEADERS: Readonly<Record<string, string>> = {
  'content-type': 'application/json',
  'cache-control': 'no-store',
};

export type ErrorCode =
  | 'malformed_request'
  | 'key_mismatch'
  | 'auth_missing'
  | 'auth_malformed'
  | 'clock_skew'
  | 'bad_signature'
  | 'nonce_reused'
  | 'not_found'
  | 'method_not_allowed'
  | 'inbox_conflict'
  | 'body_too_large'
  | 'rate_limited'
  | 'inbox_required'
  | 'slot_not_found'
  | 'slot_used'
  | 'slot_conflict'
  | 'slots_full'
  | 'inbox_not_found'
  | 'not_inbox_owner'
  | 'sender_not_allowed'
  | 'allow_conflict'
  | 'inbox_full'
  | 'invalid_cursor'
  | 'blob_not_found'
  | 'blob_too_large'
  | 'blob_quota_exceeded'
  | 'blob_conflict'
  | 'blob_incomplete'
  | 'chunk_out_of_order'
  | 'internal_error';

export function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...headers } });
}

export function errorResponse(
  status: number,
  code: ErrorCode,
  extra: Record<string, string | number> = {},
  headers: Record<string, string> = {},
): Response {
  return jsonResponse(status, { error: code, ...extra }, headers);
}
