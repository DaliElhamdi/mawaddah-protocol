// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Routing and the request flow. State lives behind the [RelayDeps]
// interfaces (Durable Objects in the Worker, in-memory fakes in tests), and
// time comes from `deps.now()`, so this module can be tested with a fake clock.
// Nothing here logs requests, bodies or IP addresses (spec 4.5).

import { type SignedRequest, verifySignedRequest } from './auth';
import { fromBase64Url, inboxIdFor } from './encoding';
import { errorResponse, JSON_HEADERS, jsonResponse } from './errors';
import type { Platform, RegisterResult, Registration } from './device_state';
import { ipBucket, type RateLimitResult } from './rate_limit';

/** The device Durable Object, as the handler uses it. */
export interface DeviceApi {
  useNonce(nonce: string, nowMs: number): Promise<boolean>;
  registration(): Promise<Registration | null>;
  register(registration: Registration): Promise<RegisterResult>;
}

/** The rate-limit Durable Object of one IP bucket. */
export interface RateLimiterApi {
  hit(nowMs: number): Promise<RateLimitResult>;
}

export interface RelayDeps {
  /** The Durable Object of the device whose inbox ID is [inboxId]. */
  device(inboxId: string): DeviceApi;
  /** The rate limiter of the IP bucket [bucket] (see `ipBucket`). */
  registrationLimiter(bucket: string): Promise<RateLimiterApi>;
  /** The relay clock, in milliseconds since the Unix epoch. */
  now(): number;
}

/** Largest accepted body of `POST /v1/inbox`. */
export const MAX_REGISTRATION_BODY = 8 * 1024;

/** Longest accepted push token (FCM tokens are about 160 characters). */
export const MAX_PUSH_TOKEN_LENGTH = 4096;

const PUSH_TOKEN = /^[\x21-\x7e]+$/;

export async function handleRequest(request: Request, deps: RelayDeps): Promise<Response> {
  try {
    return await route(request, deps);
  } catch {
    // Never return what went wrong: no stack traces or internal messages.
    return errorResponse(500, 'internal_error');
  }
}

async function route(request: Request, deps: RelayDeps): Promise<Response> {
  const url = new URL(request.url);
  switch (url.pathname) {
    case '/health':
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return errorResponse(405, 'method_not_allowed', {}, { allow: 'GET, HEAD' });
      }
      return new Response(request.method === 'HEAD' ? null : JSON.stringify({ ok: true }), {
        status: 200,
        headers: JSON_HEADERS,
      });
    case '/v1/inbox':
      if (request.method !== 'POST') return errorResponse(405, 'method_not_allowed', {}, { allow: 'POST' });
      return registerInbox(request, url, deps);
    default:
      return errorResponse(404, 'not_found');
  }
}

type Authenticated =
  | { readonly ok: true; readonly signed: SignedRequest; readonly inboxId: string; readonly body: Uint8Array }
  | { readonly ok: false; readonly response: Response };

/**
 * Reads the body (at most [maxBody] bytes) and checks the signature, the
 * clock window and the nonce. The nonce is recorded in the signer's device
 * object, so a replay of the same request is refused for 15 minutes.
 */
async function authenticate(request: Request, url: URL, deps: RelayDeps, maxBody: number): Promise<Authenticated> {
  const body = await readBody(request, maxBody);
  if (body === null) return { ok: false, response: errorResponse(413, 'body_too_large') };
  const now = deps.now();
  const result = await verifySignedRequest(request.method, url.pathname + url.search, request.headers, body, now);
  if (!result.ok) {
    const extra: Record<string, number> = result.serverTime === undefined ? {} : { server_time: result.serverTime };
    return { ok: false, response: errorResponse(401, result.code, extra) };
  }
  const inboxId = await inboxIdFor(result.request.key);
  if (!(await deps.device(inboxId).useNonce(result.request.nonce, now))) {
    return { ok: false, response: errorResponse(401, 'nonce_reused') };
  }
  return { ok: true, signed: result.request, inboxId, body };
}

/** The body, or null when it is longer than [max] bytes. */
async function readBody(request: Request, max: number): Promise<Uint8Array | null> {
  const declared = request.headers.get('content-length');
  if (declared !== null && Number(declared) > max) return null;
  if (request.body === null) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

/**
 * `POST /v1/inbox`: registers the signer's inbox. The request is signed with
 * the key it registers, which proves the device holds that key; the inbox ID
 * is computed from the key (PROTOCOL.md section 3), never chosen by the client.
 */
async function registerInbox(request: Request, url: URL, deps: RelayDeps): Promise<Response> {
  const auth = await authenticate(request, url, deps, MAX_REGISTRATION_BODY);
  if (!auth.ok) return auth.response;
  const registration = parseRegistration(auth.body);
  if (registration === null) return errorResponse(400, 'malformed_request');
  if (registration.signingKey !== auth.signed.keyText) return errorResponse(400, 'key_mismatch');

  const device = deps.device(auth.inboxId);
  // Registering again with the same key (a retry after a lost answer) is not
  // counted against the IP limit.
  if ((await device.registration()) === null) {
    const limiter = await deps.registrationLimiter(ipBucket(request.headers.get('cf-connecting-ip')));
    const limit = await limiter.hit(deps.now());
    if (!limit.allowed) {
      return errorResponse(
        429,
        'rate_limited',
        { retry_after: limit.retryAfterSeconds },
        { 'retry-after': String(limit.retryAfterSeconds) },
      );
    }
  }
  switch (await device.register(registration)) {
    case 'created':
      return jsonResponse(201, { inbox_id: auth.inboxId });
    case 'updated':
      return jsonResponse(200, { inbox_id: auth.inboxId });
    case 'conflict':
      return errorResponse(409, 'inbox_conflict');
  }
}

/**
 * Body of `POST /v1/inbox`: `{"signing_key": base64url 32 bytes,
 * "push_token": string or null, "platform": "android" | "ios"}`. Unknown
 * fields are ignored; a missing or wrong field makes the body invalid.
 */
export function parseRegistration(body: Uint8Array): Registration | null {
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(body));
  } catch {
    return null;
  }
  if (typeof json !== 'object' || json === null || Array.isArray(json)) return null;
  const fields = json as Record<string, unknown>;
  const { signing_key: signingKey, push_token: pushToken, platform } = fields;
  if (typeof signingKey !== 'string' || fromBase64Url(signingKey, 32) === null) return null;
  if (!('push_token' in fields)) return null;
  if (
    pushToken !== null &&
    (typeof pushToken !== 'string' || pushToken.length > MAX_PUSH_TOKEN_LENGTH || !PUSH_TOKEN.test(pushToken))
  ) {
    return null;
  }
  if (platform !== 'android' && platform !== 'ios') return null;
  return { signingKey, pushToken: pushToken as string | null, platform: platform as Platform };
}
