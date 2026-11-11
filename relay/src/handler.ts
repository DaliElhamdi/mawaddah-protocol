// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Routing and the request flow. State lives behind the [RelayDeps]
// interfaces (Durable Objects in the Worker, in-memory fakes in tests), and
// time comes from `deps.now()`, so this module can be tested with a fake clock.
// Nothing here logs requests, bodies or IP addresses (spec 4.5).

import { type SignedRequest, verifySignedRequest } from './auth';
import { fromBase64Url, inboxIdFor, jsonObject } from './encoding';
import { errorResponse, JSON_HEADERS, jsonResponse } from './errors';
import type { Platform, RegisterResult, Registration } from './device_state';
import { parseBundle, parseReply } from './pairing_messages';
import type { CreateResult, LookupResult, ReadReplyResult, ReplyResult } from './pairing_slots';
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

/** The pairing-slot Durable Object (one for all slots, see `PairingSlots`). */
export interface PairingSlotsApi {
  create(creator: string, bundle: string, nowMs: number): Promise<CreateResult>;
  lookup(handle: { readonly slotId: string } | { readonly code: string }, nowMs: number): Promise<LookupResult>;
  reply(slotId: string, replier: string, reply: string, nowMs: number): Promise<ReplyResult>;
  readReply(slotId: string, creator: string, nowMs: number): Promise<ReadReplyResult>;
}

/** The code-lookup counter of one IP bucket. */
export interface LookupLimiterApi {
  /** Counts one code lookup at [nowMs] if the bucket is under the limit. */
  reserve(nowMs: number): Promise<RateLimitResult>;
  /** Takes back the lookup counted at [atMs] (it found an open slot). */
  refund(atMs: number): Promise<void>;
}

export interface RelayDeps {
  /** The Durable Object of the device whose inbox ID is [inboxId]. */
  device(inboxId: string): DeviceApi;
  /** The registration rate limiter of the IP bucket [bucket] (see `ipBucket`). */
  registrationLimiter(bucket: string): RateLimiterApi;
  /** The code-lookup limiter of the IP bucket [bucket]. */
  lookupLimiter(bucket: string): LookupLimiterApi;
  pairingSlots(): PairingSlotsApi;
  /** The relay clock, in milliseconds since the Unix epoch. */
  now(): number;
}

/** Largest accepted body of `POST /v1/inbox`. */
export const MAX_REGISTRATION_BODY = 8 * 1024;

/** Largest accepted body of the pairing-slot routes (a bundle or reply is about 400 bytes). */
export const MAX_PAIRING_BODY = 4 * 1024;

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
      if (request.method !== 'POST') return methodNotAllowed('POST');
      return registerInbox(request, url, deps);
    case '/v1/pairing-slot':
      if (request.method !== 'POST') return methodNotAllowed('POST');
      return createSlot(request, url, deps);
  }
  const slot = /^\/v1\/pairing-slot\/([^/]+)(\/reply)?$/.exec(url.pathname);
  if (slot !== null) {
    const handle = slot[1] ?? '';
    if (slot[2] === undefined) {
      if (request.method !== 'GET') return methodNotAllowed('GET');
      return lookupSlot(request, handle, deps);
    }
    if (request.method === 'POST') return postReply(request, url, handle, deps);
    if (request.method === 'GET') return readReply(request, url, handle, deps);
    return methodNotAllowed('GET, POST');
  }
  return errorResponse(404, 'not_found');
}

function methodNotAllowed(allow: string): Response {
  return errorResponse(405, 'method_not_allowed', {}, { allow });
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
  // A declared length over the limit is refused at once; a missing or
  // unreadable one (NaN) is caught while reading.
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
  // counted against the IP limit. Check-then-act across two objects: two
  // first registrations of one key sent at the same moment may both count.
  if ((await device.registration()) === null) {
    const limiter = deps.registrationLimiter(ipBucket(request.headers.get('cf-connecting-ip')));
    const limit = await limiter.hit(deps.now());
    if (!limit.allowed) return rateLimited(limit.retryAfterSeconds);
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
  const fields = jsonObject(body);
  if (fields === null) return null;
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

// --- pairing slots (spec 4.5, PROTOCOL.md section 4.5) ----------------------

const CODE = /^[0-9]{6}$/;

/** Unix seconds of a relay time in milliseconds. */
function seconds(ms: number): number {
  return Math.floor(ms / 1000);
}

/** A slot ID as sent in a path: canonical base64url of 16 bytes. */
function isSlotId(text: string): boolean {
  return fromBase64Url(text, 16) !== null;
}

function rateLimited(retryAfterSeconds: number): Response {
  return errorResponse(
    429,
    'rate_limited',
    { retry_after: retryAfterSeconds },
    { 'retry-after': String(retryAfterSeconds) },
  );
}

/** Refuses a signer that has no inbox: slots cost the relay storage, inboxes are rate-limited. */
async function requireInbox(deps: RelayDeps, inboxId: string): Promise<Response | null> {
  return (await deps.device(inboxId).registration()) === null ? errorResponse(403, 'inbox_required') : null;
}

/**
 * `POST /v1/pairing-slot`: the initiator opens a slot with its bundle
 * (PROTOCOL.md section 4.1). Signed by the bundle's own key, which must
 * already have an inbox. A retry with the same bundle gets the same slot.
 */
async function createSlot(request: Request, url: URL, deps: RelayDeps): Promise<Response> {
  const auth = await authenticate(request, url, deps, MAX_PAIRING_BODY);
  if (!auth.ok) return auth.response;
  const bundle = await parseBundle(auth.body);
  if (bundle === null) return errorResponse(400, 'malformed_request');
  if (bundle.sigPub !== auth.signed.keyText) return errorResponse(400, 'key_mismatch');
  const noInbox = await requireInbox(deps, auth.inboxId);
  if (noInbox !== null) return noInbox;
  const result = await deps.pairingSlots().create(auth.signed.keyText, bundle.json, deps.now());
  switch (result.kind) {
    case 'created':
    case 'repeat':
      return jsonResponse(result.kind === 'created' ? 201 : 200, {
        slot_id: result.slotId,
        code: result.code,
        expires_at: seconds(result.expiresAt),
      });
    case 'conflict':
      return errorResponse(409, 'slot_conflict');
    case 'full':
      return errorResponse(503, 'slots_full');
  }
}

/**
 * `GET /v1/pairing-slot/{slot_id or code}`: the one unsigned route. The
 * joiner reads the bundle. Code lookups that find no open slot are limited
 * per IP bucket. Each code lookup is counted **before** the code is looked
 * up, in one call to the bucket's object, and given back only when it finds
 * an open slot: parallel guesses cannot pass the limit, and a bucket over it
 * learns nothing more until the window has passed.
 */
async function lookupSlot(request: Request, handle: string, deps: RelayDeps): Promise<Response> {
  let result: LookupResult;
  if (CODE.test(handle)) {
    const limiter = deps.lookupLimiter(ipBucket(request.headers.get('cf-connecting-ip')));
    const countedAt = deps.now();
    const limit = await limiter.reserve(countedAt);
    if (!limit.allowed) return rateLimited(limit.retryAfterSeconds);
    result = await deps.pairingSlots().lookup({ code: handle }, deps.now());
    if (result.kind === 'found') await limiter.refund(countedAt);
  } else if (isSlotId(handle)) {
    // 128-bit IDs cannot be guessed, so ID lookups are not counted.
    result = await deps.pairingSlots().lookup({ slotId: handle }, deps.now());
  } else {
    return errorResponse(404, 'slot_not_found');
  }
  switch (result.kind) {
    case 'found':
      return jsonResponse(200, { slot_id: result.slotId, bundle: JSON.parse(result.bundle) as unknown });
    case 'not_found':
      return errorResponse(404, 'slot_not_found');
    case 'used':
      return errorResponse(409, 'slot_used');
  }
}

/**
 * `POST /v1/pairing-slot/{slot_id}/reply`: the joiner posts its reply
 * (PROTOCOL.md section 4.3), signed by the reply's own key, which must
 * already have an inbox. The first reply wins (the pair is locked, spec 5.2).
 */
async function postReply(request: Request, url: URL, slotId: string, deps: RelayDeps): Promise<Response> {
  const auth = await authenticate(request, url, deps, MAX_PAIRING_BODY);
  if (!auth.ok) return auth.response;
  if (!isSlotId(slotId)) return errorResponse(404, 'slot_not_found');
  const reply = parseReply(auth.body);
  if (reply === null) return errorResponse(400, 'malformed_request');
  if (reply.sigPub !== auth.signed.keyText) return errorResponse(400, 'key_mismatch');
  const noInbox = await requireInbox(deps, auth.inboxId);
  if (noInbox !== null) return noInbox;
  const result = await deps.pairingSlots().reply(slotId, auth.signed.keyText, reply.json, deps.now());
  switch (result.kind) {
    case 'accepted':
      return jsonResponse(201, {});
    case 'repeat':
      return jsonResponse(200, {});
    case 'not_found':
      return errorResponse(404, 'slot_not_found');
    case 'used':
      return errorResponse(409, 'slot_used');
  }
}

/**
 * `GET /v1/pairing-slot/{slot_id}/reply`: the initiator reads the reply,
 * signed by the key that opened the slot (any other key gets
 * `slot_not_found`). `{"reply": null}` while nobody has replied. Reading the
 * reply closes the slot: the relay erases the bundle and the reply.
 */
async function readReply(request: Request, url: URL, slotId: string, deps: RelayDeps): Promise<Response> {
  const auth = await authenticate(request, url, deps, MAX_PAIRING_BODY);
  if (!auth.ok) return auth.response;
  if (!isSlotId(slotId)) return errorResponse(404, 'slot_not_found');
  const result = await deps.pairingSlots().readReply(slotId, auth.signed.keyText, deps.now());
  switch (result.kind) {
    case 'reply':
      return jsonResponse(200, { reply: JSON.parse(result.reply) as unknown });
    case 'waiting':
      return jsonResponse(200, { reply: null });
    case 'not_found':
      return errorResponse(404, 'slot_not_found');
    case 'used':
      return errorResponse(409, 'slot_used');
  }
}
