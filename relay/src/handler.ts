// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Routing and the request flow. State lives behind the [RelayDeps]
// interfaces (Durable Objects in the Worker, in-memory fakes in tests), and
// time comes from `deps.now()`, so this module can be tested with a fake clock.
// Nothing here logs requests, bodies or IP addresses (spec 4.5).

import { type SignedRequest, verifySignedRequest } from './auth';
import { fromBase64Url, inboxIdFor, jsonObject, toBase64Url } from './encoding';
import { errorResponse, JSON_HEADERS, jsonResponse } from './errors';
import {
  type AllowResult,
  type DepositResult,
  type AckResult,
  BLOB_CHUNK_BYTES,
  chunkCount,
  chunkLength,
  type DeleteBlobResult,
  type FetchResult,
  type GetChunkResult,
  MAX_BLOB_BYTES,
  MAX_ENVELOPE_BYTES,
  type PutChunkResult,
  type Platform,
  type RegisterResult,
  type Registration,
} from './device_state';
import type { PushSender } from './fcm';
import { parseBundle, parseReply } from './pairing_messages';
import type { CreateResult, LookupResult, ReadReplyResult, ReplyResult } from './pairing_slots';
import { ipBucket, type RateLimitResult } from './rate_limit';

/** The device Durable Object, as the handler uses it. */
export interface DeviceApi {
  useNonce(nonce: string, nowMs: number): Promise<boolean>;
  registration(): Promise<Registration | null>;
  register(registration: Registration): Promise<RegisterResult>;
  allow(senderKey: string): Promise<AllowResult>;
  deposit(senderKey: string, body: Uint8Array, nowMs: number): Promise<DepositResult>;
  fetchEnvelopes(after: number | null, nowMs: number): Promise<FetchResult>;
  ack(cursor: number): Promise<AckResult>;
  putBlobChunk(
    senderKey: string,
    blobId: string,
    size: number,
    index: number,
    body: Uint8Array,
    nowMs: number,
  ): Promise<PutChunkResult>;
  getBlobChunk(blobId: string, index: number, nowMs: number): Promise<GetChunkResult>;
  deleteBlob(blobId: string, senderKey: string | null): Promise<DeleteBlobResult>;
  setPushToken(pushToken: string | null): Promise<boolean>;
  /** Forgets [pushToken] if it is still the stored one (FCM called it unregistered). */
  clearPushToken(pushToken: string): Promise<boolean>;
  deleteInbox(): Promise<void>;
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
  /** Sends FCM wake-ups; null when the relay has no service account (then none are sent). */
  readonly push: PushSender | null;
  /**
   * Runs [task] after the answer is sent (the Worker's `waitUntil`), so a
   * slow push never delays a deposit. [task] never rejects.
   */
  background(task: Promise<void>): void;
  /** The relay clock, in milliseconds since the Unix epoch. */
  now(): number;
}

/** Largest accepted body of `POST /v1/inbox`. */
export const MAX_REGISTRATION_BODY = 8 * 1024;

/** Largest accepted body of the pairing-slot routes (a bundle or reply is about 400 bytes). */
export const MAX_PAIRING_BODY = 4 * 1024;

/** Largest accepted body of the small JSON inbox routes (allow, ack, push token). */
export const MAX_INBOX_BODY = 8 * 1024;

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
  const blob = /^\/v1\/inbox\/([^/]+)\/blobs\/([^/]+)$/.exec(url.pathname);
  if (blob !== null) {
    const inboxId = blob[1] ?? '';
    const blobId = blob[2] ?? '';
    if (request.method === 'PUT') return putBlobChunk(request, url, inboxId, blobId, deps);
    if (request.method === 'GET') return getBlobChunk(request, url, inboxId, blobId, deps);
    if (request.method === 'DELETE') return deleteBlob(request, url, inboxId, blobId, deps);
    return methodNotAllowed('DELETE, GET, PUT');
  }
  const inbox = /^\/v1\/inbox\/([^/]+)(\/allow|\/envelopes|\/ack|\/push-token)?$/.exec(url.pathname);
  if (inbox !== null) {
    const inboxId = inbox[1] ?? '';
    switch (inbox[2]) {
      case undefined:
        if (request.method !== 'DELETE') return methodNotAllowed('DELETE');
        return deleteInbox(request, url, inboxId, deps);
      case '/allow':
        if (request.method !== 'POST') return methodNotAllowed('POST');
        return allowSender(request, url, inboxId, deps);
      case '/envelopes':
        if (request.method === 'PUT') return depositEnvelope(request, url, inboxId, deps);
        if (request.method === 'GET') return fetchEnvelopes(request, url, inboxId, deps);
        return methodNotAllowed('GET, PUT');
      case '/ack':
        if (request.method !== 'POST') return methodNotAllowed('POST');
        return ackEnvelopes(request, url, inboxId, deps);
      case '/push-token':
        if (request.method !== 'POST') return methodNotAllowed('POST');
        return updatePushToken(request, url, inboxId, deps);
    }
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
  const { signing_key: signingKey, platform } = fields;
  if (typeof signingKey !== 'string' || fromBase64Url(signingKey, 32) === null) return null;
  const pushToken = pushTokenField(fields);
  if (pushToken === undefined) return null;
  if (platform !== 'android' && platform !== 'ios') return null;
  return { signingKey, pushToken, platform: platform as Platform };
}

/**
 * The required `push_token` field: visible ASCII (at most
 * `MAX_PUSH_TOKEN_LENGTH` characters) or null. Undefined when it is missing
 * or invalid.
 */
function pushTokenField(fields: Record<string, unknown>): string | null | undefined {
  if (!('push_token' in fields)) return undefined;
  const token = fields.push_token;
  if (token === null) return null;
  if (typeof token !== 'string' || token.length > MAX_PUSH_TOKEN_LENGTH || !PUSH_TOKEN.test(token)) return undefined;
  return token;
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

// --- inbox routes (spec 4.5): allow, envelopes, ACK, push token, delete -----

/** Envelope cursors: decimal, no leading zeros, at most 2^53 - 1. */
const CURSOR = /^(0|[1-9][0-9]{0,15})$/;

/** The cursor in [text], or null when it is not a canonical cursor. */
function parseCursor(text: string): number | null {
  if (!CURSOR.test(text)) return null;
  const value = Number(text);
  return Number.isSafeInteger(value) ? value : null;
}

/** An inbox ID as sent in a path: canonical base64url of 16 bytes. */
function isInboxId(text: string): boolean {
  return fromBase64Url(text, 16) !== null;
}

type Owned =
  | { readonly ok: true; readonly body: Uint8Array }
  | { readonly ok: false; readonly response: Response };

/**
 * Authenticates a request on the inbox [inboxId] that only its owner may
 * make: the signing key must be the one the inbox ID is derived from.
 */
async function authenticateOwner(
  request: Request,
  url: URL,
  inboxId: string,
  deps: RelayDeps,
  maxBody: number,
): Promise<Owned> {
  const auth = await authenticate(request, url, deps, maxBody);
  if (!auth.ok) return auth;
  if (!isInboxId(inboxId)) return { ok: false, response: errorResponse(404, 'inbox_not_found') };
  if (auth.inboxId !== inboxId) return { ok: false, response: errorResponse(403, 'not_inbox_owner') };
  return { ok: true, body: auth.body };
}

/**
 * `POST /v1/inbox/{id}/allow`, by the owner, body `{"sender_key": IKsig of
 * the partner}`: from then on only that key may deposit (spec 4.5). One key
 * per inbox; the same key again gets `200`, another key `409 allow_conflict`.
 */
async function allowSender(request: Request, url: URL, inboxId: string, deps: RelayDeps): Promise<Response> {
  const owned = await authenticateOwner(request, url, inboxId, deps, MAX_INBOX_BODY);
  if (!owned.ok) return owned.response;
  const fields = jsonObject(owned.body);
  const senderKey = fields?.sender_key;
  if (typeof senderKey !== 'string' || fromBase64Url(senderKey, 32) === null) {
    return errorResponse(400, 'malformed_request');
  }
  switch (await deps.device(inboxId).allow(senderKey)) {
    case 'allowed':
      return jsonResponse(201, {});
    case 'repeat':
      return jsonResponse(200, {});
    case 'conflict':
      return errorResponse(409, 'allow_conflict');
    case 'no_inbox':
      return errorResponse(404, 'inbox_not_found');
  }
}

/**
 * `PUT /v1/inbox/{id}/envelopes`: deposits one sealed envelope (the raw
 * bytes, at most 65,536) signed by the inbox's allowed sender. Header
 * `Maw-Wake: 0|1` says whether the sender asks for a push: with `1`, once the
 * envelope is stored, the inbox's phone gets a content-free FCM wake-up
 * (spec 4.5, 8.7). The answer does not wait for it or depend on it.
 */
async function depositEnvelope(request: Request, url: URL, inboxId: string, deps: RelayDeps): Promise<Response> {
  const auth = await authenticate(request, url, deps, MAX_ENVELOPE_BYTES);
  if (!auth.ok) return auth.response;
  if (!isInboxId(inboxId)) return errorResponse(404, 'inbox_not_found');
  const wake = request.headers.get('maw-wake');
  if ((wake !== '0' && wake !== '1') || auth.body.byteLength === 0) return errorResponse(400, 'malformed_request');
  const device = deps.device(inboxId);
  const result = await device.deposit(auth.signed.keyText, auth.body, deps.now());
  switch (result.kind) {
    case 'stored':
      if (wake === '1' && result.pushToken !== null && deps.push !== null) {
        deps.background(sendWake(deps.push, device, result.pushToken));
      }
      return jsonResponse(201, {});
    case 'no_inbox':
      return errorResponse(404, 'inbox_not_found');
    case 'not_allowed':
      return errorResponse(403, 'sender_not_allowed');
    case 'full':
      return errorResponse(409, 'inbox_full');
  }
}

/**
 * Sends one wake-up to [pushToken]; if FCM says the token is unregistered,
 * forgets it (unless the device has sent a new one meanwhile). Best effort:
 * nothing is retried and nothing is logged; the phone also syncs when the
 * app opens.
 */
async function sendWake(push: PushSender, device: DeviceApi, pushToken: string): Promise<void> {
  try {
    if ((await push.wake(pushToken)) === 'unregistered') await device.clearPushToken(pushToken);
  } catch {
    // Nothing to report: the deposit already succeeded.
  }
}

/**
 * `GET /v1/inbox/{id}/envelopes[?after=cursor]`, by the owner: the waiting
 * envelopes after the cursor, in deposit order, one page at a time. A
 * cursor the relay never handed out gets `invalid_cursor`.
 */
async function fetchEnvelopes(request: Request, url: URL, inboxId: string, deps: RelayDeps): Promise<Response> {
  const owned = await authenticateOwner(request, url, inboxId, deps, 0);
  if (!owned.ok) return owned.response;
  let after: number | null = null;
  if (url.search !== '') {
    const match = /^\?after=([^&]*)$/.exec(url.search);
    after = match === null ? null : parseCursor(match[1] ?? '');
    if (after === null) return errorResponse(400, 'malformed_request');
  }
  const page = await deps.device(inboxId).fetchEnvelopes(after, deps.now());
  if (page === 'no_inbox') return errorResponse(404, 'inbox_not_found');
  if (page === 'ahead') return errorResponse(400, 'invalid_cursor');
  return jsonResponse(200, {
    envelopes: page.envelopes.map((e) => ({ cursor: String(e.cursor), body: toBase64Url(e.body) })),
    more: page.more,
  });
}

/**
 * `POST /v1/inbox/{id}/ack`, by the owner, body `{"cursor": "<cursor>"}`:
 * deletes every envelope up to and including that cursor at once. A cursor
 * the relay never handed out gets `invalid_cursor`.
 */
async function ackEnvelopes(request: Request, url: URL, inboxId: string, deps: RelayDeps): Promise<Response> {
  const owned = await authenticateOwner(request, url, inboxId, deps, MAX_INBOX_BODY);
  if (!owned.ok) return owned.response;
  const text = jsonObject(owned.body)?.cursor;
  const cursor = typeof text === 'string' ? parseCursor(text) : null;
  if (cursor === null) return errorResponse(400, 'malformed_request');
  const deleted = await deps.device(inboxId).ack(cursor);
  if (deleted === 'no_inbox') return errorResponse(404, 'inbox_not_found');
  if (deleted === 'ahead') return errorResponse(400, 'invalid_cursor');
  return jsonResponse(200, {});
}

/** `POST /v1/inbox/{id}/push-token`, by the owner, body `{"push_token": string or null}`. */
async function updatePushToken(request: Request, url: URL, inboxId: string, deps: RelayDeps): Promise<Response> {
  const owned = await authenticateOwner(request, url, inboxId, deps, MAX_INBOX_BODY);
  if (!owned.ok) return owned.response;
  const fields = jsonObject(owned.body);
  const pushToken = fields === null ? undefined : pushTokenField(fields);
  if (pushToken === undefined) return errorResponse(400, 'malformed_request');
  if (!(await deps.device(inboxId).setPushToken(pushToken))) return errorResponse(404, 'inbox_not_found');
  return jsonResponse(200, {});
}

/**
 * `DELETE /v1/inbox/{id}`, by the owner: deletes the inbox, its allowed
 * sender and its envelopes (unpair, "Delete all data"). `200` also when
 * there was nothing to delete, so a retry after a lost answer succeeds.
 */
async function deleteInbox(request: Request, url: URL, inboxId: string, deps: RelayDeps): Promise<Response> {
  const owned = await authenticateOwner(request, url, inboxId, deps, 0);
  if (!owned.ok) return owned.response;
  await deps.device(inboxId).deleteInbox();
  return jsonResponse(200, {});
}

// --- blobs (spec 4.5, PROTOCOL.md section 12) -------------------------------

/** A blob ID as sent in a path: canonical base64url of 16 bytes (chosen by the sender). */
function isBlobId(text: string): boolean {
  return fromBase64Url(text, 16) !== null;
}

/** The decimal numbers of the query `?<names[0]>=<n>&<names[1]>=<n>…`, in that order, or null. */
function numbersOf(search: string, names: readonly string[]): number[] | null {
  const parts = search.startsWith('?') ? search.slice(1).split('&') : [];
  if (parts.length !== names.length) return null;
  const out: number[] = [];
  for (const [i, part] of parts.entries()) {
    const [name, value, ...rest] = part.split('=');
    const n = parseCursor(value ?? '');
    if (name !== names[i] || rest.length > 0 || n === null) return null;
    out.push(n);
  }
  return out;
}

/**
 * `PUT /v1/inbox/{id}/blobs/{blob_id}?size=<bytes>&chunk=<index>`, by the
 * inbox's allowed sender, body: the raw bytes of that chunk. A blob is 1 to
 * 10 MiB, sent in order in chunks of 1 MiB (the last one shorter). The
 * first chunk reserves the whole size in the inbox's 100 MiB quota.
 */
async function putBlobChunk(
  request: Request,
  url: URL,
  inboxId: string,
  blobId: string,
  deps: RelayDeps,
): Promise<Response> {
  const auth = await authenticate(request, url, deps, BLOB_CHUNK_BYTES);
  if (!auth.ok) return auth.response;
  if (!isInboxId(inboxId)) return errorResponse(404, 'inbox_not_found');
  if (!isBlobId(blobId)) return errorResponse(404, 'blob_not_found');
  const query = numbersOf(url.search, ['size', 'chunk']);
  if (query === null) return errorResponse(400, 'malformed_request');
  const [size = 0, index = 0] = query;
  if (size > MAX_BLOB_BYTES) return errorResponse(413, 'blob_too_large');
  if (size === 0 || index >= chunkCount(size) || auth.body.byteLength !== chunkLength(size, index)) {
    return errorResponse(400, 'malformed_request');
  }
  const result = await deps
    .device(inboxId)
    .putBlobChunk(auth.signed.keyText, blobId, size, index, auth.body, deps.now());
  switch (result.kind) {
    case 'stored':
      return jsonResponse(201, {});
    case 'repeat':
      return jsonResponse(200, {});
    case 'no_inbox':
      return errorResponse(404, 'inbox_not_found');
    case 'not_allowed':
      return errorResponse(403, 'sender_not_allowed');
    case 'quota':
      return errorResponse(413, 'blob_quota_exceeded');
    case 'conflict':
      return errorResponse(409, 'blob_conflict');
    case 'out_of_order':
      return errorResponse(409, 'chunk_out_of_order', { next_chunk: result.next });
  }
}

/**
 * `GET /v1/inbox/{id}/blobs/{blob_id}?chunk=<index>`, by the owner: the raw
 * bytes of one chunk, once the whole blob is uploaded. The header
 * `Maw-Blob-Size` gives the blob's size, so the client knows the chunk count.
 */
async function getBlobChunk(
  request: Request,
  url: URL,
  inboxId: string,
  blobId: string,
  deps: RelayDeps,
): Promise<Response> {
  const owned = await authenticateOwner(request, url, inboxId, deps, 0);
  if (!owned.ok) return owned.response;
  if (!isBlobId(blobId)) return errorResponse(404, 'blob_not_found');
  const query = numbersOf(url.search, ['chunk']);
  if (query === null) return errorResponse(400, 'malformed_request');
  const result = await deps.device(inboxId).getBlobChunk(blobId, query[0] ?? 0, deps.now());
  switch (result.kind) {
    case 'chunk':
      return new Response(result.body, {
        status: 200,
        headers: {
          'content-type': 'application/octet-stream',
          'cache-control': 'no-store',
          'maw-blob-size': String(result.size),
        },
      });
    case 'no_inbox':
      return errorResponse(404, 'inbox_not_found');
    case 'not_found':
      return errorResponse(404, 'blob_not_found');
    case 'incomplete':
      return errorResponse(409, 'blob_incomplete');
    case 'no_chunk':
      return errorResponse(400, 'malformed_request');
  }
}

/**
 * `DELETE /v1/inbox/{id}/blobs/{blob_id}`, by the owner once it has the file
 * (the blob's ACK), or by the allowed sender (an upload it gave up). `200`
 * also when the blob was already gone.
 */
async function deleteBlob(
  request: Request,
  url: URL,
  inboxId: string,
  blobId: string,
  deps: RelayDeps,
): Promise<Response> {
  const auth = await authenticate(request, url, deps, 0);
  if (!auth.ok) return auth.response;
  if (!isInboxId(inboxId)) return errorResponse(404, 'inbox_not_found');
  if (!isBlobId(blobId)) return errorResponse(404, 'blob_not_found');
  const sender = auth.inboxId === inboxId ? null : auth.signed.keyText;
  switch (await deps.device(inboxId).deleteBlob(blobId, sender)) {
    case 'deleted':
    case 'absent':
      return jsonResponse(200, {});
    case 'no_inbox':
      return errorResponse(404, 'inbox_not_found');
    case 'not_allowed':
      return errorResponse(403, 'sender_not_allowed');
  }
}
