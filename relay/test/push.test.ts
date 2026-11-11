// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Content-free FCM wake-ups (spec 4.5, 8.7): the service-account JWT, the
// access-token cache, the exact message, the unregistered token, and the
// deposit route that triggers them. `fetch` is a fake Google (no network);
// the RSA key is made fresh for the test run.

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { inboxIdFor } from '../src/encoding';
import {
  ASSERTION_LIFETIME_S,
  FCM_SCOPE,
  FcmSender,
  fcmSendUrl,
  GOOGLE_TOKEN_URL,
  parseServiceAccount,
  type PushSender,
  type ServiceAccount,
  TOKEN_REFRESH_MARGIN_MS,
  type WakeResult,
  wakeMessage,
} from '../src/fcm';
import { handleRequest } from '../src/handler';
import { type CryptoKey, FakeGoogle, testServiceAccount, UNREGISTERED } from './support/fake_google';
import { FakeRelay } from './support/fake_relay';
import { freshNonce, registrationBody, seedOf, signHeaders, type TestKey, testKey } from './support/signing';

const t0 = 1762862400000;

let account: ServiceAccount;
let accountJson: string;
let publicKey: CryptoKey;

beforeAll(async () => {
  ({ account, json: accountJson, publicKey } = await testServiceAccount());
});

let consoleCalls: unknown[];
beforeEach(() => {
  consoleCalls = [];
  for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, m).mockImplementation((...args) => void consoleCalls.push(args));
  }
});
afterEach(() => {
  vi.restoreAllMocks();
  // Spec 4.5: nothing is logged, the secret least of all.
  expect(consoleCalls).toEqual([]);
});

describe('parseServiceAccount', () => {
  it('keeps the four fields it needs from a service-account key file', () => {
    expect(parseServiceAccount(accountJson)).toEqual(account);
  });

  it('refuses anything that is not a service-account key', () => {
    const fields = JSON.parse(accountJson) as Record<string, unknown>;
    const variant = (patch: Record<string, unknown>) => JSON.stringify({ ...fields, ...patch });
    for (const text of [
      '',
      'not json',
      '[]',
      'null',
      variant({ type: 'authorized_user' }),
      variant({ project_id: undefined }),
      variant({ project_id: 'Has Spaces' }),
      variant({ project_id: '../../evil' }),
      variant({ client_email: 'no-at-sign' }),
      variant({ client_email: 7 }),
      variant({ private_key_id: 'not hex!' }),
      variant({ private_key: 'not a pem' }),
      variant({ private_key: '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n' }),
      variant({ private_key: '-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----\n' }),
      variant({ private_key: '-----BEGIN PRIVATE KEY-----\n@@@@\n-----END PRIVATE KEY-----\n' }),
    ]) {
      expect(parseServiceAccount(text), text.slice(0, 60)).toBeNull();
    }
  });
});

describe('wakeMessage', () => {
  it('is a high-priority data message whose data is exactly {"t":"s"}', () => {
    expect(JSON.parse(wakeMessage('device-token'))).toStrictEqual({
      message: {
        token: 'device-token',
        data: { t: 's' },
        android: { priority: 'HIGH', collapse_key: 's' },
      },
    });
  });
});

describe('FcmSender', () => {
  let google: FakeGoogle;
  let now: number;
  let sender: FcmSender;

  beforeEach(() => {
    google = new FakeGoogle(publicKey, account);
    now = t0;
    sender = new FcmSender(account, google.fetch, () => now);
  });

  it('signs an RS256 assertion for the FCM scope only, and exchanges it at Google', async () => {
    expect(await sender.wake('device-token')).toBe('sent');
    expect(google.tokenRequests).toHaveLength(1);
    const [tokenRequest] = google.tokenRequests;
    expect(tokenRequest?.method).toBe('POST');
    expect(tokenRequest?.headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect([...new URLSearchParams(tokenRequest?.body).keys()].sort()).toEqual(['assertion', 'grant_type']);
    expect(google.assertions).toEqual([
      {
        header: { alg: 'RS256', typ: 'JWT', kid: account.privateKeyId },
        claims: {
          iss: account.clientEmail,
          scope: FCM_SCOPE,
          aud: GOOGLE_TOKEN_URL,
          iat: t0 / 1000,
          exp: t0 / 1000 + ASSERTION_LIFETIME_S,
        },
      },
    ]);
  });

  it('uses Google’s fixed addresses, not the token_uri in the key file', async () => {
    await sender.wake('device-token');
    expect(google.requests.map((r) => r.url)).toEqual([
      'https://oauth2.googleapis.com/token',
      'https://fcm.googleapis.com/v1/projects/mawaddah-test/messages:send',
    ]);
    expect(fcmSendUrl('mawaddah-test')).toBe('https://fcm.googleapis.com/v1/projects/mawaddah-test/messages:send');
  });

  it('sends exactly the wake-up message: no content, inbox or sender', async () => {
    await sender.wake('device-token');
    const [send] = google.sends;
    expect(send?.method).toBe('POST');
    expect(send?.headers).toEqual({ authorization: 'Bearer ya29.test-1', 'content-type': 'application/json' });
    expect(send?.body).toBe(
      '{"message":{"token":"device-token","data":{"t":"s"},"android":{"priority":"HIGH","collapse_key":"s"}}}',
    );
  });

  it('caches the access token until shortly before it expires', async () => {
    google.expiresIn = 3600;
    await sender.wake('a');
    now = t0 + 3600_000 - TOKEN_REFRESH_MARGIN_MS - 1;
    await sender.wake('b');
    expect(google.tokenRequests).toHaveLength(1);
    now += 1;
    await sender.wake('c');
    expect(google.tokenRequests).toHaveLength(2);
    expect(google.sends.map((s) => s.headers.authorization)).toEqual([
      'Bearer ya29.test-1',
      'Bearer ya29.test-1',
      'Bearer ya29.test-2',
    ]);
  });

  it('sends wake-ups that start at the same time, then reuses the token', async () => {
    const results = await Promise.all(['a', 'b', 'c', 'd'].map((t) => sender.wake(t)));
    expect(results).toEqual(['sent', 'sent', 'sent', 'sent']);
    expect(google.sends).toHaveLength(4);
    // No request in flight is shared (Workers ties I/O to its request), so each may ask once.
    const asked = google.tokenRequests.length;
    expect(asked).toBeGreaterThanOrEqual(1);
    expect(asked).toBeLessThanOrEqual(4);
    await sender.wake('e');
    expect(google.tokenRequests).toHaveLength(asked);
  });

  it('reports an unregistered token', async () => {
    google.fcmAnswers.push(UNREGISTERED);
    expect(await sender.wake('gone')).toBe('unregistered');
  });

  it('does not take other FCM errors for an unregistered token', async () => {
    const answers: { status: number; body?: unknown }[] = [
      { status: 404, body: { error: { code: 404, status: 'NOT_FOUND' } } },
      { status: 404, body: 'not json at all' },
      {
        status: 404,
        body: {
          error: {
            details: [{ '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError', errorCode: 'INTERNAL' }],
          },
        },
      },
      {
        status: 404,
        body: { error: { details: [{ '@type': 'type.googleapis.com/google.rpc.BadRequest', errorCode: 'UNREGISTERED' }] } },
      },
      { status: 400, body: { error: { code: 400, status: 'INVALID_ARGUMENT', details: [UNREGISTERED] } } },
      {
        status: 400,
        body: {
          error: {
            details: [{ '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError', errorCode: 'UNREGISTERED' }],
          },
        },
      },
      { status: 403, body: { error: { code: 403, status: 'PERMISSION_DENIED' } } },
      { status: 429, body: { error: { code: 429, status: 'RESOURCE_EXHAUSTED' } } },
      { status: 500 },
      { status: 503 },
    ];
    for (const answer of answers) {
      google.fcmAnswers.push(answer);
      expect(await sender.wake('device-token'), JSON.stringify(answer)).toBe('failed');
    }
  });

  it('fails without throwing when Google gives no usable access token', async () => {
    const answers = [
      { status: 400, body: { error: 'invalid_grant' } },
      { status: 500 },
      { status: 200, body: { expires_in: 3599 } },
      { status: 200, body: { access_token: 'ya29.x', expires_in: '3599' } },
      { status: 200, body: { access_token: 'ya29.x', expires_in: 0 } },
      { status: 200, body: { access_token: 'has space', expires_in: 3599 } },
      { status: 200, body: null },
      'network_error' as const,
    ];
    for (const answer of answers) {
      google.tokenAnswers.push(answer);
      expect(await sender.wake('device-token'), JSON.stringify(answer)).toBe('failed');
    }
    expect(google.sends).toEqual([]);
    // A later wake-up asks again and works.
    expect(await sender.wake('device-token')).toBe('sent');
  });

  it('fails without throwing on a network error at FCM', async () => {
    google.fcmAnswers.push('network_error');
    expect(await sender.wake('device-token')).toBe('failed');
    expect(await sender.wake('device-token')).toBe('sent');
    expect(google.tokenRequests).toHaveLength(1);
  });

  it('gets a new access token once when FCM refuses the cached one', async () => {
    await sender.wake('a');
    google.revoked.add('ya29.test-1');
    expect(await sender.wake('b')).toBe('sent');
    expect(google.tokenRequests).toHaveLength(2);
    expect(google.sends.map((s) => s.headers.authorization)).toEqual([
      'Bearer ya29.test-1',
      'Bearer ya29.test-1',
      'Bearer ya29.test-2',
    ]);
    // A token refused again is not retried a second time.
    google.revoked.add('ya29.test-2');
    google.revoked.add('ya29.test-3');
    expect(await sender.wake('c')).toBe('failed');
    expect(google.tokenRequests).toHaveLength(3);
  });

  it('fails when the private key cannot be imported, and leaks nothing about it', async () => {
    const broken = new FcmSender(
      { ...account, privateKeyPem: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n' },
      google.fetch,
      () => now,
    );
    expect(await broken.wake('device-token')).toBe('failed');
    expect(google.requests).toEqual([]);
  });
});

// --- the deposit route --------------------------------------------------------

/** A push sender that records the tokens it was asked to wake. */
class RecordingPush implements PushSender {
  readonly woken: string[] = [];
  constructor(private readonly answer: () => Promise<WakeResult> = async () => 'sent') {}
  async wake(pushToken: string): Promise<WakeResult> {
    this.woken.push(pushToken);
    return this.answer();
  }
}

describe('deposit wake-ups', () => {
  let relay: FakeRelay;
  let owner: TestKey;
  let partner: TestKey;
  let inbox: string;

  beforeEach(async () => {
    relay = new FakeRelay(t0);
    owner = await testKey(seedOf(1));
    partner = await testKey(seedOf(2));
    inbox = await inboxIdFor(owner.publicKey);
  });
  afterEach(() => {
    relay.close();
  });

  async function send(key: TestKey, method: string, path: string, body: string | Uint8Array, headers = {}) {
    const signed = await signHeaders(key, {
      method,
      path,
      body,
      timestamp: Math.floor(relay.nowMs / 1000),
      nonce: freshNonce(),
    });
    return handleRequest(
      new Request(`https://relay.test${path}`, {
        method,
        body,
        headers: { ...signed, 'cf-connecting-ip': '203.0.113.7', ...headers },
      }),
      relay,
    );
  }

  async function pair(pushToken: string | null = 'test-fcm-token'): Promise<void> {
    expect((await send(owner, 'POST', '/v1/inbox', registrationBody(owner, pushToken))).status).toBe(201);
    const allow = JSON.stringify({ sender_key: partner.keyText });
    expect((await send(owner, 'POST', `/v1/inbox/${inbox}/allow`, allow)).status).toBe(201);
  }

  function deposit(wake: string, key = partner, body = new Uint8Array(300).fill(7)): Promise<Response> {
    return send(key, 'PUT', `/v1/inbox/${inbox}/envelopes`, body, { 'maw-wake': wake });
  }

  function storedToken(): unknown {
    return relay.deviceSql.get(inbox)?.('SELECT push_token FROM inbox')[0];
  }

  it('wakes the inbox’s phone once the envelope is stored, with Maw-Wake: 1', async () => {
    const push = new RecordingPush();
    relay.push = push;
    await pair();
    expect((await deposit('1')).status).toBe(201);
    await relay.settle();
    expect(push.woken).toEqual(['test-fcm-token']);
  });

  it('sends nothing for Maw-Wake: 0', async () => {
    const push = new RecordingPush();
    relay.push = push;
    await pair();
    expect((await deposit('0')).status).toBe(201);
    await relay.settle();
    expect(push.woken).toEqual([]);
    expect(relay.tasks).toEqual([]);
  });

  it('sends nothing when the deposit is refused', async () => {
    const push = new RecordingPush();
    relay.push = push;
    await pair();
    const stranger = await testKey(seedOf(3));
    expect((await deposit('1', stranger)).status).toBe(403);
    expect((await deposit('1', partner, new Uint8Array(0))).status).toBe(400);
    expect((await deposit('yes')).status).toBe(400);
    await relay.settle();
    expect(push.woken).toEqual([]);
  });

  it('sends nothing when the inbox has no push token, or the relay has no service account', async () => {
    const push = new RecordingPush();
    relay.push = push;
    await pair(null);
    expect((await deposit('1')).status).toBe(201);
    await relay.settle();
    expect(push.woken).toEqual([]);

    relay.push = null;
    expect((await send(owner, 'POST', `/v1/inbox/${inbox}/push-token`, '{"push_token":"t2"}')).status).toBe(200);
    expect((await deposit('1')).status).toBe(201);
    expect(relay.tasks).toEqual([]);
  });

  it('wakes the newest push token', async () => {
    const push = new RecordingPush();
    relay.push = push;
    await pair();
    expect((await send(owner, 'POST', `/v1/inbox/${inbox}/push-token`, '{"push_token":"token-2"}')).status).toBe(200);
    await deposit('1');
    await relay.settle();
    expect(push.woken).toEqual(['token-2']);
  });

  it('answers the deposit before the push finishes, and whatever the push does', async () => {
    let release: (r: WakeResult) => void = () => {};
    relay.push = new RecordingPush(() => new Promise((resolve) => (release = resolve)));
    await pair();
    const res = await deposit('1');
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({});
    release('failed');
    await relay.settle();

    relay.push = new RecordingPush(() => Promise.reject(new Error('push broke')));
    expect((await deposit('1')).status).toBe(201);
    await relay.settle();
    expect(storedToken()).toEqual({ push_token: 'test-fcm-token' });
  });

  it('forgets a token FCM calls unregistered', async () => {
    relay.push = new RecordingPush(async () => 'unregistered');
    await pair();
    await deposit('1');
    await relay.settle();
    expect(storedToken()).toEqual({ push_token: null });
    // No token, no more wake-ups, and deposits still work.
    const push = new RecordingPush();
    relay.push = push;
    expect((await deposit('1')).status).toBe(201);
    await relay.settle();
    expect(push.woken).toEqual([]);
  });

  it('keeps a token the phone sent while FCM was answering about the old one', async () => {
    let release: (r: WakeResult) => void = () => {};
    relay.push = new RecordingPush(() => new Promise((resolve) => (release = resolve)));
    await pair();
    await deposit('1');
    expect((await send(owner, 'POST', `/v1/inbox/${inbox}/push-token`, '{"push_token":"token-2"}')).status).toBe(200);
    release('unregistered');
    await relay.settle();
    expect(storedToken()).toEqual({ push_token: 'token-2' });
  });

  it('end to end with the FCM sender: one message to the right token, nothing else', async () => {
    const google = new FakeGoogle(publicKey, account);
    relay.push = new FcmSender(account, google.fetch, () => relay.nowMs);
    await pair();
    await deposit('1');
    await deposit('0');
    await deposit('1');
    await relay.settle();
    expect(google.tokenRequests).toHaveLength(1);
    expect(google.sends.map((s) => s.body)).toEqual([wakeMessage('test-fcm-token'), wakeMessage('test-fcm-token')]);
    // Nothing that names the inbox, the sender or the envelope leaves the relay.
    const everything = JSON.stringify(google.requests);
    for (const secret of [inbox, partner.keyText, owner.keyText, Buffer.from(new Uint8Array(300).fill(7)).toString('base64')]) {
      expect(everything).not.toContain(secret);
    }

    google.fcmAnswers.push(UNREGISTERED);
    await deposit('1');
    await relay.settle();
    expect(storedToken()).toEqual({ push_token: null });
  });
});
