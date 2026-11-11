// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// A stand-in for Google's OAuth token endpoint and the FCM HTTP v1 API,
// used as the `fetch` of `FcmSender`. It checks the signed assertion with
// the public half of a throwaway RSA key made for the test, and records
// every request so the tests can show exactly what left the relay.

import { webcrypto } from 'node:crypto';
import { fcmSendUrl, GOOGLE_TOKEN_URL, PKCS8_PEM_LABEL, type ServiceAccount } from '../../src/fcm';

export type CryptoKey = webcrypto.CryptoKey;

export interface SeenRequest {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: string;
}

/**
 * A PEM block around [body] (already base64, with any line breaks). The
 * header is built here, so no source file holds a literal PEM key header
 * (the CI secret scan would report it).
 */
export function pemOf(body: string, label = PKCS8_PEM_LABEL): string {
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

/** A throwaway service account: a new 2048-bit RSA key, never a real one. */
export async function testServiceAccount(projectId = 'mawaddah-test'): Promise<{
  account: ServiceAccount;
  json: string;
  publicKey: CryptoKey;
}> {
  const pair = (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as webcrypto.CryptoKeyPair;
  const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const b64 = Buffer.from(der).toString('base64');
  const pem = pemOf(b64.replace(/(.{64})/g, '$1\n').trimEnd());
  const fields = {
    type: 'service_account',
    project_id: projectId,
    // Low-entropy on purpose (a real one is 40 random hex digits), so it does not look like a secret.
    private_key_id: 'a'.repeat(40),
    private_key: pem,
    client_email: `relay@${projectId}.iam.gserviceaccount.com`,
    client_id: '100000000000000000000',
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://example.invalid/not-google',
    universe_domain: 'googleapis.com',
  };
  return {
    account: {
      projectId,
      clientEmail: fields.client_email,
      privateKeyId: fields.private_key_id,
      privateKeyPem: pem,
    },
    json: JSON.stringify(fields),
    publicKey: pair.publicKey,
  };
}

function fromBase64Url(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

export type FcmAnswer = { status: number; body?: unknown } | 'network_error';

export class FakeGoogle {
  readonly requests: SeenRequest[] = [];
  /** Decoded claims of every assertion the token endpoint accepted. */
  readonly assertions: { header: Record<string, unknown>; claims: Record<string, unknown> }[] = [];
  /** Access tokens handed out, in order. */
  readonly issued: string[] = [];
  /** `expires_in` of the next tokens. */
  expiresIn = 3599;
  /** The next answers of the token endpoint (then 200 with a token). */
  readonly tokenAnswers: FcmAnswer[] = [];
  /** The next answers of the FCM endpoint (then 200). */
  readonly fcmAnswers: FcmAnswer[] = [];
  /** Access tokens FCM refuses with 401. */
  readonly revoked = new Set<string>();

  constructor(
    private readonly publicKey: CryptoKey,
    private readonly account: ServiceAccount,
  ) {}

  readonly fetch = async (url: string, init: RequestInit): Promise<Response> => {
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((v, k) => {
      headers[k] = v;
    });
    const body = typeof init.body === 'string' ? init.body : '';
    this.requests.push({ url, method: init.method ?? 'GET', headers, body });
    if (url === GOOGLE_TOKEN_URL) return this.token(body);
    if (url === fcmSendUrl(this.account.projectId)) return this.fcm(headers);
    return new Response('unexpected address', { status: 599 });
  };

  /** The FCM sends seen so far. */
  get sends(): SeenRequest[] {
    return this.requests.filter((r) => r.url !== GOOGLE_TOKEN_URL);
  }

  /** The token requests seen so far. */
  get tokenRequests(): SeenRequest[] {
    return this.requests.filter((r) => r.url === GOOGLE_TOKEN_URL);
  }

  private async token(body: string): Promise<Response> {
    const answer = this.tokenAnswers.shift();
    if (answer === 'network_error') throw new TypeError('network');
    if (answer !== undefined) return Response.json(answer.body ?? {}, { status: answer.status });
    const form = new URLSearchParams(body);
    if (form.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
      return Response.json({ error: 'unsupported_grant_type' }, { status: 400 });
    }
    const parts = (form.get('assertion') ?? '').split('.');
    if (parts.length !== 3) return Response.json({ error: 'invalid_grant' }, { status: 400 });
    const [h, c, sig] = parts as [string, string, string];
    const ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      this.publicKey,
      fromBase64Url(sig),
      new TextEncoder().encode(`${h}.${c}`),
    );
    if (!ok) return Response.json({ error: 'invalid_grant' }, { status: 400 });
    this.assertions.push({
      header: JSON.parse(Buffer.from(h, 'base64url').toString()) as Record<string, unknown>,
      claims: JSON.parse(Buffer.from(c, 'base64url').toString()) as Record<string, unknown>,
    });
    const token = `ya29.test-${this.issued.length + 1}`;
    this.issued.push(token);
    return Response.json({ access_token: token, expires_in: this.expiresIn, token_type: 'Bearer' });
  }

  private fcm(headers: Record<string, string>): Response {
    const token = (headers.authorization ?? '').replace(/^Bearer /, '');
    if (!this.issued.includes(token) || this.revoked.has(token)) {
      return Response.json({ error: { code: 401, status: 'UNAUTHENTICATED' } }, { status: 401 });
    }
    const answer = this.fcmAnswers.shift();
    if (answer === 'network_error') throw new TypeError('network');
    if (answer !== undefined) return Response.json(answer.body ?? {}, { status: answer.status });
    return Response.json({ name: `projects/${this.account.projectId}/messages/0:1` });
  }
}

/** FCM's documented answer for a token that is no longer valid. */
export const UNREGISTERED: FcmAnswer = {
  status: 404,
  body: {
    error: {
      code: 404,
      message: 'Requested entity was not found.',
      status: 'NOT_FOUND',
      details: [{ '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError', errorCode: 'UNREGISTERED' }],
    },
  },
};
