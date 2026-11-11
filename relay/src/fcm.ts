// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Content-free wake-ups through Firebase Cloud Messaging (spec 4.5, 8.7).
//
// The relay sends one FCM HTTP v1 *data message*, high priority, whose data
// is exactly {"t":"s"}: no content, no inbox ID, no sender, no count. The
// phone that wakes up syncs and builds its notification from what it
// decrypts. The Worker signs Google's service-account JWT itself
// (RFC 7523 / Google's "OAuth 2.0 for server to server applications"): the
// key is the Worker secret FCM_SERVICE_ACCOUNT and never leaves the Worker.
//
// Google's addresses are fixed here, not read from the secret, so a changed
// secret cannot send push tokens or signed assertions anywhere else.
//
// Nothing here logs: not the secret, not a push token, not an answer.

import { toBase64Url } from './encoding';

/** Where the signed assertion is exchanged for an access token (also the JWT `aud`). */
export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';

/** The FCM HTTP v1 send endpoint of a Firebase project. */
export function fcmSendUrl(projectId: string): string {
  return `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/messages:send`;
}

/** The only scope the relay asks for: sending FCM messages. */
export const FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';

/** Lifetime asked for in the JWT (Google's maximum: one hour). */
export const ASSERTION_LIFETIME_S = 3600;

/** An access token is renewed this long before Google says it expires. */
export const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;

/** The whole data payload of every wake-up (spec 4.5): "sync". */
export const WAKE_DATA: Readonly<Record<string, string>> = Object.freeze({ t: 's' });

/**
 * The FCM collapse key of every wake-up. While the phone is offline FCM keeps
 * only the newest message with this key, so a phone that comes back gets one
 * wake-up, not one per envelope (the payload is the same anyway).
 */
export const WAKE_COLLAPSE_KEY = 's';

/** The fields of a Google service-account key file the relay uses. */
export interface ServiceAccount {
  readonly projectId: string;
  readonly clientEmail: string;
  readonly privateKeyId: string;
  /** The PKCS#8 private key in PEM form, as in the key file (see `pkcs8FromPem`). */
  readonly privateKeyPem: string;
}

/** Firebase project IDs: 6 to 30 characters, lowercase letters, digits and hyphens. */
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

/**
 * Reads the service-account JSON (as downloaded from the Firebase console),
 * or null when it is not one. Only the four fields above are kept.
 */
export function parseServiceAccount(text: string): ServiceAccount | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const f = parsed as Record<string, unknown>;
  const { type, project_id, client_email, private_key_id, private_key } = f;
  if (type !== 'service_account') return null;
  if (typeof project_id !== 'string' || !PROJECT_ID.test(project_id)) return null;
  if (typeof client_email !== 'string' || !/^[^\s@]+@[^\s@]+$/.test(client_email)) return null;
  if (typeof private_key_id !== 'string' || !/^[0-9a-f]{1,128}$/i.test(private_key_id)) return null;
  if (typeof private_key !== 'string' || pkcs8FromPem(private_key) === null) return null;
  return { projectId: project_id, clientEmail: client_email, privateKeyId: private_key_id, privateKeyPem: private_key };
}

/** The PEM label of a PKCS#8 private key. */
export const PKCS8_PEM_LABEL = 'PRIVATE KEY';

/**
 * A PKCS#8 PEM block. Built from the label at run time, so this source file
 * never contains a PEM header that secret scanners would report as a key.
 */
const PKCS8_PEM = new RegExp(
  `^\\s*-----BEGIN ${PKCS8_PEM_LABEL}-----([A-Za-z0-9+/=\\s]+)-----END ${PKCS8_PEM_LABEL}-----\\s*$`,
);

/** The DER bytes of a PKCS#8 PEM private key, or null. */
export function pkcs8FromPem(pem: string): Uint8Array | null {
  const match = PKCS8_PEM.exec(pem);
  if (match === null) return null;
  try {
    const binary = atob((match[1] ?? '').replace(/\s+/g, ''));
    if (binary.length === 0) return null;
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** What happened to one wake-up. */
export type WakeResult =
  /** FCM accepted the message (delivery is up to Google and the phone). */
  | 'sent'
  /** FCM says the token is no longer valid (app uninstalled, data cleared): forget it. */
  | 'unregistered'
  /** Anything else: no access token, network, quota, FCM error. Not retried. */
  | 'failed';

/** Sends wake-ups; the handler uses it after an envelope with `Maw-Wake: 1` is stored. */
export interface PushSender {
  wake(pushToken: string): Promise<WakeResult>;
}

export type FetchFn = (url: string, init: RequestInit) => Promise<Response>;

/** A WebCrypto key (named this way so the Worker and Node type sets both accept it). */
type SigningKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>;

interface AccessToken {
  readonly value: string;
  /** When to stop using it (Google's expiry minus the margin), in ms. */
  readonly renewAt: number;
}

/**
 * Sends wake-ups through FCM with one service account. One instance lives
 * per Worker isolate, so the access token is shared by the requests that
 * isolate serves and asked for again only when it nears expiry.
 */
export class FcmSender implements PushSender {
  private key: Promise<SigningKey> | null = null;
  /**
   * The cached access token. Only this plain value is shared between
   * requests: a request in flight is not, because Workers ties I/O to the
   * request that started it, so wake-ups that start together while no token
   * is cached each ask for one (only right after the isolate starts).
   */
  private token: AccessToken | null = null;

  constructor(
    private readonly account: ServiceAccount,
    private readonly fetchFn: FetchFn,
    /** Clock in ms since the Unix epoch. */
    private readonly now: () => number,
  ) {}

  async wake(pushToken: string): Promise<WakeResult> {
    try {
      return await this.tryWake(pushToken);
    } catch {
      // A network error, or an answer that is not what FCM documents.
      return 'failed';
    }
  }

  private async tryWake(pushToken: string): Promise<WakeResult> {
    let token = await this.accessToken();
    if (token === null) return 'failed';
    let res = await this.send(token, pushToken);
    if (res.status === 401) {
      // Google refused the access token before its time (revoked key):
      // forget it and try once with a new one.
      this.forget(token);
      token = await this.accessToken();
      if (token === null) return 'failed';
      res = await this.send(token, pushToken);
    }
    if (res.ok) {
      await discard(res);
      return 'sent';
    }
    return (await isUnregistered(res)) ? 'unregistered' : 'failed';
  }

  private send(token: AccessToken, pushToken: string): Promise<Response> {
    return this.fetchFn(fcmSendUrl(this.account.projectId), {
      method: 'POST',
      headers: { authorization: `Bearer ${token.value}`, 'content-type': 'application/json' },
      body: wakeMessage(pushToken),
    });
  }

  private forget(token: AccessToken): void {
    if (this.token === token) this.token = null;
  }

  /** A cached access token, or a new one; null when Google did not give one. */
  private async accessToken(): Promise<AccessToken | null> {
    if (this.token !== null && this.now() < this.token.renewAt) return this.token;
    return this.requestToken();
  }

  private async requestToken(): Promise<AccessToken | null> {
    try {
      const issuedAt = this.now();
      const assertion = await this.assertion(issuedAt);
      const res = await this.fetchFn(GOOGLE_TOKEN_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }).toString(),
      });
      if (!res.ok) {
        await discard(res);
        return null;
      }
      const fields = (await res.json()) as Record<string, unknown> | null;
      const value = fields?.access_token;
      const expiresIn = fields?.expires_in;
      if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value)) return null;
      if (typeof expiresIn !== 'number' || !Number.isInteger(expiresIn) || expiresIn <= 0) return null;
      // Counted from before the request, so network time only shortens the use.
      const token = { value, renewAt: issuedAt + expiresIn * 1000 - TOKEN_REFRESH_MARGIN_MS };
      this.token = token;
      return token;
    } catch {
      return null;
    }
  }

  /** The signed JWT (RS256) Google exchanges for an access token. */
  async assertion(issuedAtMs: number): Promise<string> {
    const iat = Math.floor(issuedAtMs / 1000);
    const header = { alg: 'RS256', typ: 'JWT', kid: this.account.privateKeyId };
    const claims = {
      iss: this.account.clientEmail,
      scope: FCM_SCOPE,
      aud: GOOGLE_TOKEN_URL,
      iat,
      exp: iat + ASSERTION_LIFETIME_S,
    };
    const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      await this.signingKey(),
      new TextEncoder().encode(signingInput),
    );
    return `${signingInput}.${toBase64Url(new Uint8Array(signature))}`;
  }

  private signingKey(): Promise<SigningKey> {
    if (this.key === null) {
      const key = (async () => {
        const der = pkcs8FromPem(this.account.privateKeyPem);
        if (der === null) throw new Error('bad key');
        return crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
      })();
      // A key that failed to import is tried again next time.
      key.catch(() => {
        if (this.key === key) this.key = null;
      });
      this.key = key;
    }
    return this.key;
  }
}

/**
 * The FCM HTTP v1 request body of one wake-up: a data message (no
 * `notification` block, so Android never shows anything by itself), high
 * priority so a sleeping phone wakes, data exactly {"t":"s"}.
 */
export function wakeMessage(pushToken: string): string {
  return JSON.stringify({
    message: {
      token: pushToken,
      data: WAKE_DATA,
      android: { priority: 'HIGH', collapse_key: WAKE_COLLAPSE_KEY },
    },
  });
}

/** True when FCM's error answer names the token as unregistered (HTTP 404, `UNREGISTERED`). */
async function isUnregistered(res: Response): Promise<boolean> {
  if (res.status !== 404) {
    await discard(res);
    return false;
  }
  try {
    const body = (await res.json()) as { error?: { details?: unknown } } | null;
    const details = body?.error?.details;
    return (
      Array.isArray(details) &&
      details.some(
        (d) =>
          typeof d === 'object' &&
          d !== null &&
          (d as Record<string, unknown>)['@type'] === 'type.googleapis.com/google.firebase.fcm.v1.FcmError' &&
          (d as Record<string, unknown>).errorCode === 'UNREGISTERED',
      )
    );
  } catch {
    return false;
  }
}

/** Reads and drops an answer body, so the connection can be reused. */
async function discard(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    // Nothing to do.
  }
}

function base64UrlJson(value: unknown): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}
