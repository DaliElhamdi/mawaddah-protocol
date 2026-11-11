// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Blind relay (spec 4.5): the Worker entry point. It wires the request
// handler to the Durable Objects and the clock. Nothing here logs requests,
// bodies or IP addresses.

import { type Env } from './durable_objects';
import { FcmSender, parseServiceAccount, type PushSender } from './fcm';
import { handleRequest, type RelayDeps } from './handler';
import { bucketObjectName } from './rate_limit';

export { DeviceObject, LookupLimitObject, PairingSlotsObject, RegistrationLimitObject } from './durable_objects';

/** The name of the one Durable Object that holds every pairing slot. */
const PAIRING_SLOTS_NAME = 'pairing-slots';

/**
 * The push sender of this isolate, kept between requests so its FCM access
 * token is reused until it nears expiry. Rebuilt when the secret changes; the
 * secret string is kept only to notice that (it is in `env` anyway).
 */
let fcm: { readonly secret: string; readonly sender: PushSender | null } | null = null;

/** The push sender for the secret FCM_SERVICE_ACCOUNT; null when it is unset or not a service-account key. */
function pushFor(env: Env): PushSender | null {
  const secret = env.FCM_SERVICE_ACCOUNT;
  if (secret === undefined || secret === '') return null;
  if (fcm?.secret !== secret) {
    const account = parseServiceAccount(secret);
    const sender =
      account === null ? null : new FcmSender(account, (url, init) => fetch(url, init), () => Date.now());
    fcm = { secret, sender };
  }
  return fcm.sender;
}

function depsFor(env: Env, ctx: ExecutionContext): RelayDeps {
  return {
    device: (inboxId) => env.DEVICES.get(env.DEVICES.idFromName(inboxId)),
    registrationLimiter: (bucket) => ({
      hit: async (nowMs) =>
        env.REGISTRATION_LIMITS.get(env.REGISTRATION_LIMITS.idFromName(await bucketObjectName(bucket))).hit(nowMs),
    }),
    lookupLimiter: (bucket) => {
      const stub = async () => env.LOOKUP_LIMITS.get(env.LOOKUP_LIMITS.idFromName(await bucketObjectName(bucket)));
      return {
        reserve: async (nowMs) => (await stub()).reserve(nowMs),
        refund: async (atMs) => (await stub()).refund(atMs),
      };
    },
    pairingSlots: () => env.PAIRING_SLOTS.get(env.PAIRING_SLOTS.idFromName(PAIRING_SLOTS_NAME)),
    push: pushFor(env),
    background: (task) => ctx.waitUntil(task),
    now: () => Date.now(),
  };
}

export default {
  fetch(request, env, ctx): Promise<Response> {
    return handleRequest(request, depsFor(env, ctx));
  },
} satisfies ExportedHandler<Env>;
