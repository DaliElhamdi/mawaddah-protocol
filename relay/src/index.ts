// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Blind relay (spec 4.5): the Worker entry point. It wires the request
// handler to the Durable Objects and the clock. Nothing here logs requests,
// bodies or IP addresses.

import { type Env } from './durable_objects';
import { handleRequest, type RelayDeps } from './handler';
import { bucketObjectName } from './rate_limit';

export { DeviceObject, LookupLimitObject, PairingSlotsObject, RegistrationLimitObject } from './durable_objects';

/** The name of the one Durable Object that holds every pairing slot. */
const PAIRING_SLOTS_NAME = 'pairing-slots';

function depsFor(env: Env): RelayDeps {
  return {
    device: (inboxId) => env.DEVICES.get(env.DEVICES.idFromName(inboxId)),
    registrationLimiter: (bucket) => ({
      hit: async (nowMs) =>
        env.REGISTRATION_LIMITS.get(env.REGISTRATION_LIMITS.idFromName(await bucketObjectName(bucket))).hit(nowMs),
    }),
    lookupLimiter: (bucket) => {
      const stub = async () => env.LOOKUP_LIMITS.get(env.LOOKUP_LIMITS.idFromName(await bucketObjectName(bucket)));
      return {
        check: async (nowMs) => (await stub()).check(nowMs),
        fail: async (nowMs) => (await stub()).fail(nowMs),
      };
    },
    pairingSlots: () => env.PAIRING_SLOTS.get(env.PAIRING_SLOTS.idFromName(PAIRING_SLOTS_NAME)),
    now: () => Date.now(),
  };
}

export default {
  fetch(request, env): Promise<Response> {
    return handleRequest(request, depsFor(env));
  },
} satisfies ExportedHandler<Env>;
