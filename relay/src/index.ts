// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Blind relay (spec 4.5): the Worker entry point. It wires the request
// handler to the Durable Objects and the clock. Nothing here logs requests,
// bodies or IP addresses.

import { type Env } from './durable_objects';
import { handleRequest, type RelayDeps } from './handler';
import { bucketObjectName } from './rate_limit';

export { DeviceObject, RegistrationLimitObject } from './durable_objects';

function depsFor(env: Env): RelayDeps {
  return {
    device: (inboxId) => env.DEVICES.get(env.DEVICES.idFromName(inboxId)),
    registrationLimiter: (bucket) => ({
      hit: async (nowMs) =>
        env.REGISTRATION_LIMITS.get(env.REGISTRATION_LIMITS.idFromName(await bucketObjectName(bucket))).hit(nowMs),
    }),
    now: () => Date.now(),
  };
}

export default {
  fetch(request, env): Promise<Response> {
    return handleRequest(request, depsFor(env));
  },
} satisfies ExportedHandler<Env>;
