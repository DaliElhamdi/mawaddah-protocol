// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// The handler's dependencies backed by the real state classes over in-memory
// SQLite, with a settable clock: the Durable Objects without the runtime.

import type { DeviceApi, RateLimiterApi, RelayDeps } from '../../src/handler';
import { DeviceState } from '../../src/device_state';
import { RegistrationCounter } from '../../src/rate_limit';
import { memorySql } from './sqlite';

export class FakeRelay implements RelayDeps {
  constructor(public nowMs: number) {}

  readonly devices = new Map<string, DeviceState>();
  readonly buckets = new Map<string, RegistrationCounter>();
  private readonly closers: (() => void)[] = [];

  device(inboxId: string): DeviceApi {
    let state = this.devices.get(inboxId);
    if (state === undefined) {
      const sql = memorySql();
      this.closers.push(sql.close);
      state = new DeviceState(sql);
      this.devices.set(inboxId, state);
    }
    const s = state;
    return {
      useNonce: async (nonce, now) => s.useNonce(nonce, now),
      registration: async () => s.registration(),
      register: async (r) => s.register(r),
    };
  }

  async registrationLimiter(bucket: string): Promise<RateLimiterApi> {
    let counter = this.buckets.get(bucket);
    if (counter === undefined) {
      const sql = memorySql();
      this.closers.push(sql.close);
      counter = new RegistrationCounter(sql);
      this.buckets.set(bucket, counter);
    }
    const c = counter;
    return { hit: async (now) => c.hit(now) };
  }

  now(): number {
    return this.nowMs;
  }

  close(): void {
    for (const c of this.closers) c();
  }
}
