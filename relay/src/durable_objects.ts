// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// The two SQLite-backed Durable Object classes (spec 4.5). They are thin:
// the logic is in DeviceState and RegistrationCounter, which the unit tests
// run on Node's SQLite with a fake clock. Alarms delete what has expired, and
// an object with nothing left deletes all of its storage.
//
// Times: requests pass the Worker's clock in (`nowMs`), so the handler and
// the unit tests share one clock; alarms read the object's own `Date.now()`.
// Both are Cloudflare's clock, so the difference is negligible.

import { DurableObject } from 'cloudflare:workers';
import { DeviceState, type RegisterResult, type Registration } from './device_state';
import { type RateLimitResult, RegistrationCounter } from './rate_limit';
import type { Sql, SqlRow, SqlValue } from './sql';

export interface Env {
  DEVICES: DurableObjectNamespace<DeviceObject>;
  REGISTRATION_LIMITS: DurableObjectNamespace<RegistrationLimitObject>;
}

function sqlOf(storage: DurableObjectStorage): Sql {
  return {
    exec: (query: string, ...bindings: SqlValue[]) => storage.sql.exec(query, ...bindings).toArray() as SqlRow[],
  };
}

/** One per device, named by its inbox ID: its nonces and its inbox. */
export class DeviceObject extends DurableObject<Env> {
  private cached: DeviceState | null = null;

  private get state(): DeviceState {
    this.cached ??= new DeviceState(sqlOf(this.ctx.storage));
    return this.cached;
  }

  async useNonce(nonce: string, nowMs: number): Promise<boolean> {
    const fresh = this.state.useNonce(nonce, nowMs);
    if ((await this.ctx.storage.getAlarm()) === null) {
      const next = this.state.pruneNonces(nowMs);
      if (next !== null) await this.ctx.storage.setAlarm(next);
    }
    return fresh;
  }

  async registration(): Promise<Registration | null> {
    return this.state.registration();
  }

  async register(registration: Registration): Promise<RegisterResult> {
    return this.state.register(registration);
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    const next = this.state.pruneNonces(now);
    if (next !== null) {
      await this.ctx.storage.setAlarm(next);
    } else if (this.state.isEmpty(now)) {
      // A key that never registered (or whose inbox is gone) leaves nothing.
      await this.ctx.storage.deleteAll();
      this.cached = null;
    }
  }
}

/** One per IP bucket, named by a hash of it: registration times of the last hour. */
export class RegistrationLimitObject extends DurableObject<Env> {
  private cached: RegistrationCounter | null = null;

  private get counter(): RegistrationCounter {
    this.cached ??= new RegistrationCounter(sqlOf(this.ctx.storage));
    return this.cached;
  }

  async hit(nowMs: number): Promise<RateLimitResult> {
    const result = this.counter.hit(nowMs);
    if (result.allowed) await this.ctx.storage.setAlarm(result.clearAt);
    return result;
  }

  override async alarm(): Promise<void> {
    const clearAt = this.counter.prune(Date.now());
    if (clearAt !== null) {
      await this.ctx.storage.setAlarm(clearAt);
    } else {
      await this.ctx.storage.deleteAll();
      this.cached = null;
    }
  }
}
