// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// The SQLite-backed Durable Object classes (spec 4.5). They are thin: the
// logic is in DeviceState, PairingSlots and the WindowCounter classes, which the unit tests
// run on Node's SQLite with a fake clock. Alarms delete what has expired, and
// an object with nothing left deletes all of its storage.
//
// Times: requests pass the Worker's clock in (`nowMs`), so the handler and
// the unit tests share one clock; alarms read the object's own `Date.now()`.
// Both are Cloudflare's clock, so the difference is negligible.

import { DurableObject } from 'cloudflare:workers';
import {
  type AllowResult,
  type DepositResult,
  DeviceState,
  type AckResult,
  type FetchResult,
  type RegisterResult,
  type Registration,
} from './device_state';
import {
  type CreateResult,
  type LookupResult,
  PairingSlots,
  type ReadReplyResult,
  type ReplyResult,
} from './pairing_slots';
import { LookupFailureCounter, type RateLimitResult, RegistrationCounter, type WindowCounter } from './rate_limit';
import type { Sql, SqlRow, SqlValue } from './sql';

export interface Env {
  DEVICES: DurableObjectNamespace<DeviceObject>;
  REGISTRATION_LIMITS: DurableObjectNamespace<RegistrationLimitObject>;
  LOOKUP_LIMITS: DurableObjectNamespace<LookupLimitObject>;
  PAIRING_SLOTS: DurableObjectNamespace<PairingSlotsObject>;
}

/** Durable Object SQL takes and returns BLOBs as `ArrayBuffer`; the state classes use `Uint8Array`. */
function sqlOf(storage: DurableObjectStorage): Sql {
  const toStorage = (v: SqlValue) =>
    v instanceof Uint8Array ? v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) : v;
  const fromStorage = (row: Record<string, SqlStorageValue>): SqlRow => {
    const out: SqlRow = {};
    for (const [k, v] of Object.entries(row)) out[k] = v instanceof ArrayBuffer ? new Uint8Array(v) : v;
    return out;
  };
  return {
    exec: (query: string, ...bindings: SqlValue[]) =>
      storage.sql
        .exec(query, ...bindings.map(toStorage))
        .toArray()
        .map(fromStorage),
  };
}

/** One per device, named by its inbox ID: its nonces, its inbox, its allowed sender and its envelopes. */
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

  async allow(senderKey: string): Promise<AllowResult> {
    return this.state.allow(senderKey);
  }

  async deposit(senderKey: string, body: Uint8Array, nowMs: number): Promise<DepositResult> {
    return this.state.deposit(senderKey, body, nowMs);
  }

  async fetchEnvelopes(after: number | null): Promise<FetchResult> {
    return this.state.fetchEnvelopes(after);
  }

  async ack(cursor: number): Promise<AckResult> {
    return this.state.ack(cursor);
  }

  async setPushToken(pushToken: string | null): Promise<boolean> {
    return this.state.setPushToken(pushToken);
  }

  async deleteInbox(): Promise<void> {
    // The request that asked for this recorded a nonce, so an alarm is set:
    // it deletes all of the object's storage once that nonce has expired.
    this.state.deleteInbox();
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

/** A per-IP-bucket counter whose storage is deleted once its window has passed. */
abstract class WindowLimitObject extends DurableObject<Env> {
  private cached: WindowCounter | null = null;

  protected abstract makeCounter(sql: Sql): WindowCounter;

  protected get counter(): WindowCounter {
    this.cached ??= this.makeCounter(sqlOf(this.ctx.storage));
    return this.cached;
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

/** One per IP bucket, named by a hash of it: registration times of the last hour. */
export class RegistrationLimitObject extends WindowLimitObject {
  protected makeCounter(sql: Sql): WindowCounter {
    return new RegistrationCounter(sql);
  }

  async hit(nowMs: number): Promise<RateLimitResult> {
    const result = this.counter.hit(nowMs);
    if (result.allowed) await this.ctx.storage.setAlarm(result.clearAt);
    return result;
  }
}

/**
 * One per IP bucket, named by a hash of it: code lookups of the last
 * 10 minutes that found no open slot. Every counted lookup sets the alarm,
 * also when it is refunded, so the object always deletes itself.
 */
export class LookupLimitObject extends WindowLimitObject {
  protected makeCounter(sql: Sql): WindowCounter {
    return new LookupFailureCounter(sql);
  }

  async reserve(nowMs: number): Promise<RateLimitResult> {
    const result = this.counter.hit(nowMs);
    if (result.allowed) await this.ctx.storage.setAlarm(result.clearAt);
    return result;
  }

  async refund(atMs: number): Promise<void> {
    this.counter.refund(atMs);
  }
}

/** The one object holding every live pairing slot (named `PAIRING_SLOTS_NAME`). */
export class PairingSlotsObject extends DurableObject<Env> {
  private cached: PairingSlots | null = null;

  private get slots(): PairingSlots {
    this.cached ??= new PairingSlots(sqlOf(this.ctx.storage));
    return this.cached;
  }

  async create(creator: string, bundle: string, nowMs: number): Promise<CreateResult> {
    const result = this.slots.create(creator, bundle, nowMs);
    await this.scheduleExpiry(nowMs);
    return result;
  }

  async lookup(handle: { readonly slotId: string } | { readonly code: string }, nowMs: number): Promise<LookupResult> {
    return this.slots.lookup(handle, nowMs);
  }

  async reply(slotId: string, replier: string, reply: string, nowMs: number): Promise<ReplyResult> {
    return this.slots.reply(slotId, replier, reply, nowMs);
  }

  async readReply(slotId: string, creator: string, nowMs: number): Promise<ReadReplyResult> {
    return this.slots.readReply(slotId, creator, nowMs);
  }

  /** Wakes up when the next slot expires, unless an earlier alarm is already set. */
  private async scheduleExpiry(nowMs: number): Promise<void> {
    const next = this.slots.prune(nowMs);
    if (next === null) return;
    const alarm = await this.ctx.storage.getAlarm();
    if (alarm === null || alarm > next) await this.ctx.storage.setAlarm(next);
  }

  override async alarm(): Promise<void> {
    const next = this.slots.prune(Date.now());
    if (next !== null) {
      await this.ctx.storage.setAlarm(next);
    } else {
      await this.ctx.storage.deleteAll();
      this.cached = null;
    }
  }
}
