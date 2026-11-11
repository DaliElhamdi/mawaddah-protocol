// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// The handler's dependencies backed by the real state classes over in-memory
// SQLite, with a settable clock: the Durable Objects without the runtime.

import type { DeviceApi, LookupLimiterApi, PairingSlotsApi, RateLimiterApi, RelayDeps } from '../../src/handler';
import { DeviceState } from '../../src/device_state';
import { PairingSlots, type RandomBytes, secureRandomBytes } from '../../src/pairing_slots';
import { LookupFailureCounter, RegistrationCounter } from '../../src/rate_limit';
import { memorySql } from './sqlite';

export class FakeRelay implements RelayDeps {
  constructor(
    public nowMs: number,
    private readonly random: RandomBytes = secureRandomBytes,
  ) {}

  readonly devices = new Map<string, DeviceState>();
  /** Runs a statement on a device's database (to show what the relay stores). */
  readonly deviceSql = new Map<string, (query: string) => unknown[]>();
  readonly buckets = new Map<string, RegistrationCounter>();
  readonly lookupBuckets = new Map<string, LookupFailureCounter>();
  private slots: PairingSlots | null = null;
  /** Every statement run on the slot database (to show what the relay stores). */
  slotSql: ((query: string) => unknown[]) | null = null;
  private readonly closers: (() => void)[] = [];

  /** The pairing-slot state (made on first use). */
  get slotState(): PairingSlots {
    if (this.slots === null) {
      const sql = memorySql();
      this.closers.push(sql.close);
      this.slotSql = (q) => sql.exec(q);
      this.slots = new PairingSlots(sql, this.random);
    }
    return this.slots;
  }

  pairingSlots(): PairingSlotsApi {
    const s = this.slotState;
    return {
      create: async (creator, bundle, now) => s.create(creator, bundle, now),
      lookup: async (handle, now) => s.lookup(handle, now),
      reply: async (slotId, replier, reply, now) => s.reply(slotId, replier, reply, now),
      readReply: async (slotId, creator, now) => s.readReply(slotId, creator, now),
    };
  }

  lookupLimiter(bucket: string): LookupLimiterApi {
    let counter = this.lookupBuckets.get(bucket);
    if (counter === undefined) {
      const sql = memorySql();
      this.closers.push(sql.close);
      counter = new LookupFailureCounter(sql);
      this.lookupBuckets.set(bucket, counter);
    }
    const c = counter;
    return {
      reserve: async (now) => c.hit(now),
      refund: async (at) => c.refund(at),
    };
  }

  device(inboxId: string): DeviceApi {
    let state = this.devices.get(inboxId);
    if (state === undefined) {
      const sql = memorySql();
      this.closers.push(sql.close);
      state = new DeviceState(sql);
      this.devices.set(inboxId, state);
      this.deviceSql.set(inboxId, (q) => sql.exec(q));
    }
    const s = state;
    return {
      useNonce: async (nonce, now) => s.useNonce(nonce, now),
      registration: async () => s.registration(),
      register: async (r) => s.register(r),
      allow: async (key) => s.allow(key),
      // Copied, as Durable Object RPC does: the state must not keep the caller's buffer.
      deposit: async (key, body, now) => s.deposit(key, body.slice(), now),
      fetchEnvelopes: async (after, now) => s.fetchEnvelopes(after, now),
      putBlobChunk: async (key, blobId, size, index, body, now) =>
        s.putBlobChunk(key, blobId, size, index, body.slice(), now),
      // Copied out too: the handler must not see the state's buffer.
      getBlobChunk: async (blobId, index, now) => {
        const r = s.getBlobChunk(blobId, index, now);
        return r.kind === 'chunk' ? { ...r, body: r.body.slice() } : r;
      },
      deleteBlob: async (blobId, key) => s.deleteBlob(blobId, key),
      ack: async (cursor) => s.ack(cursor),
      setPushToken: async (token) => s.setPushToken(token),
      deleteInbox: async () => s.deleteInbox(),
    };
  }

  registrationLimiter(bucket: string): RateLimiterApi {
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
