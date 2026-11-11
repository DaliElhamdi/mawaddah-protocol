// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from 'vitest';
import { PairingSlots, type RandomBytes, SLOT_LIFETIME_MS } from '../src/pairing_slots';
import { memorySql } from './support/sqlite';

const t0 = 1762862400000;
const minute = 60 * 1000;
const bundle = '{"v":1,"b":"initiator"}';
const reply = '{"v":1,"r":"joiner"}';

let close: () => void = () => {};
function fresh(random?: RandomBytes, maxLive?: number): { slots: PairingSlots; rows: () => Record<string, unknown>[] } {
  const sql = memorySql();
  close = sql.close;
  return { slots: new PairingSlots(sql, random, maxLive), rows: () => sql.exec('SELECT * FROM slots ORDER BY code') };
}
afterEach(() => close());

/** A random source that returns [draws] (u32 values) for 4-byte requests, and counts up for slot IDs. */
function scripted(draws: number[]): RandomBytes {
  let id = 0;
  return (length) => {
    const out = new Uint8Array(length);
    if (length === 4) {
      const next = draws.shift();
      if (next === undefined) throw new Error('no more draws');
      new DataView(out.buffer).setUint32(0, next);
    } else {
      new DataView(out.buffer).setUint32(length - 4, ++id);
    }
    return out;
  };
}

function created(r: ReturnType<PairingSlots['create']>) {
  if (r.kind !== 'created' && r.kind !== 'repeat') throw new Error(`not created: ${r.kind}`);
  return r;
}

describe('PairingSlots.create', () => {
  it('returns a 16-byte slot ID, a 6-digit code and the expiry 10 minutes on', () => {
    const { slots } = fresh();
    const r = created(slots.create('key-a', bundle, t0));
    expect(r.kind).toBe('created');
    expect(r.slotId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(r.code).toMatch(/^[0-9]{6}$/);
    expect(r.expiresAt).toBe(t0 + SLOT_LIFETIME_MS);
    expect(SLOT_LIFETIME_MS).toBe(10 * minute);
  });

  it('gives the same slot to a retry with the same bundle, and refuses another bundle from that key', () => {
    const { slots, rows } = fresh();
    const first = created(slots.create('key-a', bundle, t0));
    expect(slots.create('key-a', bundle, t0 + minute)).toEqual({ ...first, kind: 'repeat' });
    expect(slots.create('key-a', '{"v":1,"b":"other"}', t0 + minute)).toEqual({ kind: 'conflict' });
    expect(rows()).toHaveLength(1);
  });

  it('keeps leading zeros and redraws values that would bias the code', () => {
    // 0xFFFFFFFF is above the last full block of 10^6, so it is redrawn.
    const { slots } = fresh(scripted([0xffffffff, 5]));
    expect(created(slots.create('key-a', bundle, t0)).code).toBe('000005');
  });

  it('gives each live slot its own code, drawing again on a clash', () => {
    const { slots } = fresh(scripted([123456, 123456, 1_123_456, 654321]));
    expect(created(slots.create('key-a', bundle, t0)).code).toBe('123456');
    // 123456 and 1,123,456 (same code mod 10^6) are taken; the third draw is used.
    expect(created(slots.create('key-b', bundle, t0)).code).toBe('654321');
  });

  it('draws again when a slot ID is taken', () => {
    let calls = 0;
    // Slot IDs: the same 16 bytes twice, then different ones. Codes: 1, 2, 3.
    const random: RandomBytes = (length) => {
      const out = new Uint8Array(length);
      if (length === 4) new DataView(out.buffer).setUint32(0, ++calls);
      else if (calls >= 3) out[0] = 0xff;
      return out;
    };
    const { slots } = fresh(random);
    const a = created(slots.create('key-a', bundle, t0));
    const b = created(slots.create('key-b', bundle, t0));
    expect([a.code, b.code]).toEqual(['000001', '000003']);
    expect(b.slotId).not.toBe(a.slotId);
  });

  it('answers full when no free code is found', () => {
    const { slots, rows } = fresh(scripted([7, ...new Array<number>(32).fill(7)]));
    created(slots.create('key-a', bundle, t0));
    expect(slots.create('key-b', bundle, t0)).toEqual({ kind: 'full' });
    expect(rows()).toHaveLength(1);
  });

  it('answers full at the live-slot cap, and has room again once slots expire', () => {
    const { slots } = fresh(undefined, 3);
    for (const k of ['a', 'b', 'c']) created(slots.create(k, bundle, t0));
    expect(slots.create('d', bundle, t0 + minute)).toEqual({ kind: 'full' });
    expect(created(slots.create('d', bundle, t0 + SLOT_LIFETIME_MS)).kind).toBe('created');
  });

  it('hands out many codes, all different', () => {
    const { slots } = fresh();
    const codes = new Set<string>();
    for (let i = 0; i < 2000; i++) codes.add(created(slots.create(`key-${i}`, bundle, t0)).code);
    expect(codes.size).toBe(2000);
  });
});

describe('PairingSlots lifetime', () => {
  it('serves a slot until it expires, then deletes it whole', () => {
    const { slots, rows } = fresh();
    const s = created(slots.create('key-a', bundle, t0));
    const last = t0 + SLOT_LIFETIME_MS - 1;
    expect(slots.lookup({ code: s.code }, last)).toEqual({ kind: 'found', slotId: s.slotId, bundle });
    expect(slots.lookup({ slotId: s.slotId }, last)).toEqual({ kind: 'found', slotId: s.slotId, bundle });
    const end = t0 + SLOT_LIFETIME_MS;
    expect(slots.lookup({ code: s.code }, end)).toEqual({ kind: 'not_found' });
    expect(rows()).toEqual([]);
    expect(slots.lookup({ slotId: s.slotId }, end)).toEqual({ kind: 'not_found' });
    expect(slots.reply(s.slotId, 'key-j', reply, end)).toEqual({ kind: 'not_found' });
    expect(slots.readReply(s.slotId, 'key-a', end)).toEqual({ kind: 'not_found' });
  });

  it('prune says when the next slot expires', () => {
    const { slots } = fresh();
    created(slots.create('key-a', bundle, t0));
    created(slots.create('key-b', bundle, t0 + minute));
    expect(slots.prune(t0)).toBe(t0 + SLOT_LIFETIME_MS);
    expect(slots.prune(t0 + SLOT_LIFETIME_MS)).toBe(t0 + minute + SLOT_LIFETIME_MS);
    expect(slots.prune(t0 + minute + SLOT_LIFETIME_MS)).toBeNull();
    expect(slots.count()).toBe(0);
  });

  it('expires a replied or closed slot too, and lets its key and code be used again', () => {
    const { slots, rows } = fresh(scripted([42, 42]));
    const s = created(slots.create('key-a', bundle, t0));
    slots.reply(s.slotId, 'key-j', reply, t0 + minute);
    slots.readReply(s.slotId, 'key-a', t0 + 2 * minute);
    expect(rows()).toHaveLength(1);
    const again = created(slots.create('key-a', bundle, t0 + SLOT_LIFETIME_MS));
    expect(again.code).toBe(s.code);
    expect(again.slotId).not.toBe(s.slotId);
  });
});

describe('PairingSlots single use', () => {
  it('takes the first reply and refuses a second one', () => {
    const { slots } = fresh();
    const s = created(slots.create('key-a', bundle, t0));
    expect(slots.reply(s.slotId, 'key-j', reply, t0)).toEqual({ kind: 'accepted' });
    expect(slots.reply(s.slotId, 'key-x', '{"v":1,"r":"thief"}', t0)).toEqual({ kind: 'used' });
    // The same joiner retrying the same reply (lost answer) is told it worked.
    expect(slots.reply(s.slotId, 'key-j', reply, t0)).toEqual({ kind: 'repeat' });
    // The same joiner with a different reply is not.
    expect(slots.reply(s.slotId, 'key-j', '{"v":1,"r":"changed"}', t0)).toEqual({ kind: 'used' });
    // Nobody can read the bundle any more.
    expect(slots.lookup({ code: s.code }, t0)).toEqual({ kind: 'used' });
    expect(slots.lookup({ slotId: s.slotId }, t0)).toEqual({ kind: 'used' });
    expect(slots.readReply(s.slotId, 'key-a', t0)).toEqual({ kind: 'reply', reply });
  });

  it('gives the reply only to the key that opened the slot, once, and then erases it', () => {
    const { slots, rows } = fresh();
    const s = created(slots.create('key-a', bundle, t0));
    expect(slots.readReply(s.slotId, 'key-a', t0)).toEqual({ kind: 'waiting' });
    expect(slots.readReply(s.slotId, 'key-j', t0)).toEqual({ kind: 'not_found' });
    slots.reply(s.slotId, 'key-j', reply, t0);
    expect(slots.readReply(s.slotId, 'key-j', t0)).toEqual({ kind: 'not_found' });
    expect(slots.readReply(s.slotId, 'key-a', t0)).toEqual({ kind: 'reply', reply });
    expect(rows()).toEqual([
      {
        slot_id: s.slotId,
        code: s.code,
        creator: 'key-a',
        bundle: null,
        replier: 'key-j',
        reply: null,
        state: 'closed',
        expires_at: t0 + SLOT_LIFETIME_MS,
      },
    ]);
    expect(slots.readReply(s.slotId, 'key-a', t0)).toEqual({ kind: 'used' });
    expect(slots.lookup({ code: s.code }, t0)).toEqual({ kind: 'used' });
    expect(slots.reply(s.slotId, 'key-x', reply, t0)).toEqual({ kind: 'used' });
    expect(slots.reply(s.slotId, 'key-j', reply, t0)).toEqual({ kind: 'repeat' });
    // The closed slot still holds its key: the initiator cannot open a second one with it.
    expect(slots.create('key-a', bundle, t0)).toEqual({ kind: 'conflict' });
  });
});
