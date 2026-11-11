// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';

import '../ratchet/support.dart' show pair;

/// The relay could not be reached.
final class RelayDown implements Exception {
  const RelayDown(this.what);
  final String what;
  @override
  String toString() => 'RelayDown($what)';
}

/// A [FakeRelayClient] with faults: offline, failing deposits, lost ACKs,
/// duplicate and repeated deliveries, and a gate that holds fetches.
final class FlakyRelay implements RelayClient {
  final inner = FakeRelayClient();

  /// Every call fails before reaching the relay.
  var online = true;

  /// The next this-many deposits fail before reaching the relay.
  var failDeposits = 0;

  /// The next this-many ACKs reach the relay (which deletes) but the answer
  /// is lost: the caller sees a failure.
  var loseAckAnswers = 0;

  /// The next this-many ACKs fail before reaching the relay.
  var failAcks = 0;

  /// ACKs answer success but delete nothing.
  var dropAcks = false;

  /// Fetch ignores `after` and returns every pending envelope twice.
  var duplicates = false;

  /// When set, fetch waits for it.
  Completer<void>? gate;

  /// Every deposit that reached the relay: inbox and bytes.
  final deposited = <(String, Uint8List)>[];
  var fetches = 0, acks = 0, active = 0, maxActive = 0;

  Future<T> _call<T>(String what, Future<T> Function() body) async {
    active++;
    if (active > maxActive) maxActive = active;
    try {
      if (!online) throw RelayDown(what);
      return await body();
    } finally {
      active--;
    }
  }

  @override
  Future<void> deposit(String inboxId, Uint8List body, {bool wake = false}) =>
      _call('deposit', () async {
        if (failDeposits > 0) {
          failDeposits--;
          throw const RelayDown('deposit');
        }
        deposited.add((inboxId, Uint8List.fromList(body)));
        await inner.deposit(inboxId, body, wake: wake);
      });

  @override
  Future<List<RelayEnvelope>> fetch(String inboxId, {String? after}) =>
      _call('fetch', () async {
        fetches++;
        if (gate case final g?) await g.future;
        if (!duplicates) return inner.fetch(inboxId, after: after);
        final all = await inner.fetch(inboxId);
        return [
          for (final e in all) ...[e, e],
        ];
      });

  @override
  Future<void> ack(String inboxId, String cursor) => _call('ack', () async {
    acks++;
    if (failAcks > 0) {
      failAcks--;
      throw const RelayDown('ack');
    }
    if (dropAcks) return;
    await inner.ack(inboxId, cursor);
    if (loseAckAnswers > 0) {
      loseAckAnswers--;
      throw const RelayDown('ack answer');
    }
  });

  /// Envelopes waiting in [inbox].
  Future<int> pending(String inbox) async => (await inner.fetch(inbox)).length;
}

/// One paired phone: its stores, HLC, event factory and sync engine.
final class Device {
  Device._(
    this.name,
    this.crypto,
    this.pairing,
    this.clock,
    this.relay,
    this.seed,
  ) : events = InMemoryEventStore() {
    store = InMemorySyncStore(events);
  }

  final String name;
  final Crypto crypto;
  final PairingResult pairing;
  final FakeClock clock;
  final RelayClient relay;
  final int seed;
  final InMemoryEventStore events;
  late final InMemorySyncStore store;
  late SyncEngine engine;
  late EventFactory factory;
  var _restarts = 0;

  DeviceIdentity get identity => pairing.identity;
  String get inbox => identity.deviceId.toBase64Url();

  /// A fresh engine over the same stores, as after the app restarts.
  Future<void> restart() async {
    _restarts++;
    final hlc = HlcClock(clock, last: await store.hlc());
    factory = EventFactory(
      hlc: hlc,
      random: SeededRandom(seed * 1000 + _restarts),
      author: identity.deviceId,
    );
    engine = SyncEngine(
      crypto: crypto,
      random: SeededRandom(seed * 1000 + 500 + _restarts),
      relay: relay,
      store: store,
      applier: Applier(events, localDevice: identity.deviceId),
      identity: identity,
      partner: pairing.partner,
      hlc: hlc,
    );
  }

  Event message(String text) => factory.make(
    entityType: 'message',
    entityId: factory.newEntityId(),
    op: EventOp.create,
    payload: {'text': text},
  );

  Future<void> say(String text) => engine.commitLocal([message(text)]);

  /// Chat texts, in the order they were written.
  List<String> messages() {
    final list =
        events.entities
            .where((e) => e.entityType == 'message' && !e.isDeleted)
            .toList()
          ..sort((a, b) => a.created!.compareTo(b.created!));
    return [for (final e in list) e.values['text']! as String];
  }

  Future<SyncReport> sync() => engine.syncOnce();

  /// Seals [plaintext] for the partner outside the engine, with the next
  /// counter and the stored session, and deposits it (for refused
  /// plaintexts).
  Future<void> sendRaw(Uint8List plaintext) async {
    final session = RatchetSession.fromStorageBytes(
      crypto: crypto,
      random: SeededRandom(seed * 7919),
      clock: clock,
      bytes: (await store.session())!,
    );
    final counter = await store.lastCounter() + 1;
    await store.putLastCounter(counter);
    final bytes = Envelope.seal(
      crypto: crypto,
      sender: identity,
      recipient: pairing.partner.deviceId,
      counter: counter,
      hlc: engine.hlc.send(),
      session: session,
      plaintext: plaintext,
    );
    await store.putSession(session.toStorageBytes());
    session.dispose();
    await relay.deposit(pairing.partner.deviceId.toBase64Url(), bytes);
  }
}

/// A paired couple: `alice` is the joiner (sends first), `bob` the
/// initiator. Each has its own clock, both start at the same time.
Future<({Device alice, Device bob, FlakyRelay relay})> couple(
  Crypto crypto, {
  DateTime? start,
}) async {
  final p = pair(crypto);
  final relay = FlakyRelay();
  final t = start ?? DateTime.utc(2026, 11, 11, 12);
  Future<Device> make(String name, PairingResult r, int seed) async {
    final d = Device._(name, crypto, r, FakeClock(t), relay, seed);
    final session = RatchetSession.fromPairing(
      crypto: crypto,
      random: SeededRandom(seed),
      clock: d.clock,
      pairing: r,
    );
    await d.store.putSession(session.toStorageBytes());
    session.dispose();
    await d.restart();
    return d;
  }

  return (
    alice: await make('alice', p.joiner, 10),
    bob: await make('bob', p.initiator, 11),
    relay: relay,
  );
}

/// Moves both phones' clocks forward.
void advanceBoth(Device a, Device b, Duration by) {
  a.clock.advance(by);
  b.clock.advance(by);
}
