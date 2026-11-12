// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Compaction (spec 4.6, PROTOCOL.md section 10): after 5,000 logged events of
// an entity type, the log of that type becomes one local snapshot event; the
// merged state does not change, and no content survives in the log.

import 'dart:convert';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';
import 'sync_support.dart' as sync;

/// Everything the store holds, as raw JSON text, to search for content.
Future<String> _raw(InMemoryEventStore store) async => jsonEncode({
  'events': [for (final e in store.events.values) e.toJson()],
  'entities': [
    for (final e in store.entities)
      {
        'type': e.entityType,
        'id': e.entityId,
        'fields': {
          for (final MapEntry(:key, :value) in e.fields.entries)
            key: value.value,
        },
      },
  ],
  'unapplied': [for (final u in await store.unapplied()) u.json],
});

List<Event> _logged(InMemoryEventStore store, String type) => [
  for (final e in store.events.values)
    if (e.entityType == type) e,
];

void main() {
  late Maker a, b;
  late InMemoryEventStore store;
  late Applier applier;
  late Compactor compactor;

  setUp(() {
    a = Maker(alice, 1);
    b = Maker(bob, 2);
    store = InMemoryEventStore();
    applier = Applier(store, localDevice: alice);
    compactor = Compactor(store, factory: Maker(alice, 3).factory);
  });

  /// [n] message events from both phones: creates, some deleted ("secret"
  /// texts), received in batches and made locally.
  Future<List<Event>> fill(int n) async {
    final made = <Event>[];
    final ids = <String>[];
    var pending = <Event>[];
    for (var i = 0; made.length < n; i++) {
      final fromBob = i.isOdd;
      final m = fromBob ? b : a;
      final Event e;
      if (i % 50 == 49 && ids.isNotEmpty) {
        e = m.make('message', ids.removeLast(), EventOp.delete);
      } else {
        final id = m.newId();
        ids.add(id);
        // The text of every message that is deleted later says "secret".
        final deletedLater = (i + 1) % 50 == 49;
        e = m.make('message', id, EventOp.create, {
          'text': deletedLater ? 'secret $i' : 'm$i',
        });
      }
      made.add(e);
      if (fromBob) {
        pending.add(e);
        if (pending.length == 7) {
          await applier.applyReceived(batch(pending), sender: bob);
          pending = [];
        }
      } else {
        await applier.applyLocal([e]);
      }
    }
    if (pending.isNotEmpty) {
      await applier.applyReceived(batch(pending), sender: bob);
    }
    return made;
  }

  test('5,001 events give one snapshot and the same state', () async {
    final made = await fill(5001);
    expect(made.where((e) => e.op == EventOp.delete), isNotEmpty);
    // A profile is another type, below the threshold.
    final profile = a.make('profile', a.newId(), EventOp.update, {
      'first_name': 'Amina',
    });
    await applier.applyLocal([profile]);
    expect(await store.loggedEventCount('message'), 5001);
    final before = await dump(store, log: false);

    expect(await compactor.compactIfNeeded(), {'message': 5001});

    expect(await dump(store, log: false), before);
    final log = _logged(store, 'message');
    expect(log, hasLength(1));
    final snapshot = log.single;
    expect(snapshot.op, EventOp.snapshot);
    expect(snapshot.payload, {'replaced': 5001});
    expect(snapshot.authorDevice, alice);
    expect(snapshot.entityId, isNot(anyOf([for (final e in made) e.entityId])));
    expect(store.droppedEventIds, {
      for (final e in made) e.eventId,
    }, reason: 'the IDs are kept to spot late copies');
    expect(_logged(store, 'profile'), [profile], reason: 'not compacted');
    expect(await store.loggedEventCount('message'), 1);
  });

  test('below the threshold nothing changes', () async {
    await fill(4999);
    final before = await dump(store);
    expect(await compactor.compactIfNeeded(), isEmpty);
    expect(await dump(store), before);
  });

  test('deleted content and replaced values are gone from the store', () async {
    await fill(5001);
    final id = a.newId();
    await applier.applyLocal([
      a.make('profile', id, EventOp.update, {'first_name': 'Oldname'}),
    ]);
    a.clock.advance(const Duration(seconds: 1));
    await applier.applyLocal([
      a.make('profile', id, EventOp.update, {'first_name': 'Amina'}),
    ]);
    // Before compaction the log keeps the deleted creates without payload,
    // but the replaced name is still there.
    expect(await _raw(store), isNot(contains('secret')));
    expect(await _raw(store), contains('Oldname'));

    await compactor.compact('profile');
    await compactor.compactIfNeeded();

    final raw = await _raw(store);
    expect(raw, isNot(contains('secret')));
    expect(raw, isNot(contains('Oldname')));
    expect(raw, contains('Amina'), reason: 'the current value stays');
    for (final e in store.events.values) {
      expect(e.op, EventOp.snapshot, reason: '$e');
      expect(e.payload.keys, ['replaced']);
    }
    final m = store.entities.where((e) => e.entityType == 'message');
    expect(m.where((e) => e.isDeleted), isNotEmpty);
    expect(m.where((e) => e.isDeleted).every((e) => e.fields.isEmpty), isTrue);
  });

  test('a late copy of a dropped event is still a duplicate', () async {
    final made = await fill(5001);
    await compactor.compactIfNeeded();
    final before = await dump(store);

    final fromBob = made.where((e) => e.authorDevice == bob).take(40).toList();
    final again = await applier.applyReceived(batch(fromBob), sender: bob);
    expect(again.duplicates, fromBob.length);
    expect(again.applied, isEmpty, reason: 'no second notification');
    final own = made.firstWhere((e) => e.authorDevice == alice);
    final tap = await applier.applyLocal([own]);
    expect(tap.duplicates, 1);
    expect(await dump(store), before, reason: 'nothing logged again');
    // The store itself refuses to log a dropped event again.
    await store.putEvent(own);
    expect(await dump(store), before);
  });

  test('a delete after compaction still deletes and purges', () async {
    final made = await fill(5001);
    await compactor.compactIfNeeded();
    final live = made.lastWhere(
      (e) =>
          e.op == EventOp.create &&
          !store.entities.any((s) => s.entityId == e.entityId && s.isDeleted),
    );
    final text = live.payload['text']! as String;
    expect(await _raw(store), contains('"$text"'));

    b.clock.advance(const Duration(minutes: 1));
    final delete = b.make('message', live.entityId, EventOp.delete);
    await applier.applyReceived(batch([delete]), sender: bob);

    final state = await store.entity('message', live.entityId);
    expect(state!.isDeleted, isTrue);
    expect(state.fields, isEmpty);
    expect(await _raw(store), isNot(contains('"$text"')));
    expect(_logged(store, 'message').map((e) => e.op), [
      EventOp.snapshot,
      EventOp.delete,
    ]);
  });

  test('a late event of an entity deleted before compaction', () async {
    final id = b.newId();
    final create = b.make('message', id, EventOp.create, {'text': 'gone'});
    b.clock.advance(const Duration(seconds: 1));
    final delete = b.make('message', id, EventOp.delete);
    await applier.applyReceived(batch([create, delete]), sender: bob);
    await compactor.compact('message');
    final tomb = (await store.entity('message', id))!;

    // A newer schema this release cannot apply, then a second delete.
    b.clock.advance(const Duration(seconds: 1));
    final late = b.make('message', id, EventOp.create, {'text': 'late'}, 2);
    b.clock.advance(const Duration(seconds: 1));
    final again = b.make('message', id, EventOp.delete);
    final r = await applier.applyReceived(batch([late, again]), sender: bob);
    expect(r.unapplied, isEmpty, reason: 'a tombstone is final');
    expect((await store.event(late.eventId))!.payload, isEmpty);
    final state = (await store.entity('message', id))!;
    expect(state.fields, isEmpty);
    expect(state.deleted, again.stamp, reason: 'the latest delete');
    expect(tomb.deleted, delete.stamp);
    expect(await _raw(store), isNot(contains('late')));
    expect(await _raw(store), isNot(contains('gone')));
  });

  test('a second compaction replaces the first snapshot', () async {
    await fill(5001);
    await compactor.compactIfNeeded();
    await fill(4999);
    expect(await store.loggedEventCount('message'), 5000);
    expect(await compactor.compactIfNeeded(), {'message': 5000});
    final log = _logged(store, 'message');
    expect(log.single.op, EventOp.snapshot);
    expect(log.single.payload, {'replaced': 5000});
  });

  test('unapplied events are kept and still apply after an update', () async {
    final note = b.make('note', b.newId(), EventOp.update, {'text': 'later'});
    final newer = b.make('message', b.newId(), EventOp.create, {
      'text': 'v2',
    }, 2);
    await applier.applyReceived(batch([note, newer]), sender: bob);
    final kept = (await store.unapplied()).map((u) => u.eventId).toList();
    expect(kept, hasLength(2));

    final small = Compactor(
      store,
      factory: Maker(alice, 4).factory,
      threshold: 2,
    );
    await fill(10);
    expect(await small.compactIfNeeded(), {'message': 10});
    expect((await store.unapplied()).map((u) => u.eventId), kept);

    final updated = EntityRegistry.v1
        .withRule(
          'note',
          const EntityRule(
            merge: MergeRule.lastWriterWins,
            ops: {EventOp.update},
          ),
        )
        .withRule(
          'message',
          const EntityRule(
            merge: MergeRule.appendOnly,
            ops: {EventOp.create, EventOp.delete},
            schemaVersion: 2,
          ),
        );
    final r = await Applier(
      store,
      localDevice: alice,
      registry: updated,
    ).reapplyUnapplied();
    expect(r.applied, hasLength(2));
    expect(await store.unapplied(), isEmpty);
    expect((await store.entity('message', newer.entityId))!.values, {
      'text': 'v2',
    });
  });

  test('a snapshot from the partner stays unapplied', () async {
    final s = b.make('message', b.newId(), EventOp.snapshot, {'replaced': 3});
    final r = await applier.applyReceived(batch([s]), sender: bob);
    expect(r.unapplied.single.reason, UnappliedReason.unknownOp);
    expect(store.events, isEmpty);
  });

  test('a failed compaction keeps the log as it was', () async {
    await fill(20);
    final before = await dump(store);
    final failing = Compactor(
      _FailOnPut(store),
      factory: Maker(alice, 5).factory,
      threshold: 2,
    );
    await expectLater(failing.compactIfNeeded(), throwsStateError);
    expect(await dump(store), before);
    expect(store.droppedEventIds, isEmpty);
    expect(await store.containsEvent(store.events.keys.first), isTrue);
  });

  test('compact on an empty type writes no snapshot', () async {
    expect(await compactor.isDue(), isFalse);
    expect(await compactor.compact('message'), 0);
    expect(store.events, isEmpty);
    expect(
      () => Compactor(store, factory: a.factory, threshold: 1),
      throwsArgumentError,
    );
  });

  group('in the sync engine', () {
    late Crypto crypto;
    setUpAll(() async => crypto = await SodiumCrypto.load());

    test('each run compacts; snapshots never leave the phone', () async {
      final (:alice, :bob, relay: _) = await sync.couple(crypto);
      alice.compactAfter = bob.compactAfter = 5;
      await alice.restart();
      await bob.restart();

      var compacted = 0;
      final texts = <String>[];
      for (var i = 0; i < 12; i++) {
        final from = i.isEven ? alice : bob;
        final t = 'msg $i';
        texts.add(t);
        await from.say(t);
        compacted += (await from.sync()).eventsCompacted;
        compacted += (await (i.isEven ? bob : alice).sync()).eventsCompacted;
      }
      // Both phones end with the same chat.
      await alice.sync();
      await bob.sync();
      expect(alice.messages(), texts);
      expect(bob.messages(), texts);
      expect(compacted, greaterThan(0));

      for (final d in [alice, bob]) {
        expect(await d.events.loggedEventCount('message'), lessThan(5));
        // The HLC the snapshot used is saved.
        expect(await d.store.hlc(), d.engine.hlc.last);
        expect(
          await d.events.unapplied(),
          isEmpty,
          reason: 'no snapshot reached the partner',
        );
        expect(await d.store.outbox(), isEmpty);
      }
    });

    test('compaction runs when the relay is down', () async {
      final (:alice, bob: _, :relay) = await sync.couple(crypto);
      alice.compactAfter = 3;
      await alice.restart();
      for (var i = 0; i < 3; i++) {
        await alice.say('offline $i');
      }
      relay.online = false;
      final r = await alice.sync();
      expect(r.relayError, isNotNull);
      expect(r.eventsCompacted, 3);
      // The snapshot took the last HLC value, and it is saved.
      expect(await alice.store.hlc(), alice.engine.hlc.last);
      expect(await alice.store.outbox(), hasLength(3), reason: 'still sent');
      expect(alice.messages(), ['offline 0', 'offline 1', 'offline 2']);
    });
  });
}

/// Fails on the first log write after a drop.
final class _FailOnPut implements EventStore {
  _FailOnPut(this.inner);
  final InMemoryEventStore inner;

  @override
  Future<T> transaction<T>(Future<T> Function() action) =>
      inner.transaction(action);

  @override
  Future<bool> containsEvent(String eventId) => inner.containsEvent(eventId);

  @override
  Future<void> putEvent(Event event) async => throw StateError('disk full');

  @override
  Future<Event?> event(String eventId) => inner.event(eventId);

  @override
  Future<int> loggedEventCount(String entityType) =>
      inner.loggedEventCount(entityType);

  @override
  Future<int> dropLoggedEvents(String entityType) =>
      inner.dropLoggedEvents(entityType);

  @override
  Future<void> purgePayloads(String entityType, String entityId) =>
      inner.purgePayloads(entityType, entityId);

  @override
  Future<EntityState?> entity(String entityType, String entityId) =>
      inner.entity(entityType, entityId);

  @override
  Future<void> putEntity(EntityState state) => inner.putEntity(state);

  @override
  Future<void> putUnapplied(UnappliedEvent event) => inner.putUnapplied(event);

  @override
  Future<void> removeUnapplied(String eventId) =>
      inner.removeUnapplied(eventId);

  @override
  Future<List<UnappliedEvent>> unapplied() => inner.unapplied();

  @override
  Stream<List<UnappliedEvent>> watchUnapplied() => inner.watchUnapplied();
}
