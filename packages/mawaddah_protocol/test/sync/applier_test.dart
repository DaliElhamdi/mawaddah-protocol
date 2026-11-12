// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late InMemoryEventStore store;
  late Applier applier;
  late Maker me, partner;

  setUp(() {
    store = InMemoryEventStore();
    applier = Applier(store, localDevice: alice);
    me = Maker(alice, 1);
    partner = Maker(bob, 2);
  });

  Future<JsonMap> values(String type, String id) async =>
      (await store.entity(type, id))!.values;

  group('idempotency', () {
    test('the same received event twice has no effect', () async {
      final id = partner.newId();
      final e = partner.make('profile', id, EventOp.update, {'gender': 'male'});
      final first = await applier.applyReceived(batch([e]), sender: bob);
      final before = await dump(store);
      final second = await applier.applyReceived(batch([e]), sender: bob);
      expect(first.applied, [e]);
      expect(second.applied, isEmpty);
      expect(second.duplicates, 1);
      expect(await dump(store), before);
    });

    test('a duplicate inside one batch counts once', () async {
      final e = partner.make('reaction', partner.newId(), EventOp.update, {
        'k': 1,
      });
      final r = await applier.applyReceived(batch([e, e]), sender: bob);
      expect(r.applied, [e]);
      expect(r.duplicates, 1);
    });

    test(
      'a local event applied twice (a repeated Done tap) counts once',
      () async {
        final e = me.make('reaction', me.newId(), EventOp.update, {
          'done': true,
        });
        await applier.applyLocal([e]);
        final before = await dump(store);
        final r = await applier.applyLocal([e]);
        expect(r.duplicates, 1);
        expect(await dump(store), before);
      },
    );

    test('an unapplied event received again stays as it was', () async {
      final e = partner.make('note', partner.newId(), EventOp.create, {'x': 1});
      await applier.applyReceived(batch([e]), sender: bob);
      final r = await applier.applyReceived(batch([e]), sender: bob);
      expect(r.duplicates, 1);
      expect(r.unapplied, isEmpty);
      expect(await store.unapplied(), hasLength(1));
    });
  });

  group('last-writer-wins', () {
    test('each field keeps the value of its latest event', () async {
      final id = me.newId();
      final a1 = me.make('profile', id, EventOp.update, {
        'first_name': 'Amina',
        'gender': 'female',
        'mode': 'engaged',
      });
      partner.clock.advance(const Duration(seconds: 5));
      final b1 = partner.make('profile', id, EventOp.update, {
        'mode': 'contracted',
      });
      // Applied newest first: the older event still sets the fields it wins.
      await applier.applyReceived(batch([b1]), sender: bob);
      await applier.applyLocal([a1]);
      expect(await values('profile', id), {
        'first_name': 'Amina',
        'gender': 'female',
        'mode': 'contracted',
      });
      final state = (await store.entity('profile', id))!;
      expect(state.fields['mode']!.stamp, b1.stamp);
      expect(state.fields['gender']!.stamp, a1.stamp);
    });

    test('same HLC: the higher author bytes win', () async {
      final id = me.newId();
      final hlc = Hlc(1762862400000, 3);
      Event at(DeviceId who, String name, int seed) => Event(
        eventId: Uuid7.generate(me.clock, SeededRandom(seed)),
        entityType: 'profile',
        entityId: id,
        op: EventOp.update,
        payload: {'first_name': name},
        hlc: hlc,
        authorDevice: who,
        schemaVersion: 1,
      );
      final fromAlice = at(alice, 'Amina', 1), fromBob = at(bob, 'Yusuf', 2);
      await applier.applyReceived(batch([fromBob]), sender: bob);
      await applier.applyLocal([fromAlice]);
      expect(await values('profile', id), {'first_name': 'Yusuf'});
    });

    test('an invalid payload is stored unapplied, not applied', () async {
      final id = partner.newId();
      final e = partner.make('profile', id, EventOp.update, {
        'gender': 'other',
      });
      final r = await applier.applyReceived(batch([e]), sender: bob);
      expect(r.unapplied.single.reason, UnappliedReason.invalidPayload);
      expect(await store.entity('profile', id), isNull);
      expect(await store.event(e.eventId), isNull);
    });
  });

  group('append-only and tombstones', () {
    test('a delete hides the entity and purges logged payloads', () async {
      final id = partner.newId();
      final create = partner.make('message', id, EventOp.create, {
        'text': 'salam',
      });
      final delete = partner.make('message', id, EventOp.delete);
      await applier.applyReceived(batch([create]), sender: bob);
      expect(await values('message', id), {'text': 'salam'});
      await applier.applyReceived(batch([delete]), sender: bob);
      final state = (await store.entity('message', id))!;
      expect(state.isDeleted, isTrue);
      expect(state.fields, isEmpty);
      expect(state.deleted, delete.stamp);
      expect((await store.event(create.eventId))!.payload, isEmpty);
      expect(await dump(store), isNot(contains('salam')));
    });

    test(
      'a create arriving after its delete is logged without payload',
      () async {
        final id = partner.newId();
        final create = partner.make('message', id, EventOp.create, {
          'text': 'salam',
        });
        final delete = partner.make('message', id, EventOp.delete);
        await applier.applyReceived(batch([delete]), sender: bob);
        final r = await applier.applyReceived(batch([create]), sender: bob);
        expect(r.applied, [create]);
        expect((await store.entity('message', id))!.isDeleted, isTrue);
        expect((await store.event(create.eventId))!.payload, isEmpty);
        expect(await dump(store), isNot(contains('salam')));
      },
    );

    test('a second create of the same entity: the higher stamp wins', () async {
      final id = me.newId();
      final first = me.make('message', id, EventOp.create, {'text': 'a'});
      final second = me.make('message', id, EventOp.create, {'text': 'b'});
      await applier.applyLocal([second, first]);
      expect(await values('message', id), {'text': 'b'});
      expect((await store.entity('message', id))!.created, second.stamp);
    });

    test('a delete purges the payload of unapplied events too', () async {
      final id = partner.newId();
      final create = partner.make('message', id, EventOp.create, {
        'text': 'salam',
      });
      final newer = partner.make('message', id, EventOp.create, {
        'text': 'salam, newer',
      }, 2);
      await applier.applyReceived(batch([create, newer]), sender: bob);
      expect(
        (await store.unapplied()).single.reason,
        UnappliedReason.newerSchema,
      );
      await applier.applyReceived(
        batch([partner.make('message', id, EventOp.delete)]),
        sender: bob,
      );
      final kept = (await store.unapplied()).single;
      expect(kept.reason, UnappliedReason.newerSchema);
      expect(kept.json['payload'], isEmpty);
      expect(kept.json['event_id'], newer.eventId);
      expect(await dump(store), isNot(contains('salam')));
    });

    test(
      'after a delete, even an event it cannot apply keeps no payload',
      () async {
        final id = partner.newId();
        await applier.applyReceived(
          batch([partner.make('message', id, EventOp.delete)]),
          sender: bob,
        );
        final late = partner.make('message', id, 'edit', {'text': 'salam'}, 2);
        final r = await applier.applyReceived(batch([late]), sender: bob);
        expect(r.applied, [late]);
        expect(r.unapplied, isEmpty);
        expect((await store.event(late.eventId))!.payload, isEmpty);
        expect(await dump(store), isNot(contains('salam')));
      },
    );

    test('a delete is final: a later update changes nothing', () async {
      final r = Applier(
        store,
        localDevice: alice,
        registry: EntityRegistry.v1.withRule(
          'task',
          const EntityRule(
            merge: MergeRule.lastWriterWins,
            ops: {EventOp.update, EventOp.delete},
          ),
        ),
      );
      final id = me.newId();
      final del = me.make('task', id, EventOp.delete);
      final upd = me.make('task', id, EventOp.update, {'title': 'x'});
      await r.applyLocal([del, upd]);
      final state = (await store.entity('task', id))!;
      expect(state.isDeleted, isTrue);
      expect(state.fields, isEmpty);
    });
  });

  group('unapplied events', () {
    test(
      'newer protocol, unknown type, op or schema: kept with a reason',
      () async {
        final v2 = {
          'event_id': partner.newId(),
          'protocol_version': protocolVersion + 1,
          'hlc': '0000000000010000',
          'whatever': true,
        };
        final unknownType = partner.make('note', partner.newId(), 'create', {});
        final unknownOp = partner.make(
          'profile',
          partner.newId(),
          EventOp.snapshot,
          {},
        );
        final newerSchema = partner.make(
          'profile',
          partner.newId(),
          EventOp.update,
          {'gender': 'male'},
          2,
        );
        final r = await applier.applyReceived(
          rawBatch([
            v2,
            unknownType.toJson(),
            unknownOp.toJson(),
            newerSchema.toJson(),
          ]),
          sender: bob,
        );
        expect(r.applied, isEmpty);
        expect(r.unapplied.map((u) => u.reason), [
          UnappliedReason.newerProtocol,
          UnappliedReason.unknownEntityType,
          UnappliedReason.unknownOp,
          UnappliedReason.newerSchema,
        ]);
        expect(r.unapplied.first.hlc, Hlc.parse('0000000000010000'));
        expect(r.unapplied.first.json, v2);
        expect(r.unapplied.every((u) => u.reason.needsUpdate), isTrue);
        expect(await store.unapplied(), hasLength(4));
        expect(store.events, isEmpty);
      },
    );

    test('the stream shows the list now and after each commit', () async {
      final seen = <int>[];
      final sub = store.watchUnapplied().listen((l) => seen.add(l.length));
      await pumpEventQueue();
      final e = partner.make('note', partner.newId(), 'create', {});
      final f = partner.make('note', partner.newId(), 'create', {});
      await applier.applyReceived(batch([e, f]), sender: bob);
      await pumpEventQueue();
      expect(seen, [0, 2]); // one notification per transaction
      await sub.cancel();
    });

    test('after an update they are applied again, in HLC order', () async {
      final id = partner.newId();
      final n1 = partner.make('note', id, 'update', {'t': 'first'});
      final n2 = partner.make('note', id, 'update', {'t': 'second'});
      await applier.applyReceived(batch([n2, n1]), sender: bob);
      expect((await store.unapplied()).map((u) => u.eventId), [
        n1.eventId,
        n2.eventId,
      ]);

      final updated = Applier(
        store,
        localDevice: alice,
        registry: EntityRegistry.v1.withRule(
          'note',
          const EntityRule(merge: MergeRule.lastWriterWins, ops: {'update'}),
        ),
      );
      final r = await updated.reapplyUnapplied();
      expect(r.applied, [n1, n2]);
      expect(r.unapplied, isEmpty);
      expect(await store.unapplied(), isEmpty);
      expect(await values('note', id), {'t': 'second'});
    });

    test(
      'still unknown after an update: the reason is brought up to date',
      () async {
        final e = partner.make('note', partner.newId(), 'pin', {});
        await applier.applyReceived(batch([e]), sender: bob);
        final updated = Applier(
          store,
          localDevice: alice,
          registry: EntityRegistry.v1.withRule(
            'note',
            const EntityRule(merge: MergeRule.lastWriterWins, ops: {'update'}),
          ),
        );
        final r = await updated.reapplyUnapplied();
        expect(r.unapplied.single.reason, UnappliedReason.unknownOp);
        expect(
          (await store.unapplied()).single.reason,
          UnappliedReason.unknownOp,
        );
      },
    );

    test(
      'a newer event that turns out unreadable or forged is rejected',
      () async {
        final unreadable = {'event_id': partner.newId(), 'protocol_version': 2};
        final forged = {
          ...partner.make('profile', partner.newId(), 'update', {
            'gender': 'male',
          }).toJson(),
          'author_device': alice.toBase64Url(),
          'protocol_version': 2,
        };
        await applier.applyReceived(
          rawBatch([unreadable, forged]),
          sender: bob,
        );
        // The app was updated to a release that speaks protocol 2 with the same
        // event layout.
        final updated = Applier(
          store,
          localDevice: alice,
          supportedProtocol: 2,
        );
        final r = await updated.reapplyUnapplied();
        expect(r.applied, isEmpty);
        expect(r.unapplied.map((u) => u.reason), [
          UnappliedReason.rejected,
          UnappliedReason.rejected,
        ]);
        expect(UnappliedReason.rejected.needsUpdate, isFalse);
        expect(store.entities, isEmpty);
      },
    );
  });

  group('refusals', () {
    test('a refused plaintext changes nothing', () async {
      final good = partner.make('profile', partner.newId(), 'update', {
        'gender': 'male',
      });
      final forged = me.make('profile', me.newId(), 'update', {
        'gender': 'female',
      });
      await expectLater(
        applier.applyReceived(batch([good, forged]), sender: bob),
        throwsA(isA<EventException>()),
      );
      expect(await dump(store), await dump(InMemoryEventStore()));
    });

    test('applyLocal refuses events it would not apply', () async {
      final notMine = partner.make('profile', partner.newId(), 'update', {
        'gender': 'male',
      });
      final unknown = me.make('note', me.newId(), 'create', {});
      final invalid = me.make('profile', me.newId(), 'update', {'age': 3});
      for (final e in [notMine, unknown, invalid]) {
        await expectLater(applier.applyLocal([e]), throwsArgumentError);
      }
      expect(store.events, isEmpty);
    });

    test('a store failure rolls the whole batch back', () async {
      final inner = InMemoryEventStore();
      final a = Applier(_FailingStore(inner, failAfter: 3), localDevice: alice);
      final id = partner.newId();
      final events = [
        partner.make('profile', id, 'update', {'gender': 'male'}),
        partner.make('profile', id, 'update', {'mode': 'engaged'}),
      ];
      await expectLater(
        a.applyReceived(batch(events), sender: bob),
        throwsStateError,
      );
      expect(await dump(inner), await dump(InMemoryEventStore()));
    });
  });

  group('registry', () {
    test('device hello payload', () {
      bool ok(JsonMap p) => validateDevicePayload('update', p);
      expect(
        ok({
          'protocol_version': 1,
          'min_supported_protocol': 1,
          'envelope_versions': [1],
        }),
        isTrue,
      );
      expect(ok({'protocol_version': 2}), isTrue);
      expect(ok({}), isFalse);
      expect(ok({'protocol_version': 0}), isFalse);
      expect(ok({'envelope_versions': <int>[]}), isFalse);
      expect(
        ok({
          'envelope_versions': [256],
        }),
        isFalse,
      );
      expect(ok({'other': 1}), isFalse);
    });

    test('profile payload', () {
      bool ok(JsonMap p) => validateProfilePayload('update', p);
      expect(
        ok({'first_name': 'Amina', 'gender': 'female', 'mode': 'engaged'}),
        isTrue,
      );
      expect(ok({'mode': 'married_remote'}), isTrue);
      expect(ok({}), isFalse);
      expect(ok({'first_name': ' Amina'}), isFalse);
      expect(ok({'first_name': 'a' * 51}), isFalse);
      expect(ok({'first_name': 7}), isFalse);
      expect(ok({'gender': 'other'}), isFalse);
      expect(ok({'mode': 'married'}), isFalse);
      expect(ok({'age': 30}), isFalse);
    });

    test('withValidators sets a check and refuses unknown types', () {
      final r = EntityRegistry.v1.withValidators({
        'message': (op, p) => p['text'] is String,
      });
      expect(r['message']!.validate!('create', {'text': 'x'}), isTrue);
      expect(r['message']!.merge, MergeRule.appendOnly);
      expect(
        () => EntityRegistry.v1.withValidators({'nope': (_, _) => true}),
        throwsArgumentError,
      );
    });
  });
}

/// An in-memory store whose writes fail after a number of them.
final class _FailingStore implements EventStore {
  _FailingStore(this.inner, {required this.failAfter});
  final InMemoryEventStore inner;
  final int failAfter;
  var _writes = 0;

  void _tick() {
    if (++_writes > failAfter) throw StateError('disk full');
  }

  @override
  Future<T> transaction<T>(Future<T> Function() action) =>
      inner.transaction(action);

  @override
  Future<bool> containsEvent(String eventId) => inner.containsEvent(eventId);

  @override
  Future<void> putEvent(Event event) async {
    _tick();
    await inner.putEvent(event);
  }

  @override
  Future<Event?> event(String eventId) => inner.event(eventId);

  @override
  Future<int> loggedEventCount(String entityType) =>
      inner.loggedEventCount(entityType);

  @override
  Future<int> dropLoggedEvents(String entityType) async {
    _tick();
    return inner.dropLoggedEvents(entityType);
  }

  @override
  Future<void> purgePayloads(String entityType, String entityId) =>
      inner.purgePayloads(entityType, entityId);

  @override
  Future<EntityState?> entity(String entityType, String entityId) =>
      inner.entity(entityType, entityId);

  @override
  Future<void> putEntity(EntityState state) async {
    _tick();
    await inner.putEntity(state);
  }

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
