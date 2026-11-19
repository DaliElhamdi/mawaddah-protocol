// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

/// The registry of package 0.1.0 (the Phase 1 app): the chat types only.
final _v010 = EntityRegistry({
  for (final type in ['device', 'profile', 'message', 'reaction', 'receipt'])
    type: EntityRegistry.v1[type]!,
});

void main() {
  late Maker partner;
  late InMemoryEventStore store;

  setUp(() {
    partner = Maker(bob, 68);
    store = InMemoryEventStore();
  });

  List<Event> questionEvents() {
    final session = partner.newId();
    return [
      partner.make('quiz_session', session, EventOp.create, {
        'kind': 'shuffle',
        'question_ids': ['kn_001', 'kn_002'],
        'status': 'open',
      }),
      partner.make('answer_lock', partner.newId(), EventOp.create, {
        'round': session,
        'question_id': 'kn_001',
        'skipped': false,
      }),
      partner.make('answer', partner.newId(), EventOp.create, {
        'round': session,
        'question_id': 'kn_001',
        'scale': 7,
      }),
      partner.make('topic_thread', partner.newId(), EventOp.create, {
        'origin': 'question',
        'origin_id': '$session/kn_001',
        'title': 'Sleep',
        'archived': false,
      }),
      partner.make('intimacy_opt_in', partner.newId(), EventOp.create, {
        'enabled': false,
        'adult_married': false,
      }),
    ];
  }

  test('a Phase 1 app keeps the question types unapplied, then applies them '
      'after an update', () async {
    final events = questionEvents();
    final thread = events[3].entityId;
    final topicMessage = partner.make(
      'message',
      partner.newId(),
      EventOp.create,
      {'text': 'about sleep', 'thread_id': thread, 'content_ref': 'kn_001'},
    );

    final old = Applier(store, localDevice: alice, registry: _v010);
    final r = await old.applyReceived(
      batch([...events, topicMessage]),
      sender: bob,
    );
    // The message is applied in the general chat: 0.1.0 ignores the new
    // fields.
    expect(r.applied.map((e) => e.eventId), [topicMessage.eventId]);
    expect(
      (await store.entity(
        'message',
        topicMessage.entityId,
      ))!.fields['thread_id']!.value,
      thread,
    );
    expect(r.unapplied.map((u) => u.reason).toSet(), {
      UnappliedReason.unknownEntityType,
    });
    expect(r.unapplied, hasLength(events.length));
    expect(r.unapplied.every((u) => u.reason.needsUpdate), isTrue);
    for (final e in events) {
      expect(await store.entity(e.entityType, e.entityId), isNull);
    }

    // The same phone after the update.
    final updated = Applier(store, localDevice: alice);
    final again = await updated.reapplyUnapplied();
    expect(again.unapplied, isEmpty);
    expect(again.applied.map((e) => e.eventId).toSet(), {
      for (final e in events) e.eventId,
    });
    expect(await store.unapplied(), isEmpty);
    final answer = await store.entity('answer', events[2].entityId);
    expect(answer!.fields['scale']!.value, 7);
    expect(answer.created, events[2].stamp);
  });

  group('the new release refuses', () {
    late Applier applier;
    setUp(() => applier = Applier(store, localDevice: alice));

    Future<UnappliedReason?> reasonFor(Event e) async {
      final r = await applier.applyReceived(batch([e]), sender: bob);
      return r.unapplied.isEmpty ? null : r.unapplied.single.reason;
    }

    test('an update or delete of an answer or a lock', () async {
      final id = partner.newId();
      expect(
        await reasonFor(
          partner.make('answer', id, EventOp.update, {'scale': 2}),
        ),
        UnappliedReason.unknownOp,
      );
      expect(
        await reasonFor(partner.make('answer_lock', id, EventOp.delete)),
        UnappliedReason.unknownOp,
      );
    });

    test('an update that moves an entity to another key', () async {
      final id = partner.newId();
      expect(
        await reasonFor(
          partner.make('category_block', id, EventOp.create, {
            'category': 'fun',
            'blocked': true,
          }),
        ),
        isNull,
      );
      expect(
        await reasonFor(
          partner.make('category_block', id, EventOp.update, {
            'category': 'faith',
          }),
        ),
        UnappliedReason.invalidPayload,
      );
      final state = await store.entity('category_block', id);
      expect(state!.fields['category']!.value, 'fun');
    });

    test('a delete where the type has none', () async {
      expect(
        await reasonFor(
          partner.make('quiz_session', partner.newId(), EventOp.delete),
        ),
        UnappliedReason.unknownOp,
      );
    });

    test('a newer schema of a question type', () async {
      expect(
        await reasonFor(
          partner.make('nikah_topic', partner.newId(), EventOp.create, {
            'topic_id': 'mahr',
            'state': 'talked',
          }, 2),
        ),
        UnappliedReason.newerSchema,
      );
    });
  });
}
