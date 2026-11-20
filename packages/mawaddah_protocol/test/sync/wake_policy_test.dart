// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

/// The wake table, written by hand from spec 8.7 and ADR 0014 of the app
/// (not read from [WakePolicy]): the ops of each type that wake the partner.
const _expected = <String, Set<String>>{
  'device': {},
  'profile': {},
  'message': {EventOp.create},
  'reaction': {},
  'receipt': {},
  'answer_lock': {EventOp.create},
  'answer': {EventOp.create},
  'reveal_mark': {},
  'topic_thread': {EventOp.create},
  'understanding': {},
  'daily_assignment': {},
  'daily_pin': {},
  'own_question': {},
  'shuffle_preset': {},
  'quiz_session': {EventOp.create},
  'category_block': {},
  'nikah_topic': {},
  'intimacy_opt_in': {},
  'pair_setting': {},
  'joke_reaction': {},
};

const _ops = [EventOp.create, EventOp.update, EventOp.delete];

final _f = EventFactory(
  hlc: HlcClock(FakeClock(DateTime.utc(2026, 11, 20))),
  random: SeededRandom(69),
  author: DeviceId.fromBytes(Uint8List(16)),
);

Event _event(String type, String op) =>
    _f.make(entityType: type, entityId: _f.newEntityId(), op: op);

void main() {
  const p = WakePolicy.v1;

  test('the wake table and the registry list the same entity types', () {
    expect(p.table.keys.toSet(), EntityRegistry.v1.rules.keys.toSet());
    expect(_expected.keys.toSet(), EntityRegistry.v1.rules.keys.toSet());
  });

  test('a type only wakes for ops the registry accepts', () {
    for (final MapEntry(key: type, value: ops) in p.table.entries) {
      expect(
        EntityRegistry.v1[type]!.ops.containsAll(ops),
        isTrue,
        reason: type,
      );
    }
  });

  group('every entity type and op', () {
    for (final MapEntry(key: type, value: waking) in _expected.entries) {
      test(type, () {
        for (final op in _ops) {
          expect(
            p.wakes(_event(type, op)),
            waking.contains(op),
            reason: '$type $op',
          );
        }
      });
    }

    test('a type not in the table never wakes', () {
      for (final op in _ops) {
        expect(p.wakes(_event('unknown_type', op)), isFalse, reason: op);
      }
    });
  });

  group('an envelope', () {
    test('wakes when any one of its events does', () {
      expect(
        p.wakesAny([
          _event('reveal_mark', EventOp.create),
          _event('understanding', EventOp.create),
          _event('answer', EventOp.create),
        ]),
        isTrue,
      );
    });

    test('of quiet events only does not wake', () {
      expect(
        p.wakesAny([
          for (final MapEntry(key: type, value: rule)
              in EntityRegistry.v1.rules.entries)
            for (final op in rule.ops)
              if (!_expected[type]!.contains(op)) _event(type, op),
        ]),
        isFalse,
      );
    });
  });

  group('wake.json', () {
    final file = jsonDecode(
      File('test/vectors/wake.json').readAsStringSync(),
    ) as JsonMap;
    final cases = (file['cases']! as List).cast<JsonMap>();

    test('file header and one case per entity type', () {
      expect(file['file'], 'wake');
      expect(file['protocol_version'], 1);
      final types = {
        for (final c in cases)
          if ('${c['name']}'.startsWith('type: '))
            (c['input']! as JsonMap)['entity_type'],
      };
      expect(types, {...EntityRegistry.v1.rules.keys, 'unknown_type'});
    });

    for (final c in cases) {
      test(c['name'], () {
        final input = c['input']! as JsonMap;
        final output = c['output']! as JsonMap;
        if (input.containsKey('entity_type')) {
          final type = input['entity_type']! as String;
          expect(output.keys.toSet(), _ops.toSet());
          for (final op in _ops) {
            expect(p.wakes(_event(type, op)), output[op], reason: op);
            expect(
              output[op],
              _expected[type]?.contains(op) ?? false,
              reason: 'the vector agrees with the hand-written table',
            );
          }
        } else {
          final events = [
            for (final e in (input['events']! as List).cast<JsonMap>())
              _event(e['entity_type']! as String, e['op']! as String),
          ];
          expect(p.wakesAny(events), output['wake']);
        }
      });
    }
  });
}
