// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  final maker = Maker(alice, 1);
  final profileId = maker.newId();
  final sample = maker.make('profile', profileId, EventOp.update, {
    'first_name': 'Amina',
    'gender': 'female',
  });

  Matcher failsWith(EventFailure f) =>
      throwsA(isA<EventException>().having((e) => e.failure, 'failure', f));

  group('Event JSON', () {
    test('round-trips, fields in the section 10 order', () {
      final json = sample.toJson();
      expect(json.keys, [
        'event_id',
        'entity_type',
        'entity_id',
        'op',
        'payload',
        'hlc',
        'author_device',
        'protocol_version',
        'schema_version',
      ]);
      expect(json['protocol_version'], protocolVersion);
      expect(json['author_device'], alice.toBase64Url());
      final back = Event.fromJson(jsonDecode(jsonEncode(json)));
      expect(back, sample);
      expect(back.stamp, sample.stamp);
    });

    test('payload is read-only all the way down', () {
      final e = maker.make('reaction', maker.newId(), EventOp.update, {
        'list': [1, 2],
        'map': {'a': 1},
      });
      expect(() => e.payload['x'] = 1, throwsUnsupportedError);
      expect(() => (e.payload['list']! as List).add(3), throwsUnsupportedError);
      expect(() => (e.payload['map']! as Map)['b'] = 2, throwsUnsupportedError);
    });

    test('toString never shows the payload', () {
      expect(sample.toString(), isNot(contains('Amina')));
    });

    final good = sample.toJson();
    final bad = <String, JsonMap>{
      'missing field': Map.of(good)..remove('hlc'),
      'extra field': {...good, 'extra': 1},
      'event_id not v7': {
        ...good,
        'event_id': '00000000-0000-4000-8000-000000000000',
      },
      'event_id upper case': {
        ...good,
        'event_id': (good['event_id']! as String).toUpperCase(),
      },
      'entity_id not a uuid': {...good, 'entity_id': 'me'},
      'entity_type with a digit': {...good, 'entity_type': 'profile2'},
      'entity_type too long': {...good, 'entity_type': 'a' * 33},
      'entity_type empty': {...good, 'entity_type': ''},
      'op with a capital': {...good, 'op': 'Update'},
      'payload a list': {...good, 'payload': <Object?>[]},
      'payload null': {...good, 'payload': null},
      'hlc upper case': {...good, 'hlc': 'ABCDEF0123456789'},
      'hlc short': {...good, 'hlc': '0123'},
      'author not base64url': {...good, 'author_device': 'not a device'},
      'protocol_version 0': {...good, 'protocol_version': 0},
      'protocol_version a float': {...good, 'protocol_version': 1.0},
      'schema_version 0': {...good, 'schema_version': 0},
      'schema_version a string': {...good, 'schema_version': '1'},
      'delete with a payload': {...good, 'op': 'delete'},
      'payload too deep': {
        ...good,
        'payload': _nest(Event.maxPayloadDepth + 1),
      },
    };
    for (final MapEntry(:key, :value) in bad.entries) {
      test('refuses: $key', () {
        expect(() => Event.fromJson(value), failsWith(EventFailure.malformed));
      });
    }

    test('accepts a payload exactly at the depth limit', () {
      final ok = {...good, 'payload': _nest(Event.maxPayloadDepth)};
      expect(Event.fromJson(ok).payload, isNotEmpty);
    });

    test('accepts an unknown entity type and op (they are judged later)', () {
      final e = Event.fromJson({...good, 'entity_type': 'note', 'op': 'pin'});
      expect(e.entityType, 'note');
      expect(e.op, 'pin');
    });

    test('the constructor checks the same rules', () {
      expect(
        () => maker.make('profile', 'nope', EventOp.update),
        throwsArgumentError,
      );
      expect(
        () => maker.make('message', profileId, EventOp.delete, {'a': 1}),
        throwsArgumentError,
      );
    });
  });

  group('EventStamp', () {
    test('orders by hlc, then author bytes, then event id', () {
      final h1 = Hlc(10, 0), h2 = Hlc(10, 1);
      const id1 = '01900000-0000-7000-8000-000000000001';
      const id2 = '01900000-0000-7000-8000-000000000002';
      expect(EventStamp(h1, bob, id1) < EventStamp(h2, alice, id1), isTrue);
      expect(EventStamp(h1, alice, id2) < EventStamp(h1, bob, id1), isTrue);
      expect(EventStamp(h1, alice, id1) < EventStamp(h1, alice, id2), isTrue);
      // Author bytes compare unsigned.
      expect(
        EventStamp(h1, deviceId(0x7f), id1) <
            EventStamp(h1, deviceId(0x80), id1),
        isTrue,
      );
    });
  });

  group('EventBatch', () {
    test('encode is {"events": [...]} with no whitespace', () {
      final text = utf8.decode(batch([sample]));
      expect(text, '{"events":[${jsonEncode(sample.toJson())}]}');
      expect(text, isNot(contains(' ')));
      expect(() => EventBatch.encode([]), throwsArgumentError);
    });

    test('decode reads every event', () {
      final second = maker.make('device', maker.newId(), EventOp.update, {
        'protocol_version': 1,
      });
      final got = EventBatch.decode(batch([sample, second]), sender: alice);
      expect(got.map((r) => r.event), [sample, second]);
      expect(got.map((r) => r.eventId), [sample.eventId, second.eventId]);
      expect(got.every((r) => r.sender == alice), isTrue);
    });

    test('an event by another author refuses the whole plaintext', () {
      expect(
        () => EventBatch.decode(batch([sample]), sender: bob),
        failsWith(EventFailure.wrongAuthor),
      );
    });

    test('a newer protocol_version is kept as raw JSON, unchecked', () {
      final v2 = {
        'event_id': maker.newId(),
        'protocol_version': 2,
        'anything': ['new', 'layout'],
      };
      final got = EventBatch.decode(
        rawBatch([v2, sample.toJson()]),
        sender: alice,
      );
      expect(got[0].event, isNull);
      expect(got[0].json, v2);
      expect(got[1].event, sample);
    });

    final malformedTexts = <String, Uint8List>{
      'not UTF-8': Uint8List.fromList([0xff, 0xfe]),
      'not JSON': utf8.encode('{"events": ['),
      'a list': utf8.encode('[]'),
      'no events key': utf8.encode('{"evts": []}'),
      'extra key': utf8.encode(
        jsonEncode({
          'events': [sample.toJson()],
          'more': 1,
        }),
      ),
      'empty list': utf8.encode('{"events": []}'),
      'an event not an object': utf8.encode('{"events": [1]}'),
      'newer event without event_id': rawBatch([
        {'protocol_version': 2},
      ]),
      'newer event with a bad event_id': rawBatch([
        {'protocol_version': 2, 'event_id': 'x'},
      ]),
      'protocol_version missing': rawBatch([
        {'event_id': '01900000-0000-7000-8000-000000000001'},
      ]),
      'newer event nested too deep': rawBatch([
        {
          'protocol_version': 2,
          'event_id': '01900000-0000-7000-8000-000000000001',
          'x': _nest(Event.maxPayloadDepth + 1),
        },
      ]),
      'one good, one malformed': rawBatch([
        sample.toJson(),
        {...sample.toJson(), 'hlc': 'x'},
      ]),
    };
    for (final MapEntry(:key, :value) in malformedTexts.entries) {
      test('refuses: $key', () {
        expect(
          () => EventBatch.decode(value, sender: alice),
          failsWith(EventFailure.malformed),
        );
      });
    }

    test('a deeply nested text does not overflow the stack', () {
      final deep = '${'[' * 100000}${']' * 100000}';
      final text = utf8.encode(
        '{"events": [{"event_id": "01900000-0000-7000-8000-000000000001", '
        '"protocol_version": 1, "p": $deep}]}',
      );
      expect(
        () => EventBatch.decode(text, sender: alice),
        failsWith(EventFailure.malformed),
      );
    });
  });

  group('EventFactory', () {
    test('makes UUID v7 IDs, increasing HLCs and sets the author', () {
      final m = Maker(bob, 9);
      final id = m.newId();
      final a = m.make('profile', id, EventOp.update, {'gender': 'male'});
      final b = m.make('profile', id, EventOp.update, {'gender': 'male'});
      expect(Uuid7.isValid(a.eventId), isTrue);
      expect(a.eventId, isNot(b.eventId));
      expect(b.hlc > a.hlc, isTrue);
      expect(a.authorDevice, bob);
      expect(a.protocolVersion, protocolVersion);
      expect(m.factory.hlc.last, b.hlc);
    });
  });
}

/// A JSON map nested [levels] deep: `{}` is 1.
JsonMap _nest(int levels) {
  JsonMap v = {};
  for (var i = 1; i < levels; i++) {
    v = {'a': v};
  }
  return v;
}
