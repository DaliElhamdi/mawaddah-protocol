// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import '../crypto/support.dart' show hex;
import 'support.dart';

String _toHex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

const _reasons = {
  UnappliedReason.newerProtocol: 'newer_protocol',
  UnappliedReason.unknownEntityType: 'unknown_entity_type',
  UnappliedReason.unknownOp: 'unknown_op',
  UnappliedReason.newerSchema: 'newer_schema',
  UnappliedReason.invalidPayload: 'invalid_payload',
  UnappliedReason.rejected: 'rejected',
};

const _failures = {
  EventFailure.malformed: 'malformed',
  EventFailure.wrongAuthor: 'wrong_author',
};

/// The case output of a store, written the way the vector file has it.
Future<JsonMap> _output(InMemoryEventStore store) async {
  final entities = [...store.entities]
    ..sort(
      (x, y) => '${x.entityType}/${x.entityId}'.compareTo(
        '${y.entityType}/${y.entityId}',
      ),
    );
  final log = store.events.keys.toList()..sort();
  return {
    'entities': [
      for (final s in entities)
        {
          'entity_type': s.entityType,
          'entity_id': s.entityId,
          'fields': {
            for (final MapEntry(:key, :value) in s.fields.entries)
              key: {'value': value.value, 'event_id': value.stamp.eventId},
          },
          'created': s.created?.eventId,
          'deleted': s.deleted?.eventId,
        },
    ],
    'log': [
      for (final id in log)
        {
          'event_id': id,
          'payload_purged':
              store.events[id]!.payload.isEmpty &&
              store.events[id]!.op != EventOp.delete,
        },
    ],
    'unapplied': [
      for (final u in await store.unapplied())
        {'event_id': u.eventId, 'reason': _reasons[u.reason]},
    ],
  };
}

void main() {
  final file =
      jsonDecode(File('test/vectors/event.json').readAsStringSync()) as JsonMap;
  final cases = (file['cases']! as List).cast<JsonMap>();

  test('file header', () {
    expect(file['file'], 'event');
    expect(file['protocol_version'], 1);
    expect(cases.where((c) => '${c['name']}'.startsWith('apply')), isNotEmpty);
  });

  for (final c in cases) {
    final name = c['name']! as String;
    final input = c['input']! as JsonMap;
    if (name.startsWith('encode')) {
      test(name, () {
        final events = [
          for (final e in input['events']! as List) Event.fromJson(e),
        ];
        final output = c['output']! as JsonMap;
        expect(_toHex(EventBatch.encode(events)), output['plaintext']);
        // And back: the plaintext decodes to the same events.
        final back = EventBatch.decode(
          hex(output['plaintext']),
          sender: events.first.authorDevice,
        );
        expect(back.map((r) => r.event), events);
      });
    } else if (name.startsWith('decode')) {
      test(name, () {
        expect(
          () => EventBatch.decode(
            hex(input['plaintext']),
            sender: DeviceId.fromBytes(hex(input['sender'])),
          ),
          throwsA(
            isA<EventException>().having(
              (e) => _failures[e.failure],
              'failure',
              c['error'],
            ),
          ),
        );
      });
    } else if (name.startsWith('apply')) {
      final batches = [
        for (final b in (input['batches']! as List).cast<JsonMap>())
          (
            DeviceId.fromBytes(hex(b['sender'])),
            utf8.encode(jsonEncode({'events': b['events']})),
          ),
      ];
      final local = DeviceId.fromBytes(hex(input['local_device']));

      Future<JsonMap> run(List<(DeviceId, Uint8List)> order) async {
        final store = InMemoryEventStore();
        final applier = Applier(store, localDevice: local);
        for (final (sender, bytes) in order) {
          await applier.applyReceived(bytes, sender: sender);
        }
        return _output(store);
      }

      test(name, () async {
        expect(canonical(await run(batches)), canonical(c['output']));
      });

      test('$name (20 shuffles with repeats)', () async {
        final rnd = Random(16);
        for (var i = 0; i < 20; i++) {
          final order = [...batches, ...batches.take(rnd.nextInt(3))]
            ..shuffle(rnd);
          expect(canonical(await run(order)), canonical(c['output']));
        }
      });
    } else {
      throw StateError('unknown case kind: $name');
    }
  }
}
