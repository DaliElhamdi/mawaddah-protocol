// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';

/// A device ID whose 16 bytes are all [b].
DeviceId deviceId(int b) =>
    DeviceId.fromBytes(Uint8List(16)..fillRange(0, 16, b));

final alice = deviceId(0x0a);
final bob = deviceId(0x0b);

/// A device that makes events: its own clock, HLC and seeded randomness.
final class Maker {
  Maker(this.device, int seed, {DateTime? start})
    : clock = FakeClock(start ?? DateTime.utc(2026, 11, 11, 12)) {
    factory = EventFactory(
      hlc: HlcClock(clock),
      random: SeededRandom(seed),
      author: device,
    );
  }

  final DeviceId device;
  final FakeClock clock;
  late final EventFactory factory;

  Event make(
    String type,
    String id,
    String op, [
    JsonMap payload = const {},
    int schemaVersion = 1,
  ]) => factory.make(
    entityType: type,
    entityId: id,
    op: op,
    payload: payload,
    schemaVersion: schemaVersion,
  );

  String newId() => factory.newEntityId();
}

/// JSON text with object keys sorted, so equal values give equal text.
String canonical(Object? v) => jsonEncode(_sorted(v));

Object? _sorted(Object? v) {
  if (v is Map) {
    final keys = v.keys.cast<String>().toList()..sort();
    return {for (final k in keys) k: _sorted(v[k])};
  }
  if (v is List) return v.map(_sorted).toList();
  return v;
}

String _stamp(EventStamp? s) =>
    s == null ? '-' : '${s.hlc.toHex()}/${s.author.toBase64Url()}/${s.eventId}';

/// Everything a store holds, as comparable text: entities with field stamps,
/// the event log and the unapplied events.
Future<String> dump(InMemoryEventStore store) async {
  final entities = [
    for (final e in store.entities)
      {
        'key': '${e.entityType}/${e.entityId}',
        'created': _stamp(e.created),
        'deleted': _stamp(e.deleted),
        'fields': {
          for (final MapEntry(:key, :value) in e.fields.entries)
            key: [value.value, _stamp(value.stamp)],
        },
      },
  ]..sort((a, b) => (a['key']! as String).compareTo(b['key']! as String));
  final events = {
    for (final MapEntry(:key, :value) in store.events.entries)
      key: value.toJson(),
  };
  final unapplied = [
    for (final u in await store.unapplied()) '${u.eventId}:${u.reason.name}',
  ];
  return const JsonEncoder.withIndent(' ').convert(
    _sorted({'entities': entities, 'events': events, 'unapplied': unapplied}),
  );
}

/// The envelope plaintext for [events].
Uint8List batch(List<Event> events) => EventBatch.encode(events);

/// The envelope plaintext for raw JSON events.
Uint8List rawBatch(List<JsonMap> events) =>
    utf8.encode(jsonEncode({'events': events}));
