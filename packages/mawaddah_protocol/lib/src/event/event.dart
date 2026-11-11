// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Events and the envelope plaintext that carries them (PROTOCOL.md
/// section 10).
library;

import 'dart:convert';
import 'dart:typed_data';

import '../envelope/hlc.dart';
import '../identity/identity.dart';
import '../version.dart' as version;
import 'uuid7.dart';

typedef JsonMap = Map<String, Object?>;

/// The ops of protocol v1. An event may carry another op (a newer release
/// may add one); it is then stored unapplied.
abstract final class EventOp {
  static const create = 'create';
  static const update = 'update';
  static const delete = 'delete';
  static const snapshot = 'snapshot';
}

/// Why an event, or a whole envelope plaintext, was refused.
enum EventFailure {
  /// Not the v1 structure: not JSON, a missing or extra field, a value of the
  /// wrong type or form, or a payload nested too deep.
  malformed,

  /// An event's `author_device` is not the sender of the envelope that
  /// carried it.
  wrongAuthor,
}

/// Thrown when an envelope plaintext or an event is refused. Nothing of the
/// plaintext is applied (see [EventBatch.decode]).
final class EventException implements Exception {
  const EventException(this.failure, this.message);

  final EventFailure failure;
  final String message;

  @override
  String toString() => 'EventException(${failure.name}): $message';
}

/// The last-writer-wins order of events (PROTOCOL.md sections 9 and 10):
/// `hlc`, then the `author_device` bytes, then the `event_id`.
///
/// The `event_id` only separates two different events with the same `hlc`
/// and author, which a correct author never makes; it keeps the result the
/// same on both phones even then.
final class EventStamp implements Comparable<EventStamp> {
  const EventStamp(this.hlc, this.author, this.eventId);

  final Hlc hlc;
  final DeviceId author;
  final String eventId;

  @override
  int compareTo(EventStamp other) {
    final byHlc = hlc.compareTo(other.hlc);
    if (byHlc != 0) return byHlc;
    for (var i = 0; i < DeviceId.byteLength; i++) {
      final d = author.bytes[i] - other.author.bytes[i];
      if (d != 0) return d;
    }
    return eventId.compareTo(other.eventId);
  }

  bool operator >(EventStamp other) => compareTo(other) > 0;
  bool operator <(EventStamp other) => compareTo(other) < 0;

  @override
  bool operator ==(Object other) =>
      other is EventStamp &&
      other.hlc == hlc &&
      other.author == author &&
      other.eventId == eventId;

  @override
  int get hashCode => Object.hash(hlc, author, eventId);

  @override
  String toString() =>
      'EventStamp(${hlc.toHex()}, ${author.toBase64Url()}, $eventId)';
}

/// One immutable event of protocol v1 (PROTOCOL.md section 10).
final class Event {
  /// Throws [ArgumentError] when a field breaks the section 10 rules.
  Event({
    required this.eventId,
    required this.entityType,
    required this.entityId,
    required this.op,
    required JsonMap payload,
    required this.hlc,
    required this.authorDevice,
    this.protocolVersion = version.protocolVersion,
    required this.schemaVersion,
  }) : payload = _freezeMap(payload) {
    final problem = _check();
    if (problem != null) throw ArgumentError(problem);
  }

  /// Reads one event in the v1 layout. Throws [EventException]
  /// ([EventFailure.malformed]) for anything else. It does not judge the
  /// `protocol_version` value: [EventBatch.decode] keeps an event of a newer
  /// protocol as raw JSON instead of calling this.
  factory Event.fromJson(Object? json) {
    if (json is! Map<String, Object?>) throw _malformed('not a JSON object');
    if (json.length != _fields.length || !_fields.every(json.containsKey)) {
      throw _malformed('needs exactly the fields ${_fields.join(', ')}');
    }
    final payload = json['payload'];
    if (payload is! Map<String, Object?>) {
      throw _malformed('"payload" is not an object');
    }
    if (_depth(payload) > maxPayloadDepth) {
      throw _malformed('"payload" nests more than $maxPayloadDepth levels');
    }
    final hlc = json['hlc'], author = json['author_device'];
    if (hlc is! String) throw _malformed('"hlc" is not a string');
    if (author is! String) throw _malformed('"author_device" is not a string');
    final strings = ['event_id', 'entity_type', 'entity_id', 'op'];
    for (final k in strings) {
      if (json[k] is! String) throw _malformed('"$k" is not a string');
    }
    for (final k in ['protocol_version', 'schema_version']) {
      if (json[k] is! int) throw _malformed('"$k" is not an integer');
    }
    try {
      return Event(
        eventId: json['event_id']! as String,
        entityType: json['entity_type']! as String,
        entityId: json['entity_id']! as String,
        op: json['op']! as String,
        payload: payload,
        hlc: Hlc.parse(hlc),
        authorDevice: DeviceId.parse(author),
        protocolVersion: json['protocol_version']! as int,
        schemaVersion: json['schema_version']! as int,
      );
    } on FormatException catch (e) {
      throw _malformed(e.message);
    } on ArgumentError catch (e) {
      throw _malformed('${e.message}');
    }
  }

  /// Deepest nesting of a payload: `{}` is 1 level, `{"a": []}` 2.
  static const maxPayloadDepth = 32;

  /// The JSON field names, in the order [toJson] writes them.
  static const _fields = [
    'event_id',
    'entity_type',
    'entity_id',
    'op',
    'payload',
    'hlc',
    'author_device',
    'protocol_version',
    'schema_version',
  ];
  static final _name = RegExp(r'^[a-z_]{1,32}$');

  /// UUID v7, unique; applying the same `event_id` twice has no effect.
  final String eventId;

  /// The kind of entity (`[a-z_]`, 1 to 32 characters).
  final String entityType;

  /// UUID v7 of the entity changed.
  final String entityId;

  /// One of [EventOp], or an op of a newer release (`[a-z_]`, 1 to 32
  /// characters).
  final String op;

  /// Type-specific fields, read-only all the way down; `{}` for a delete.
  final JsonMap payload;

  /// When the author made the change.
  final Hlc hlc;

  final DeviceId authorDevice;

  /// The protocol the author used; at least 1.
  final int protocolVersion;

  /// Version of this `entity_type`'s payload; at least 1.
  final int schemaVersion;

  /// The last-writer-wins position of this event.
  EventStamp get stamp => EventStamp(hlc, authorDevice, eventId);

  /// The same event with an empty payload: what stays in the log once its
  /// entity is deleted.
  Event withoutPayload() => Event(
    eventId: eventId,
    entityType: entityType,
    entityId: entityId,
    op: op,
    payload: const {},
    hlc: hlc,
    authorDevice: authorDevice,
    protocolVersion: protocolVersion,
    schemaVersion: schemaVersion,
  );

  /// The JSON object, fields in the order of PROTOCOL.md section 10.
  JsonMap toJson() => {
    'event_id': eventId,
    'entity_type': entityType,
    'entity_id': entityId,
    'op': op,
    'payload': payload,
    'hlc': hlc.toHex(),
    'author_device': authorDevice.toBase64Url(),
    'protocol_version': protocolVersion,
    'schema_version': schemaVersion,
  };

  String? _check() {
    if (!Uuid7.isValid(eventId)) return '"event_id" is not a UUID v7';
    if (!_name.hasMatch(entityType)) return '"entity_type" is not [a-z_]{1,32}';
    if (!Uuid7.isValid(entityId)) return '"entity_id" is not a UUID v7';
    if (!_name.hasMatch(op)) return '"op" is not [a-z_]{1,32}';
    if (op == EventOp.delete && payload.isNotEmpty) {
      return 'a delete has an empty payload';
    }
    if (protocolVersion < 1) return '"protocol_version" is below 1';
    if (schemaVersion < 1) return '"schema_version" is below 1';
    if (_depth(payload) > maxPayloadDepth) {
      return '"payload" nests more than $maxPayloadDepth levels';
    }
    return null;
  }

  @override
  bool operator ==(Object other) =>
      other is Event && jsonEncode(other.toJson()) == jsonEncode(toJson());

  @override
  int get hashCode => eventId.hashCode;

  /// Shows only where the event sits, never its payload.
  @override
  String toString() =>
      'Event($eventId, $entityType/$entityId, $op, ${hlc.toHex()})';
}

/// The envelope plaintext: the UTF-8 JSON text `{"events": [...]}`
/// (PROTOCOL.md section 10).
abstract final class EventBatch {
  /// The plaintext for [events], with no whitespace. Throws [ArgumentError]
  /// for an empty list.
  static Uint8List encode(List<Event> events) {
    if (events.isEmpty) throw ArgumentError.value(events, 'events', 'empty');
    return utf8.encode(
      jsonEncode({
        'events': [for (final e in events) e.toJson()],
      }),
    );
  }

  /// Reads an opened envelope's plaintext sent by [sender].
  ///
  /// Every event must have a UUID v7 `event_id` and an integer
  /// `protocol_version` of at least 1, whatever its version: they are read
  /// first. An event whose `protocol_version` is above [supportedProtocol] is
  /// returned as raw JSON ([ReceivedEvent.event] is null), to be stored
  /// unapplied. Every other event must follow the v1 rules ([Event.fromJson])
  /// and have [sender] as its `author_device`.
  ///
  /// Throws [EventException] if the text or any one event breaks these
  /// rules; then nothing of it may be applied.
  static List<ReceivedEvent> decode(
    Uint8List plaintext, {
    required DeviceId sender,
    int supportedProtocol = version.protocolVersion,
  }) {
    final Object? json;
    try {
      json = jsonDecode(utf8.decode(plaintext));
    } on FormatException {
      throw _malformed('not UTF-8 JSON');
    }
    if (json is! Map<String, Object?> ||
        json.length != 1 ||
        json['events'] is! List<Object?>) {
      throw _malformed('not {"events": [...]}');
    }
    final list = json['events']! as List<Object?>;
    if (list.isEmpty) throw _malformed('no events');
    return [
      for (final item in list) _decodeOne(item, sender, supportedProtocol),
    ];
  }

  static ReceivedEvent _decodeOne(Object? item, DeviceId sender, int max) {
    if (item is! Map<String, Object?>) throw _malformed('not a JSON object');
    final id = item['event_id'];
    final version = item['protocol_version'];
    if (id is! String || !Uuid7.isValid(id)) {
      throw _malformed('"event_id" is not a UUID v7');
    }
    if (version is! int || version < 1) {
      throw _malformed('"protocol_version" is not an integer of at least 1');
    }
    if (_depth(item) > Event.maxPayloadDepth + 1) {
      throw _malformed('event nests more than ${Event.maxPayloadDepth + 1}');
    }
    if (version > max) {
      return ReceivedEvent._(id, _freezeMap(item), null, sender);
    }
    final event = Event.fromJson(item);
    if (event.authorDevice != sender) {
      throw EventException(
        EventFailure.wrongAuthor,
        '"author_device" is not the envelope sender',
      );
    }
    return ReceivedEvent._(id, event.toJson(), event, sender);
  }
}

/// One event read from an envelope plaintext.
final class ReceivedEvent {
  const ReceivedEvent._(this.eventId, this.json, this.event, this.sender);

  final String eventId;

  /// The event's JSON object (read-only).
  final JsonMap json;

  /// The parsed event, or null when its `protocol_version` is newer than
  /// this release.
  final Event? event;

  /// The device that sent the envelope.
  final DeviceId sender;
}

EventException _malformed(String message) =>
    EventException(EventFailure.malformed, message);

/// Nesting depth of a JSON value, without recursion (the text may come from
/// the partner): a scalar is 0, `{}` and `[]` are 1.
int _depth(Object? value) {
  var deepest = 0;
  final stack = <(Object?, int)>[(value, 0)];
  while (stack.isNotEmpty) {
    final (v, d) = stack.removeLast();
    final Iterable<Object?> children;
    if (v is Map) {
      children = v.values;
    } else if (v is List) {
      children = v;
    } else {
      continue;
    }
    if (d + 1 > deepest) deepest = d + 1;
    for (final c in children) {
      if (c is Map || c is List) stack.add((c, d + 1));
    }
  }
  return deepest;
}

/// A read-only deep copy of a JSON map. Callers check the depth first, so the
/// recursion is bounded.
JsonMap _freezeMap(JsonMap map) =>
    Map.unmodifiable({for (final e in map.entries) e.key: _freeze(e.value)});

Object? _freeze(Object? v) {
  if (v is Map) {
    return Map<String, Object?>.unmodifiable({
      for (final e in v.entries) e.key as String: _freeze(e.value),
    });
  }
  if (v is List) return List<Object?>.unmodifiable(v.map(_freeze));
  if (v == null || v is String || v is num || v is bool) return v;
  throw ArgumentError.value(v, 'payload', 'not a JSON value');
}
