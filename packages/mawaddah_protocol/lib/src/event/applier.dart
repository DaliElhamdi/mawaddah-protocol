// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Applying events to the merged state (PROTOCOL.md sections 10 and 11).
library;

import 'dart:typed_data';

import '../envelope/hlc.dart';
import '../identity/identity.dart';
import '../random_source.dart';
import '../version.dart';
import 'event.dart';
import 'event_store.dart';
import 'registry.dart';
import 'uuid7.dart';

/// What one call of the [Applier] did.
final class ApplyResult {
  const ApplyResult({
    required this.applied,
    required this.unapplied,
    required this.duplicates,
  });

  /// Events added to the log, in the order given. An event of an entity
  /// that is already deleted is here too: it was logged, but changed
  /// nothing.
  final List<Event> applied;

  /// Events stored unapplied by this call.
  final List<UnappliedEvent> unapplied;

  /// Events skipped because their `event_id` was already stored.
  final int duplicates;
}

/// Applies events to an [EventStore] with the merge rule of each entity
/// type.
///
/// Applying an event whose `event_id` is already stored (logged or
/// unapplied) has no effect, and the result does not depend on the order
/// events arrive in: last-writer-wins compares [EventStamp]s, and a delete is
/// final whatever its stamp.
final class Applier {
  Applier(
    this.store, {
    required this.localDevice,
    this.registry = EntityRegistry.v1,
    this.supportedProtocol = protocolVersion,
  });

  final EventStore store;

  /// This device: the author of every local event.
  final DeviceId localDevice;

  final EntityRegistry registry;

  /// The highest `protocol_version` applied; newer events stay unapplied.
  final int supportedProtocol;

  /// Applies the plaintext of an envelope opened from [sender], in one
  /// [EventStore.transaction].
  ///
  /// Fails with [EventException] before changing anything when the plaintext is
  /// refused ([EventBatch.decode]). The envelope was opened all the same, so
  /// the app still commits the ratchet session, the replay window and the HLC
  /// (PROTOCOL.md section 8 step 8), keeps the envelope in its own unapplied
  /// envelope store (as for an undecryptable one; [EventStore] holds events
  /// only) and acknowledges it. It must not roll back that transaction.
  Future<ApplyResult> applyReceived(
    Uint8List plaintext, {
    required DeviceId sender,
  }) async {
    final items = EventBatch.decode(
      plaintext,
      sender: sender,
      supportedProtocol: supportedProtocol,
    );
    return store.transaction(() async {
      final applied = <Event>[];
      final unapplied = <UnappliedEvent>[];
      var duplicates = 0;
      for (final item in items) {
        if (await store.containsEvent(item.eventId)) {
          duplicates++;
          continue;
        }
        final event = item.event;
        final reason = event == null
            ? UnappliedReason.newerProtocol
            : _classify(event);
        if (reason != null && event != null && await _isDeleted(event)) {
          // A tombstone is final: an event of a deleted entity changes
          // nothing, even one this release cannot apply, and keeps no
          // payload.
          await store.putEvent(event.withoutPayload());
          applied.add(event);
        } else if (reason != null) {
          final u = UnappliedEvent(
            eventId: item.eventId,
            json: item.json,
            reason: reason,
            sender: sender,
            hlc: event?.hlc ?? _tryHlc(item.json['hlc']),
          );
          await store.putUnapplied(u);
          unapplied.add(u);
        } else {
          await _apply(event!);
          applied.add(event);
        }
      }
      return ApplyResult(
        applied: applied,
        unapplied: unapplied,
        duplicates: duplicates,
      );
    });
  }

  /// Applies events made on this device, in one [EventStore.transaction].
  ///
  /// Fails with [ArgumentError] before changing anything when an event's author
  /// is not [localDevice] or this release would not apply it.
  Future<ApplyResult> applyLocal(List<Event> events) async {
    for (final e in events) {
      if (e.authorDevice != localDevice) {
        throw ArgumentError.value(e, 'events', 'author is not this device');
      }
      if (e.protocolVersion > supportedProtocol) {
        throw ArgumentError.value(e, 'events', 'newer protocol');
      }
      final reason = _classify(e);
      if (reason != null) {
        throw ArgumentError.value(e, 'events', 'not applicable: $reason');
      }
    }
    return store.transaction(() async {
      final applied = <Event>[];
      var duplicates = 0;
      for (final e in events) {
        if (await store.containsEvent(e.eventId)) {
          duplicates++;
          continue;
        }
        await _apply(e);
        applied.add(e);
      }
      return ApplyResult(
        applied: applied,
        unapplied: const [],
        duplicates: duplicates,
      );
    });
  }

  /// Tries every unapplied event again, in HLC order (after an update of the
  /// app), in one [EventStore.transaction]. Events this release applies leave
  /// the unapplied list; the others stay, with their reason brought up to
  /// date.
  Future<ApplyResult> reapplyUnapplied() => store.transaction(() async {
    final applied = <Event>[];
    final still = <UnappliedEvent>[];
    for (final u in await store.unapplied()) {
      final version = u.json['protocol_version'];
      UnappliedReason? reason;
      Event? event;
      if (version is int && version > supportedProtocol) {
        reason = UnappliedReason.newerProtocol;
      } else {
        try {
          event = Event.fromJson(u.json);
        } on EventException {
          reason = UnappliedReason.rejected;
        }
        if (event != null) {
          reason = event.authorDevice != u.sender
              ? UnappliedReason.rejected
              : _classify(event);
        }
      }
      if (reason == null) {
        await store.removeUnapplied(u.eventId);
        await _apply(event!);
        applied.add(event);
      } else {
        if (reason != u.reason) await store.putUnapplied(u.withReason(reason));
        still.add(u.withReason(reason));
      }
    }
    return ApplyResult(applied: applied, unapplied: still, duplicates: 0);
  });

  Future<bool> _isDeleted(Event e) async =>
      (await store.entity(e.entityType, e.entityId))?.isDeleted ?? false;

  UnappliedReason? _classify(Event e) {
    final rule = registry[e.entityType];
    if (rule == null) return UnappliedReason.unknownEntityType;
    if (e.schemaVersion > rule.schemaVersion) {
      return UnappliedReason.newerSchema;
    }
    if (!rule.ops.contains(e.op)) return UnappliedReason.unknownOp;
    final check = rule.validate;
    if (e.op != EventOp.delete && check != null && !check(e.op, e.payload)) {
      return UnappliedReason.invalidPayload;
    }
    return null;
  }

  Future<void> _apply(Event e) async {
    final rule = registry[e.entityType]!;
    final s = e.stamp;
    final old =
        await store.entity(e.entityType, e.entityId) ??
        EntityState(entityType: e.entityType, entityId: e.entityId);

    final tomb = old.deleted;
    if (tomb != null) {
      // A delete is final: the event is logged without its payload and
      // changes nothing, except that the latest delete is the tombstone.
      await store.putEvent(e.withoutPayload());
      if (e.op == EventOp.delete && s > tomb) {
        await store.putEntity(_tombstone(old, s));
      }
      return;
    }

    if (e.op == EventOp.delete) {
      await store.putEntity(_tombstone(old, s));
      await store.purgePayloads(e.entityType, e.entityId);
      await store.putEvent(e);
      return;
    }

    final EntityState next;
    switch (rule.merge) {
      case MergeRule.lastWriterWins:
        final fields = Map.of(old.fields);
        for (final MapEntry(:key, :value) in e.payload.entries) {
          final current = fields[key];
          if (current == null || s > current.stamp) {
            fields[key] = FieldValue(value, s);
          }
        }
        next = EntityState(
          entityType: old.entityType,
          entityId: old.entityId,
          fields: Map.unmodifiable(fields),
        );
      case MergeRule.appendOnly:
        final created = old.created;
        next = created != null && !(s > created)
            ? old
            : EntityState(
                entityType: old.entityType,
                entityId: old.entityId,
                fields: Map.unmodifiable({
                  for (final MapEntry(:key, :value) in e.payload.entries)
                    key: FieldValue(value, s),
                }),
                created: s,
              );
    }
    await store.putEntity(next);
    await store.putEvent(e);
  }

  static EntityState _tombstone(EntityState old, EventStamp s) => EntityState(
    entityType: old.entityType,
    entityId: old.entityId,
    deleted: s,
  );

  static Hlc? _tryHlc(Object? value) {
    if (value is! String) return null;
    try {
      return Hlc.parse(value);
    } on FormatException {
      return null;
    }
  }
}

/// Makes the events of this device: a new UUID v7 `event_id`, the next
/// value of [hlc] and this device as author.
///
/// The app saves `hlc.last` in the same transaction as the events it made.
final class EventFactory {
  EventFactory({required this.hlc, required this.random, required this.author});

  final HlcClock hlc;

  /// A cryptographically secure source in the app.
  final RandomSource random;

  final DeviceId author;

  /// A new UUID v7 for an entity.
  String newEntityId() => Uuid7.generate(hlc.clock, random);

  /// A new event; [payload] must be `{}` for a delete.
  Event make({
    required String entityType,
    required String entityId,
    required String op,
    JsonMap payload = const {},
    int schemaVersion = 1,
  }) => Event(
    eventId: Uuid7.generate(hlc.clock, random),
    entityType: entityType,
    entityId: entityId,
    op: op,
    payload: payload,
    hlc: hlc.send(),
    authorDevice: author,
    schemaVersion: schemaVersion,
  );
}
