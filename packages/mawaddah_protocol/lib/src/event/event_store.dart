// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Where events and the state they build are kept. The app implements
/// [EventStore] over its encrypted database; `InMemoryEventStore` is the
/// fake for tests and the partner bot.
library;

import '../envelope/hlc.dart';
import '../identity/identity.dart';
import 'event.dart';

/// Why an event is stored but not applied (PROTOCOL.md section 11). The event
/// is tried again after an update (`Applier.reapplyUnapplied`).
enum UnappliedReason {
  /// `protocol_version` is above this release's.
  newerProtocol,

  /// `entity_type` is not in the registry.
  unknownEntityType,

  /// `op` is not one this release applies for the type.
  unknownOp,

  /// `schema_version` is above the one this release knows for the type.
  newerSchema,

  /// The payload fails the type's check (a newer partner may have added a
  /// value this release does not know).
  invalidPayload,

  /// Kept from a newer protocol, but after an update this release still
  /// cannot read it, or its author is not the device that sent it. Never
  /// applied; shown only in the debug log.
  rejected;

  /// Whether the app shows "Your partner has a newer version — please
  /// update" for it.
  bool get needsUpdate => this != rejected;
}

/// An event kept without being applied.
final class UnappliedEvent {
  const UnappliedEvent({
    required this.eventId,
    required this.json,
    required this.reason,
    required this.sender,
    this.hlc,
  });

  final String eventId;

  /// The event's JSON object as received (read-only).
  final JsonMap json;

  final UnappliedReason reason;

  /// The device whose envelope carried it; its author must be this device
  /// when it is applied later.
  final DeviceId sender;

  /// The event's `hlc` when it can be read, for the order of a later apply.
  final Hlc? hlc;

  UnappliedEvent withReason(UnappliedReason r) => UnappliedEvent(
    eventId: eventId,
    json: json,
    reason: r,
    sender: sender,
    hlc: hlc,
  );

  @override
  String toString() => 'UnappliedEvent($eventId, ${reason.name})';
}

/// The value of one field and the event that set it.
final class FieldValue {
  const FieldValue(this.value, this.stamp);

  /// A JSON value (read-only).
  final Object? value;
  final EventStamp stamp;
}

/// The merged state of one entity.
final class EntityState {
  const EntityState({
    required this.entityType,
    required this.entityId,
    this.fields = const {},
    this.created,
    this.deleted,
  });

  final String entityType;
  final String entityId;

  /// Current fields; empty once [deleted].
  final Map<String, FieldValue> fields;

  /// For an append-only entity: the `create` whose payload is in [fields].
  final EventStamp? created;

  /// The tombstone: set by a `delete`, final (later events change nothing).
  final EventStamp? deleted;

  bool get isDeleted => deleted != null;

  /// The fields as a plain JSON map, without stamps.
  JsonMap get values => {
    for (final MapEntry(:key, :value) in fields.entries) key: value.value,
  };
}

/// Storage for the event log, the merged entity state and the unapplied
/// events.
///
/// The [Applier] does every change for one batch inside one [transaction].
/// The app runs that inside the same database transaction as the ratchet
/// session, the replay window and the HLC (PROTOCOL.md section 8 step 8);
/// a nested call must join the outer transaction. The [Applier] never catches
/// a store error: any failure ends the outermost transaction.
abstract interface class EventStore {
  /// Runs [action] atomically: if it throws, no change it made is kept.
  Future<T> transaction<T>(Future<T> Function() action);

  /// Whether an event with [eventId] is in the log or unapplied.
  Future<bool> containsEvent(String eventId);

  /// Adds [event] to the log. Does nothing if an event with the same ID is
  /// already logged (the [Applier] checks [containsEvent] first).
  Future<void> putEvent(Event event);

  /// The logged event with [eventId], or null.
  Future<Event?> event(String eventId);

  /// Replaces the payload of every logged event of the entity with `{}`
  /// (the entity was deleted, PROTOCOL.md section 10), and the `payload` of
  /// every unapplied event whose JSON names the same `entity_type` and
  /// `entity_id` (keeping the rest of its JSON and its reason).
  Future<void> purgePayloads(String entityType, String entityId);

  /// The state of an entity, or null if no event touched it.
  Future<EntityState?> entity(String entityType, String entityId);

  /// Stores [state], replacing the previous state of the same entity.
  Future<void> putEntity(EntityState state);

  /// Adds or replaces the unapplied event with the same `eventId`.
  Future<void> putUnapplied(UnappliedEvent event);

  /// Removes an unapplied event (it was applied); nothing if absent.
  Future<void> removeUnapplied(String eventId);

  /// All unapplied events: those with an [UnappliedEvent.hlc] in HLC order
  /// (ties by event ID), then the rest by event ID.
  Future<List<UnappliedEvent>> unapplied();

  /// The unapplied events now and after every committed change to them:
  /// the app shows the update card while the list is not empty.
  Stream<List<UnappliedEvent>> watchUnapplied();
}
