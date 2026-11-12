// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Compaction of the local event log (spec 4.6, PROTOCOL.md section 10).
library;

import 'applier.dart';
import 'event.dart';
import 'event_store.dart';
import 'registry.dart';

/// Keeps the event log small: once an entity type has [threshold] logged
/// events, they are all dropped and one local `snapshot` event takes their
/// place.
///
/// The [EventStore] already keeps the merged state of every entity, with the
/// stamp of the event that set each field, the `create` stamp and the
/// tombstone. Merging never reads the log, so that state is the snapshot:
/// dropping the events changes no state and no later merge. The `snapshot`
/// event records that the events were replaced. Its payload is only
/// `{"replaced": n}`, so no content and no superseded value survives in
/// the log, and a later delete has nothing more to purge.
///
/// Snapshots never leave the phone: they are not in the outbox, and a
/// `snapshot` received from a partner stays unapplied (unknown op).
///
/// Unapplied events are not touched, and the IDs of dropped events stay
/// stored ([EventStore.dropLoggedEvents]), so a late copy is still a
/// duplicate.
final class Compactor {
  Compactor(
    this.store, {
    required this.factory,
    this.registry = EntityRegistry.v1,
    this.threshold = defaultThreshold,
  }) {
    if (threshold < 2) {
      throw ArgumentError.value(threshold, 'threshold', 'must be at least 2');
    }
  }

  /// Spec 4.6: after 5,000 events per entity type.
  static const defaultThreshold = 5000;

  final EventStore store;

  /// Makes the snapshot events (this device's factory: its HLC moves on, so
  /// the app saves `hlc.last` in the same transaction).
  final EventFactory factory;

  /// The entity types to check: only types the [Applier] knows have logged
  /// events.
  final EntityRegistry registry;

  /// The number of logged events of one type that starts a compaction.
  final int threshold;

  /// Compacts every entity type of [registry] with at least [threshold]
  /// logged events, in one [EventStore.transaction]. Returns the number of
  /// events dropped for each type it compacted.
  Future<Map<String, int>> compactIfNeeded() => store.transaction(() async {
    final out = <String, int>{};
    for (final type in registry.rules.keys) {
      if (await store.loggedEventCount(type) >= threshold) {
        out[type] = await _compact(type);
      }
    }
    return out;
  });

  /// Compacts [entityType] now, whatever its count, in one
  /// [EventStore.transaction]. Returns the number of events dropped (0 and
  /// no snapshot when the log has none of that type).
  Future<int> compact(String entityType) =>
      store.transaction(() => _compact(entityType));

  Future<int> _compact(String entityType) async {
    final dropped = await store.dropLoggedEvents(entityType);
    if (dropped == 0) return 0;
    await store.putEvent(
      factory.make(
        entityType: entityType,
        entityId: factory.newEntityId(),
        op: EventOp.snapshot,
        payload: {'replaced': dropped},
      ),
    );
    return dropped;
  }
}
