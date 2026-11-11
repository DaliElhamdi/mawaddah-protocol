// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Which events ask the relay for a push (spec 8.7, PROTOCOL.md section 17).
library;

import '../event/event.dart';

/// Whether an envelope asks the relay to send a content-free wake-up
/// (`wake: 1`). The sender decides: events that deserve a notification
/// (chat messages, invitations, reveal-ready, partner updates) wake the
/// partner's phone; read receipts, settings sync and similar do not.
///
/// One table by `entity_type`, then `op`. A type or op not in the table does
/// not wake. Each feature that adds an entity type adds its row here, in the
/// same pull request.
final class WakePolicy {
  const WakePolicy(this.table);

  /// The table of protocol v1 (PROTOCOL.md section 17).
  static const v1 = WakePolicy({
    // Hello and app updates: synced quietly at the next sync.
    'device': {},
    // Name, gender, mode: shared settings.
    'profile': {},
    // A new chat message notifies; deleting one does not.
    'message': {EventOp.create},
    // Reactions and receipts are small and frequent.
    'reaction': {},
    'receipt': {},
  });

  /// For each `entity_type`, the ops whose events wake the partner.
  final Map<String, Set<String>> table;

  /// Whether [event] alone would wake the partner.
  bool wakes(Event event) =>
      table[event.entityType]?.contains(event.op) ?? false;

  /// Whether an envelope carrying [events] wakes the partner: when any one of
  /// them does.
  bool wakesAny(Iterable<Event> events) => events.any(wakes);
}
