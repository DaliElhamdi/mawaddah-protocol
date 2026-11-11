// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Where the sync engine keeps its state. The app implements [SyncStore]
/// over the same encrypted database as its `EventStore`;
/// `InMemorySyncStore` is the fake for tests and the partner bot.
library;

import 'dart:typed_data';

import '../envelope/hlc.dart';
import '../event/event.dart';

/// An envelope sealed for the partner and not yet confirmed deposited.
///
/// It is deposited again as the same bytes until the relay takes it, so a
/// failed upload never uses up another ratchet key (PROTOCOL.md section 17).
final class SealedEnvelope {
  SealedEnvelope({
    required this.counter,
    required Uint8List bytes,
    required List<String> eventIds,
    required this.wake,
    required this.sealedAt,
  }) : bytes = Uint8List.fromList(bytes).asUnmodifiableView(),
       eventIds = List.unmodifiable(eventIds);

  /// The envelope counter (unique per sender); also its key in the store.
  final int counter;

  /// The whole envelope (read-only copy).
  final Uint8List bytes;

  /// The outbox events it carries.
  final List<String> eventIds;

  /// Whether the deposit asks the relay for a push.
  final bool wake;

  /// When it was sealed (UTC, from the engine's clock).
  final DateTime sealedAt;

  @override
  String toString() =>
      'SealedEnvelope($counter, ${eventIds.length} events, wake: $wake)';
}

/// Why a received envelope is kept as raw bytes instead of being applied
/// (PROTOCOL.md section 8).
enum UnappliedEnvelopeReason {
  /// Its `version` or `type` byte is newer than this release. Shows the
  /// "newer version" card.
  unknownVersion,

  /// Signed by the partner, but the ratchet could not open it. Debug log
  /// only.
  undecryptable,

  /// Opened, but its plaintext was refused (`EventException`: malformed or
  /// an event whose author is not the sender). Debug log only.
  refused;

  /// Whether the app shows "Your partner has a newer version — please
  /// update" for it.
  bool get needsUpdate => this == unknownVersion;
}

/// A received envelope kept as raw bytes. At most
/// [SyncStore.maxKeptEnvelopes] are kept per reason, the oldest deleted
/// first.
final class UnappliedEnvelope {
  UnappliedEnvelope({
    required this.id,
    required Uint8List bytes,
    required this.reason,
    required this.receivedAt,
  }) : bytes = Uint8List.fromList(bytes).asUnmodifiableView();

  /// The relay cursor it came with (unique per inbox); its key in the store.
  final String id;

  /// The whole envelope (read-only copy).
  final Uint8List bytes;

  final UnappliedEnvelopeReason reason;

  /// When it was received (UTC).
  final DateTime receivedAt;

  @override
  String toString() => 'UnappliedEnvelope($id, ${reason.name})';
}

/// The sync engine's state: the envelope counter, the ratchet session and
/// replay window bytes, the HLC, the outbox, sealed envelopes, the relay
/// cursor and the envelopes kept unapplied.
///
/// [transaction] must be the **same** database transaction as the
/// `EventStore` the engine's `Applier` uses: a nested call of either joins
/// the outer one, and if the outermost action throws, no change made
/// through either store is kept (PROTOCOL.md section 8 step 8).
///
/// Byte values given to a `put` method must be copied: the engine zeroes
/// them once the call completes. Byte values returned are the caller's to
/// zero.
abstract interface class SyncStore {
  /// At most this many envelopes are kept per [UnappliedEnvelopeReason];
  /// the engine deletes the oldest first (PROTOCOL.md sections 8 and 17).
  static const maxKeptEnvelopes = 100;

  /// Runs [action] atomically, joined with the `EventStore` transaction.
  Future<T> transaction<T>(Future<T> Function() action);

  /// The last envelope counter used (0 before the first envelope).
  Future<int> lastCounter();

  Future<void> putLastCounter(int counter);

  /// The ratchet session (`RatchetSession.toStorageBytes`), or null before
  /// pairing. Never put in a backup.
  Future<Uint8List?> session();

  Future<void> putSession(Uint8List bytes);

  /// The replay window (`ReplayWindow.toStorageBytes`), or null before the
  /// first envelope from the partner.
  Future<Uint8List?> replayWindow();

  Future<void> putReplayWindow(Uint8List bytes);

  /// The last HLC value this device used ([Hlc.zero] at first): the app
  /// starts its `HlcClock` from it.
  Future<Hlc> hlc();

  Future<void> putHlc(Hlc hlc);

  /// Appends [events] to the outbox, after those already there. An event
  /// whose ID is already in the outbox is not added again.
  Future<void> addToOutbox(List<Event> events);

  /// The outbox, in the order events were added.
  Future<List<Event>> outbox();

  /// Removes the events with these IDs from the outbox (absent ones are
  /// ignored).
  Future<void> removeFromOutbox(Iterable<String> eventIds);

  /// Sealed envelopes not yet confirmed deposited, by counter.
  Future<List<SealedEnvelope>> sealedEnvelopes();

  /// Adds [envelope], or replaces the one with the same counter.
  Future<void> putSealedEnvelope(SealedEnvelope envelope);

  Future<void> removeSealedEnvelope(int counter);

  /// The relay cursor of the last received envelope that was handled
  /// (applied, kept or discarded), or null before the first.
  Future<String?> cursor();

  Future<void> putCursor(String cursor);

  /// Adds [envelope], or replaces the one with the same ID.
  Future<void> putUnappliedEnvelope(UnappliedEnvelope envelope);

  /// Every kept envelope, oldest first (by `receivedAt`, then ID).
  Future<List<UnappliedEnvelope>> unappliedEnvelopes();

  Future<void> removeUnappliedEnvelope(String id);

  /// When an envelope from the partner was first left on the relay because
  /// its time is ahead of this phone's clock (PROTOCOL.md section 8 step 5),
  /// or null when none is waiting.
  Future<DateTime?> clockAheadSince();

  Future<void> putClockAheadSince(DateTime? since);
}
