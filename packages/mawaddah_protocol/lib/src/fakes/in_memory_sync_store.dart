// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'dart:typed_data';

import '../envelope/hlc.dart';
import '../event/event.dart';
import '../sync/sync_store.dart';
import 'in_memory_event_store.dart';

/// [SyncStore] in memory, for tests and the partner bot. Its transactions
/// are those of [events]: a failure rolls back both stores together.
final class InMemorySyncStore implements SyncStore {
  InMemorySyncStore(this.events);

  /// The event store whose transaction this store joins.
  final InMemoryEventStore events;

  /// Called before every change, with the method name; a test throws from
  /// it to simulate a database failure.
  void Function(String method)? onWrite;

  var _s = _State();
  static final _inTransaction = Object();

  @override
  Future<T> transaction<T>(Future<T> Function() action) {
    if (Zone.current[_inTransaction] == this) return action();
    return events.transaction(() async {
      final before = _s.copy();
      try {
        return await runZoned(action, zoneValues: {_inTransaction: this});
      } catch (_) {
        _s = before;
        rethrow;
      }
    });
  }

  void _write(String method) => onWrite?.call(method);

  static Uint8List? _copy(Uint8List? b) =>
      b == null ? null : Uint8List.fromList(b);

  @override
  Future<int> lastCounter() async => _s.counter;

  @override
  Future<void> putLastCounter(int counter) async {
    _write('putLastCounter');
    _s.counter = counter;
  }

  @override
  Future<Uint8List?> session() async => _copy(_s.session);

  @override
  Future<void> putSession(Uint8List bytes) async {
    _write('putSession');
    _s.session = _copy(bytes);
  }

  @override
  Future<Uint8List?> replayWindow() async => _copy(_s.window);

  @override
  Future<void> putReplayWindow(Uint8List bytes) async {
    _write('putReplayWindow');
    _s.window = _copy(bytes);
  }

  @override
  Future<Hlc> hlc() async => _s.hlc;

  @override
  Future<void> putHlc(Hlc hlc) async {
    _write('putHlc');
    _s.hlc = hlc;
  }

  @override
  Future<void> addToOutbox(List<Event> events) async {
    _write('addToOutbox');
    for (final e in events) {
      _s.outbox.putIfAbsent(e.eventId, () => e);
    }
  }

  @override
  Future<List<Event>> outbox() async => List.unmodifiable(_s.outbox.values);

  @override
  Future<void> removeFromOutbox(Iterable<String> eventIds) async {
    _write('removeFromOutbox');
    eventIds.forEach(_s.outbox.remove);
  }

  @override
  Future<List<SealedEnvelope>> sealedEnvelopes() async {
    final list = _s.sealed.values.toList()
      ..sort((a, b) => a.counter.compareTo(b.counter));
    return List.unmodifiable(list);
  }

  @override
  Future<void> putSealedEnvelope(SealedEnvelope envelope) async {
    _write('putSealedEnvelope');
    _s.sealed[envelope.counter] = envelope;
  }

  @override
  Future<void> removeSealedEnvelope(int counter) async {
    _write('removeSealedEnvelope');
    _s.sealed.remove(counter);
  }

  @override
  Future<String?> cursor() async => _s.cursor;

  @override
  Future<void> putCursor(String cursor) async {
    _write('putCursor');
    _s.cursor = cursor;
  }

  @override
  Future<void> putUnappliedEnvelope(UnappliedEnvelope envelope) async {
    _write('putUnappliedEnvelope');
    _s.unapplied[envelope.id] = envelope;
  }

  @override
  Future<List<UnappliedEnvelope>> unappliedEnvelopes() async {
    final list = _s.unapplied.values.toList()
      ..sort((a, b) {
        final c = a.receivedAt.compareTo(b.receivedAt);
        if (c != 0) return c;
        final l = a.id.length.compareTo(b.id.length);
        return l != 0 ? l : a.id.compareTo(b.id);
      });
    return List.unmodifiable(list);
  }

  @override
  Future<void> removeUnappliedEnvelope(String id) async {
    _write('removeUnappliedEnvelope');
    _s.unapplied.remove(id);
  }

  @override
  Future<DateTime?> clockAheadSince() async => _s.clockAheadSince;

  @override
  Future<void> putClockAheadSince(DateTime? since) async {
    _write('putClockAheadSince');
    _s.clockAheadSince = since;
  }
}

final class _State {
  var counter = 0;
  Uint8List? session;
  Uint8List? window;
  var hlc = Hlc.zero;
  var outbox = <String, Event>{};
  var sealed = <int, SealedEnvelope>{};
  String? cursor;
  var unapplied = <String, UnappliedEnvelope>{};
  DateTime? clockAheadSince;

  _State copy() => _State()
    ..counter = counter
    ..session = session
    ..window = window
    ..hlc = hlc
    ..outbox = Map.of(outbox)
    ..sealed = Map.of(sealed)
    ..cursor = cursor
    ..unapplied = Map.of(unapplied)
    ..clockAheadSince = clockAheadSince;
}
