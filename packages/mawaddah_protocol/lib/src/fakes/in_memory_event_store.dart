// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';

import '../event/event.dart';
import '../event/event_store.dart';

/// [EventStore] in memory, for tests and the partner bot.
///
/// Transactions run one at a time; a nested call joins the outer one. When
/// an action throws, the maps go back to their state before the outermost
/// transaction.
final class InMemoryEventStore implements EventStore {
  var _events = <String, Event>{};
  var _entities = <(String, String), EntityState>{};
  var _unapplied = <String, UnappliedEvent>{};
  final _watchers = <MultiStreamController<List<UnappliedEvent>>>{};

  static final _inTransaction = Object();
  Future<void> _tail = Future.value();
  var _unappliedChanged = false;

  /// Logged events by ID (read-only view).
  Map<String, Event> get events => Map.unmodifiable(_events);

  /// Every entity state (read-only view).
  List<EntityState> get entities => List.unmodifiable(_entities.values);

  @override
  Future<T> transaction<T>(Future<T> Function() action) {
    if (Zone.current[_inTransaction] == this) return action();
    final done = Completer<void>();
    final previous = _tail;
    _tail = done.future;
    return previous.then((_) async {
      final events = Map.of(_events);
      final entities = Map.of(_entities);
      final unapplied = Map.of(_unapplied);
      _unappliedChanged = false;
      try {
        final result = await runZoned(
          action,
          zoneValues: {_inTransaction: this},
        );
        if (_unappliedChanged) _notify();
        return result;
      } catch (_) {
        _events = events;
        _entities = entities;
        _unapplied = unapplied;
        rethrow;
      } finally {
        _unappliedChanged = false;
        done.complete();
      }
    });
  }

  bool get _inside => Zone.current[_inTransaction] == this;

  void _changedUnapplied() {
    if (_inside) {
      _unappliedChanged = true;
    } else {
      _notify();
    }
  }

  void _notify() {
    final list = _sortedUnapplied();
    for (final w in _watchers) {
      w.add(list);
    }
  }

  @override
  Future<bool> containsEvent(String eventId) async =>
      _events.containsKey(eventId) || _unapplied.containsKey(eventId);

  @override
  Future<void> putEvent(Event event) async {
    _events.putIfAbsent(event.eventId, () => event);
  }

  @override
  Future<Event?> event(String eventId) async => _events[eventId];

  @override
  Future<void> purgePayloads(String entityType, String entityId) async {
    for (final MapEntry(:key, :value) in _events.entries.toList()) {
      if (value.entityType == entityType &&
          value.entityId == entityId &&
          value.payload.isNotEmpty) {
        _events[key] = value.withoutPayload();
      }
    }
  }

  @override
  Future<EntityState?> entity(String entityType, String entityId) async =>
      _entities[(entityType, entityId)];

  @override
  Future<void> putEntity(EntityState state) async {
    _entities[(state.entityType, state.entityId)] = state;
  }

  @override
  Future<void> putUnapplied(UnappliedEvent event) async {
    _unapplied[event.eventId] = event;
    _changedUnapplied();
  }

  @override
  Future<void> removeUnapplied(String eventId) async {
    if (_unapplied.remove(eventId) != null) _changedUnapplied();
  }

  @override
  Future<List<UnappliedEvent>> unapplied() async => _sortedUnapplied();

  List<UnappliedEvent> _sortedUnapplied() {
    final list = _unapplied.values.toList()
      ..sort((a, b) {
        final ha = a.hlc, hb = b.hlc;
        if (ha != null && hb != null) {
          final c = ha.compareTo(hb);
          if (c != 0) return c;
        } else if (ha != null) {
          return -1;
        } else if (hb != null) {
          return 1;
        }
        return a.eventId.compareTo(b.eventId);
      });
    return List.unmodifiable(list);
  }

  @override
  Stream<List<UnappliedEvent>> watchUnapplied() => Stream.multi((c) {
    _watchers.add(c);
    c
      ..add(_sortedUnapplied())
      ..onCancel = () => _watchers.remove(c);
  });
}
