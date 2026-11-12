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
  var _dropped = <String>{};
  final _watchers = <MultiStreamController<List<UnappliedEvent>>>{};

  static final _inTransaction = Object();
  Future<void> _tail = Future.value();
  var _unappliedChanged = false;

  /// Logged events by ID (read-only view).
  Map<String, Event> get events => Map.unmodifiable(_events);

  /// IDs of the events [dropLoggedEvents] removed (read-only view).
  Set<String> get droppedEventIds => Set.unmodifiable(_dropped);

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
      final dropped = Set.of(_dropped);
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
        _dropped = dropped;
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
      _events.containsKey(eventId) ||
      _unapplied.containsKey(eventId) ||
      _dropped.contains(eventId);

  @override
  Future<void> putEvent(Event event) async {
    if (_dropped.contains(event.eventId)) return;
    _events.putIfAbsent(event.eventId, () => event);
  }

  @override
  Future<int> loggedEventCount(String entityType) async =>
      _events.values.where((e) => e.entityType == entityType).length;

  @override
  Future<int> dropLoggedEvents(String entityType) async {
    final ids = [
      for (final e in _events.values)
        if (e.entityType == entityType) e.eventId,
    ];
    for (final id in ids) {
      _events.remove(id);
      _dropped.add(id);
    }
    return ids.length;
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
    for (final MapEntry(:key, :value) in _unapplied.entries.toList()) {
      final json = value.json;
      if (json['entity_type'] == entityType &&
          json['entity_id'] == entityId &&
          json['payload'] is Map &&
          (json['payload']! as Map).isNotEmpty) {
        _unapplied[key] = UnappliedEvent(
          eventId: value.eventId,
          json: Map.unmodifiable({
            ...json,
            'payload': const <String, Object?>{},
          }),
          reason: value.reason,
          sender: value.sender,
          hlc: value.hlc,
        );
        _changedUnapplied();
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
