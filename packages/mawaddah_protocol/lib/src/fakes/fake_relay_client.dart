// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import '../relay_client.dart';

/// In-memory relay for tests: keeps envelopes per inbox, in deposit order.
class FakeRelayClient implements RelayClient {
  final Map<String, List<RelayEnvelope>> _inboxes = {};
  final Map<String, List<bool>> _wakes = {};
  int _counter = 0;

  /// The `wake` flag of each envelope ever deposited into [inboxId].
  List<bool> wakesFor(String inboxId) =>
      List.unmodifiable(_wakes[inboxId] ?? const <bool>[]);

  @override
  Future<void> deposit(String inboxId, Uint8List body,
      {bool wake = false}) async {
    _counter++;
    // Zero-padded so cursors compare correctly as strings.
    final cursor = _counter.toString().padLeft(12, '0');
    (_inboxes[inboxId] ??= []).add(
      RelayEnvelope(cursor: cursor, body: Uint8List.fromList(body)),
    );
    (_wakes[inboxId] ??= []).add(wake);
  }

  @override
  Future<List<RelayEnvelope>> fetch(String inboxId, {String? after}) async {
    final all = _inboxes[inboxId] ?? const <RelayEnvelope>[];
    return all
        .where((e) => after == null || e.cursor.compareTo(after) > 0)
        .toList();
  }

  @override
  Future<void> ack(String inboxId, String cursor) async {
    _inboxes[inboxId]?.removeWhere((e) => e.cursor.compareTo(cursor) <= 0);
  }
}
