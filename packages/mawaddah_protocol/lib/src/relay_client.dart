// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

/// One sealed envelope held by the relay.
final class RelayEnvelope {
  const RelayEnvelope({required this.cursor, required this.body});

  /// Opaque, increasing position used to resume fetching.
  final String cursor;

  /// Sealed (already encrypted) bytes. The relay never sees plaintext.
  final Uint8List body;
}

/// Minimal view of the blind relay (spec 4.5). The full endpoint surface
/// (pairing slots, blobs, push tokens) is added in Phase 1.
abstract interface class RelayClient {
  /// Deposits one sealed envelope into [inboxId]. [wake] asks the relay to
  /// send a content-free push.
  Future<void> deposit(String inboxId, Uint8List body, {bool wake = false});

  /// Pending envelopes of [inboxId] after [cursor] (from the start if null).
  Future<List<RelayEnvelope>> fetch(String inboxId, {String? after});

  /// Acknowledges envelopes up to and including [cursor]; the relay deletes them.
  Future<void> ack(String inboxId, String cursor);
}
