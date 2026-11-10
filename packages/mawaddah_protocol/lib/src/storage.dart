// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

/// Asynchronous key-value store for protocol state (opaque bytes).
abstract interface class Storage {
  /// The value stored under [key], or null.
  Future<Uint8List?> read(String key);

  /// Stores [value] under [key], replacing any previous value.
  Future<void> write(String key, Uint8List value);

  /// Removes [key]; does nothing if it is absent.
  Future<void> delete(String key);

  /// All keys that start with [prefix] (all keys when empty), sorted.
  Future<List<String>> keys({String prefix = ''});
}
