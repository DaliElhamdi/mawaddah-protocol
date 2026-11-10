// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import '../storage.dart';

/// [Storage] kept in memory, for tests.
class InMemoryStorage implements Storage {
  final Map<String, Uint8List> _data = {};

  @override
  Future<Uint8List?> read(String key) async {
    final v = _data[key];
    return v == null ? null : Uint8List.fromList(v);
  }

  @override
  Future<void> write(String key, Uint8List value) async {
    _data[key] = Uint8List.fromList(value);
  }

  @override
  Future<void> delete(String key) async {
    _data.remove(key);
  }

  @override
  Future<List<String>> keys({String prefix = ''}) async =>
      _data.keys.where((k) => k.startsWith(prefix)).toList()..sort();
}
