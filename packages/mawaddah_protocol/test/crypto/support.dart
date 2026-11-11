// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// One case of a vector file (PROTOCOL.md section 15).
typedef VectorCase = ({
  String name,
  Map<String, Object?> input,
  Map<String, Object?> output,
});

/// Reads `test/vectors/<file>.json` (tests run from the package root).
List<VectorCase> loadVectors(String file) {
  final json = jsonDecode(File('test/vectors/$file.json').readAsStringSync())
      as Map<String, Object?>;
  if (json['file'] != file) throw StateError('$file: wrong "file" field');
  final cases = (json['cases']! as List<Object?>).cast<Map<String, Object?>>();
  if (cases.isEmpty) throw StateError('$file: no cases');
  return [
    for (final c in cases)
      (
        name: c['name']! as String,
        input: c['input']! as Map<String, Object?>,
        output: c['output']! as Map<String, Object?>,
      ),
  ];
}

Uint8List hex(Object? value) {
  final s = value! as String;
  if (s.length.isOdd) throw FormatException('odd hex length', s);
  return Uint8List.fromList([
    for (var i = 0; i < s.length; i += 2)
      int.parse(s.substring(i, i + 2), radix: 16),
  ]);
}

String toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
