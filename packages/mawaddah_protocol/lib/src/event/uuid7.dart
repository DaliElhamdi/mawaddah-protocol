// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// UUID version 7 (RFC 9562 section 5.7) for event and entity IDs
/// (PROTOCOL.md section 10).
library;

import 'dart:typed_data';

import '../clock.dart';
import '../random_source.dart';

/// Makes and checks UUID v7 strings: 48 bits of Unix time in milliseconds
/// from the injected [Clock], then the version, 74 random bits from the
/// injected [RandomSource] and the variant.
abstract final class Uuid7 {
  /// Random bytes drawn per UUID.
  static const randomLength = 10;

  static final _form = RegExp(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
  );

  /// A new UUID v7 in the 36-character lowercase form.
  ///
  /// Draws [randomLength] bytes `r`: `unix_ts_ms` (48 bits, big-endian),
  /// then `0x70 | (r[0] & 0x0f)`, `r[1]`, `0x80 | (r[2] & 0x3f)`, `r[3..10]`
  /// (RFC 9562 fixed-bit-length random fields, no counter).
  static String generate(Clock clock, RandomSource random) {
    var ms = clock.now().millisecondsSinceEpoch;
    if (ms < 0) ms = 0;
    if (ms > 0xFFFFFFFFFFFF) throw StateError('clock past the UUID v7 range');
    final r = random.nextBytes(randomLength);
    if (r.length != randomLength) throw StateError('short random read');
    final b = Uint8List(16);
    ByteData.sublistView(b)
      ..setUint32(0, ms ~/ 0x10000)
      ..setUint16(4, ms % 0x10000);
    b
      ..[6] = 0x70 | (r[0] & 0x0f)
      ..[7] = r[1]
      ..[8] = 0x80 | (r[2] & 0x3f)
      ..setAll(9, Uint8List.sublistView(r, 3));
    final h = [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();
    return '${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-'
        '${h.substring(16, 20)}-${h.substring(20)}';
  }

  /// Whether [text] is a UUID v7 in the 36-character lowercase form (with
  /// the RFC 9562 variant).
  static bool isValid(String text) => _form.hasMatch(text);
}
