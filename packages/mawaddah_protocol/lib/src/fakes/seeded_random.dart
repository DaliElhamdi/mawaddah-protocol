// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:math' as math;
import 'dart:typed_data';

import '../random_source.dart';

/// Deterministic [RandomSource] for tests. NOT secure: never use in production.
class SeededRandom implements RandomSource {
  SeededRandom(int seed) : _random = math.Random(seed);

  final math.Random _random;

  @override
  Uint8List nextBytes(int length) {
    if (length < 0) throw RangeError.value(length, 'length');
    final out = Uint8List(length);
    for (var i = 0; i < length; i++) {
      out[i] = _random.nextInt(256);
    }
    return out;
  }
}
