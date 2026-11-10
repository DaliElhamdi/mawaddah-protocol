// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

/// Source of random bytes (secure in production, seeded in tests).
///
/// Named `RandomSource` so it does not clash with `dart:math`'s `Random`.
abstract interface class RandomSource {
  /// Returns [length] random bytes.
  Uint8List nextBytes(int length);
}
