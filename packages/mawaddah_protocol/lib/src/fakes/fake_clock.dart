// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import '../clock.dart';

/// A [Clock] that only moves when told to.
class FakeClock implements Clock {
  FakeClock([DateTime? start])
    : _now = (start ?? DateTime.utc(2026, 1, 1)).toUtc();

  DateTime _now;

  @override
  DateTime now() => _now;

  /// Sets the current time.
  void set(DateTime value) => _now = value.toUtc();

  /// Moves time forward (or backward, for a negative [by]).
  void advance(Duration by) => _now = _now.add(by);
}
