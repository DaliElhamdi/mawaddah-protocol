// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Source of the current time. Logic code never reads the system clock
/// directly; the app supplies a real implementation, tests use [FakeClock].
abstract interface class Clock {
  /// The current instant, in UTC.
  DateTime now();
}
