// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import '../pairing/support.dart' show ReplayRandom;

void main() {
  test('time, version and variant bits; random bits from the source', () {
    final clock = FakeClock(DateTime.utc(2026, 11, 11, 12));
    final ms = clock.now().millisecondsSinceEpoch;
    final zeros = Uuid7.generate(clock, ReplayRandom([Uint8List(10)]));
    final ones = Uuid7.generate(
      clock,
      ReplayRandom([Uint8List(10)..fillRange(0, 10, 0xff)]),
    );
    final time = ms.toRadixString(16).padLeft(12, '0');
    expect(
      zeros,
      '${time.substring(0, 8)}-${time.substring(8)}-7000-8000-000000000000',
    );
    expect(
      ones,
      '${time.substring(0, 8)}-${time.substring(8)}-7fff-bfff-ffffffffffff',
    );
    expect(Uuid7.isValid(zeros), isTrue);
    expect(Uuid7.isValid(ones), isTrue);
  });

  test('isValid refuses other forms', () {
    for (final s in [
      '',
      '019a7a3c-6c00-4000-8000-000000000000', // version 4
      '019a7a3c-6c00-7000-c000-000000000000', // variant 110
      '019A7A3C-6C00-7000-8000-000000000000', // uppercase
      '019a7a3c6c0070008000000000000000', // no dashes
      '019a7a3c-6c00-7000-8000-00000000000', // short
    ]) {
      expect(Uuid7.isValid(s), isFalse, reason: s);
    }
  });

  test('later clock readings sort later', () {
    final clock = FakeClock(DateTime.utc(2026));
    final random = SeededRandom(1);
    var prev = Uuid7.generate(clock, random);
    for (var i = 0; i < 50; i++) {
      clock.advance(const Duration(milliseconds: 1));
      final u = Uuid7.generate(clock, random);
      expect(u.compareTo(prev), greaterThan(0));
      expect(Uuid7.isValid(u), isTrue);
      prev = u;
    }
  });
}
