// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

void main() {
  final t0 = DateTime.utc(2026, 11, 11, 12);
  final ms = t0.millisecondsSinceEpoch;

  group('Hlc', () {
    test('bytes and hex forms round-trip and keep the order', () {
      final values = [
        Hlc.zero,
        Hlc(0, 1),
        Hlc(1, 0),
        Hlc(ms, 0xffff),
        Hlc(ms + 1, 0),
        Hlc(0x7fffffffffff, 0),
        Hlc(0x800000000000, 0), // top bit of the 64-bit value set
        Hlc(Hlc.maxPhysicalMs, Hlc.maxLogical),
      ];
      for (final (i, h) in values.indexed) {
        expect(Hlc.fromBytes(h.toBytes()), h);
        expect(Hlc.parse(h.toHex()), h);
        expect(h.toHex(), matches(RegExp(r'^[0-9a-f]{16}$')));
        if (i > 0) {
          final prev = values[i - 1];
          expect(prev < h, isTrue);
          expect(prev.toHex().compareTo(h.toHex()), lessThan(0));
        }
      }
      expect(Hlc(Hlc.maxPhysicalMs, Hlc.maxLogical).toHex(), 'f' * 16);
      expect(Hlc(0x0102030405, 0x0607).toHex(), '0001020304050607');
      expect(Hlc(0x0102030405, 0x0607).toBytes(), [0, 1, 2, 3, 4, 5, 6, 7]);
      expect(Hlc(ms, 0).physicalTime, t0);
    });

    test('refuses values outside their bits and malformed text', () {
      expect(() => Hlc(-1, 0), throwsRangeError);
      expect(() => Hlc(Hlc.maxPhysicalMs + 1, 0), throwsRangeError);
      expect(() => Hlc(0, 0x10000), throwsRangeError);
      expect(() => Hlc(0, -1), throwsRangeError);
      for (final s in ['', '0' * 15, '0' * 17, 'F' * 16, 'g${'0' * 15}']) {
        expect(() => Hlc.parse(s), throwsFormatException, reason: s);
      }
      expect(() => Hlc.fromBytes(Uint8List(7)), throwsFormatException);
    });
  });

  group('HlcClock', () {
    test('send: monotonic on a still clock, resets when the clock moves', () {
      final clock = FakeClock(t0);
      final hlc = HlcClock(clock);
      expect(hlc.send(), Hlc(ms, 0));
      expect(hlc.send(), Hlc(ms, 1));
      expect(hlc.send(), Hlc(ms, 2));
      clock.advance(const Duration(milliseconds: 5));
      expect(hlc.send(), Hlc(ms + 5, 0));
    });

    test('survives the clock jumping back and forth', () {
      final clock = FakeClock(t0);
      final hlc = HlcClock(clock);
      final seen = <Hlc>[hlc.send()];
      for (final jump in [
        -3600000,
        10,
        -86400000,
        7200000,
        2 * 86400000,
        -1,
        0,
        -7200000,
      ]) {
        clock.advance(Duration(milliseconds: jump));
        seen.add(hlc.send());
      }
      for (var i = 1; i < seen.length; i++) {
        expect(seen[i] > seen[i - 1], isTrue, reason: '${seen[i]}');
      }
      // While the clock is behind, time stands still and the counter grows.
      expect(seen[1], Hlc(ms, 1));
      expect(seen[4], Hlc(ms, 4));
      // Once it is ahead again, the physical part follows it.
      final later = ms - 3600000 + 10 - 86400000 + 7200000 + 2 * 86400000;
      expect(seen[5], Hlc(later, 0));
      expect(seen[8], Hlc(later, 3));
    });

    test('receive: the four cases of Kulkarni et al.', () {
      final clock = FakeClock(t0);
      // l' == l == l_m: max(c, c_m) + 1.
      var hlc = HlcClock(clock, last: Hlc(ms + 100, 4));
      expect(hlc.receive(Hlc(ms + 100, 9)), Hlc(ms + 100, 10));
      hlc = HlcClock(clock, last: Hlc(ms + 100, 9));
      expect(hlc.receive(Hlc(ms + 100, 4)), Hlc(ms + 100, 10));
      // l' == l only: c + 1.
      hlc = HlcClock(clock, last: Hlc(ms + 100, 4));
      expect(hlc.receive(Hlc(ms + 50, 99)), Hlc(ms + 100, 5));
      // l' == l_m only: c_m + 1.
      hlc = HlcClock(clock, last: Hlc(ms - 100, 4));
      expect(hlc.receive(Hlc(ms + 200, 7)), Hlc(ms + 200, 8));
      // now is the largest: 0.
      hlc = HlcClock(clock, last: Hlc(ms - 100, 4));
      expect(hlc.receive(Hlc(ms - 50, 7)), Hlc(ms, 0));
      // The result is above both inputs.
      expect(hlc.last, Hlc(ms, 0));
    });

    test('a full counter moves the physical part on by 1 ms', () {
      final clock = FakeClock(t0);
      var hlc = HlcClock(clock, last: Hlc(ms, Hlc.maxLogical));
      expect(hlc.send(), Hlc(ms + 1, 0));
      expect(hlc.send(), Hlc(ms + 1, 1));
      // A remote clock ahead of ours with a full counter.
      hlc = HlcClock(clock);
      expect(hlc.receive(Hlc(ms + 60000, Hlc.maxLogical)), Hlc(ms + 60001, 0));
      // Many sends within one millisecond stay strictly increasing.
      hlc = HlcClock(clock);
      var prev = hlc.send();
      for (var i = 0; i < 70000; i++) {
        final h = hlc.send();
        expect(h > prev, isTrue);
        prev = h;
      }
      expect(prev, Hlc(ms + 1, 70000 - 65536));
    });

    test('a clock before 1970 counts as 0; the maximum value is refused', () {
      final clock = FakeClock(DateTime.utc(1960));
      // The start value (0, 0) counts as seen, so the first is (0, 1).
      expect(HlcClock(clock).send(), Hlc(0, 1));
      final full = HlcClock(
        clock,
        last: Hlc(Hlc.maxPhysicalMs, Hlc.maxLogical),
      );
      expect(full.send, throwsStateError);
    });

    test('restarts from the saved value', () {
      final clock = FakeClock(t0);
      final first = HlcClock(clock);
      first.send();
      final saved = first.send();
      final again = HlcClock(clock, last: Hlc.fromBytes(saved.toBytes()));
      expect(again.send(), Hlc(ms, 2));
    });
  });
}
