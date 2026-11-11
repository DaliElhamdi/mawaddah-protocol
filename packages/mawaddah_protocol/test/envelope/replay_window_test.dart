// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:math';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

/// The rule of PROTOCOL.md section 8 step 4, written plainly over a set.
final class _Model {
  final accepted = <int>{};
  var highest = 0;
  bool accepts(int c) =>
      c >= 1 && c > highest - ReplayWindow.size && !accepted.contains(c);
  void mark(int c) {
    accepted.add(c);
    if (c > highest) highest = c;
  }
}

void main() {
  test('accepts new counters once, in any order inside the window', () {
    final w = ReplayWindow();
    expect(w.accepts(0), isFalse);
    expect(w.accepts(-1), isFalse);
    for (final c in [5, 1, 3, 2, 4, 6]) {
      expect(w.accepts(c), isTrue, reason: '$c');
      w.mark(c);
      expect(w.accepts(c), isFalse, reason: '$c');
    }
    expect(w.highest, 6);
    expect(() => w.mark(3), throwsStateError);
  });

  test('the window edge: highest - 1023 is inside, highest - 1024 is not', () {
    final w = ReplayWindow()..mark(5000);
    expect(w.accepts(5000 - 1023), isTrue);
    expect(w.accepts(5000 - 1024), isFalse);
    expect(w.accepts(1), isFalse);
    w.mark(5000 - 1023);
    // Sliding by one pushes the oldest marked counter out of the window.
    w.mark(5001);
    expect(w.accepts(5000 - 1023), isFalse);
    expect(w.accepts(5000 - 1022), isTrue);
  });

  test('a jump larger than the window forgets everything below it', () {
    final w = ReplayWindow();
    for (var c = 1; c <= 100; c++) {
      w.mark(c);
    }
    w.mark(100000);
    for (var c = 100000 - 1023; c < 100000; c++) {
      expect(w.accepts(c), isTrue);
    }
    expect(w.accepts(100000), isFalse);
  });

  test('matches the plain rule on random traffic', () {
    final random = Random(7);
    final w = ReplayWindow();
    final model = _Model();
    var next = 1;
    for (var i = 0; i < 20000; i++) {
      // Mostly near the top, sometimes old, sometimes a jump ahead.
      final r = random.nextInt(100);
      final c = r < 70
          ? next - random.nextInt(1100) + random.nextInt(4)
          : r < 95
          ? next++
          : (next += random.nextInt(3000));
      expect(w.accepts(c), model.accepts(c), reason: 'counter $c');
      if (model.accepts(c)) {
        w.mark(c);
        model.mark(c);
      }
      expect(w.highest, model.highest);
    }
  });

  test('saves and restores; a copy is independent', () {
    final w = ReplayWindow();
    for (final c in [1, 2, 900, 1500, 1499, 2000]) {
      w.mark(c);
    }
    final bytes = w.toStorageBytes();
    expect(bytes.length, ReplayWindow.storageLength);
    expect(ReplayWindow.storageLength, 137);
    final r = ReplayWindow.fromStorageBytes(bytes);
    expect(r.highest, 2000);
    for (var c = 1; c <= 2100; c++) {
      expect(r.accepts(c), w.accepts(c), reason: '$c');
    }
    final copy = w.copy()..mark(1998);
    expect(w.accepts(1998), isTrue);
    expect(copy.accepts(1998), isFalse);
    expect(ReplayWindow().toStorageBytes(), [1, ...List.filled(136, 0)]);
    // A counter above 2^32 survives.
    final big = ReplayWindow()..mark(0x123456789);
    expect(
      ReplayWindow.fromStorageBytes(big.toStorageBytes()).highest,
      0x123456789,
    );
  });

  test('refuses damaged bytes', () {
    final good = (ReplayWindow()..mark(3)).toStorageBytes();
    Uint8List changed(void Function(Uint8List b) f) =>
        Uint8List.fromList(good)..apply(f);
    for (final (what, b) in [
      ('short', Uint8List.sublistView(good, 0, 136)),
      ('long', Uint8List.fromList([...good, 0])),
      ('version', changed((b) => b[0] = 2)),
      ('counter >= 2^63', changed((b) => b[1] = 0x80)),
      ('highest not marked', changed((b) => b[9] = 0)),
      ('bit below counter 1', changed((b) => b[9] |= 8)),
      (
        'bits with highest 0',
        Uint8List(137)
          ..[0] = 1
          ..[9] = 2,
      ),
    ]) {
      expect(
        () => ReplayWindow.fromStorageBytes(b),
        throwsFormatException,
        reason: what,
      );
    }
  });
}

extension on Uint8List {
  void apply(void Function(Uint8List b) f) => f(this);
}
