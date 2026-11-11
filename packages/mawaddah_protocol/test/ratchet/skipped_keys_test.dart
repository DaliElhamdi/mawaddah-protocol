// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Skipped message keys (PROTOCOL.md section 6, Signal 3.5): out-of-order
// delivery, both people sending at once, MAX_SKIP, the 1,000-key store and
// the 30-day lifetime.

import 'dart:math' as math;

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late Crypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  Matcher fails(RatchetFailure f) =>
      throwsA(isA<RatchetException>().having((e) => e.failure, 'failure', f));

  /// The session's saved bytes, to show that a call changed nothing.
  List<int> snapshot(RatchetSession s) => s.toStorageBytes();

  group('out-of-order delivery', () {
    test('a chain delivered in reverse order', () {
      final s = sessions(crypto);
      final sent = [for (var i = 0; i < 6; i++) send(s.alice, 'a$i', i + 1)];
      expect(open(s.bob, sent[5]), 'a5');
      expect(s.bob.skippedKeyCount, 5);
      for (final m in sent.reversed.skip(1)) {
        expect(open(s.bob, m), m.text);
      }
      expect(s.bob.skippedKeyCount, 0);
      // Nothing is stuck: the conversation goes on in both directions.
      expect(open(s.alice, send(s.bob, 'b0', 1)), 'b0');
      expect(open(s.bob, send(s.alice, 'a6', 7)), 'a6');
    });

    test('the initiator may receive the first message late', () {
      final s = sessions(crypto);
      final a0 = send(s.alice, 'a0', 1);
      final a1 = send(s.alice, 'a1', 2);
      expect(open(s.bob, a1), 'a1');
      expect(s.bob.canSend, isTrue);
      expect(open(s.bob, a0), 'a0');
      expect(open(s.alice, send(s.bob, 'b0', 1)), 'b0');
    });

    test('messages of a previous chain arrive after the turn (pn)', () {
      final s = sessions(crypto);
      expect(open(s.bob, send(s.alice, 'a0', 1)), 'a0');
      final b0 = send(s.bob, 'b0', 1);
      final b1 = send(s.bob, 'b1', 2);
      final b2 = send(s.bob, 'b2', 3);
      expect(open(s.alice, b0), 'b0');
      expect(open(s.bob, send(s.alice, 'a1', 2)), 'a1');
      final b3 = send(s.bob, 'b3', 4);
      expect(b3.m.header.pn, 3);
      // b3 opens a new chain; b1 and b2 are skipped from the old one.
      expect(open(s.alice, b3), 'b3');
      expect(s.alice.skippedKeyCount, 2);
      expect(open(s.alice, b2), 'b2');
      expect(open(s.alice, b1), 'b1');
      expect(s.alice.skippedKeyCount, 0);
    });

    test('a message opened from a skipped key cannot be opened again', () {
      final s = sessions(crypto);
      final a0 = send(s.alice, 'a0', 1);
      final a1 = send(s.alice, 'a1', 2);
      open(s.bob, a1);
      expect(open(s.bob, a0), 'a0');
      expect(() => open(s.bob, a0), fails(RatchetFailure.oldMessage));
    });

    test('a forged message for a skipped slot keeps the key', () {
      final s = sessions(crypto);
      final a0 = send(s.alice, 'a0', 1);
      open(s.bob, send(s.alice, 'a1', 2));
      final before = snapshot(s.bob);
      expect(
        () => open(s.bob, tampered(a0)),
        fails(RatchetFailure.decryptionFailed),
      );
      expect(snapshot(s.bob), before);
      expect(open(s.bob, a0), 'a0');
    });

    test('a failed message that needed skipping stores no keys', () {
      final s = sessions(crypto);
      open(s.bob, send(s.alice, 'a0', 1));
      final b = [for (var i = 0; i < 4; i++) send(s.bob, 'b$i', i + 1)];
      open(s.alice, b[0]);
      open(s.bob, send(s.alice, 'a1', 2));
      final c = [for (var i = 0; i < 4; i++) send(s.bob, 'c$i', i + 5)];
      final before = snapshot(s.alice);
      // c3 would skip b1..b3 (old chain) and c0..c2, then fails the tag.
      expect(
        () => open(s.alice, tampered(c[3])),
        fails(RatchetFailure.decryptionFailed),
      );
      expect(s.alice.skippedKeyCount, 0);
      expect(snapshot(s.alice), before);
      for (final m in [c[3], b[2], c[0], b[1], c[2], b[3], c[1]]) {
        expect(open(s.alice, m), m.text);
      }
      expect(s.alice.skippedKeyCount, 0);
    });

    test('both send at once, delivered late and in random order', () {
      final s = sessions(crypto);
      // Alice sends first (Bob cannot send before her first message).
      final toBob = <Sent>[send(s.alice, 'a-first', 1)];
      final toAlice = <Sent>[];
      expect(open(s.bob, toBob.removeAt(0)), 'a-first');
      final rnd = math.Random(14);
      var aliceCounter = 1;
      var bobCounter = 0;
      var opened = 0;
      for (var i = 0; i < 600; i++) {
        switch (rnd.nextInt(4)) {
          case 0:
            toBob.add(send(s.alice, 'a$i', ++aliceCounter));
          case 1:
            toAlice.add(send(s.bob, 'b$i', ++bobCounter));
          case 2 when toBob.isNotEmpty:
            final m = toBob.removeAt(rnd.nextInt(toBob.length));
            expect(open(s.bob, m), m.text);
            opened++;
          case 3 when toAlice.isNotEmpty:
            final m = toAlice.removeAt(rnd.nextInt(toAlice.length));
            expect(open(s.alice, m), m.text);
            opened++;
        }
      }
      for (final m in toBob) {
        expect(open(s.bob, m), m.text);
      }
      for (final m in toAlice) {
        expect(open(s.alice, m), m.text);
      }
      expect(opened, greaterThan(100));
      expect(s.alice.skippedKeyCount, 0);
      expect(s.bob.skippedKeyCount, 0);
    });
  });

  group('limits', () {
    test('1,001 skipped keys are refused, 1,000 are accepted', () {
      final s = sessions(crypto);
      final sent = [
        for (var i = 0; i <= maxSkip + 1; i++) send(s.alice, 'a$i', i + 1),
      ];
      final before = snapshot(s.bob);
      // n = 1001 needs keys 0..1000: one too many.
      expect(
        () => open(s.bob, sent[maxSkip + 1]),
        fails(RatchetFailure.tooManySkipped),
      );
      expect(snapshot(s.bob), before);
      expect(s.bob.canSend, isFalse);
      expect(open(s.bob, sent[maxSkip]), 'a1000');
      expect(s.bob.skippedKeyCount, maxSkip);
      expect(open(s.bob, sent[maxSkip + 1]), 'a1001');
      expect(open(s.bob, sent[0]), 'a0');
      expect(open(s.bob, sent[999]), 'a999');
      expect(s.bob.skippedKeyCount, maxSkip - 2);
    });

    test('a turn counts the old and the new chain together', () {
      final s = sessions(crypto);
      open(s.bob, send(s.alice, 'a0', 1));
      open(s.alice, send(s.bob, 'b0', 1));
      // Bob reads only the first of 601 messages in Alice's chain ...
      final a = [for (var i = 0; i < 601; i++) send(s.alice, 'a$i', i + 2)];
      open(s.bob, a[0]);
      open(s.alice, send(s.bob, 'b1', 2));
      // ... and Alice's next chain says pn = 601: 600 keys to skip there.
      final c = [for (var i = 0; i < 402; i++) send(s.alice, 'c$i', i + 603)];
      expect(c[0].m.header.pn, 601);
      final before = snapshot(s.bob);
      expect(
        () => open(s.bob, c[401]), // 600 + 401 = 1001
        fails(RatchetFailure.tooManySkipped),
      );
      expect(snapshot(s.bob), before);
      expect(open(s.bob, c[400]), 'c400'); // 600 + 400 = 1000
      expect(s.bob.skippedKeyCount, 1000);
      expect(open(s.bob, a[600]), 'a600');
      expect(open(s.bob, c[0]), 'c0');
    });

    test('a huge message number is refused without work', () {
      final s = sessions(crypto);
      final m = send(s.alice, 'a0', 1);
      final forged = RatchetHeader(
        dhPub: m.m.header.dhPub,
        pn: 0,
        n: 0xFFFFFFFF,
      );
      expect(
        () => s.bob.decrypt(forged, m.m.ciphertext, envelopePrefix: m.prefix),
        fails(RatchetFailure.tooManySkipped),
      );
      expect(open(s.bob, m), 'a0');
    });

    test('at most 1,000 keys are stored; the oldest go first', () {
      final s = sessions(crypto);
      final a = [for (var i = 0; i <= 1000; i++) send(s.alice, 'a$i', i + 1)];
      open(s.bob, a[1000]); // stores a0..a999
      expect(s.bob.skippedKeyCount, 1000);
      open(s.alice, send(s.bob, 'b0', 1));
      final c = [for (var i = 0; i <= 10; i++) send(s.alice, 'c$i', i + 1002)];
      open(s.bob, c[10]); // stores c0..c9, deletes a0..a9
      expect(s.bob.skippedKeyCount, 1000);
      for (final m in [a[0], a[9]]) {
        expect(() => open(s.bob, m), throwsA(isA<RatchetException>()));
      }
      expect(open(s.bob, a[10]), 'a10');
      expect(open(s.bob, c[0]), 'c0');
      expect(open(s.bob, a[999]), 'a999');
    });
  });

  group('lifetime (30 days)', () {
    test('a key is usable for 30 days and gone after', () {
      final clock = FakeClock(DateTime.utc(2026, 3, 1));
      final s = sessions(crypto, clock: clock);
      final a = [for (var i = 0; i < 3; i++) send(s.alice, 'a$i', i + 1)];
      open(s.bob, a[2]); // a0, a1 skipped now
      clock.advance(const Duration(days: 30));
      expect(open(s.bob, a[0]), 'a0');
      clock.advance(const Duration(days: 1));
      // a1's key is 31 days old: treated as gone, and the failure changes
      // nothing (the key is only deleted by a success or the explicit call).
      expect(() => open(s.bob, a[1]), fails(RatchetFailure.oldMessage));
      expect(s.bob.skippedKeyCount, 1);
      s.bob.deleteExpiredSkippedKeys();
      expect(s.bob.skippedKeyCount, 0);
    });

    test('a successful decrypt deletes expired keys', () {
      final clock = FakeClock(DateTime.utc(2026, 3, 1));
      final s = sessions(crypto, clock: clock);
      final a = [for (var i = 0; i < 6; i++) send(s.alice, 'a$i', i + 1)];
      open(s.bob, a[2]); // a0, a1 stored on day 0
      clock.advance(const Duration(days: 20));
      open(s.bob, a[4]); // a3 stored on day 20
      expect(s.bob.skippedKeyCount, 3);
      clock.advance(const Duration(days: 11)); // day 31
      expect(open(s.bob, a[5]), 'a5');
      expect(s.bob.skippedKeyCount, 1);
      expect(open(s.bob, a[3]), 'a3');
      expect(() => open(s.bob, a[0]), fails(RatchetFailure.oldMessage));
    });

    test('a clock set back does not delete keys early', () {
      final clock = FakeClock(DateTime.utc(2026, 3, 1));
      final s = sessions(crypto, clock: clock);
      final a = [for (var i = 0; i < 2; i++) send(s.alice, 'a$i', i + 1)];
      open(s.bob, a[1]);
      clock.advance(const Duration(days: -400));
      s.bob.deleteExpiredSkippedKeys();
      expect(open(s.bob, a[0]), 'a0');
    });
  });

  test('dispose wipes the skipped keys', () {
    final s = sessions(crypto);
    final a = [for (var i = 0; i < 2; i++) send(s.alice, 'a$i', i + 1)];
    open(s.bob, a[1]);
    s.bob.dispose();
    expect(() => s.bob.skippedKeyCount, throwsStateError);
    expect(() => s.bob.deleteExpiredSkippedKeys(), throwsStateError);
    expect(() => s.bob.toStorageBytes(), throwsStateError);
  });
}
