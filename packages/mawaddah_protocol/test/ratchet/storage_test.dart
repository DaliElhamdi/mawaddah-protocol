// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Saving and restoring a RatchetSession (toStorageBytes / fromStorageBytes,
// save / load), crash-restore, and "a failed decrypt never advances state".

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late Crypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  final clock = FakeClock(DateTime.utc(2026, 5, 1));

  RatchetSession restore(Uint8List bytes, {int seed = 77}) =>
      RatchetSession.fromStorageBytes(
        crypto: crypto,
        random: SeededRandom(seed),
        clock: clock,
        bytes: bytes,
      );

  /// Restores a copy of [s]'s bytes and checks the copy saves to the same
  /// bytes; [s] is disposed and the restored session returned.
  RatchetSession roundTrip(RatchetSession s) {
    final bytes = s.toStorageBytes();
    final copy = Uint8List.fromList(bytes);
    s.dispose();
    final r = restore(copy);
    expect(copy.every((b) => b == 0), isTrue, reason: 'input zeroed');
    expect(r.toStorageBytes(), bytes);
    return r;
  }

  group('round trip', () {
    test('the three shapes of a fresh session', () {
      final s = sessions(crypto, clock: clock);
      // Bob before the first message: no DHr, CKs or CKr.
      final bobBytes = s.bob.toStorageBytes();
      expect(bobBytes.length, 306);
      expect(bobBytes[0], RatchetSession.storageFormatVersion);
      expect(bobBytes[129], 0);
      // Alice before the first reply: DHr and CKs.
      expect(s.alice.toStorageBytes()[129], 3);
      final alice = roundTrip(s.alice);
      final bob = roundTrip(s.bob);
      expect(bob.canSend, isFalse);
      expect(open(bob, send(alice, 'a0', 1)), 'a0');
      expect(bob.toStorageBytes()[129], 7);
      expect(open(alice, send(bob, 'b0', 1)), 'b0');
    });

    test('mid-conversation with skipped keys of two chains', () {
      final s = sessions(crypto, clock: clock);
      open(s.bob, send(s.alice, 'a0', 1));
      final b = [for (var i = 0; i < 3; i++) send(s.bob, 'b$i', i + 1)];
      open(s.alice, b[0]);
      open(s.bob, send(s.alice, 'a1', 2));
      final c = [for (var i = 0; i < 3; i++) send(s.bob, 'c$i', i + 4)];
      open(s.alice, c[2]); // skips b1, b2, c0, c1
      expect(s.alice.skippedKeyCount, 4);
      final bytes = s.alice.toStorageBytes();
      expect(bytes.length, 306 + 4 * 76);

      final alice = roundTrip(s.alice);
      expect(alice.skippedKeyCount, 4);
      for (final m in [b[2], c[0], b[1], c[1]]) {
        expect(open(alice, m), m.text);
      }
      expect(open(s.bob, send(alice, 'a2', 3)), 'a2');
      expect(open(alice, send(s.bob, 'c3', 7)), 'c3');
    });

    test('the time each skipped key was stored is kept', () {
      final c = FakeClock(DateTime.utc(2026, 5, 1));
      final s = sessions(crypto, clock: c);
      final a = [for (var i = 0; i < 3; i++) send(s.alice, 'a$i', i + 1)];
      open(s.bob, a[2]);
      final bytes = s.bob.toStorageBytes();
      s.bob.dispose();
      c.advance(const Duration(days: 31));
      final bob = RatchetSession.fromStorageBytes(
        crypto: crypto,
        random: SeededRandom(5),
        clock: c,
        bytes: bytes,
      );
      expect(() => open(bob, a[0]), throwsA(isA<RatchetException>()));
      bob.deleteExpiredSkippedKeys();
      expect(bob.skippedKeyCount, 0);
    });
  });

  group('crash and restore through Storage', () {
    test(
      'a message read but not committed opens again after restart',
      () async {
        final storage = InMemoryStorage();
        final s = sessions(crypto, clock: clock);
        var alice = s.alice;
        var bob = s.bob;
        Future<RatchetSession> reload(String key) async =>
            (await RatchetSession.load(
              crypto: crypto,
              random: SeededRandom(key.length + 900),
              clock: clock,
              storage: storage,
              key: key,
            ))!;

        // The sender saves before the message leaves the device.
        final a0 = send(alice, 'a0', 1);
        final a1 = send(alice, 'a1', 2);
        await alice.save(storage, 'alice');
        // Bob reads a1 first (a0 is late) and commits.
        expect(open(bob, a1), 'a1');
        await bob.save(storage, 'bob');
        // Bob reads a0 but dies before committing: the relay sends it again.
        expect(open(bob, a0), 'a0');
        bob.dispose();
        bob = await reload('bob');
        expect(bob.skippedKeyCount, 1);
        expect(open(bob, a0), 'a0');
        await bob.save(storage, 'bob');

        // Same for a DH ratchet step: Bob replies, Alice dies mid-read.
        final b0 = send(bob, 'b0', 1);
        await bob.save(storage, 'bob');
        expect(open(alice, b0), 'b0');
        alice.dispose();
        alice = await reload('alice');
        expect(open(alice, b0), 'b0');
        await alice.save(storage, 'alice');

        // Both restored sessions keep talking.
        alice.dispose();
        bob.dispose();
        alice = await reload('alice');
        bob = await reload('bob');
        expect(open(bob, send(alice, 'a2', 3)), 'a2');
        expect(open(alice, send(bob, 'b1', 2)), 'b1');
      },
    );

    test('load returns null when nothing is saved', () async {
      expect(
        await RatchetSession.load(
          crypto: crypto,
          random: SeededRandom(1),
          clock: clock,
          storage: InMemoryStorage(),
          key: 'none',
        ),
        isNull,
      );
    });
  });

  group('a failed decrypt never advances the state', () {
    test('for every kind of failure', () {
      final s = sessions(crypto, clock: clock);
      open(s.bob, send(s.alice, 'a0', 1));
      open(s.alice, send(s.bob, 'b0', 1));
      final a = [for (var i = 0; i < 4; i++) send(s.alice, 'a$i', i + 2)];
      open(s.bob, a[3]); // a0..a2 of this chain skipped
      final before = s.bob.toStorageBytes();

      final forgedKey = crypto.generateX25519KeyPair().publicKey;
      final attempts = <String, void Function()>{
        'bad tag, skipped slot': () => open(s.bob, tampered(a[1])),
        'bad tag, same chain ahead': () =>
            open(s.bob, tampered(send(s.alice, 'x', 9))),
        'bad tag, new chain': () => s.bob.decrypt(
          RatchetHeader(dhPub: forgedKey, pn: 9, n: 5),
          a[0].m.ciphertext,
          envelopePrefix: a[0].prefix,
        ),
        'small-order key': () => s.bob.decrypt(
          RatchetHeader(dhPub: X25519PublicKey(Uint8List(32)), pn: 0, n: 0),
          a[0].m.ciphertext,
          envelopePrefix: a[0].prefix,
        ),
        'too many skipped': () => s.bob.decrypt(
          RatchetHeader(dhPub: a[0].m.header.dhPub, pn: 0, n: 5000),
          a[0].m.ciphertext,
          envelopePrefix: a[0].prefix,
        ),
        'repeat': () => open(s.bob, a[3]),
      };
      for (final MapEntry(:key, :value) in attempts.entries) {
        expect(value, throwsA(isA<RatchetException>()), reason: key);
        expect(s.bob.toStorageBytes(), before, reason: key);
      }
      for (final m in a.take(3)) {
        expect(open(s.bob, m), m.text);
      }
    });
  });

  group('damaged bytes', () {
    late Uint8List good;

    setUp(() {
      final s = sessions(crypto, clock: clock);
      final a = [for (var i = 0; i < 3; i++) send(s.alice, 'a$i', i + 1)];
      open(s.bob, a[2]);
      good = s.bob.toStorageBytes();
      s.alice.dispose();
      s.bob.dispose();
    });

    Uint8List changed(void Function(Uint8List b, ByteData d) edit) {
      final b = Uint8List.fromList(good);
      edit(b, ByteData.sublistView(b));
      return b;
    }

    test('are refused, and the input is zeroed', () {
      final bad = <String, Uint8List>{
        'empty': Uint8List(0),
        'too short': Uint8List.fromList(good.sublist(0, 305)),
        'unknown version': changed((b, _) => b[0] = 2),
        'unknown flag': changed((b, _) => b[129] |= 8),
        'CKr without DHr': changed((b, _) => b[129] = 4),
        'CKs without DHr': changed((b, _) => b[129] = 2),
        'one skipped key missing': Uint8List.fromList(
          good.sublist(0, good.length - 76),
        ),
        'count too high': changed((_, d) => d.setUint32(302, 1001)),
        'count does not match': changed((_, d) => d.setUint32(302, 1)),
        'repeated skipped key': changed((b, _) {
          b.setRange(306 + 76, 306 + 76 + 36, b.sublist(306, 306 + 36));
        }),
        'time out of range': changed(
          (_, d) => d.setInt64(306 + 36, 0x7FFFFFFFFFFFFFFF),
        ),
      };
      for (final MapEntry(:key, :value) in bad.entries) {
        expect(() => restore(value), throwsFormatException, reason: key);
        expect(value.every((b) => b == 0), isTrue, reason: '$key zeroed');
      }
      // The unchanged bytes still restore.
      restore(Uint8List.fromList(good)).dispose();
    });
  });
}
