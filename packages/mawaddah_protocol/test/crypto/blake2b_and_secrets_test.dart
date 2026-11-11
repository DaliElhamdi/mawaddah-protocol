// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late SodiumCrypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  group('BLAKE2b', () {
    for (final c in loadVectors('rfc7693_blake2b')) {
      test(c.name, () {
        final digest = crypto.blake2b(hex(c.input['message']),
            length: c.input['length']! as int);
        expect(toHex(digest), c.output['digest']);
      });
    }
    test('default length is 32 bytes; a key changes the digest', () {
      final m = Uint8List.fromList([1, 2, 3]);
      expect(crypto.blake2b(m), hasLength(32));
      final key = crypto.importSecret(Uint8List.fromList(List.filled(32, 9)));
      expect(crypto.blake2b(m, key: key), isNot(crypto.blake2b(m)));
      key.dispose();
    });
    test('lengths outside 16..64 are refused', () {
      expect(() => crypto.blake2b(Uint8List(1), length: 15), throwsRangeError);
      expect(() => crypto.blake2b(Uint8List(1), length: 65), throwsRangeError);
    });
  });

  group('secret handling', () {
    test('importSecret zeroes the caller list', () {
      final b = Uint8List.fromList([1, 2, 3, 4]);
      final s = crypto.importSecret(b);
      expect(b, everyElement(0));
      expect(s.extractBytes(), [1, 2, 3, 4]);
      s.dispose();
    });

    test('use after dispose throws; dispose twice is fine', () {
      final s = crypto.importSecret(Uint8List.fromList([5, 6]));
      s.dispose();
      s.dispose();
      expect(s.isDisposed, isTrue);
      expect(s.extractBytes, throwsStateError);
      final pair = crypto.generateEd25519KeyPair()..dispose();
      expect(() => crypto.sign(pair.secretKey, Uint8List(1)), throwsStateError);
    });

    test('slice and concat', () {
      final a = crypto.importSecret(Uint8List.fromList([1, 2, 3]));
      final b = crypto.importSecret(Uint8List.fromList([4, 5]));
      final ab = crypto.concat([a, b]);
      expect(ab.extractBytes(), [1, 2, 3, 4, 5]);
      expect(ab.slice(1, 4).extractBytes(), [2, 3, 4]);
      expect(ab.slice(3).extractBytes(), [4, 5]);
      expect(() => ab.slice(2, 9), throwsRangeError);
      expect(() => crypto.concat([]), throwsArgumentError);
    });

    test('toString never shows secret bytes', () {
      final s = crypto.importSecret(Uint8List.fromList([0xab, 0xcd]));
      expect(s.toString(), isNot(contains('ab')));
      expect(s.toString(), 'SecretBytes(2 bytes)');
    });

    test('public values compare by value', () {
      final pk = Uint8List.fromList(List.filled(32, 1));
      expect(X25519PublicKey(pk), X25519PublicKey(Uint8List.fromList(pk)));
      expect(X25519PublicKey(pk).hashCode,
          X25519PublicKey(Uint8List.fromList(pk)).hashCode);
      expect(X25519PublicKey(pk), isNot(Ed25519PublicKey(pk)));
      // The stored bytes are a copy and cannot be changed through the getter.
      final k = X25519PublicKey(pk);
      pk[0] = 2;
      expect(k.bytes[0], 1);
      expect(() => k.bytes[0] = 3, throwsUnsupportedError);
    });

    test('SodiumRandomSource gives the requested length', () async {
      final c = await SodiumCrypto.load();
      expect(c.libsodiumVersion, startsWith('1.0.'));
      final key = c.generateAeadKey();
      expect(key.length, 32);
      key.dispose();
    });
  });
}
