// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late SodiumCrypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  group('XChaCha20-Poly1305 known answers', () {
    for (final c in loadVectors('xchacha20poly1305')) {
      test(c.name, () {
        final key = crypto.importAeadKey(hex(c.input['key']));
        final nonce = AeadNonce(hex(c.input['nonce']));
        final ad = hex(c.input['ad']);
        final plaintext = hex(c.input['plaintext']);
        final ct = crypto.encrypt(
          key: key,
          nonce: nonce,
          plaintext: plaintext,
          associatedData: ad,
        );
        expect(toHex(ct), c.output['ciphertext']);
        expect(
          crypto.decrypt(
            key: key,
            nonce: nonce,
            ciphertext: ct,
            associatedData: ad,
          ),
          plaintext,
        );
        key.dispose();
      });
    }
  });

  group('decryption is refused on', () {
    late AeadKey key;
    late AeadNonce nonce;
    final plaintext = Uint8List.fromList('salam'.codeUnits);
    final ad = Uint8List.fromList([1, 2, 3]);
    late Uint8List ct;
    setUp(() {
      key = crypto.generateAeadKey();
      nonce = crypto.generateAeadNonce();
      ct = crypto.encrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        associatedData: ad,
      );
    });
    tearDown(() => key.dispose());

    Matcher refused() => throwsA(isA<DecryptionFailedException>());

    test('a changed ciphertext byte', () {
      for (var i = 0; i < ct.length; i++) {
        final bad = Uint8List.fromList(ct)..[i] ^= 0x80;
        expect(
          () => crypto.decrypt(
            key: key,
            nonce: nonce,
            ciphertext: bad,
            associatedData: ad,
          ),
          refused(),
        );
      }
    });
    test('changed associated data', () {
      expect(
        () => crypto.decrypt(
          key: key,
          nonce: nonce,
          ciphertext: ct,
          associatedData: Uint8List.fromList([1, 2, 4]),
        ),
        refused(),
      );
      expect(
        () => crypto.decrypt(key: key, nonce: nonce, ciphertext: ct),
        refused(),
      );
    });
    test('another nonce or key', () {
      expect(
        () => crypto.decrypt(
          key: key,
          nonce: crypto.generateAeadNonce(),
          ciphertext: ct,
          associatedData: ad,
        ),
        refused(),
      );
      final other = crypto.generateAeadKey();
      expect(
        () => crypto.decrypt(
          key: other,
          nonce: nonce,
          ciphertext: ct,
          associatedData: ad,
        ),
        refused(),
      );
      other.dispose();
    });
    test('a ciphertext shorter than the tag', () {
      expect(
        () => crypto.decrypt(key: key, nonce: nonce, ciphertext: Uint8List(15)),
        refused(),
      );
    });
  });

  test('empty plaintext and missing associated data work', () {
    final key = crypto.generateAeadKey();
    final nonce = crypto.generateAeadNonce();
    final ct = crypto.encrypt(key: key, nonce: nonce, plaintext: Uint8List(0));
    expect(ct, hasLength(16));
    expect(crypto.decrypt(key: key, nonce: nonce, ciphertext: ct), isEmpty);
    // Empty associated data is the same as none.
    expect(
      crypto.decrypt(
        key: key,
        nonce: nonce,
        ciphertext: ct,
        associatedData: Uint8List(0),
      ),
      isEmpty,
    );
    key.dispose();
  });

  test('keys and nonces come from the injected RandomSource', () async {
    final seeded = await SodiumCrypto.load(random: SeededRandom(3));
    final r = SeededRandom(3);
    final key = seeded.generateAeadKey();
    expect(key.extractBytes(), r.nextBytes(32));
    expect(seeded.generateAeadNonce().bytes, r.nextBytes(24));
  });

  test('aeadKeyFrom takes the first 32 bytes of derived material', () {
    final material = Uint8List.fromList(List.generate(56, (i) => i));
    final derived = crypto.importSecret(Uint8List.fromList(material));
    final key = crypto.aeadKeyFrom(derived);
    expect(key.extractBytes(), material.sublist(0, 32));
    expect(derived.isDisposed, isFalse);
    expect(
      () => crypto.aeadKeyFrom(crypto.importSecret(Uint8List(31))),
      throwsArgumentError,
    );
  });
}
