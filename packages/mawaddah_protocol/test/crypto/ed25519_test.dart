// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late SodiumCrypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  group('RFC 8032 known answers', () {
    for (final c in loadVectors('rfc8032_ed25519')) {
      test(c.name, () {
        final pair = crypto.importEd25519KeyPair(hex(c.input['seed']));
        final message = hex(c.input['message']);
        expect(toHex(pair.publicKey.bytes), c.output['public_key']);
        final sig = crypto.sign(pair.secretKey, message);
        expect(toHex(sig.bytes), c.output['signature']);
        expect(crypto.verify(pair.publicKey, message, sig), isTrue);
        expect(
          toHex(pair.secretKey.extractBytes()),
          c.input['seed'],
          reason: 'extractBytes returns the seed',
        );
        pair.dispose();
      });
    }
  });

  group('verification fails on', () {
    late Ed25519KeyPair pair;
    final message = Uint8List.fromList('mawaddah'.codeUnits);
    late Ed25519Signature sig;
    setUp(() {
      pair = crypto.generateEd25519KeyPair();
      sig = crypto.sign(pair.secretKey, message);
    });
    tearDown(() => pair.dispose());

    test('a changed message', () {
      final changed = Uint8List.fromList(message)..[0] ^= 1;
      expect(crypto.verify(pair.publicKey, changed, sig), isFalse);
    });
    test('a changed signature', () {
      final bad = Uint8List.fromList(sig.bytes)..[10] ^= 1;
      expect(
        crypto.verify(pair.publicKey, message, Ed25519Signature(bad)),
        isFalse,
      );
    });
    test('another key', () {
      final other = crypto.generateEd25519KeyPair();
      expect(crypto.verify(other.publicKey, message, sig), isFalse);
      other.dispose();
    });
  });

  test('keys come from the injected RandomSource', () async {
    final a = (await SodiumCrypto.load(random: SeededRandom(7)))
        .generateEd25519KeyPair();
    final seed = SeededRandom(7).nextBytes(32);
    final b = crypto.importEd25519KeyPair(seed);
    expect(seed, everyElement(0), reason: 'imported seed is zeroed');
    expect(a.publicKey, b.publicKey);
  });

  test('wrong sizes are refused', () {
    expect(() => Ed25519PublicKey(Uint8List(33)), throwsArgumentError);
    expect(() => Ed25519Signature(Uint8List(63)), throwsArgumentError);
    expect(
      () => crypto.importEd25519KeyPair(Uint8List(64)),
      throwsArgumentError,
    );
  });
}
