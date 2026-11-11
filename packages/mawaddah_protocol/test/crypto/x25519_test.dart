// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late SodiumCrypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  Uint8List dh(Uint8List scalar, Uint8List u) {
    final pair = crypto.importX25519KeyPair(Uint8List.fromList(scalar));
    final out = crypto.x25519(pair.secretKey, X25519PublicKey(u));
    try {
      return out.extractBytes();
    } finally {
      out.dispose();
      pair.dispose();
    }
  }

  group('RFC 7748 known answers', () {
    final cases = loadVectors('rfc7748_x25519');
    for (final c in cases) {
      test(c.name, () {
        if (c.input.containsKey('scalar')) {
          expect(
            toHex(dh(hex(c.input['scalar']), hex(c.input['u']))),
            c.output['u'],
          );
        } else if (c.input.containsKey('iterations')) {
          // Section 5.2: k = u = 9; repeat: k, u = X25519(k, u), k.
          var k = Uint8List(32)..[0] = 9;
          var u = Uint8List.fromList(k);
          for (var i = 0; i < (c.input['iterations']! as int); i++) {
            final next = dh(k, u);
            u = k;
            k = next;
          }
          expect(toHex(k), c.output['k']);
        } else {
          final alice = crypto.importX25519KeyPair(
            hex(c.input['alice_secret']),
          );
          final bob = crypto.importX25519KeyPair(hex(c.input['bob_secret']));
          expect(toHex(alice.publicKey.bytes), c.output['alice_public']);
          expect(toHex(bob.publicKey.bytes), c.output['bob_public']);
          final k1 = crypto.x25519(alice.secretKey, bob.publicKey);
          final k2 = crypto.x25519(bob.secretKey, alice.publicKey);
          expect(toHex(k1.extractBytes()), c.output['shared']);
          expect(toHex(k2.extractBytes()), c.output['shared']);
          k1.dispose();
          k2.dispose();
          alice.dispose();
          bob.dispose();
        }
      });
    }
  });

  test('a small-order public key (all zeros) is refused', () {
    final pair = crypto.generateX25519KeyPair();
    expect(
      () => crypto.x25519(pair.secretKey, X25519PublicKey(Uint8List(32))),
      throwsA(isA<InvalidPublicKeyException>()),
    );
    pair.dispose();
  });

  test('keys come from the injected RandomSource', () async {
    final a = (await SodiumCrypto.load(random: SeededRandom(42)))
        .generateX25519KeyPair();
    final b = (await SodiumCrypto.load(random: SeededRandom(42)))
        .generateX25519KeyPair();
    expect(a.publicKey, b.publicKey);
    final seed = SeededRandom(42).nextBytes(32);
    final c = crypto.importX25519KeyPair(seed);
    expect(c.publicKey, a.publicKey);
    expect(seed, everyElement(0), reason: 'imported secret is zeroed');
    expect(c.secretKey.extractBytes(), SeededRandom(42).nextBytes(32));
  });

  test('wrong sizes are refused', () {
    expect(() => X25519PublicKey(Uint8List(31)), throwsArgumentError);
    final short = Uint8List.fromList(List.filled(31, 7));
    expect(() => crypto.importX25519KeyPair(short), throwsArgumentError);
    expect(short, everyElement(0));
  });
}
