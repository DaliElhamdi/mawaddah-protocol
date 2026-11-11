// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late SodiumCrypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  group('HMAC-SHA-512-256', () {
    for (final c in loadVectors('rfc4231_hmac')) {
      test(c.name, () {
        final key = crypto.importSecret(hex(c.input['key']));
        final tag = crypto.hmac(key, hex(c.input['message']));
        expect(toHex(tag), c.output['tag']);
        expect(crypto.verifyHmac(key, hex(c.input['message']), tag), isTrue);
        key.dispose();
      });
    }

    test('a changed message, key or tag does not verify', () {
      final key = crypto.importSecret(Uint8List.fromList(List.filled(32, 7)));
      final other = crypto.importSecret(Uint8List.fromList(List.filled(32, 8)));
      final msg = Uint8List.fromList([1, 2, 3]);
      final tag = crypto.hmac(key, msg);
      expect(crypto.verifyHmac(key, Uint8List.fromList([1, 2, 4]), tag), false);
      expect(crypto.verifyHmac(other, msg, tag), false);
      final bad = Uint8List.fromList(tag)..[31] ^= 1;
      expect(crypto.verifyHmac(key, msg, bad), false);
      expect(crypto.verifyHmac(key, msg, Uint8List(31)), false);
      key.dispose();
      other.dispose();
    });

    test('a key that is not 32 bytes is refused', () {
      final key = crypto.importSecret(Uint8List.fromList(List.filled(16, 1)));
      expect(() => crypto.hmac(key, Uint8List(1)), throwsArgumentError);
      expect(
        () => crypto.verifyHmac(key, Uint8List(1), Uint8List(32)),
        throwsArgumentError,
      );
      key.dispose();
    });
  });
}
