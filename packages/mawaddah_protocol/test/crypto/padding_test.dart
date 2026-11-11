// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

void main() {
  late Crypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  test('ISO/IEC 7816-4: 0x80 then zeros to the next block, always', () {
    for (final (len, padded) in [(0, 16), (1, 16), (15, 16), (16, 32)]) {
      final data = Uint8List.fromList(List.generate(len, (i) => i + 1));
      final p = crypto.pad(data, 16);
      expect(p.length, padded, reason: '$len');
      expect(p.sublist(0, len), data);
      expect(p[len], 0x80);
      expect(p.sublist(len + 1), everyElement(0));
      expect(crypto.unpad(p, 16), data);
    }
  });

  test('pad does not change its input', () {
    final data = Uint8List.fromList([1, 2, 3]);
    crypto.pad(data, 256);
    expect(data, [1, 2, 3]);
  });

  test('unpad refuses data without valid padding', () {
    for (final (what, data) in [
      ('empty', Uint8List(0)),
      ('not a block', Uint8List(15)..[14] = 0x80),
      ('no marker', Uint8List(16)),
      (
        'marker then a non-zero byte',
        Uint8List(16)
          ..[3] = 0x80
          ..[15] = 1,
      ),
      ('wrong marker', Uint8List(16)..[15] = 0x81),
    ]) {
      expect(
        () => crypto.unpad(data, 16),
        throwsA(isA<InvalidPaddingException>()),
        reason: what,
      );
    }
  });
}
