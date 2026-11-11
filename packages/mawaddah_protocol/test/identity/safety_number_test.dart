// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import '../crypto/support.dart';

PublicIdentity _public(Object? json) {
  final m = json! as Map<String, Object?>;
  return PublicIdentity(
    signingKey: Ed25519PublicKey(hex(m['sig_pub'])),
    dhKey: X25519PublicKey(hex(m['dh_pub'])),
  );
}

/// The digit mapping of PROTOCOL.md section 5, written separately from the
/// library with BigInt: group g = u40(H[5g .. 5g+5]) mod 10000.
String _digitsFromHash(Uint8List h) => [
  for (var g = 0; g < 5; g++)
    (BigInt.parse(toHex(h.sublist(5 * g, 5 * g + 5)), radix: 16) %
            BigInt.from(10000))
        .toString()
        .padLeft(4, '0'),
].join();

void main() {
  late SodiumCrypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  group('safety_number.json', () {
    for (final c in loadVectors('safety_number')) {
      test(c.name, () {
        final a = _public(c.input['a']);
        final b = _public(c.input['b']);
        final expected = c.output['safety_number']! as String;
        expect(safetyNumber(crypto, a, b), expected);
        expect(safetyNumber(crypto, b, a), expected, reason: 'order-free');

        // The hash: BLAKE2b-256(label || K1 || K2), keys sorted unsigned.
        final ka = toHex([...a.signingKey.bytes, ...a.dhKey.bytes]);
        final kb = toHex([...b.signingKey.bytes, ...b.dhKey.bytes]);
        final sorted = [ka, kb]..sort();
        final h = crypto.blake2b(
          Uint8List.fromList([
            ...ascii.encode('mawaddah/v1/safety-number'),
            ...hex(sorted[0]),
            ...hex(sorted[1]),
          ]),
        );
        expect(toHex(h), c.output['hash']);
        expect(_digitsFromHash(h), expected);

        // Where the vector gives the secrets, they make these public keys.
        for (final side in [c.input['a'], c.input['b']]) {
          final m = side! as Map<String, Object?>;
          if (!m.containsKey('sig_seed')) continue;
          final sig = crypto.importEd25519KeyPair(hex(m['sig_seed']));
          final dh = crypto.importX25519KeyPair(hex(m['dh_secret']));
          expect(toHex(sig.publicKey.bytes), m['sig_pub']);
          expect(toHex(dh.publicKey.bytes), m['dh_pub']);
          sig.dispose();
          dh.dispose();
        }
      });
    }

    test('the vectors include a group with leading zeros', () {
      final all = [
        for (final c in loadVectors('safety_number'))
          ...safetyNumberGroups(c.output['safety_number']! as String),
      ];
      expect(all.any((g) => g.startsWith('0')), isTrue);
    });
  });

  group('safetyNumber', () {
    late DeviceIdentity a;
    late DeviceIdentity b;
    setUp(() {
      a = DeviceIdentity.generate(crypto, SeededRandom(21));
      b = DeviceIdentity.generate(crypto, SeededRandom(22));
    });
    tearDown(() {
      a.dispose();
      b.dispose();
    });

    test('is 20 ASCII digits, the same in both orders', () {
      final n = safetyNumber(crypto, a.publicIdentity, b.publicIdentity);
      expect(n, matches(RegExp(r'^[0-9]{20}$')));
      expect(safetyNumber(crypto, b.publicIdentity, a.publicIdentity), n);
    });

    test('changes when any byte of either key changes', () {
      final n = safetyNumber(crypto, a.publicIdentity, b.publicIdentity);
      PublicIdentity flip(PublicIdentity p, {required bool sig, int i = 31}) {
        final s = Uint8List.fromList(p.signingKey.bytes);
        final d = Uint8List.fromList(p.dhKey.bytes);
        (sig ? s : d)[i] ^= 1;
        return PublicIdentity(
          signingKey: Ed25519PublicKey(s),
          dhKey: X25519PublicKey(d),
        );
      }

      for (final sig in [true, false]) {
        for (final i in [0, 31]) {
          expect(
            safetyNumber(
              crypto,
              flip(a.publicIdentity, sig: sig, i: i),
              b.publicIdentity,
            ),
            isNot(n),
          );
          expect(
            safetyNumber(
              crypto,
              a.publicIdentity,
              flip(b.publicIdentity, sig: sig, i: i),
            ),
            isNot(n),
          );
        }
      }
    });

    test('swapping the two keys inside one device changes it', () {
      // K = IKsig || IKdh is ordered: the halves are not interchangeable.
      final n = safetyNumber(crypto, a.publicIdentity, b.publicIdentity);
      final swapped = PublicIdentity(
        signingKey: Ed25519PublicKey(a.publicIdentity.dhKey.bytes),
        dhKey: X25519PublicKey(a.publicIdentity.signingKey.bytes),
      );
      expect(safetyNumber(crypto, swapped, b.publicIdentity), isNot(n));
    });
  });

  group('safetyNumberGroups', () {
    test('splits into 5 groups of 4', () {
      expect(safetyNumberGroups('12345678901234567890'), [
        '1234',
        '5678',
        '9012',
        '3456',
        '7890',
      ]);
    });
    for (final bad in [
      '1234567890123456789',
      '123456789012345678901',
      '1234 5678 9012 3456 7890',
      '١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦٧٨٩٠',
    ]) {
      test('rejects "$bad"', () {
        expect(() => safetyNumberGroups(bad), throwsArgumentError);
      });
    }
  });
}
