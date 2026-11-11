// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as dart_crypto;
import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:sodium/sodium.ffi.dart' as raw;
import 'package:test/test.dart';

import 'support.dart';

/// libsodium's `crypto_kdf_hkdf_sha256_expand` called directly with byte
/// `info`. The `sodium` Dart API (and so [Crypto.hkdfExpand]) only takes
/// `info` as a String, which cannot carry the binary `info` of RFC 5869
/// cases 1 and 2. Used only to check those cases and to compare the wrapper.
Uint8List rawExpand(Uint8List prk, Uint8List info, int length) {
  const lib = raw.LibSodiumFFI();
  final out = raw.SodiumPointer<UnsignedChar>.alloc(lib, count: length);
  final ctx = info.toSodiumPointer<Char>(lib);
  final key = prk.toSodiumPointer<UnsignedChar>(lib);
  try {
    final rc = lib.crypto_kdf_hkdf_sha256_expand(
        out.ptr, length, ctx.ptr, info.length, key.ptr);
    if (rc != 0) throw StateError('expand failed: $rc');
    return Uint8List.fromList(out.asListView<Uint8List>());
  } finally {
    out.dispose();
    ctx.dispose();
    key.dispose();
  }
}

void main() {
  late SodiumCrypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  SecretBytes secret(Uint8List b) => crypto.importSecret(b);

  group('RFC 5869 known answers', () {
    for (final c in loadVectors('rfc5869_hkdf')) {
      test(c.name, () {
        final saltBytes = hex(c.input['salt']);
        final info = hex(c.input['info']);
        final length = c.input['length']! as int;
        final salt = saltBytes.isEmpty ? null : secret(saltBytes);
        final prk =
            crypto.hkdfExtract(salt: salt, ikm: secret(hex(c.input['ikm'])));
        expect(toHex(prk.extractBytes()), c.output['prk'], reason: 'PRK');

        if (info.isEmpty) {
          // Through the wrapper (case 3): empty info is the ASCII label "".
          final okm = crypto.hkdfExpand(prk: prk, info: '', length: length);
          expect(toHex(okm.extractBytes()), c.output['okm'], reason: 'OKM');
        } else {
          // Binary info (cases 1 and 2): libsodium directly.
          expect(toHex(rawExpand(prk.extractBytes(), info, length)),
              c.output['okm'],
              reason: 'OKM');
        }
      });
    }
  });

  group('expand with an ASCII label', () {
    const label = 'mawaddah/v1/ratchet/mk';
    late SecretBytes prk;
    setUp(() => prk = secret(Uint8List.fromList(List.generate(32, (i) => i))));
    tearDown(() => prk.dispose());

    test('matches libsodium called with the label bytes', () {
      for (final length in [1, 32, 56, 64, 100]) {
        final okm = crypto.hkdfExpand(prk: prk, info: label, length: length);
        expect(okm.extractBytes(),
            rawExpand(prk.extractBytes(), ascii.encode(label), length));
      }
    });

    test('matches HMAC-SHA-256 from package:crypto (RFC 5869 T(1))', () {
      // T(1) = HMAC-Hash(PRK, info || 0x01); independent implementation.
      final t1 = dart_crypto.Hmac(dart_crypto.sha256, prk.extractBytes())
          .convert([...ascii.encode(label), 1]).bytes;
      final okm = crypto.hkdfExpand(prk: prk, info: label, length: 32);
      expect(okm.extractBytes(), t1);
    });

    test('a NUL inside the label is kept (not a C-string terminator)', () {
      const withNul = 'a\u0000b';
      final okm = crypto.hkdfExpand(prk: prk, info: withNul, length: 32);
      expect(okm.extractBytes(),
          rawExpand(prk.extractBytes(), ascii.encode(withNul), 32));
      expect(
          okm.extractBytes(),
          isNot(crypto
              .hkdfExpand(prk: prk, info: 'a', length: 32)
              .extractBytes()));
    });

    test('length must be 1..8160 and prk 32 bytes', () {
      expect(
          crypto
              .hkdfExpand(prk: prk, info: label, length: hkdfMaxLength)
              .length,
          8160);
      expect(() => crypto.hkdfExpand(prk: prk, info: label, length: 8161),
          throwsRangeError);
      expect(() => crypto.hkdfExpand(prk: prk, info: label, length: 0),
          throwsRangeError);
      final short = crypto.importSecret(Uint8List(31));
      expect(() => crypto.hkdfExpand(prk: short, info: label, length: 32),
          throwsArgumentError);
    });

    test('copy is independent of the original', () {
      final c = prk.copy();
      expect(c.extractBytes(), prk.extractBytes());
      c.dispose();
      expect(prk.isDisposed, isFalse);
      expect(prk.extractBytes(), hasLength(32));
    });

    test('a non-ASCII label is refused', () {
      expect(() => crypto.hkdfExpand(prk: prk, info: 'مودة', length: 32),
          throwsArgumentError);
    });
  });

  test('hkdf() equals extract then expand', () {
    final ikm = Uint8List.fromList(List.filled(32, 0x0b));
    final salt = Uint8List.fromList(List.filled(32, 0x5a));
    final full = crypto.hkdf(
        salt: secret(Uint8List.fromList(salt)),
        ikm: secret(Uint8List.fromList(ikm)),
        info: 'mawaddah/v1/ratchet/rk',
        length: 64);
    final prk = crypto.hkdfExtract(salt: secret(salt), ikm: secret(ikm));
    final parts =
        crypto.hkdfExpand(prk: prk, info: 'mawaddah/v1/ratchet/rk', length: 64);
    expect(full.extractBytes(), parts.extractBytes());
  });

  test('a missing salt equals 32 zero bytes (RFC 5869 section 2.2)', () {
    final ikm = Uint8List.fromList(List.filled(22, 0x0b));
    final a = crypto.hkdfExtract(ikm: secret(Uint8List.fromList(ikm)));
    final b = crypto.hkdfExtract(
        salt: secret(Uint8List(32)), ikm: secret(Uint8List.fromList(ikm)));
    expect(a.extractBytes(), b.extractBytes());
  });
}
