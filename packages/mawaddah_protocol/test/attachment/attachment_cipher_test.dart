// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import '../crypto/support.dart';

Uint8List pattern(int length) =>
    Uint8List.fromList([for (var i = 0; i < length; i++) (i * 7 + 3) & 0xff]);

Uint8List mutate(Uint8List c, String mutation) {
  const header = 24;
  const first = header + 65536 + 17;
  switch (mutation) {
    case 'drop_last_chunk':
      return c.sublist(0, first);
    case 'cut_5':
      return c.sublist(0, c.length - 5);
    case 'drop_first_chunk':
      return Uint8List.fromList([...c.sublist(0, header), ...c.sublist(first)]);
    case 'swap_chunks':
      return Uint8List.fromList([
        ...c.sublist(0, header),
        ...c.sublist(first),
        ...c.sublist(header, first),
      ]);
    case 'append_byte':
      return Uint8List.fromList([...c, 0]);
    case 'flip_header':
      return c.sublist(0)..[3] ^= 1;
    case 'flip_first_chunk':
      return c.sublist(0)..[header + 100] ^= 1;
    case 'flip_last_chunk':
      return c.sublist(0)..[c.length - 1] ^= 0x80;
    case 'header_only':
      return c.sublist(0, header);
    case 'short_header':
      return c.sublist(0, header - 1);
    case 'empty':
      return Uint8List(0);
    case 'none':
      return c;
  }
  throw StateError(mutation);
}

void main() {
  late SodiumCrypto crypto;
  late AttachmentCipher cipher;
  setUpAll(() async {
    crypto = await SodiumCrypto.load();
    cipher = AttachmentCipher(crypto, SeededRandom(1));
  });

  SecretBytes key([int seed = 7]) =>
      crypto.importSecret(SeededRandom(seed).nextBytes(32));

  group('round trip', () {
    for (final n in [0, 1, 5, 65535, 65536, 65537, 131072, 131073, 300000]) {
      test('$n bytes', () async {
        final k = key();
        final ct = await cipher.encrypt(key: k, plaintext: pattern(n));
        expect(ct.length, attachmentCiphertextLength(n));
        expect(await cipher.decrypt(key: k, ciphertext: ct), pattern(n));
        k.dispose();
      });
    }

    test('two encryptions of one file differ (fresh stream header)', () async {
      final k = key();
      final a = await cipher.encrypt(key: k, plaintext: pattern(10));
      final b = await cipher.encrypt(key: k, plaintext: pattern(10));
      expect(a, isNot(b));
      k.dispose();
    });
  });

  group('size limit', () {
    test('the largest file is accepted and fills the relay limit', () async {
      expect(
        attachmentCiphertextLength(maxAttachmentPlaintext),
        maxAttachmentCiphertext,
      );
      final k = key();
      final ct = await cipher.encrypt(
        key: k,
        plaintext: pattern(maxAttachmentPlaintext),
      );
      expect(ct.length, 10485760);
      expect(
        await cipher.decrypt(key: k, ciphertext: ct),
        pattern(maxAttachmentPlaintext),
      );
      k.dispose();
    });

    test('one byte more is refused both ways', () async {
      final k = key();
      await expectLater(
        cipher.encrypt(key: k, plaintext: pattern(maxAttachmentPlaintext + 1)),
        throwsA(isA<AttachmentTooLargeException>()),
      );
      await expectLater(
        cipher.decrypt(key: k, ciphertext: Uint8List(10485761)),
        throwsA(isA<AttachmentTooLargeException>()),
      );
      k.dispose();
    });
  });

  group('refused', () {
    late Uint8List base;
    setUpAll(() async {
      final k = key();
      base = await cipher.encrypt(key: k, plaintext: pattern(65537));
      k.dispose();
    });

    for (final m in [
      'drop_last_chunk',
      'cut_5',
      'drop_first_chunk',
      'swap_chunks',
      'append_byte',
      'flip_header',
      'flip_first_chunk',
      'flip_last_chunk',
      'header_only',
      'short_header',
      'empty',
    ]) {
      test(m, () async {
        final k = key();
        await expectLater(
          cipher.decrypt(key: k, ciphertext: mutate(base, m)),
          throwsA(isA<DecryptionFailedException>()),
        );
        k.dispose();
      });
    }

    test('wrong key', () async {
      final k = key(8);
      await expectLater(
        cipher.decrypt(key: k, ciphertext: base),
        throwsA(isA<DecryptionFailedException>()),
      );
      k.dispose();
    });

    test('an empty file cut after its header, and a full chunk cut', () async {
      final k = key();
      final empty = await cipher.encrypt(key: k, plaintext: Uint8List(0));
      expect(empty.length, 24 + 17);
      await expectLater(
        cipher.decrypt(key: k, ciphertext: empty.sublist(0, 24 + 16)),
        throwsA(isA<DecryptionFailedException>()),
      );
      // An exact multiple of the chunk size: the first chunk is FINAL, so
      // a stream continued after it is refused.
      final one = await cipher.encrypt(key: k, plaintext: pattern(65536));
      await expectLater(
        cipher.decrypt(key: k, ciphertext: Uint8List.fromList([...one, 1])),
        throwsA(isA<DecryptionFailedException>()),
      );
      k.dispose();
    });
  });

  test('the constants match libsodium', () {
    expect(attachmentHeaderLength, 24);
    expect(attachmentChunkOverhead, 17);
    expect(attachmentKeyLength, 32);
  });

  group('keys and ids', () {
    test('generateKey and generateBlobId draw from the injected source', () {
      final a = AttachmentCipher(crypto, SeededRandom(5));
      final b = AttachmentCipher(crypto, SeededRandom(5));
      final ka = a.generateKey();
      final kb = b.generateKey();
      expect(ka.extractBytes(), kb.extractBytes());
      expect(ka.length, 32);
      final id = a.generateBlobId();
      expect(id.length, 16);
      expect(id, b.generateBlobId());
      ka.dispose();
      kb.dispose();
    });

    test('a disposed key cannot be used', () async {
      final k = key()..dispose();
      await expectLater(
        cipher.encrypt(key: k, plaintext: pattern(3)),
        throwsA(isA<StateError>()),
      );
    });

    test('a short random source is refused', () {
      final bad = AttachmentCipher(crypto, _Short());
      expect(bad.generateBlobId, throwsStateError);
    });
  });

  group('vectors', () {
    final cases = loadVectors('attachment');
    final byName = {for (final c in cases) c.name: c};
    for (final c in cases) {
      test(c.name, () async {
        final k = crypto.importSecret(hex(c.input['key']));
        if (c.output['verdict'] == 'ok') {
          final ct = hex(c.output['ciphertext']);
          expect(
            await cipher.decrypt(key: k, ciphertext: ct),
            pattern(c.input['pattern_length']! as int),
          );
        } else {
          final base = hex(byName[c.input['base']]!.output['ciphertext']);
          await expectLater(
            cipher.decrypt(
              key: k,
              ciphertext: mutate(base, c.input['mutation']! as String),
            ),
            throwsA(isA<DecryptionFailedException>()),
          );
        }
        k.dispose();
      });
    }
  });
}

class _Short implements RandomSource {
  @override
  Uint8List nextBytes(int length) => Uint8List(length - 1);
}
