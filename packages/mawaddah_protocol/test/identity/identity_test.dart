// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import '../crypto/support.dart';

/// Hands out exactly the given bytes, in order, then fails.
class ReplayRandom implements RandomSource {
  ReplayRandom(List<Uint8List> chunks)
    : _bytes = [for (final c in chunks) ...c];

  final List<int> _bytes;
  var _at = 0;

  @override
  Uint8List nextBytes(int length) {
    if (_at + length > _bytes.length) throw StateError('replay exhausted');
    final out = Uint8List.fromList(_bytes.sublist(_at, _at + length));
    _at += length;
    return out;
  }
}

/// Returns fewer bytes than asked for.
class ShortRandom implements RandomSource {
  @override
  Uint8List nextBytes(int length) => Uint8List(length - 1);
}

void main() {
  late SodiumCrypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  group('identity.json', () {
    for (final c in loadVectors('identity')) {
      test(c.name, () {
        final sigSeed = hex(c.input['sig_seed']);
        final dhSecret = hex(c.input['dh_secret']);
        final id = DeviceIdentity.generate(
          crypto,
          ReplayRandom([sigSeed, dhSecret]),
        );
        final p = id.publicIdentity;
        expect(toHex(p.signingKey.bytes), c.output['sig_pub']);
        expect(toHex(p.dhKey.bytes), c.output['dh_pub']);
        expect(toHex(id.deviceId.bytes), c.output['device_id']);
        expect(id.deviceId.toBase64Url(), c.output['device_id_base64url']);
        expect(
          DeviceId.parse(c.output['device_id_base64url']! as String),
          id.deviceId,
        );
        id.dispose();
      });
    }

    test('SeededRandom draws the Ed25519 seed first, then the X25519 key', () {
      final c = loadVectors('identity').first;
      final id = DeviceIdentity.generate(crypto, SeededRandom(1));
      expect(toHex(id.publicIdentity.signingKey.bytes), c.output['sig_pub']);
      expect(toHex(id.publicIdentity.dhKey.bytes), c.output['dh_pub']);
      id.dispose();
    });
  });

  group('DeviceIdentity', () {
    test('the two key pairs are independent and usable', () {
      final a = DeviceIdentity.generate(crypto, SeededRandom(7));
      final b = DeviceIdentity.generate(crypto, SeededRandom(8));
      final message = Uint8List.fromList('mawaddah'.codeUnits);
      final sig = crypto.sign(a.signingSecretKey, message);
      expect(crypto.verify(a.publicIdentity.signingKey, message, sig), isTrue);
      final ab = crypto.x25519(a.dhSecretKey, b.publicIdentity.dhKey);
      final ba = crypto.x25519(b.dhSecretKey, a.publicIdentity.dhKey);
      expect(ab.extractBytes(), ba.extractBytes());
      for (final s in [ab, ba]) {
        s.dispose();
      }
      a.dispose();
      b.dispose();
    });

    test('storage bytes: 0x01, Ed25519 seed, X25519 secret; round trip', () {
      final c = loadVectors('identity').first;
      final id = DeviceIdentity.generate(crypto, SeededRandom(1));
      final stored = id.toStorageBytes();
      expect(stored.length, DeviceIdentity.storageLength);
      expect(toHex(stored), '01${c.input['sig_seed']}${c.input['dh_secret']}');

      final again = DeviceIdentity.fromStorageBytes(crypto, stored);
      expect(again.publicIdentity, id.publicIdentity);
      expect(again.deviceId, id.deviceId);
      expect(stored, everyElement(0), reason: 'input is zeroed');
      id.dispose();
      again.dispose();
    });

    group('fromStorageBytes rejects and zeroes', () {
      Uint8List valid() {
        final id = DeviceIdentity.generate(crypto, SeededRandom(2));
        final b = id.toStorageBytes();
        id.dispose();
        return b;
      }

      test('a wrong length', () {
        final bytes = Uint8List.fromList(valid().sublist(0, 64));
        expect(
          () => DeviceIdentity.fromStorageBytes(crypto, bytes),
          throwsFormatException,
        );
        expect(bytes, everyElement(0));
      });

      test('an unknown format version', () {
        final bytes = valid()..[0] = 2;
        expect(
          () => DeviceIdentity.fromStorageBytes(crypto, bytes),
          throwsFormatException,
        );
        expect(bytes, everyElement(0));
      });
    });

    test('toString shows the device ID and no secret bytes', () {
      final c = loadVectors('identity').first;
      final id = DeviceIdentity.generate(crypto, SeededRandom(1));
      final text = id.toString();
      expect(text, contains(c.output['device_id_base64url']));
      expect(text, contains('redacted'));
      for (final secret in [
        c.input['sig_seed']! as String,
        c.input['dh_secret']! as String,
      ]) {
        expect(text.toLowerCase(), isNot(contains(secret.substring(0, 8))));
      }
      expect('${id.signingSecretKey}', isNot(contains(c.input['sig_seed'])));
      expect('${id.dhSecretKey}', isNot(contains(c.input['dh_secret'])));
      id.dispose();
    });

    test('dispose wipes both private keys', () {
      final id = DeviceIdentity.generate(crypto, SeededRandom(3));
      expect(id.isDisposed, isFalse);
      id
        ..dispose()
        ..dispose();
      expect(id.isDisposed, isTrue);
      expect(id.signingSecretKey.isDisposed, isTrue);
      expect(id.dhSecretKey.isDisposed, isTrue);
      expect(id.toStorageBytes, throwsStateError);
      expect(
        id.publicIdentity.deviceId,
        isA<DeviceId>(),
        reason: 'public part stays',
      );
    });

    test('a RandomSource that returns too few bytes is an error', () {
      expect(
        () => DeviceIdentity.generate(crypto, ShortRandom()),
        throwsStateError,
      );
    });
  });

  group('DeviceId.parse rejects', () {
    final good =
        loadVectors('identity').first.output['device_id_base64url']! as String;
    final bad = {
      'too short': good.substring(1),
      'too long': '${good}A',
      'padding': '${good.substring(0, 20)}==',
      'standard base64 characters': '${good.substring(0, 21)}+',
      // 16 bytes use 128 of the 132 bits of 22 characters; the last 4 must be 0.
      'non-canonical last character': '${good.substring(0, 21)}h',
    };
    for (final MapEntry(:key, :value) in bad.entries) {
      test(
        key,
        () => expect(() => DeviceId.parse(value), throwsFormatException),
      );
    }
  });
}
