// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import '../crypto/support.dart';
import '../pairing/support.dart' show ReplayRandom;

Uint8List _b64(String s) =>
    base64Url.decode(s.padRight((s.length + 3) ~/ 4 * 4, '='));

void main() {
  late Crypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  /// The identity whose Ed25519 seed is [sigSeed] (the X25519 half is not
  /// used for request signing).
  DeviceIdentity identityFrom(Uint8List sigSeed) =>
      DeviceIdentity.generate(crypto, ReplayRandom([sigSeed, Uint8List(32)]));

  group('relay_signing.json', () {
    for (final c in loadVectors('relay_signing')) {
      test(c.name, () {
        final i = c.input;
        final o = c.output;
        final identity = identityFrom(hex(i['sig_seed']));
        addTearDown(identity.dispose);
        final timestamp = i['timestamp']! as int;
        final headers =
            RelayRequestSigner(
              crypto: crypto,
              identity: identity,
              clock: FakeClock(
                DateTime.fromMillisecondsSinceEpoch(
                  timestamp * 1000 + 999,
                  isUtc: true,
                ),
              ),
              random: ReplayRandom([hex(i['nonce'])]),
            ).sign(
              method: i['method']! as String,
              pathAndQuery: i['path']! as String,
              body: hex(i['body']),
            );
        expect(headers, o['headers']);
        expect(identity.deviceId.toBase64Url(), o['inbox_id']);

        final input = RelayRequestSigner.signingInput(
          method: i['method']! as String,
          pathAndQuery: i['path']! as String,
          body: hex(i['body']),
          timestamp: timestamp,
          nonce: headers['Maw-Nonce']!,
        );
        expect(ascii.decode(input), o['signing_input']);
        expect(ascii.decode(input).split('\n')[3], o['body_sha256']);
        final signature = hex(o['signature']);
        expect(_b64(headers['Maw-Signature']!), signature);
        expect(
          crypto.verify(
            identity.publicIdentity.signingKey,
            input,
            Ed25519Signature(signature),
          ),
          isTrue,
        );
      });
    }
  });

  group('RelayRequestSigner', () {
    test('a fresh nonce for each request, time in whole seconds', () {
      final identity = DeviceIdentity.generate(crypto, SeededRandom(7));
      addTearDown(identity.dispose);
      final clock = FakeClock(DateTime.utc(2026, 11, 11, 12, 0, 0, 750));
      final signer = RelayRequestSigner(
        crypto: crypto,
        identity: identity,
        clock: clock,
        random: SeededRandom(8),
      );
      final a = signer.sign(
        method: 'POST',
        pathAndQuery: '/v1/inbox',
        body: Uint8List(0),
      );
      final b = signer.sign(
        method: 'POST',
        pathAndQuery: '/v1/inbox',
        body: Uint8List(0),
      );
      expect(a['Maw-Nonce'], isNot(b['Maw-Nonce']));
      expect(
        a['Maw-Timestamp'],
        '${DateTime.utc(2026, 11, 11, 12).millisecondsSinceEpoch ~/ 1000}',
      );
      expect(a.keys, {
        'Maw-Key',
        'Maw-Timestamp',
        'Maw-Nonce',
        'Maw-Signature',
      });
    });

    test('every line of the signing input is covered by the signature', () {
      final identity = DeviceIdentity.generate(crypto, SeededRandom(9));
      addTearDown(identity.dispose);
      final base = (
        method: 'PUT',
        path: '/v1/inbox/x/envelopes',
        body: Uint8List.fromList([1, 2, 3]),
        timestamp: 1762862400,
        nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
      );
      Uint8List input({
        String? method,
        String? path,
        Uint8List? body,
        int? timestamp,
        String? nonce,
      }) => RelayRequestSigner.signingInput(
        method: method ?? base.method,
        pathAndQuery: path ?? base.path,
        body: body ?? base.body,
        timestamp: timestamp ?? base.timestamp,
        nonce: nonce ?? base.nonce,
      );
      final signature = crypto.sign(identity.signingSecretKey, input());
      bool ok(Uint8List message) =>
          crypto.verify(identity.publicIdentity.signingKey, message, signature);
      expect(ok(input()), isTrue);
      expect(ok(input(method: 'POST')), isFalse);
      expect(ok(input(path: '/v1/inbox/y/envelopes')), isFalse);
      expect(ok(input(body: Uint8List.fromList([1, 2, 4]))), isFalse);
      expect(ok(input(timestamp: base.timestamp + 1)), isFalse);
      expect(ok(input(nonce: 'AAAAAAAAAAAAAAAAAAAAAQ')), isFalse);
    });

    test('rejects inputs the relay could not match', () {
      Uint8List input({
        String method = 'GET',
        String path = '/health',
        int timestamp = 1,
        String nonce = 'AAAAAAAAAAAAAAAAAAAAAA',
      }) => RelayRequestSigner.signingInput(
        method: method,
        pathAndQuery: path,
        body: Uint8List(0),
        timestamp: timestamp,
        nonce: nonce,
      );
      expect(() => input(method: 'get'), throwsArgumentError);
      expect(() => input(method: ''), throwsArgumentError);
      expect(() => input(path: 'v1/inbox'), throwsArgumentError);
      expect(() => input(path: '/v1/a b'), throwsArgumentError);
      expect(() => input(path: '/v1/a\nb'), throwsArgumentError);
      expect(() => input(path: '/v1/é'), throwsArgumentError);
      // Paths that URL parsing would change, so the relay would rebuild a
      // different line and answer bad_signature.
      for (final path in [
        '/v1/./inbox',
        '/v1/../inbox',
        '/v1/inbox/.',
        '/v1/%41',
        '/v1/inbox#x',
        r'/v1\inbox',
        '/v1/inbox?',
        '/v1/inbox?a b',
        '/v1/inbox?a=%20',
        '/v1/inbox?a?b',
      ]) {
        expect(() => input(path: path), throwsArgumentError, reason: path);
      }
      expect(
        input(path: '/v1/inbox/AbC-_9/envelopes?after=17&x=y'),
        isNotEmpty,
      );
      expect(() => input(timestamp: -1), throwsArgumentError);
      expect(() => input(nonce: 'short'), throwsArgumentError);
      expect(() => input(nonce: 'AAAAAAAAAAAAAAAAAAAAA='), throwsArgumentError);
      expect(input(timestamp: 0), isNotEmpty);
    });
  });
}
