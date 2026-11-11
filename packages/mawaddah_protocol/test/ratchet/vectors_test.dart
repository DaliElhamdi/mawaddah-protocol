// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import '../crypto/support.dart';
import '../pairing/support.dart' show ReplayRandom;

typedef Json = Map<String, Object?>;

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  late Crypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  for (final c in loadVectors('ratchet')) {
    test(c.name, () {
      final input = c.input;
      final steps = (c.output['steps']! as List<Object?>).cast<Json>();
      ReplayRandom draws(String key) =>
          ReplayRandom([for (final d in input[key]! as List<Object?>) hex(d)]);

      final bobPair = crypto.importX25519KeyPair(
        hex(input['bob_ratchet_secret']),
      );
      expect(_hex(bobPair.publicKey.bytes), c.output['bob_ratchet_pub']);
      final sessions = {
        'alice': RatchetSession.initAlice(
          crypto: crypto,
          random: draws('alice_random'),
          rootKey: crypto.importSecret(hex(input['root_key'])),
          associatedData: hex(input['associated_data']),
          remoteRatchetKey: bobPair.publicKey,
        ),
        'bob': RatchetSession.initBob(
          crypto: crypto,
          random: draws('bob_random'),
          rootKey: crypto.importSecret(hex(input['root_key'])),
          associatedData: hex(input['associated_data']),
          ratchetKeyPair: bobPair,
        ),
      };
      expect(
        _hex(sessions['alice']!.ratchetPublicKey.bytes),
        c.output['alice_initial_ratchet_pub'],
      );

      final sentBy = <String, Json>{};
      for (final step in steps) {
        final s = sessions[step['side']]!;
        final id = step['message']! as String;
        if (step['op'] == 'send') {
          final m = s.encrypt(
            hex(step['plaintext']),
            envelopePrefix: hex(step['envelope_prefix']),
          );
          expect(_hex(m.header.encode()), step['header'], reason: id);
          expect(_hex(m.ciphertext), step['ciphertext'], reason: id);
          sentBy[id] = step;
        } else {
          final sent = sentBy[id]!;
          final plaintext = s.decrypt(
            RatchetHeader.decode(hex(sent['header'])),
            hex(sent['ciphertext']),
            envelopePrefix: hex(sent['envelope_prefix']),
          );
          expect(_hex(plaintext), step['plaintext'], reason: id);
          if (step['dh_ratchet'] case final Json dh) {
            expect(
              _hex(s.ratchetPublicKey.bytes),
              dh['new_ratchet_pub'],
              reason: id,
            );
          }
        }
      }
      for (final s in sessions.values) {
        s.dispose();
      }
    });
  }

  test('a corrupted ciphertext in the vectors would fail', () {
    final c = loadVectors('ratchet').first;
    final step = (c.output['steps']! as List<Object?>).cast<Json>().first;
    final ct = hex(step['ciphertext']);
    ct[0] ^= 1;
    final bobPair = crypto.importX25519KeyPair(
      hex(c.input['bob_ratchet_secret']),
    );
    final bob = RatchetSession.initBob(
      crypto: crypto,
      random: ReplayRandom([
        for (final d in c.input['bob_random']! as List<Object?>) hex(d),
      ]),
      rootKey: crypto.importSecret(hex(c.input['root_key'])),
      associatedData: hex(c.input['associated_data']),
      ratchetKeyPair: bobPair,
    );
    expect(
      () => bob.decrypt(
        RatchetHeader.decode(hex(step['header'])),
        Uint8List.fromList(ct),
        envelopePrefix: hex(step['envelope_prefix']),
      ),
      throwsA(isA<RatchetException>()),
    );
    bob.dispose();
  });
}
