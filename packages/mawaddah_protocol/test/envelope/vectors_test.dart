// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import '../crypto/support.dart';
import '../pairing/support.dart' show ReplayRandom;

typedef Json = Map<String, Object?>;

/// A case of a vector file where `output` or `error` is set.
typedef Case = ({String name, Json input, Json? output, String? error});

List<Case> _load(String file) {
  final json =
      jsonDecode(File('test/vectors/$file.json').readAsStringSync()) as Json;
  if (json['file'] != file || json['protocol_version'] != 1) {
    throw StateError('$file: wrong "file" or "protocol_version"');
  }
  final cases = (json['cases']! as List<Object?>).cast<Json>();
  if (cases.isEmpty) throw StateError('$file: no cases');
  return [
    for (final c in cases)
      (
        name: c['name']! as String,
        input: c['input']! as Json,
        output: c['output'] as Json?,
        error: c['error'] as String?,
      ),
  ];
}

String _failureName(EnvelopeFailure f) => switch (f) {
  EnvelopeFailure.malformed => 'malformed',
  EnvelopeFailure.unknownVersion => 'unknown_version',
  EnvelopeFailure.wrongRecipient => 'wrong_recipient',
  EnvelopeFailure.unknownSender => 'unknown_sender',
  EnvelopeFailure.badSignature => 'bad_signature',
  EnvelopeFailure.replayed => 'replayed',
  EnvelopeFailure.fromTheFuture => 'from_the_future',
  EnvelopeFailure.tooOld => 'too_old',
  EnvelopeFailure.undecryptable => 'undecryptable',
};

/// A [Clock] reading a settable millisecond value.
final class _MsClock implements Clock {
  int ms = 0;
  @override
  DateTime now() => DateTime.fromMillisecondsSinceEpoch(ms, isUtc: true);
}

void main() {
  late Crypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  DeviceIdentity identity(Object? json) {
    final j = json! as Json;
    return DeviceIdentity.fromStorageBytes(
      crypto,
      Uint8List.fromList([1, ...hex(j['sig_seed']), ...hex(j['dh_secret'])]),
    );
  }

  group('envelope.json', () {
    for (final c in _load('envelope')) {
      test(c.name, () {
        final input = c.input;
        final clock = FakeClock(
          DateTime.fromMillisecondsSinceEpoch(
            input['receiver_now_ms']! as int,
            isUtc: true,
          ),
        );
        final alice = identity(input['alice']);
        final bob = identity(input['bob']);
        final bobPair = crypto.importX25519KeyPair(
          hex(input['bob_ratchet_secret']),
        );
        final aliceSession = RatchetSession.initAlice(
          crypto: crypto,
          random: ReplayRandom([hex(input['alice_random'])]),
          clock: clock,
          rootKey: crypto.importSecret(hex(input['root_key'])),
          associatedData: hex(input['associated_data']),
          remoteRatchetKey: bobPair.publicKey,
        );
        final bobSession = RatchetSession.initBob(
          crypto: crypto,
          random: ReplayRandom([hex(input['bob_random'])]),
          clock: clock,
          rootKey: crypto.importSecret(hex(input['root_key'])),
          associatedData: hex(input['associated_data']),
          ratchetKeyPair: bobPair,
        );
        final window = ReplayWindow();
        for (final n in (input['window_accepted'] as List<Object?>?) ?? []) {
          window.mark(n! as int);
        }
        final hlc = HlcClock(clock);
        OpenedEnvelope open(Uint8List bytes) => Envelope.open(
          crypto: crypto,
          bytes: bytes,
          self: bob.deviceId,
          partner: alice.publicIdentity,
          session: bobSession,
          window: window,
          clock: hlc,
        );

        final output = c.output;
        if (output == null) {
          try {
            open(hex(input['envelope']));
            fail('opened');
          } on EnvelopeException catch (e) {
            expect(_failureName(e.failure), c.error);
          }
          return;
        }
        expect(toHex(alice.deviceId.bytes), output['alice_device_id']);
        expect(toHex(bob.deviceId.bytes), output['bob_device_id']);
        expect(
          toHex(aliceSession.ratchetPublicKey.bytes),
          output['alice_ratchet_pub'],
        );
        final plaintext = utf8.encode(input['plaintext']! as String);
        expect(
          toHex(crypto.pad(plaintext, envelopePaddingBlock)),
          output['padded_plaintext'],
        );
        final sentHlc = Hlc.parse(input['hlc']! as String);
        final bytes = Envelope.seal(
          crypto: crypto,
          sender: alice,
          recipient: bob.deviceId,
          counter: input['counter']! as int,
          hlc: sentHlc,
          session: aliceSession,
          plaintext: plaintext,
        );
        expect(toHex(bytes), output['envelope']);
        expect(
          output['envelope'],
          '${output['prefix']}${output['header']}${output['ciphertext']}'
          '${output['signature']}',
        );
        final opened = open(bytes);
        expect(opened.plaintext, plaintext);
        expect(opened.envelope.counter, input['counter']);
        expect(window.accepts(input['counter']! as int), isFalse);
        expect(hlc.last > sentHlc, isTrue);
      });
    }
  });

  group('hlc.json', () {
    for (final c in _load('hlc')) {
      test(c.name, () {
        final clock = _MsClock();
        final hlc = HlcClock(
          clock,
          last: Hlc.parse(c.input['start']! as String),
        );
        final values = c.output!['values']! as List<Object?>;
        final ops = (c.input['ops']! as List<Object?>).cast<Json>();
        expect(ops.length, values.length);
        for (final (i, op) in ops.indexed) {
          clock.ms = op['now_ms']! as int;
          final got = op['op'] == 'send'
              ? hlc.send()
              : hlc.receive(Hlc.parse(op['remote']! as String));
          expect(got.toHex(), values[i], reason: 'op $i');
        }
      });
    }
  });

  group('uuid7.json', () {
    for (final c in _load('uuid7')) {
      test(c.name, () {
        final clock = _MsClock()..ms = c.input['now_ms']! as int;
        final uuid = Uuid7.generate(
          clock,
          ReplayRandom([hex(c.input['random'])]),
        );
        expect(uuid, c.output!['uuid']);
        expect(Uuid7.isValid(uuid), isTrue);
      });
    }
  });
}
