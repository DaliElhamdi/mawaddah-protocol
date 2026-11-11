// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';

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

typedef Json = Map<String, Object?>;

/// A case of `pairing.json`: `output` or `error` is set.
typedef PairingCase = ({String name, Json input, Json? output, String? error});

List<PairingCase> loadPairingCases() {
  final json =
      jsonDecode(File('test/vectors/pairing.json').readAsStringSync()) as Json;
  return [
    for (final c in (json['cases']! as List<Object?>).cast<Json>())
      (
        name: c['name']! as String,
        input: c['input']! as Json,
        output: c['output'] as Json?,
        error: c['error'] as String?,
      ),
  ];
}

/// The random bytes of an initiator: identity (64), `EKi` (32), `S` (16).
ReplayRandom initiatorRandom(Json input) => ReplayRandom([
  hex(input['sig_seed']),
  hex(input['dh_secret']),
  hex(input['ek_secret']),
  hex(input['secret']),
]);

/// The random bytes of a joiner: identity (64), `EKj` (32).
ReplayRandom joinerRandom(Json input) => ReplayRandom([
  hex(input['sig_seed']),
  hex(input['dh_secret']),
  hex(input['ek_secret']),
]);

PairingInitiator startInitiator(Crypto crypto, Json input, {Clock? clock}) =>
    PairingInitiator.start(
      crypto: crypto,
      random: initiatorRandom(input),
      clock: clock ?? FakeClock(),
    );

/// The exception name used in the vector files.
String failureName(PairingFailure f) => switch (f) {
  PairingFailure.badBundleSignature => 'bad_bundle_signature',
  PairingFailure.badReplySignature => 'bad_reply_signature',
  PairingFailure.confirmMismatch => 'confirm_mismatch',
  PairingFailure.invalidKey => 'invalid_key',
  PairingFailure.expired => 'expired',
  PairingFailure.alreadyUsed => 'already_used',
};

/// Operating-system randomness for tests that do not need repeatable bytes.
class SecureTestRandom implements RandomSource {
  final _random = math.Random.secure();

  @override
  Uint8List nextBytes(int length) =>
      Uint8List.fromList(List.generate(length, (_) => _random.nextInt(256)));
}
