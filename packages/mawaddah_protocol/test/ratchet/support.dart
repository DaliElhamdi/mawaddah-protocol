// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';

/// A finished QR-path pairing between two fresh test devices.
({PairingResult initiator, PairingResult joiner}) pair(
  Crypto crypto, {
  int initiatorSeed = 1,
  int joinerSeed = 2,
}) {
  final init = PairingInitiator.start(
    crypto: crypto,
    random: SeededRandom(initiatorSeed),
    clock: FakeClock(),
  );
  final joiner = PairingJoiner.fromQr(
    crypto: crypto,
    random: SeededRandom(joinerSeed),
    qrText: init.qr(Uint8List(16)).encode(),
  );
  return (initiator: init.acceptReply(joiner.reply), joiner: joiner.result);
}

/// Both sides' sessions: `alice` is the joiner (sends first), `bob` the
/// initiator.
({RatchetSession alice, RatchetSession bob}) sessions(
  Crypto crypto, {
  int seed = 10,
}) {
  final p = pair(crypto);
  return (
    alice: RatchetSession.fromPairing(
      crypto: crypto,
      random: SeededRandom(seed),
      pairing: p.joiner,
    ),
    bob: RatchetSession.fromPairing(
      crypto: crypto,
      random: SeededRandom(seed + 1),
      pairing: p.initiator,
    ),
  );
}

/// A stand-in for envelope bytes 0..50 (section 7); envelopes come in #15.
Uint8List prefix(int counter) => Uint8List(envelopePrefixLength)
  ..[0] = 1
  ..[1] = 1
  ..buffer.asByteData().setUint64(34, counter);

Uint8List text(String s) => Uint8List.fromList(utf8.encode(s));
