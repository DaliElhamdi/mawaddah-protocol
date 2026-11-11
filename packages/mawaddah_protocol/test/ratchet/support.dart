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
///
/// Both use [clock] (a fresh [FakeClock] when not given).
({RatchetSession alice, RatchetSession bob}) sessions(
  Crypto crypto, {
  int seed = 10,
  Clock? clock,
}) {
  final p = pair(crypto);
  final c = clock ?? FakeClock();
  return (
    alice: RatchetSession.fromPairing(
      crypto: crypto,
      random: SeededRandom(seed),
      clock: c,
      pairing: p.joiner,
    ),
    bob: RatchetSession.fromPairing(
      crypto: crypto,
      random: SeededRandom(seed + 1),
      clock: c,
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

/// One sent message with the envelope prefix it was sealed with.
typedef Sent = ({RatchetMessage m, Uint8List prefix, String text});

/// Seals [message] on [from] with envelope counter [counter].
Sent send(RatchetSession from, String message, int counter) {
  final p = prefix(counter);
  return (
    m: from.encrypt(text(message), envelopePrefix: p),
    prefix: p,
    text: message,
  );
}

/// Opens [sent] on [to] (header decoded from its bytes, as received).
String open(RatchetSession to, Sent sent) => utf8.decode(
  to.decrypt(
    RatchetHeader.decode(sent.m.header.encode()),
    sent.m.ciphertext,
    envelopePrefix: sent.prefix,
  ),
);

/// [sent] with one ciphertext bit flipped.
Sent tampered(Sent sent) {
  final c = Uint8List.fromList(sent.m.ciphertext);
  c[0] ^= 1;
  return (
    m: (header: sent.m.header, ciphertext: c),
    prefix: sent.prefix,
    text: sent.text,
  );
}
