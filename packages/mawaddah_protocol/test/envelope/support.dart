// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';

import '../ratchet/support.dart' show pair;

/// One paired device with everything sending and receiving needs.
final class Side {
  Side(this.crypto, this.pairing, this.session, this.clock)
    : hlc = HlcClock(clock);

  final Crypto crypto;
  final PairingResult pairing;
  final RatchetSession session;
  final FakeClock clock;
  final HlcClock hlc;
  ReplayWindow window = ReplayWindow();
  var counter = 0;

  DeviceIdentity get identity => pairing.identity;
  PublicIdentity get partner => pairing.partner;

  /// Seals [text] for the partner with the next counter and a fresh HLC.
  Uint8List send(String text, {int? counter, Hlc? hlc}) => Envelope.seal(
    crypto: crypto,
    sender: identity,
    recipient: partner.deviceId,
    counter: counter ?? ++this.counter,
    hlc: hlc ?? this.hlc.send(),
    session: session,
    plaintext: utf8.encode(text),
  );

  /// Opens [bytes] from the partner and returns the text.
  String open(Uint8List bytes) => utf8.decode(
    Envelope.open(
      crypto: crypto,
      bytes: bytes,
      self: identity.deviceId,
      partner: partner,
      session: session,
      window: window,
      clock: hlc,
    ).plaintext,
  );
}

/// A paired joiner (`alice`, sends first) and initiator (`bob`) sharing
/// one [FakeClock].
({Side alice, Side bob, FakeClock clock}) paired(Crypto crypto) {
  final p = pair(crypto);
  final clock = FakeClock(DateTime.utc(2026, 11, 11, 12));
  RatchetSession session(PairingResult r, int seed) =>
      RatchetSession.fromPairing(
        crypto: crypto,
        random: SeededRandom(seed),
        clock: clock,
        pairing: r,
      );
  return (
    alice: Side(crypto, p.joiner, session(p.joiner, 10), clock),
    bob: Side(crypto, p.initiator, session(p.initiator, 11), clock),
    clock: clock,
  );
}

/// The failure [body] throws, or null when it returns.
EnvelopeFailure? failureOf(void Function() body) {
  try {
    body();
    return null;
  } on EnvelopeException catch (e) {
    return e.failure;
  }
}

/// [bytes] with bit 0 of byte [index] flipped.
Uint8List flip(Uint8List bytes, int index) =>
    Uint8List.fromList(bytes)..[index] ^= 1;
