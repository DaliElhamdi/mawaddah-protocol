// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Signed envelopes (PROTOCOL.md sections 7 and 8).
///
/// One envelope carries one Double Ratchet message: a 90-byte header in the
/// clear (version, type, device IDs, counter, HLC, ratchet header), the
/// AEAD ciphertext of the padded plaintext, and an Ed25519 signature by the
/// sender's identity key over everything before it. Nothing here is a new
/// construction: signing is RFC 8032 Ed25519, the ciphertext is the ratchet
/// of section 6, the replay check is RFC 4303's sliding window and padding
/// is libsodium's ISO/IEC 7816-4 `sodium_pad`.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/crypto.dart';
import '../identity/identity.dart';
import '../ratchet/ratchet.dart';
import 'hlc.dart';
import 'replay_window.dart';

// --- constants (PROTOCOL.md sections 7, 8 and 14) ----------------------------

/// The envelope `version` byte of protocol v1.
const envelopeVersion = 1;

/// The envelope `type` byte of a ratchet message (the only type in v1).
const envelopeTypeRatchetMessage = 1;

/// Largest envelope, in bytes (the relay's limit).
const maxEnvelopeLength = 65536;

/// Bytes before the ciphertext: 50 envelope bytes and the 40-byte ratchet
/// header.
const envelopeHeaderLength = envelopePrefixLength + RatchetHeader.byteLength;

/// The plaintext is padded to a multiple of this many bytes.
const envelopePaddingBlock = 256;

/// The smallest v1 envelope: header, one padding block plus the 16-byte
/// tag, signature (426 bytes).
const minEnvelopeLength =
    envelopeHeaderLength +
    envelopePaddingBlock +
    _tagLength +
    Ed25519Signature.byteLength;

/// Largest plaintext [Envelope.seal] takes (65,279 bytes): padded, it must
/// fit in [maxEnvelopeLength] with the header, tag and signature.
const maxEnvelopePlaintextLength =
    (maxEnvelopeLength -
            envelopeHeaderLength -
            _tagLength -
            Ed25519Signature.byteLength) ~/
        envelopePaddingBlock *
        envelopePaddingBlock -
    1;

/// Largest envelope counter: `2^63 - 1`. A larger value is malformed.
const maxEnvelopeCounter = 0x7FFFFFFFFFFFFFFF;

/// An envelope whose HLC time is further ahead of the receiver's clock than
/// this is not acknowledged yet (section 8, step 5).
const maxEnvelopeClockAhead = Duration(hours: 1);

/// An envelope whose HLC time is further behind the receiver's clock than
/// this is rejected: the relay deletes everything after 30 days.
const maxEnvelopeAge = Duration(days: 31);

const _tagLength = 16;
const _oVersion = 0, _oType = 1, _oSender = 2, _oRecipient = 18;
const _oCounter = 34, _oHlc = 42;
final _signatureLabel = ascii.encode('mawaddah/v1/envelope');

// --- errors ------------------------------------------------------------------

/// Why a received envelope was not opened, and what the app does with it
/// (PROTOCOL.md section 8).
enum EnvelopeFailure {
  /// Wrong length, a counter of 0 or above [maxEnvelopeCounter], or a
  /// ciphertext length that padding cannot produce. Acknowledge and discard.
  malformed(acknowledge: true, keepUnapplied: false),

  /// The `version` or `type` byte is not one this release knows. Not an
  /// error to drop: keep the raw bytes as unapplied (at most 100, oldest
  /// deleted first), acknowledge, and show the "newer version" card. The
  /// signature has not been checked.
  unknownVersion(acknowledge: true, keepUnapplied: true),

  /// `recipient_id` is not this device. Acknowledge and discard.
  wrongRecipient(acknowledge: true, keepUnapplied: false),

  /// `sender_id` is not the paired partner. Acknowledge and discard.
  unknownSender(acknowledge: true, keepUnapplied: false),

  /// The signature does not verify with the partner's `IKsig`: forged or
  /// changed. Acknowledge and discard.
  badSignature(acknowledge: true, keepUnapplied: false),

  /// The counter was already accepted, or is [ReplayWindow.size] or more
  /// below the highest accepted one. Acknowledge and discard.
  replayed(acknowledge: true, keepUnapplied: false),

  /// The HLC time is more than [maxEnvelopeClockAhead] ahead of this
  /// device's clock. Do **not** acknowledge: leave it on the relay and try
  /// again at the next sync; after 24 hours of retrying, show "One of your
  /// phones has the wrong date or time".
  fromTheFuture(acknowledge: false, keepUnapplied: false),

  /// The HLC time is more than [maxEnvelopeAge] behind this device's clock.
  /// Acknowledge and discard.
  tooOld(acknowledge: true, keepUnapplied: false),

  /// The signature checked but the ratchet could not decrypt it (or the
  /// decrypted bytes had no valid padding). Keep the raw bytes as unapplied
  /// with reason `undecryptable` and acknowledge. Its counter **is** marked
  /// in the replay window (and, for bad padding, the ratchet moved on), so
  /// commit the window and the session as for an opened envelope.
  undecryptable(acknowledge: true, keepUnapplied: true);

  const EnvelopeFailure({
    required this.acknowledge,
    required this.keepUnapplied,
  });

  /// Whether the app acknowledges the envelope to the relay (which then
  /// deletes it).
  final bool acknowledge;

  /// Whether the app keeps the raw envelope bytes as unapplied rather than
  /// discarding them.
  final bool keepUnapplied;
}

/// A received envelope was not opened. Except for
/// [EnvelopeFailure.undecryptable], nothing changed: not the session, the
/// replay window nor the HLC. An `undecryptable` envelope used up its
/// counter in the window, and when only its padding was bad the ratchet
/// session also moved on.
final class EnvelopeException implements Exception {
  const EnvelopeException(this.failure, {this.ratchetFailure});

  final EnvelopeFailure failure;

  /// For [EnvelopeFailure.undecryptable] from the ratchet: its reason (null
  /// for bad padding). For the debug log only.
  final RatchetFailure? ratchetFailure;

  @override
  String toString() => ratchetFailure == null
      ? 'EnvelopeException(${failure.name})'
      : 'EnvelopeException(${failure.name}, ${ratchetFailure!.name})';
}

// --- envelope ----------------------------------------------------------------

/// The parts of a v1 envelope, read by [Envelope.parse]. Parsing checks
/// only the structure: the signature is checked by [Envelope.open].
final class Envelope {
  Envelope._({
    required this.bytes,
    required this.senderId,
    required this.recipientId,
    required this.counter,
    required this.hlc,
    required this.header,
  });

  /// Reads the structure of [bytes] (PROTOCOL.md section 8, step 1). Throws
  /// [EnvelopeException] with [EnvelopeFailure.malformed] or
  /// [EnvelopeFailure.unknownVersion].
  ///
  /// The `version` and `type` bytes are read before the v1 length rules, so
  /// an envelope of a later version is never called malformed because its
  /// layout differs.
  factory Envelope.parse(Uint8List bytes) {
    final n = bytes.length;
    if (n > maxEnvelopeLength || n < 2) {
      throw const EnvelopeException(EnvelopeFailure.malformed);
    }
    if (bytes[_oVersion] != envelopeVersion ||
        bytes[_oType] != envelopeTypeRatchetMessage) {
      throw const EnvelopeException(EnvelopeFailure.unknownVersion);
    }
    // L = n - 90 - 64 must be a multiple of 256 plus 16 (section 7).
    final l = n - envelopeHeaderLength - Ed25519Signature.byteLength;
    if (n < minEnvelopeLength || l % envelopePaddingBlock != _tagLength) {
      throw const EnvelopeException(EnvelopeFailure.malformed);
    }
    final copy = Uint8List.fromList(bytes);
    final data = ByteData.sublistView(copy);
    final counterHigh = data.getUint32(_oCounter);
    final counter = counterHigh * 0x100000000 + data.getUint32(_oCounter + 4);
    if (counterHigh > 0x7FFFFFFF || counter < 1) {
      throw const EnvelopeException(EnvelopeFailure.malformed);
    }
    return Envelope._(
      bytes: copy.asUnmodifiableView(),
      senderId: DeviceId.fromBytes(Uint8List.sublistView(copy, _oSender, 18)),
      recipientId: DeviceId.fromBytes(
        Uint8List.sublistView(copy, _oRecipient, 34),
      ),
      counter: counter,
      hlc: Hlc.fromBytes(Uint8List.sublistView(copy, _oHlc, 50)),
      header: RatchetHeader.decode(
        Uint8List.sublistView(copy, envelopePrefixLength, envelopeHeaderLength),
      ),
    );
  }

  /// The whole envelope (read-only copy).
  final Uint8List bytes;

  final DeviceId senderId;
  final DeviceId recipientId;

  /// Per sender, from 1, +1 for every envelope sealed.
  final int counter;

  /// The sender's HLC when it sealed the envelope.
  final Hlc hlc;

  /// The ratchet header (bytes 50 to 90).
  final RatchetHeader header;

  /// Bytes 0 to 50, which the ratchet authenticates with the header.
  Uint8List get prefix => Uint8List.sublistView(bytes, 0, envelopePrefixLength);

  /// The AEAD output: ciphertext and 16-byte tag.
  Uint8List get ciphertext => Uint8List.sublistView(
    bytes,
    envelopeHeaderLength,
    bytes.length - Ed25519Signature.byteLength,
  );

  /// The sender's Ed25519 signature (the last 64 bytes).
  Ed25519Signature get signature => Ed25519Signature(
    Uint8List.sublistView(bytes, bytes.length - Ed25519Signature.byteLength),
  );

  /// Seals [plaintext] (the UTF-8 JSON `{"events": [...]}` of section 7,
  /// at most [maxEnvelopePlaintextLength] bytes) for [recipient] and returns
  /// the envelope bytes (PROTOCOL.md section 7).
  ///
  /// Pads the plaintext to a multiple of [envelopePaddingBlock], encrypts it
  /// with [session] (which authenticates `AD || bytes[0..90]`) and signs
  /// `"mawaddah/v1/envelope" || bytes[0..90+L]` with [sender]'s `IKsig`.
  ///
  /// Before calling: store [counter] as used (a crash must never reuse it)
  /// and take [hlc] from [HlcClock.send]. After it returns and before the
  /// bytes leave the device: save [session] (`toStorageBytes`), because a
  /// session restored from older bytes would reuse a message key and nonce.
  ///
  /// Throws [RangeError] for a counter outside 1 to [maxEnvelopeCounter],
  /// [ArgumentError] for a plaintext that is too long, and [StateError] when
  /// [session] cannot send yet.
  static Uint8List seal({
    required Crypto crypto,
    required DeviceIdentity sender,
    required DeviceId recipient,
    required int counter,
    required Hlc hlc,
    required RatchetSession session,
    required Uint8List plaintext,
  }) {
    RangeError.checkValueInInterval(counter, 1, maxEnvelopeCounter, 'counter');
    if (plaintext.length > maxEnvelopePlaintextLength) {
      throw ArgumentError.value(
        plaintext.length,
        'plaintext',
        'is longer than $maxEnvelopePlaintextLength bytes',
      );
    }
    final prefix = Uint8List(envelopePrefixLength)
      ..[_oVersion] = envelopeVersion
      ..[_oType] = envelopeTypeRatchetMessage
      ..setAll(_oSender, sender.deviceId.bytes)
      ..setAll(_oRecipient, recipient.bytes)
      ..setAll(_oHlc, hlc.toBytes());
    ByteData.sublistView(prefix)
      ..setUint32(_oCounter, counter ~/ 0x100000000)
      ..setUint32(_oCounter + 4, counter % 0x100000000);

    final padded = crypto.pad(plaintext, envelopePaddingBlock);
    final RatchetMessage message;
    try {
      message = session.encrypt(padded, envelopePrefix: prefix);
    } finally {
      padded.fillRange(0, padded.length, 0);
    }
    final signedLength = envelopeHeaderLength + message.ciphertext.length;
    final out = Uint8List(signedLength + Ed25519Signature.byteLength)
      ..setAll(0, prefix)
      ..setAll(envelopePrefixLength, message.header.encode())
      ..setAll(envelopeHeaderLength, message.ciphertext);
    final signature = crypto.sign(
      sender.signingSecretKey,
      _signingInput(Uint8List.sublistView(out, 0, signedLength)),
    );
    out.setAll(signedLength, signature.bytes);
    return out;
  }

  /// Checks and opens an envelope from the partner, in the order of
  /// PROTOCOL.md section 8: structure, addresses ([self] is this device,
  /// [partner] the paired one), signature, [window], time window (by
  /// [clock]'s wall clock), then decryption with [session] and unpadding.
  ///
  /// On success the session has moved on, the counter is marked in
  /// [window] and [clock] has merged the envelope's HLC. The app then
  /// applies the events and commits the session, the window, the HLC and
  /// the events in **one** database transaction, and only then acknowledges
  /// the envelope to the relay (step 8). If that transaction fails, reload
  /// all three from the database: the objects here are ahead of it.
  ///
  /// Throws [EnvelopeException]; its [EnvelopeFailure] says whether to
  /// acknowledge and whether to keep the raw bytes. Only
  /// [EnvelopeFailure.undecryptable] changes anything (the window).
  static OpenedEnvelope open({
    required Crypto crypto,
    required Uint8List bytes,
    required DeviceId self,
    required PublicIdentity partner,
    required RatchetSession session,
    required ReplayWindow window,
    required HlcClock clock,
  }) {
    // 1. Parse.
    final envelope = Envelope.parse(bytes);
    // 2. Addresses.
    if (envelope.recipientId != self) {
      throw const EnvelopeException(EnvelopeFailure.wrongRecipient);
    }
    if (envelope.senderId != partner.deviceId) {
      throw const EnvelopeException(EnvelopeFailure.unknownSender);
    }
    // 3. Signature.
    final signed = Uint8List.sublistView(
      envelope.bytes,
      0,
      envelope.bytes.length - Ed25519Signature.byteLength,
    );
    if (!crypto.verify(
      partner.signingKey,
      _signingInput(signed),
      envelope.signature,
    )) {
      throw const EnvelopeException(EnvelopeFailure.badSignature);
    }
    // 4. Replay window.
    if (!window.accepts(envelope.counter)) {
      throw const EnvelopeException(EnvelopeFailure.replayed);
    }
    // 5. Time window.
    final now = clock.clock.now().millisecondsSinceEpoch;
    final t = envelope.hlc.physicalMs;
    if (t > now + maxEnvelopeClockAhead.inMilliseconds) {
      throw const EnvelopeException(EnvelopeFailure.fromTheFuture);
    }
    if (t < now - maxEnvelopeAge.inMilliseconds) {
      throw const EnvelopeException(EnvelopeFailure.tooOld);
    }
    // The HLC merge must not fail after the commit below: try it on a copy
    // first (it throws only at the end of the 48-bit range).
    HlcClock(clock.clock, last: clock.last).receive(envelope.hlc);
    // 6. Decrypt. The signature checked, so the counter is used up either
    // way.
    final Uint8List padded;
    try {
      padded = session.decrypt(
        envelope.header,
        envelope.ciphertext,
        envelopePrefix: envelope.prefix,
      );
    } on RatchetException catch (e) {
      window.mark(envelope.counter);
      throw EnvelopeException(
        EnvelopeFailure.undecryptable,
        ratchetFailure: e.failure,
      );
    }
    // 7. Unpad (the events are parsed by the caller).
    final Uint8List plaintext;
    try {
      plaintext = crypto.unpad(padded, envelopePaddingBlock);
    } on InvalidPaddingException {
      window.mark(envelope.counter);
      throw const EnvelopeException(EnvelopeFailure.undecryptable);
    } finally {
      padded.fillRange(0, padded.length, 0);
    }
    window.mark(envelope.counter);
    clock.receive(envelope.hlc);
    return OpenedEnvelope(envelope, plaintext);
  }

  static Uint8List _signingInput(Uint8List signed) =>
      Uint8List(_signatureLabel.length + signed.length)
        ..setAll(0, _signatureLabel)
        ..setAll(_signatureLabel.length, signed);

  @override
  String toString() =>
      'Envelope(counter: $counter, hlc: ${hlc.toHex()}, '
      '${bytes.length} bytes)';
}

/// An envelope that [Envelope.open] accepted, with its plaintext (the UTF-8
/// JSON `{"events": [...]}`, padding removed).
final class OpenedEnvelope {
  const OpenedEnvelope(this.envelope, this.plaintext);

  final Envelope envelope;
  final Uint8List plaintext;
}
