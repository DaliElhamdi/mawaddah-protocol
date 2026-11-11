// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Pairing key agreement (PROTOCOL.md section 4): X3DH adapted to two people
/// who are present at the same time, plus a one-time QR secret.
///
/// Two small state machines, [PairingInitiator] and [PairingJoiner], hold no
/// I/O: they take the injected [Crypto], [RandomSource] and [Clock], and
/// return messages for the caller to post to the relay and a
/// [PairingResult] with the keys both sides now share.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../clock.dart';
import '../crypto/crypto.dart';
import '../identity/identity.dart';
import '../random_source.dart';
import 'messages.dart';

export 'messages.dart';
export 'profile.dart';

/// Why a pairing attempt failed. None of these says which side is wrong.
enum PairingFailure {
  /// The bundle read with the code does not carry a valid signature.
  badBundleSignature,

  /// The reply's signature does not match its keys and the transcript.
  badReplySignature,

  /// The reply's key confirmation is wrong: wrong secret, a reply made for
  /// another bundle, or tampering.
  confirmMismatch,

  /// A public key in the reply or QR is unusable (small order).
  invalidKey,

  /// The slot's 10 minutes are over.
  expired,

  /// This attempt already took a reply.
  alreadyUsed,
}

/// A pairing attempt failed (data from outside was not acceptable). The
/// attempt is over: start a new one with new keys (PROTOCOL.md section 4.5).
final class PairingException implements Exception {
  const PairingException(this.failure);

  final PairingFailure failure;

  @override
  String toString() => 'PairingException(${failure.name})';
}

/// Whether the two people still have to compare the safety number.
enum SafetyNumberCheck {
  /// QR path: comparing is recommended, not required.
  recommended,

  /// Code path: both must tap "The numbers match" first (section 4.5).
  required,

  /// This person confirmed the numbers match.
  confirmed,
}

/// The shared outcome of a pairing: everything the next steps need.
///
/// Holds secret keys in guarded memory: call [dispose] when the pair is
/// ended, or when handing the keys over to the ratchet and storage.
final class PairingResult {
  PairingResult._({
    required this.isInitiator,
    required this.path,
    required this.identity,
    required this.partner,
    required this.rootKey,
    required this.associatedData,
    required this.initiatorRatchetKey,
    required this.initiatorRatchetKeyPair,
    required this.safetyNumber,
  }) : _check = path == PairingPath.code
           ? SafetyNumberCheck.required
           : SafetyNumberCheck.recommended;

  final bool isInitiator;
  final PairingPath path;

  /// This device's identity keys, new for this attempt.
  final DeviceIdentity identity;

  /// The partner's public identity.
  final PublicIdentity partner;

  /// `SK`: the Double Ratchet's initial root key.
  final SecretBytes rootKey;

  /// `AD` (128 bytes): associated data of every ratchet message.
  final Uint8List associatedData;

  /// `EKi` public: the first ratchet key of the initiator.
  final X25519PublicKey initiatorRatchetKey;

  /// `EKi` key pair: only on the initiator, which uses it as `DHs` until the
  /// joiner's first message. `null` on the joiner.
  final X25519KeyPair? initiatorRatchetKeyPair;

  /// The 20-digit safety number (section 5).
  final String safetyNumber;

  SafetyNumberCheck _check;

  SafetyNumberCheck get safetyNumberCheck => _check;

  /// True until this person has confirmed the numbers on the code path. While
  /// true, only the `device` hello event may be sent or accepted and nothing
  /// from the partner is shown (section 4.5).
  bool get requiresSafetyNumberConfirmation =>
      _check == SafetyNumberCheck.required;

  /// Whether `profile` events may be sent and shown.
  bool get mayExchangeProfile => !requiresSafetyNumberConfirmation;

  /// The person tapped "The numbers match".
  void confirmSafetyNumber() => _check = SafetyNumberCheck.confirmed;

  /// "They don't match" (or unpair): erases the keys held here. The caller
  /// also deletes the session from storage and this attempt's relay inbox.
  void dispose() {
    rootKey.dispose();
    initiatorRatchetKeyPair?.dispose();
    identity.dispose();
  }
}

// --- key derivation (section 4.4) -----------------------------------------

final _transcriptLabel = ascii.encode('mawaddah/v1/transcript');
final _confirmLabel = ascii.encode('mawaddah/v1/confirm');

Uint8List _cat(List<List<int>> parts) {
  final out = BytesBuilder(copy: false);
  for (final p in parts) {
    out.add(p);
  }
  return out.toBytes();
}

/// `TH`, the transcript hash.
Uint8List _transcript(
  Crypto crypto,
  PairingPath path,
  PublicIdentity i,
  X25519PublicKey eki,
  PublicIdentity j,
  X25519PublicKey ekj,
) => crypto.blake2b(
  _cat([
    _transcriptLabel,
    [pairingFormatVersion, path.byte],
    i.signingKey.bytes,
    i.dhKey.bytes,
    eki.bytes,
    j.signingKey.bytes,
    j.dhKey.bytes,
    ekj.bytes,
  ]),
  length: 32,
);

/// `AD = IKsig_j || IKdh_j || IKsig_i || IKdh_i`.
Uint8List _associatedData(PublicIdentity i, PublicIdentity j) => _cat([
  j.signingKey.bytes,
  j.dhKey.bytes,
  i.signingKey.bytes,
  i.dhKey.bytes,
]);

/// HKDF over `F || DH1 || DH2 || DH3 || S'`. Disposes [dh1], [dh2], [dh3];
/// the caller disposes the returned keys.
({SecretBytes sk, SecretBytes kc}) _deriveKeys(
  Crypto crypto,
  SecretBytes dh1,
  SecretBytes dh2,
  SecretBytes dh3,
  Uint8List sPrime,
) {
  final f = crypto.importSecret(Uint8List(32)..fillRange(0, 32, 0xff));
  final s = crypto.importSecret(Uint8List.fromList(sPrime));
  final salt = crypto.importSecret(Uint8List(32));
  SecretBytes? ikm;
  SecretBytes? prk;
  try {
    ikm = crypto.concat([f, dh1, dh2, dh3, s]);
    prk = crypto.hkdfExtract(salt: salt, ikm: ikm);
    final sk = crypto.hkdfExpand(
      prk: prk,
      info: 'mawaddah/v1/pairing/sk',
      length: 32,
    );
    try {
      final kc = crypto.hkdfExpand(
        prk: prk,
        info: 'mawaddah/v1/pairing/confirm',
        length: 32,
      );
      return (sk: sk, kc: kc);
    } catch (_) {
      sk.dispose();
      rethrow;
    }
  } finally {
    for (final secret in [f, dh1, dh2, dh3, s, salt, ikm, prk]) {
      secret?.dispose();
    }
  }
}

Uint8List _confirmInput(Uint8List th) => _cat([_confirmLabel, th]);

Uint8List _randomBytes(RandomSource random, int length) {
  final bytes = random.nextBytes(length);
  if (bytes.length != length) {
    final got = bytes.length;
    bytes.fillRange(0, got, 0);
    throw StateError('RandomSource returned $got bytes, expected $length');
  }
  return bytes;
}

X25519KeyPair _newEphemeral(Crypto crypto, RandomSource random) =>
    crypto.importX25519KeyPair(_randomBytes(random, 32));

// --- initiator ---------------------------------------------------------------

/// The person who taps "Invite" (X3DH's Bob). Create it with
/// [PairingInitiator.start], publish [bundle] in a relay slot, show
/// [qr], then give the joiner's reply to [acceptReply].
final class PairingInitiator {
  PairingInitiator._(
    this._crypto,
    this._clock,
    this._identity,
    this._ek,
    this._secret,
    this.bundle,
  ) : expiresAt = _clock.now().add(pairingSlotLifetime);

  /// New identity keys, ephemeral key and one-time secret `S`, drawn from
  /// [random] in that order (64, 32, then 16 bytes).
  factory PairingInitiator.start({
    required Crypto crypto,
    required RandomSource random,
    required Clock clock,
  }) {
    final identity = DeviceIdentity.generate(crypto, random);
    X25519KeyPair? ek;
    try {
      ek = _newEphemeral(crypto, random);
      return PairingInitiator._(
        crypto,
        clock,
        identity,
        ek,
        _randomBytes(random, pairingSecretLength),
        PairingBundle.sign(crypto, identity, ek.publicKey),
      );
    } catch (_) {
      identity.dispose();
      ek?.dispose();
      rethrow;
    }
  }

  final Crypto _crypto;
  final Clock _clock;
  final DeviceIdentity _identity;
  final X25519KeyPair _ek;
  final Uint8List _secret;
  var _used = false;

  /// The signed bundle for `POST /v1/pairing-slot`.
  final PairingBundle bundle;

  /// When the slot, the QR and the code stop working (10 minutes).
  final DateTime expiresAt;

  /// This attempt's public identity (its device ID names the inbox to
  /// register).
  PublicIdentity get publicIdentity => _identity.publicIdentity;

  /// This attempt's identity keys, to sign the relay requests of the
  /// attempt with a `RelayRequestSigner`: register the inbox, open the slot,
  /// read the reply, and delete the inbox when giving up (before [abandon]).
  /// The initiator owns them: never dispose them. After [abandon] or a
  /// failed [acceptReply] they are erased; after a successful one
  /// [PairingResult.identity] is this same object.
  DeviceIdentity get identity => _identity;

  /// The QR for the slot the relay returned. The QR carries `S`: show it
  /// only on this screen.
  PairingQr qr(Uint8List slotId) {
    if (_used) throw StateError('this pairing attempt is over');
    return PairingQr(
      signingKey: bundle.signingKey,
      dhKey: bundle.dhKey,
      ephemeralKey: bundle.ephemeralKey,
      secret: Uint8List.fromList(_secret),
      slotId: slotId,
    );
  }

  /// Gives up this attempt (the person backed out or the slot expired before
  /// any reply): erases the keys and `S`. The caller also deletes the inbox
  /// and the slot. Safe to call more than once, and after [acceptReply].
  void abandon() {
    if (_used) return;
    _used = true;
    _identity.dispose();
    _ek.dispose();
    _secret.fillRange(0, _secret.length, 0);
  }

  /// Checks the joiner's [reply] and returns the pairing result.
  ///
  /// Only one reply is ever checked: the attempt ends here whether or not it
  /// works, and a second call throws [PairingException] with
  /// [PairingFailure.alreadyUsed]. On a failure all keys of the attempt are
  /// erased; start again with new keys.
  PairingResult acceptReply(PairingReply reply) {
    if (_used) throw const PairingException(PairingFailure.alreadyUsed);
    _used = true;
    try {
      return _accept(reply);
    } catch (_) {
      _identity.dispose();
      _ek.dispose();
      rethrow;
    } finally {
      _secret.fillRange(0, _secret.length, 0);
    }
  }

  PairingResult _accept(PairingReply reply) {
    if (_clock.now().isAfter(expiresAt)) {
      throw const PairingException(PairingFailure.expired);
    }
    final me = _identity.publicIdentity;
    final joiner = reply.identity;
    final th = _transcript(
      _crypto,
      reply.path,
      me,
      _ek.publicKey,
      joiner,
      reply.ephemeralKey,
    );
    if (!_crypto.verify(
      reply.signingKey,
      PairingReply.signedBytes(th, reply.confirm),
      reply.signature,
    )) {
      throw const PairingException(PairingFailure.badReplySignature);
    }

    final SecretBytes dh1, dh2, dh3;
    try {
      dh1 = _crypto.x25519(_ek.secretKey, joiner.dhKey);
      SecretBytes? d2;
      try {
        d2 = _crypto.x25519(_identity.dhSecretKey, reply.ephemeralKey);
        dh2 = d2;
        dh3 = _crypto.x25519(_ek.secretKey, reply.ephemeralKey);
      } catch (_) {
        d2?.dispose();
        dh1.dispose();
        rethrow;
      }
    } on InvalidPublicKeyException {
      throw const PairingException(PairingFailure.invalidKey);
    }
    final sPrime = reply.path == PairingPath.qr ? _secret : Uint8List(16);
    final keys = _deriveKeys(_crypto, dh1, dh2, dh3, sPrime);
    try {
      if (!_crypto.verifyHmac(keys.kc, _confirmInput(th), reply.confirm)) {
        keys.sk.dispose();
        throw const PairingException(PairingFailure.confirmMismatch);
      }
    } finally {
      keys.kc.dispose();
    }
    return PairingResult._(
      isInitiator: true,
      path: reply.path,
      identity: _identity,
      partner: joiner,
      rootKey: keys.sk,
      associatedData: _associatedData(me, joiner),
      initiatorRatchetKey: _ek.publicKey,
      initiatorRatchetKeyPair: _ek,
      safetyNumber: safetyNumber(_crypto, me, joiner),
    );
  }
}

// --- joiner ------------------------------------------------------------------

/// The person who scans the QR or types the code (X3DH's Alice). Create it
/// with [PairingJoiner.fromQr] or [PairingJoiner.fromCode], register the
/// inbox, post [reply] to the slot, and use [result] once the relay accepted
/// it.
final class PairingJoiner {
  PairingJoiner._(this.slotId, this.reply, this.result);

  /// QR path: the scanned text (see [PairingQr.decode]). Identity keys are
  /// drawn from [random] (64 bytes, then 32 for `EKj`). Throws
  /// [FormatException] for a bad QR and [PairingException] for an unusable
  /// key.
  factory PairingJoiner.fromQr({
    required Crypto crypto,
    required RandomSource random,
    required String qrText,
  }) {
    final qr = PairingQr.decode(qrText);
    try {
      return PairingJoiner._join(
        crypto,
        random,
        PairingPath.qr,
        qr.identity,
        qr.ephemeralKey,
        qr.secret,
        qr.slotId,
      );
    } finally {
      qr.wipe();
    }
  }

  /// Code path: [bundle] and [slotId] come from `GET /v1/pairing-slot/{code}`.
  /// The bundle signature is checked **before** this device's identity keys
  /// are generated (section 5); a bad signature throws [PairingException].
  factory PairingJoiner.fromCode({
    required Crypto crypto,
    required RandomSource random,
    required PairingBundle bundle,
    required Uint8List slotId,
  }) {
    if (slotId.length != pairingSlotIdLength) {
      throw ArgumentError.value(slotId.length, 'slotId', 'must be 16 bytes');
    }
    if (!bundle.verify(crypto)) {
      throw const PairingException(PairingFailure.badBundleSignature);
    }
    return PairingJoiner._join(
      crypto,
      random,
      PairingPath.code,
      bundle.identity,
      bundle.ephemeralKey,
      Uint8List(pairingSecretLength),
      slotId,
    );
  }

  static PairingJoiner _join(
    Crypto crypto,
    RandomSource random,
    PairingPath path,
    PublicIdentity initiator,
    X25519PublicKey eki,
    Uint8List sPrime,
    Uint8List slotId,
  ) {
    final identity = DeviceIdentity.generate(crypto, random);
    X25519KeyPair? ek;
    try {
      ek = _newEphemeral(crypto, random);
      final me = identity.publicIdentity;
      final SecretBytes dh1, dh2, dh3;
      try {
        dh1 = crypto.x25519(identity.dhSecretKey, eki);
        SecretBytes? d2;
        try {
          d2 = crypto.x25519(ek.secretKey, initiator.dhKey);
          dh2 = d2;
          dh3 = crypto.x25519(ek.secretKey, eki);
        } catch (_) {
          d2?.dispose();
          dh1.dispose();
          rethrow;
        }
      } on InvalidPublicKeyException {
        throw const PairingException(PairingFailure.invalidKey);
      }
      final keys = _deriveKeys(crypto, dh1, dh2, dh3, sPrime);
      final PairingReply reply;
      try {
        final th = _transcript(crypto, path, initiator, eki, me, ek.publicKey);
        final confirm = crypto.hmac(keys.kc, _confirmInput(th));
        reply = PairingReply(
          path: path,
          signingKey: me.signingKey,
          dhKey: me.dhKey,
          ephemeralKey: ek.publicKey,
          confirm: confirm,
          signature: crypto.sign(
            identity.signingSecretKey,
            PairingReply.signedBytes(th, confirm),
          ),
        );
      } catch (_) {
        keys.sk.dispose();
        rethrow;
      } finally {
        keys.kc.dispose();
      }
      final result = PairingResult._(
        isInitiator: false,
        path: path,
        identity: identity,
        partner: initiator,
        rootKey: keys.sk,
        associatedData: _associatedData(initiator, me),
        initiatorRatchetKey: eki,
        initiatorRatchetKeyPair: null,
        safetyNumber: safetyNumber(crypto, initiator, me),
      );
      // EKj's private key is not needed any more (section 4.4).
      ek.dispose();
      return PairingJoiner._(Uint8List.fromList(slotId), reply, result);
    } catch (_) {
      identity.dispose();
      ek?.dispose();
      rethrow;
    }
  }

  /// The slot to post [reply] to.
  final Uint8List slotId;

  /// The reply for `POST /v1/pairing-slot/{slot_id}/reply`.
  final PairingReply reply;

  /// The shared keys, valid if the initiator accepts [reply].
  final PairingResult result;

  /// The relay refused the reply or the person cancelled: erases the keys
  /// held in [result]. The caller also deletes this attempt's inbox.
  void abandon() => result.dispose();
}
