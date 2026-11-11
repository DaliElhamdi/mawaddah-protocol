// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// The Double Ratchet (PROTOCOL.md section 6).
///
/// Follows *The Double Ratchet Algorithm*, T. Perrin and M. Marlinspike,
/// Signal, revision 1, 2016-11-20 (public domain), without header
/// encryption. Section numbers in the comments below ("Signal 3.4") refer to
/// that document. Nothing here is a new construction: every function maps to
/// one of its functions, with the choices listed in PROTOCOL.md section 6.
///
/// This file covers in-order delivery in both directions and the DH ratchet
/// step on every turn change. Skipped message keys (out-of-order delivery,
/// Signal 3.5 `SkipMessageKeys`) and saving the state come with issue #14:
/// until then a message that would need a skipped key is rejected with
/// [RatchetFailure.skippedMessage] and the session is left unchanged.
library;

import 'dart:typed_data';

import '../crypto/crypto.dart';
import '../pairing/pairing.dart';
import '../random_source.dart';

// --- labels (PROTOCOL.md section 6) -----------------------------------------

const _rkInfo = 'mawaddah/v1/ratchet/rk';
const _mkInfo = 'mawaddah/v1/ratchet/mk';
const _ckInfo = 'mawaddah/v1/ratchet/ck';
const _aeadInfo = 'mawaddah/v1/ratchet/aead';

/// Length of `AD` from pairing (PROTOCOL.md section 4.4).
const ratchetAssociatedDataLength = 128;

/// Length of the envelope bytes before the ratchet header: `version`,
/// `type`, `sender_id`, `recipient_id`, `counter`, `hlc` (PROTOCOL.md
/// section 7, offsets 0 to 50).
const envelopePrefixLength = 50;

const _maxU32 = 0xFFFFFFFF;

// --- header ------------------------------------------------------------------

/// The ratchet part of the envelope header (PROTOCOL.md section 7, offsets
/// 50 to 90): `dh_pub || u32 pn || u32 n`.
///
/// Signal 3.1 `HEADER(dh_pair, pn, n)`.
final class RatchetHeader {
  RatchetHeader({required this.dhPub, required this.pn, required this.n}) {
    RangeError.checkValueInInterval(pn, 0, _maxU32, 'pn');
    RangeError.checkValueInInterval(n, 0, _maxU32, 'n');
  }

  /// Reads the 40 header bytes. Throws [FormatException] on a wrong length.
  factory RatchetHeader.decode(Uint8List bytes) {
    if (bytes.length != byteLength) {
      throw FormatException('ratchet header must be $byteLength bytes');
    }
    final data = ByteData.sublistView(bytes);
    return RatchetHeader(
      dhPub: X25519PublicKey(Uint8List.sublistView(bytes, 0, 32)),
      pn: data.getUint32(32),
      n: data.getUint32(36),
    );
  }

  static const byteLength = 40;

  /// The sender's current ratchet public key.
  final X25519PublicKey dhPub;

  /// Length of the sender's previous sending chain.
  final int pn;

  /// Message number in the sender's current sending chain (from 0).
  final int n;

  Uint8List encode() {
    final out = Uint8List(byteLength)..setAll(0, dhPub.bytes);
    ByteData.sublistView(out)
      ..setUint32(32, pn)
      ..setUint32(36, n);
    return out;
  }

  @override
  bool operator ==(Object other) =>
      other is RatchetHeader &&
      other.dhPub == dhPub &&
      other.pn == pn &&
      other.n == n;

  @override
  int get hashCode => Object.hash(dhPub, pn, n);

  @override
  String toString() => 'RatchetHeader(pn: $pn, n: $n, dhPub: $dhPub)';
}

/// One encrypted ratchet message: the header and the AEAD output
/// (ciphertext followed by the 16-byte Poly1305 tag).
typedef RatchetMessage = ({RatchetHeader header, Uint8List ciphertext});

// --- errors ------------------------------------------------------------------

/// Why a received message was not accepted. The session is unchanged.
enum RatchetFailure {
  /// The AEAD tag did not match: wrong key, a changed byte in the header,
  /// the envelope prefix or the ciphertext, or a message not for this
  /// session.
  decryptionFailed,

  /// The header's ratchet key is unusable (small order: all-zero X25519).
  invalidKey,

  /// The message comes after one that has not arrived yet. Handled by
  /// skipped message keys in issue #14; until then it is rejected.
  skippedMessage,

  /// The message number was already used in this chain (a repeat, or a
  /// message older than the current one).
  oldMessage,
}

/// A received ratchet message could not be decrypted. Nothing in the session
/// changed, so the next message can still be read.
final class RatchetException implements Exception {
  const RatchetException(this.failure);

  final RatchetFailure failure;

  @override
  String toString() => 'RatchetException(${failure.name})';
}

// --- session -----------------------------------------------------------------

/// One side of a Double Ratchet session (Signal 3.2 state variables).
///
/// Create it with [RatchetSession.fromPairing]. [encrypt] and [decrypt] take
/// the [envelopePrefixLength] envelope bytes that come before the ratchet
/// header, so the AEAD authenticates `AD || envelope bytes[0..90]` exactly as
/// PROTOCOL.md section 7 says.
///
/// Not thread-safe; one session per pair. Call [dispose] to wipe the keys.
final class RatchetSession {
  RatchetSession._({
    required this._crypto,
    required this._random,
    required Uint8List associatedData,
    required this._dhs,
    required this._dhr,
    required this._rk,
    required this._cks,
  }) : _ad = Uint8List.fromList(associatedData).asUnmodifiableView();

  /// Starts the session from a finished pairing (PROTOCOL.md section 4.4).
  ///
  /// The joiner is Signal's Alice (`RatchetInitAlice(SK, EKi_pub)`): it can
  /// send at once. The initiator is Bob (`RatchetInitBob(SK, EKi_pair)`): it
  /// cannot send until the joiner's first message arrives ([canSend]).
  ///
  /// Takes over the pairing's ratchet secrets: `pairing.rootKey` is disposed
  /// here, and the initiator's `pairing.initiatorRatchetKeyPair` now belongs
  /// to the session, which disposes it at its first DH ratchet step or in
  /// [dispose]. Calling `pairing.dispose()` afterwards is safe for the
  /// identity keys but also wipes that key pair, so only do it when the
  /// session is being erased too.
  ///
  /// [random] must be a secure source in the app; it supplies every new
  /// ratchet key pair (Signal 3.1 `GENERATE_DH`).
  factory RatchetSession.fromPairing({
    required Crypto crypto,
    required RandomSource random,
    required PairingResult pairing,
  }) {
    final sk = pairing.rootKey;
    try {
      if (pairing.isInitiator) {
        final pair = pairing.initiatorRatchetKeyPair;
        if (pair == null) {
          throw ArgumentError('initiator pairing without its ratchet key pair');
        }
        return RatchetSession.initBob(
          crypto: crypto,
          random: random,
          rootKey: sk.copy(),
          associatedData: pairing.associatedData,
          ratchetKeyPair: pair,
        );
      }
      return RatchetSession.initAlice(
        crypto: crypto,
        random: random,
        rootKey: sk.copy(),
        associatedData: pairing.associatedData,
        remoteRatchetKey: pairing.initiatorRatchetKey,
      );
    } finally {
      sk.dispose();
    }
  }

  /// Signal 3.3 `RatchetInitAlice(SK, bob_dh_public_key)`: the side that
  /// sends first (the joiner). Takes [rootKey] (disposed here).
  ///
  /// The app uses [RatchetSession.fromPairing]; this and [initBob] exist for
  /// the test vectors and for other implementations to compare against.
  factory RatchetSession.initAlice({
    required Crypto crypto,
    required RandomSource random,
    required SecretBytes rootKey,
    required Uint8List associatedData,
    required X25519PublicKey remoteRatchetKey,
  }) {
    try {
      _checkAd(associatedData);
      final dhs = _generateDh(crypto, random);
      try {
        final (rk, cks) = _kdfRk(
          crypto,
          rootKey,
          _dh(crypto, dhs, remoteRatchetKey),
        );
        return RatchetSession._(
          crypto: crypto,
          random: random,
          associatedData: associatedData,
          dhs: dhs,
          dhr: remoteRatchetKey,
          rk: rk,
          cks: cks,
        );
      } catch (_) {
        dhs.dispose();
        rethrow;
      }
    } finally {
      rootKey.dispose();
    }
  }

  /// Signal 3.3 `RatchetInitBob(SK, bob_dh_key_pair)`: the side that waits
  /// for the first message (the initiator). Takes [rootKey] and
  /// [ratchetKeyPair]; the session disposes them.
  factory RatchetSession.initBob({
    required Crypto crypto,
    required RandomSource random,
    required SecretBytes rootKey,
    required Uint8List associatedData,
    required X25519KeyPair ratchetKeyPair,
  }) {
    try {
      _checkAd(associatedData);
    } catch (_) {
      rootKey.dispose();
      ratchetKeyPair.dispose();
      rethrow;
    }
    return RatchetSession._(
      crypto: crypto,
      random: random,
      associatedData: associatedData,
      dhs: ratchetKeyPair,
      dhr: null,
      rk: rootKey,
      cks: null,
    );
  }

  static void _checkAd(Uint8List ad) {
    if (ad.length != ratchetAssociatedDataLength) {
      throw ArgumentError.value(
        ad.length,
        'associatedData',
        'must be $ratchetAssociatedDataLength bytes long',
      );
    }
  }

  final Crypto _crypto;
  final RandomSource _random;
  final Uint8List _ad;

  // Signal 3.2 state variables.
  X25519KeyPair _dhs; // DHs
  X25519PublicKey? _dhr; // DHr
  SecretBytes _rk; // RK
  SecretBytes? _cks; // CKs
  SecretBytes? _ckr; // CKr
  int _ns = 0; // Ns
  int _nr = 0; // Nr
  int _pn = 0; // PN
  bool _disposed = false;

  /// Whether [encrypt] may be called. False only on the initiator before
  /// the joiner's first message (PROTOCOL.md section 4.5, step 5).
  bool get canSend => !_disposed && _cks != null;

  /// This side's current ratchet public key (`DHs`).
  X25519PublicKey get ratchetPublicKey => _live._dhs.publicKey;

  /// Signal 3.4 `RatchetEncrypt(state, plaintext, AD)`.
  ///
  /// [envelopePrefix] is the [envelopePrefixLength] bytes of the envelope
  /// before the ratchet header. Throws [StateError] when [canSend] is false.
  RatchetMessage encrypt(
    Uint8List plaintext, {
    required Uint8List envelopePrefix,
  }) {
    _checkPrefix(envelopePrefix);
    final cks = _live._cks;
    if (cks == null) {
      throw StateError('cannot send before the first message from the joiner');
    }
    if (_ns >= _maxU32) throw StateError('sending chain is full');
    final (next, mk) = _kdfCk(_crypto, cks);
    try {
      final header = RatchetHeader(dhPub: _dhs.publicKey, pn: _pn, n: _ns);
      final ciphertext = _encrypt(
        _crypto,
        mk,
        plaintext,
        _concat(envelopePrefix, header),
      );
      cks.dispose();
      _cks = next;
      _ns += 1;
      return (header: header, ciphertext: ciphertext);
    } catch (_) {
      next.dispose();
      rethrow;
    } finally {
      mk.dispose();
    }
  }

  /// Signal 3.4 `RatchetDecrypt(state, header, ciphertext, AD)`, without
  /// skipped message keys (issue #14).
  ///
  /// Works on new values and only replaces the session's keys once the AEAD
  /// tag has been checked (Signal 3.5: "if an exception is raised ... the
  /// message is discarded and changes to the state object are discarded").
  /// Throws [RatchetException]; then the session is unchanged.
  Uint8List decrypt(
    RatchetHeader header,
    Uint8List ciphertext, {
    required Uint8List envelopePrefix,
  }) {
    _checkPrefix(envelopePrefix);
    _live;
    final crypto = _crypto;
    final turn = header.dhPub != _dhr;

    // Candidate values, owned here until the AEAD tag checks out; whatever
    // is still set in `finally` was not committed and is wiped.
    X25519KeyPair? newDhs;
    SecretBytes? newRk;
    SecretBytes? newCks;
    SecretBytes? newCkr; // receiving chain key from the DH ratchet step
    SecretBytes? nextCkr; // receiving chain key after this message
    SecretBytes? mk;
    try {
      var ckr = _ckr;
      var nr = _nr;
      if (turn) {
        // Signal 3.5 `SkipMessageKeys(state, header.pn)`: messages left in
        // the old receiving chain would need skipped keys (issue #14).
        if (ckr != null && header.pn > nr) {
          throw const RatchetException(RatchetFailure.skippedMessage);
        }
        // Signal 3.5 `DHRatchet(state, header)`.
        final (rk1, ckr1) = _kdfRk(
          crypto,
          _rk,
          _dhOrReject(_dhs, header.dhPub),
        );
        newCkr = ckr1;
        try {
          newDhs = _generateDh(crypto, _random);
          (newRk, newCks) = _kdfRk(
            crypto,
            rk1,
            _dhOrReject(newDhs, header.dhPub),
          );
        } finally {
          rk1.dispose();
        }
        ckr = ckr1;
        nr = 0;
      }
      if (header.n > nr) {
        throw const RatchetException(RatchetFailure.skippedMessage);
      }
      if (header.n < nr || ckr == null) {
        throw const RatchetException(RatchetFailure.oldMessage);
      }
      (nextCkr, mk) = _kdfCk(crypto, ckr);
      final plaintext = _decrypt(
        crypto,
        mk,
        ciphertext,
        _concat(envelopePrefix, header),
      );

      // Commit (Signal 3.5: the state changes only on success).
      if (turn) {
        _pn = _ns;
        _ns = 0;
        _dhr = header.dhPub;
        _dhs.dispose();
        _dhs = newDhs!;
        _rk.dispose();
        _rk = newRk!;
        _cks?.dispose();
        _cks = newCks;
        (newDhs, newRk, newCks) = (null, null, null);
      }
      _ckr?.dispose();
      _ckr = nextCkr;
      _nr = nr + 1;
      nextCkr = null;
      return plaintext;
    } finally {
      mk?.dispose();
      nextCkr?.dispose();
      newCkr?.dispose();
      newDhs?.dispose();
      newRk?.dispose();
      newCks?.dispose();
    }
  }

  /// Wipes every key of the session. Safe to call more than once.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _dhs.dispose();
    _rk.dispose();
    _cks?.dispose();
    _ckr?.dispose();
    _cks = null;
    _ckr = null;
  }

  RatchetSession get _live {
    if (_disposed) throw StateError('RatchetSession used after dispose()');
    return this;
  }

  void _checkPrefix(Uint8List prefix) {
    if (prefix.length != envelopePrefixLength) {
      throw ArgumentError.value(
        prefix.length,
        'envelopePrefix',
        'must be $envelopePrefixLength bytes long',
      );
    }
  }

  /// Signal 3.4 `CONCAT(AD, header)`: `AD || envelope bytes[0..90]`.
  Uint8List _concat(Uint8List prefix, RatchetHeader header) {
    final out = Uint8List(
      ratchetAssociatedDataLength +
          envelopePrefixLength +
          RatchetHeader.byteLength,
    );
    out
      ..setAll(0, _ad)
      ..setAll(ratchetAssociatedDataLength, prefix)
      ..setAll(
        ratchetAssociatedDataLength + envelopePrefixLength,
        header.encode(),
      );
    return out;
  }

  SecretBytes _dhOrReject(X25519KeyPair pair, X25519PublicKey pub) {
    try {
      return _dh(_crypto, pair, pub);
    } on InvalidPublicKeyException {
      throw const RatchetException(RatchetFailure.invalidKey);
    }
  }
}

// --- external functions (Signal 3.1, choices in PROTOCOL.md section 6) ------

/// `GENERATE_DH()`: 32 random bytes as the X25519 secret key.
X25519KeyPair _generateDh(Crypto crypto, RandomSource random) {
  final bytes = random.nextBytes(X25519SecretKey.byteLength);
  if (bytes.length != X25519SecretKey.byteLength) {
    bytes.fillRange(0, bytes.length, 0);
    throw StateError('RandomSource returned ${bytes.length} bytes');
  }
  return crypto.importX25519KeyPair(bytes);
}

/// `DH(dh_pair, dh_pub)`: X25519; an all-zero output throws
/// [InvalidPublicKeyException].
SecretBytes _dh(Crypto crypto, X25519KeyPair pair, X25519PublicKey pub) =>
    crypto.x25519(pair.secretKey, pub);

/// `KDF_RK(rk, dh_out)`: HKDF-SHA-256 with `rk` as salt, 64 bytes; returns
/// (new root key, chain key). Disposes [dhOut], keeps [rk].
(SecretBytes, SecretBytes) _kdfRk(
  Crypto crypto,
  SecretBytes rk,
  SecretBytes dhOut,
) {
  final SecretBytes out;
  try {
    out = crypto.hkdf(salt: rk, ikm: dhOut, info: _rkInfo, length: 64);
  } finally {
    dhOut.dispose();
  }
  try {
    return (out.slice(0, 32), out.slice(32, 64));
  } finally {
    out.dispose();
  }
}

/// `KDF_CK(ck)`: returns (next chain key, message key), each an
/// HKDF-Expand of `ck` with its own label (Signal 5.2: HMAC with distinct
/// constants). Keeps [ck].
(SecretBytes, SecretBytes) _kdfCk(Crypto crypto, SecretBytes ck) {
  final next = crypto.hkdfExpand(prk: ck, info: _ckInfo, length: 32);
  try {
    return (next, crypto.hkdfExpand(prk: ck, info: _mkInfo, length: 32));
  } catch (_) {
    next.dispose();
    rethrow;
  }
}

/// AEAD key and nonce for one message key: HKDF-Expand(mk, 56 bytes), the
/// first 32 bytes are the key and the last 24 the nonce.
(AeadKey, AeadNonce) _aeadKeyNonce(Crypto crypto, SecretBytes mk) {
  final km = crypto.hkdfExpand(prk: mk, info: _aeadInfo, length: 56);
  try {
    final nonceSecret = km.slice(32, 56);
    final nonceBytes = nonceSecret.extractBytes();
    nonceSecret.dispose();
    return (crypto.aeadKeyFrom(km), AeadNonce(nonceBytes));
  } finally {
    km.dispose();
  }
}

/// `ENCRYPT(mk, plaintext, associated_data)`: XChaCha20-Poly1305-IETF.
Uint8List _encrypt(
  Crypto crypto,
  SecretBytes mk,
  Uint8List plaintext,
  Uint8List ad,
) {
  final (key, nonce) = _aeadKeyNonce(crypto, mk);
  try {
    return crypto.encrypt(
      key: key,
      nonce: nonce,
      plaintext: plaintext,
      associatedData: ad,
    );
  } finally {
    key.dispose();
  }
}

/// `DECRYPT(mk, ciphertext, associated_data)`; a bad tag throws
/// [RatchetException] ([RatchetFailure.decryptionFailed]).
Uint8List _decrypt(
  Crypto crypto,
  SecretBytes mk,
  Uint8List ciphertext,
  Uint8List ad,
) {
  final (key, nonce) = _aeadKeyNonce(crypto, mk);
  try {
    return crypto.decrypt(
      key: key,
      nonce: nonce,
      ciphertext: ciphertext,
      associatedData: ad,
    );
  } on DecryptionFailedException {
    throw const RatchetException(RatchetFailure.decryptionFailed);
  } finally {
    key.dispose();
  }
}
