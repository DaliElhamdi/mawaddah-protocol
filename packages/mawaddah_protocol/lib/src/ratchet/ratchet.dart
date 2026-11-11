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
/// Covers the DH ratchet step on every turn change, skipped message keys for
/// out-of-order delivery (Signal 3.5 `TrySkippedMessageKeys` and
/// `SkipMessageKeys`, with the limits of PROTOCOL.md section 6) and saving
/// the state ([RatchetSession.toStorageBytes], [RatchetSession.save]).
library;

import 'dart:typed_data';

import '../clock.dart';
import '../crypto/crypto.dart';
import '../pairing/pairing.dart';
import '../random_source.dart';
import '../storage.dart';

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

/// Most skipped message keys one received message may create, counting both
/// `SkipMessageKeys` calls of a DH ratchet step (PROTOCOL.md section 6,
/// `MAX_SKIP`). A header that would need more is rejected with
/// [RatchetFailure.tooManySkipped].
const maxSkip = 1000;

/// Most skipped message keys kept at once; when full, the oldest is deleted.
const maxStoredSkippedKeys = 1000;

/// A skipped message key older than this is deleted (PROTOCOL.md section 6).
const skippedKeyLifetime = Duration(days: 30);

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

  /// Opening the message would need more than [maxSkip] new skipped message
  /// keys (the header claims too many messages that have not arrived).
  ///
  /// This and [oldMessage] are decided from the header before the AEAD
  /// check, so they say nothing about whether the message is genuine.
  tooManySkipped,

  /// The message number was already used in the current receiving chain
  /// and no skipped key is stored for it: a repeat, or a message whose
  /// skipped key was deleted (older than [skippedKeyLifetime] or evicted).
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

/// A skipped message key (Signal 3.2 `MKSKIPPED` entry) and when it was
/// stored, for the [skippedKeyLifetime] rule.
final class _SkippedKey {
  _SkippedKey(this.mk, this.storedAt);

  final SecretBytes mk;
  final DateTime storedAt;
}

/// `MKSKIPPED` is indexed by the sender's ratchet key and the message number.
typedef _SkippedId = (X25519PublicKey, int);

/// One side of a Double Ratchet session (Signal 3.2 state variables).
///
/// Create it with [RatchetSession.fromPairing], or restore a saved one with
/// [RatchetSession.fromStorageBytes] / [RatchetSession.load]. [encrypt] and
/// [decrypt] take the [envelopePrefixLength] envelope bytes that come before
/// the ratchet header, so the AEAD authenticates `AD || envelope
/// bytes[0..90]` exactly as PROTOCOL.md section 7 says.
///
/// Not thread-safe; one session per pair. Call [dispose] to wipe the keys.
final class RatchetSession {
  RatchetSession._({
    required this._crypto,
    required this._random,
    required this._clock,
    required Uint8List associatedData,
    required this._dhs,
    required this._dhr,
    required this._rk,
    required this._cks,
    this._ckr,
    this._ns = 0,
    this._nr = 0,
    this._pn = 0,
    Map<_SkippedId, _SkippedKey>? skipped,
  }) : _ad = Uint8List.fromList(associatedData).asUnmodifiableView(),
       _skipped = skipped ?? {};

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
  /// ratchet key pair (Signal 3.1 `GENERATE_DH`). [clock] dates the skipped
  /// message keys ([skippedKeyLifetime]).
  factory RatchetSession.fromPairing({
    required Crypto crypto,
    required RandomSource random,
    required Clock clock,
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
          clock: clock,
          rootKey: sk.copy(),
          associatedData: pairing.associatedData,
          ratchetKeyPair: pair,
        );
      }
      return RatchetSession.initAlice(
        crypto: crypto,
        random: random,
        clock: clock,
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
    required Clock clock,
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
          clock: clock,
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
    required Clock clock,
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
      clock: clock,
      associatedData: associatedData,
      dhs: ratchetKeyPair,
      dhr: null,
      rk: rootKey,
      cks: null,
    );
  }

  /// A session from bytes written by [toStorageBytes]. Zeroes [bytes], also
  /// when it throws.
  ///
  /// Throws [FormatException] when [bytes] is damaged, inconsistent or in an
  /// unknown format version.
  factory RatchetSession.fromStorageBytes({
    required Crypto crypto,
    required RandomSource random,
    required Clock clock,
    required Uint8List bytes,
  }) {
    // Every secret imported so far; wiped if a later step fails.
    final owned = <Object>[];
    void wipeOwned() {
      for (final o in owned) {
        switch (o) {
          case final SecretBytes s:
            s.dispose();
          case final X25519KeyPair p:
            p.dispose();
        }
      }
    }

    try {
      if (bytes.length < _storageFixedLength) {
        throw const FormatException('stored ratchet session is too short');
      }
      if (bytes[0] != storageFormatVersion) {
        throw FormatException('unknown stored ratchet format ${bytes[0]}');
      }
      final data = ByteData.sublistView(bytes);
      final flags = bytes[_oFlags];
      if (flags & ~(_fDhr | _fCks | _fCkr) != 0) {
        throw const FormatException('unknown flags in stored ratchet session');
      }
      final hasDhr = flags & _fDhr != 0;
      final hasCks = flags & _fCks != 0;
      final hasCkr = flags & _fCkr != 0;
      // Reachable states: Bob before the first message (no DHr, CKs, CKr),
      // Alice before the first reply (DHr and CKs), and after any DH
      // ratchet step (all three).
      if (hasCkr && !(hasDhr && hasCks) || hasCks != hasDhr) {
        throw const FormatException('inconsistent stored ratchet session');
      }
      final ns = data.getUint32(_oNs);
      final nr = data.getUint32(_oNr);
      final pn = data.getUint32(_oPn);
      final count = data.getUint32(_oCount);
      if (count > maxStoredSkippedKeys ||
          bytes.length != _storageFixedLength + count * _storageSkippedLength) {
        throw const FormatException('stored ratchet session has a bad length');
      }

      Uint8List take(int offset, int length) => Uint8List.fromList(
        Uint8List.sublistView(bytes, offset, offset + length),
      );
      SecretBytes secret(int offset) {
        final s = crypto.importSecret(take(offset, 32));
        owned.add(s);
        return s;
      }

      final dhs = crypto.importX25519KeyPair(take(_oDhs, 32));
      owned.add(dhs);
      final rk = secret(_oRk);
      final cks = hasCks ? secret(_oCks) : null;
      final ckr = hasCkr ? secret(_oCkr) : null;
      final skipped = <_SkippedId, _SkippedKey>{};
      for (var i = 0; i < count; i++) {
        final o = _storageFixedLength + i * _storageSkippedLength;
        final id = (X25519PublicKey(take(o, 32)), data.getUint32(o + 32));
        final ms = data.getInt64(o + 36);
        if (ms.abs() > _maxDateMs) {
          throw const FormatException('bad time in stored ratchet session');
        }
        final storedAt = DateTime.fromMillisecondsSinceEpoch(ms, isUtc: true);
        if (skipped.containsKey(id)) {
          throw const FormatException('repeated skipped key in stored session');
        }
        skipped[id] = _SkippedKey(secret(o + 44), storedAt);
      }
      final session = RatchetSession._(
        crypto: crypto,
        random: random,
        clock: clock,
        associatedData: Uint8List.sublistView(bytes, _oAd, _oAd + 128),
        dhs: dhs,
        dhr: hasDhr ? X25519PublicKey(take(_oDhr, 32)) : null,
        rk: rk,
        cks: cks,
        ckr: ckr,
        ns: ns,
        nr: nr,
        pn: pn,
        skipped: skipped,
      );
      owned.clear();
      return session;
    } catch (_) {
      wipeOwned();
      rethrow;
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  /// Reads the session saved under [key] by [save]; null when there is none.
  /// See [RatchetSession.fromStorageBytes] for the errors.
  static Future<RatchetSession?> load({
    required Crypto crypto,
    required RandomSource random,
    required Clock clock,
    required Storage storage,
    required String key,
  }) async {
    final bytes = await storage.read(key);
    if (bytes == null) return null;
    return RatchetSession.fromStorageBytes(
      crypto: crypto,
      random: random,
      clock: clock,
      bytes: bytes,
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

  // --- storage format (local only, not part of the wire protocol) ----------

  /// Version byte at the start of [toStorageBytes].
  static const storageFormatVersion = 1;

  static const _fDhr = 1, _fCks = 2, _fCkr = 4;
  static const _oAd = 1; // AD, 128 bytes
  static const _oFlags = _oAd + ratchetAssociatedDataLength; // 129
  static const _oDhs = _oFlags + 1; // DHs secret key
  static const _oDhr = _oDhs + 32; // DHr, zeros when absent
  static const _oRk = _oDhr + 32;
  static const _oCks = _oRk + 32; // zeros when absent
  static const _oCkr = _oCks + 32; // zeros when absent
  static const _oNs = _oCkr + 32;
  static const _oNr = _oNs + 4;
  static const _oPn = _oNr + 4;
  static const _oCount = _oPn + 4;
  static const _storageFixedLength = _oCount + 4; // 306

  /// One skipped key: `dh_pub` 32, `u32 n`, `i64` stored-at time in
  /// milliseconds since the Unix epoch (UTC), message key 32.
  static const _storageSkippedLength = 32 + 4 + 8 + 32; // 76

  /// The range of a Dart [DateTime], in milliseconds.
  static const _maxDateMs = 8640000000000000;

  final Crypto _crypto;
  final RandomSource _random;
  final Clock _clock;
  final Uint8List _ad;

  // Signal 3.2 state variables.
  X25519KeyPair _dhs; // DHs
  X25519PublicKey? _dhr; // DHr
  SecretBytes _rk; // RK
  SecretBytes? _cks; // CKs
  SecretBytes? _ckr; // CKr
  int _ns; // Ns
  int _nr; // Nr
  int _pn; // PN
  // MKSKIPPED, in the order the keys were stored (oldest first).
  final Map<_SkippedId, _SkippedKey> _skipped;
  bool _disposed = false;

  /// Whether [encrypt] may be called. False only on the initiator before
  /// the joiner's first message (PROTOCOL.md section 4.5, step 5).
  bool get canSend => !_disposed && _cks != null;

  /// This side's current ratchet public key (`DHs`).
  X25519PublicKey get ratchetPublicKey {
    _ensureLive();
    return _dhs.publicKey;
  }

  /// How many skipped message keys are stored (at most
  /// [maxStoredSkippedKeys]), including any older than [skippedKeyLifetime]
  /// that [decrypt] or [deleteExpiredSkippedKeys] has not deleted yet.
  int get skippedKeyCount {
    _ensureLive();
    return _skipped.length;
  }

  /// Signal 3.4 `RatchetEncrypt(state, plaintext, AD)`.
  ///
  /// [envelopePrefix] is the [envelopePrefixLength] bytes of the envelope
  /// before the ratchet header. Throws [StateError] when [canSend] is false.
  ///
  /// Save the session ([toStorageBytes]) before the message leaves the
  /// device: a session restored from older bytes would use the same message
  /// key, and so the same AEAD nonce, for a different plaintext.
  RatchetMessage encrypt(
    Uint8List plaintext, {
    required Uint8List envelopePrefix,
  }) {
    _checkPrefix(envelopePrefix);
    _ensureLive();
    final cks = _cks;
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

  /// Signal 3.4 `RatchetDecrypt(state, header, ciphertext, AD)` with the
  /// skipped message keys of Signal 3.5.
  ///
  /// Works on new values and only changes the session once the AEAD tag has
  /// been checked (Signal 3.5: "if an exception is raised ... the message is
  /// discarded and changes to the state object are discarded"). Throws
  /// [RatchetException]; then the session is unchanged.
  ///
  /// A successful call also deletes the skipped keys older than
  /// [skippedKeyLifetime] and, past [maxStoredSkippedKeys], the oldest ones.
  Uint8List decrypt(
    RatchetHeader header,
    Uint8List ciphertext, {
    required Uint8List envelopePrefix,
  }) {
    _checkPrefix(envelopePrefix);
    _ensureLive();
    final crypto = _crypto;
    final now = _clock.now();
    final ad = _concat(envelopePrefix, header);

    // Signal 3.5 `TrySkippedMessageKeys`. An expired key counts as absent.
    final id = (header.dhPub, header.n);
    final stored = _skipped[id];
    if (stored != null && !_isExpired(stored, now)) {
      final plaintext = _decrypt(crypto, stored.mk, ciphertext, ad);
      _skipped.remove(id);
      stored.mk.dispose();
      _deleteExpired(now);
      return plaintext;
    }

    final turn = header.dhPub != _dhr;
    // Candidate values, owned here until the AEAD tag checks out; whatever
    // is still set in `finally` was not committed and is wiped.
    final newSkipped = <_SkippedId, SecretBytes>{};
    X25519KeyPair? newDhs;
    SecretBytes? newRk;
    SecretBytes? newCks;
    SecretBytes? newCkr; // receiving chain key from the DH ratchet step
    SecretBytes? skippedTo; // receiving chain key at header.n after skipping
    SecretBytes? nextCkr; // receiving chain key after this message
    SecretBytes? mk;
    try {
      SecretBytes? ckr = _ckr;
      var nr = _nr;
      if (turn) {
        // Both `SkipMessageKeys` calls together stay within MAX_SKIP.
        final oldCkr = ckr;
        final fromOld = oldCkr != null && header.pn > nr ? header.pn - nr : 0;
        if (fromOld + header.n > maxSkip) {
          throw const RatchetException(RatchetFailure.tooManySkipped);
        }
        // Signal 3.5 `SkipMessageKeys(state, header.pn)`: the rest of the
        // old receiving chain. Its last chain key is not needed.
        if (fromOld > 0) {
          _skipKeys(oldCkr!, _dhr!, nr, header.pn, newSkipped)?.dispose();
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
      } else {
        if (ckr == null || header.n < nr) {
          throw const RatchetException(RatchetFailure.oldMessage);
        }
        if (header.n - nr > maxSkip) {
          throw const RatchetException(RatchetFailure.tooManySkipped);
        }
      }
      // Signal 3.5 `SkipMessageKeys(state, header.n)` in the current chain.
      skippedTo = _skipKeys(ckr, header.dhPub, nr, header.n, newSkipped);
      (nextCkr, mk) = _kdfCk(crypto, skippedTo ?? ckr);
      final plaintext = _decrypt(crypto, mk, ciphertext, ad);

      // Commit (Signal 3.5: the state changes only on success). Nothing
      // below can throw: `dispose` on a live secret does not fail.
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
      _nr = header.n + 1;
      nextCkr = null;
      for (final MapEntry(:key, :value) in newSkipped.entries) {
        // A (dh_pub, n) is never skipped twice, but never leak a key if so.
        _skipped.remove(key)?.mk.dispose();
        _skipped[key] = _SkippedKey(value, now);
      }
      newSkipped.clear();
      _deleteExpired(now);
      while (_skipped.length > maxStoredSkippedKeys) {
        _skipped.remove(_skipped.keys.first)!.mk.dispose();
      }
      return plaintext;
    } finally {
      for (final k in newSkipped.values) {
        k.dispose();
      }
      mk?.dispose();
      nextCkr?.dispose();
      skippedTo?.dispose();
      newCkr?.dispose();
      newDhs?.dispose();
      newRk?.dispose();
      newCks?.dispose();
    }
  }

  /// Deletes the skipped message keys older than [skippedKeyLifetime]
  /// (by the injected clock). [decrypt] does this on every success; the app
  /// can also call it, for example once per sync, so keys do not outlive
  /// their 30 days while no message arrives.
  void deleteExpiredSkippedKeys() {
    _ensureLive();
    _deleteExpired(_clock.now());
  }

  /// The whole session as bytes for the app's encrypted database (local
  /// only: never sent, logged or put in a backup, PROTOCOL.md section 6).
  /// The caller must overwrite the list with zeros once it is stored.
  ///
  /// Layout (format version 1, integers big-endian): version (1), `AD`
  /// (128), flags (1: bit 0 `DHr`, bit 1 `CKs`, bit 2 `CKr` present), `DHs`
  /// secret key (32), `DHr` (32), `RK` (32), `CKs` (32), `CKr` (32) (absent
  /// values are zeros), `u32 Ns`, `u32 Nr`, `u32 PN`, `u32` number of
  /// skipped keys, then per skipped key (oldest first): `dh_pub` (32),
  /// `u32 n`, `i64` time stored in milliseconds since the Unix epoch (UTC),
  /// message key (32).
  Uint8List toStorageBytes() {
    _ensureLive();
    final count = _skipped.length;
    final out = Uint8List(_storageFixedLength + count * _storageSkippedLength);
    final data = ByteData.sublistView(out);
    void put(int offset, Uint8List secret) {
      out.setAll(offset, secret);
      secret.fillRange(0, secret.length, 0);
    }

    try {
      out
        ..[0] = storageFormatVersion
        ..setAll(_oAd, _ad)
        ..[_oFlags] =
            (_dhr != null ? _fDhr : 0) |
            (_cks != null ? _fCks : 0) |
            (_ckr != null ? _fCkr : 0);
      put(_oDhs, _dhs.secretKey.extractBytes());
      if (_dhr case final dhr?) out.setAll(_oDhr, dhr.bytes);
      put(_oRk, _rk.extractBytes());
      if (_cks case final cks?) put(_oCks, cks.extractBytes());
      if (_ckr case final ckr?) put(_oCkr, ckr.extractBytes());
      data
        ..setUint32(_oNs, _ns)
        ..setUint32(_oNr, _nr)
        ..setUint32(_oPn, _pn)
        ..setUint32(_oCount, count);
      var o = _storageFixedLength;
      for (final MapEntry(key: (dhPub, n), :value) in _skipped.entries) {
        out.setAll(o, dhPub.bytes);
        data
          ..setUint32(o + 32, n)
          ..setInt64(o + 36, value.storedAt.millisecondsSinceEpoch);
        put(o + 44, value.mk.extractBytes());
        o += _storageSkippedLength;
      }
      return out;
    } catch (_) {
      out.fillRange(0, out.length, 0);
      rethrow;
    }
  }

  /// Writes [toStorageBytes] to [storage] under [key] and zeroes the bytes
  /// once the write has finished.
  ///
  /// The app commits the session in the same database transaction as the
  /// events of the message (PROTOCOL.md section 8, step 8), so it will
  /// usually call [toStorageBytes] itself; this is for callers that keep
  /// the session on its own.
  Future<void> save(Storage storage, String key) async {
    final bytes = toStorageBytes();
    try {
      await storage.write(key, bytes);
    } finally {
      bytes.fillRange(0, bytes.length, 0);
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
    for (final k in _skipped.values) {
      k.mk.dispose();
    }
    _skipped.clear();
  }

  /// Signal 3.5 `SkipMessageKeys` on copies: derives the message keys
  /// `from .. until - 1` of chain [ck] (which stays as it is) into [into],
  /// indexed by [dhPub]. Returns the chain key at [until] (a new secret the
  /// caller disposes), or null when there is nothing to skip.
  SecretBytes? _skipKeys(
    SecretBytes ck,
    X25519PublicKey dhPub,
    int from,
    int until,
    Map<_SkippedId, SecretBytes> into,
  ) {
    SecretBytes? walked;
    try {
      for (var n = from; n < until; n++) {
        final (next, mk) = _kdfCk(_crypto, walked ?? ck);
        into[(dhPub, n)] = mk;
        walked?.dispose();
        walked = next;
      }
      final out = walked;
      walked = null;
      return out;
    } finally {
      walked?.dispose();
    }
  }

  static bool _isExpired(_SkippedKey k, DateTime now) =>
      now.difference(k.storedAt) > skippedKeyLifetime;

  void _deleteExpired(DateTime now) {
    _skipped.removeWhere((_, k) {
      if (!_isExpired(k, now)) return false;
      k.mk.dispose();
      return true;
    });
  }

  void _ensureLive() {
    if (_disposed) throw StateError('RatchetSession used after dispose()');
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
    final rkOut = out.slice(0, 32);
    try {
      return (rkOut, out.slice(32, 64));
    } catch (_) {
      rkOut.dispose();
      rethrow;
    }
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
    // The nonce is not secret (it would be sent if it were random); it is
    // only taken out of the derived key material here.
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
