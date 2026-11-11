// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Device identity keys, device ID and safety number (PROTOCOL.md sections
/// 3 and 5).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

import '../crypto/crypto.dart';
import '../random_source.dart';

/// The public half of a device identity: what the partner learns during
/// pairing and what the safety number is computed from.
final class PublicIdentity {
  PublicIdentity({required this.signingKey, required this.dhKey});

  /// `IKsig`, the Ed25519 key that signs bundles, envelopes and relay requests.
  final Ed25519PublicKey signingKey;

  /// `IKdh`, the X25519 key used in the pairing Diffie-Hellman.
  final X25519PublicKey dhKey;

  /// This device's ID (also its relay inbox ID), computed from [signingKey].
  DeviceId get deviceId => DeviceId.fromSigningKey(signingKey);

  /// `IKsig || IKdh`, 64 bytes: the per-device input of the safety number.
  Uint8List get _safetyNumberInput => Uint8List(64)
    ..setAll(0, signingKey.bytes)
    ..setAll(32, dhKey.bytes);

  @override
  bool operator ==(Object other) =>
      other is PublicIdentity &&
      other.signingKey == signingKey &&
      other.dhKey == dhKey;

  @override
  int get hashCode => Object.hash(signingKey, dhKey);

  @override
  String toString() => 'PublicIdentity(${deviceId.toBase64Url()})';
}

/// A device's two long-term key pairs (PROTOCOL.md section 3): an Ed25519
/// signing key `IKsig` and an X25519 Diffie-Hellman key `IKdh`, generated
/// independently (the X25519 key is not converted from the Ed25519 key).
///
/// Generated fresh for every pairing attempt and kept for the life of that
/// pair (ADR 0006). The private keys stay in libsodium guarded memory; call
/// [dispose] when the identity is no longer needed. [toString] never shows
/// secret bytes.
final class DeviceIdentity {
  DeviceIdentity._(this._signing, this._dh)
    : publicIdentity = PublicIdentity(
        signingKey: _signing.publicKey,
        dhKey: _dh.publicKey,
      );

  /// New identity from [random]: the first 32 bytes are the Ed25519 seed,
  /// the next 32 bytes the X25519 secret key. In the app [random] is a
  /// cryptographically secure source; `SeededRandom` is only for vectors.
  factory DeviceIdentity.generate(Crypto crypto, RandomSource random) {
    final signing = crypto.importEd25519KeyPair(
      _take(random, Ed25519SecretKey.seedLength),
    );
    try {
      final dh = crypto.importX25519KeyPair(
        _take(random, X25519SecretKey.byteLength),
      );
      return DeviceIdentity._(signing, dh);
    } catch (_) {
      signing.dispose();
      rethrow;
    }
  }

  /// Identity from bytes written by [toStorageBytes]. Zeroes [bytes], also
  /// when it throws.
  ///
  /// Throws [FormatException] when [bytes] has the wrong length or an
  /// unknown format version (the stored value is damaged or newer).
  factory DeviceIdentity.fromStorageBytes(Crypto crypto, Uint8List bytes) {
    try {
      if (bytes.length != storageLength) {
        throw FormatException(
          'stored identity must be $storageLength bytes, '
          'got ${bytes.length}',
        );
      }
      if (bytes[0] != storageFormatVersion) {
        throw FormatException('unknown stored identity format ${bytes[0]}');
      }
      final signing = crypto.importEd25519KeyPair(
        Uint8List.fromList(Uint8List.sublistView(bytes, 1, 33)),
      );
      try {
        final dh = crypto.importX25519KeyPair(
          Uint8List.fromList(Uint8List.sublistView(bytes, 33, 65)),
        );
        return DeviceIdentity._(signing, dh);
      } catch (_) {
        signing.dispose();
        rethrow;
      }
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  /// Version byte at the start of [toStorageBytes].
  static const storageFormatVersion = 1;

  /// Length of [toStorageBytes]: version, Ed25519 seed, X25519 secret key.
  static const storageLength = 1 + 32 + 32;

  final Ed25519KeyPair _signing;
  final X25519KeyPair _dh;

  /// The public keys and device ID.
  final PublicIdentity publicIdentity;

  /// This device's ID (also its relay inbox ID).
  DeviceId get deviceId => publicIdentity.deviceId;

  /// The Ed25519 secret key, for the protocol code that signs.
  Ed25519SecretKey get signingSecretKey => _signing.secretKey;

  /// The X25519 secret key, for the pairing Diffie-Hellman.
  X25519SecretKey get dhSecretKey => _dh.secretKey;

  /// The private keys as bytes for the platform's secure storage (for
  /// example the Android Keystore through the app's `Storage`):
  /// `0x01 || Ed25519 seed (32) || X25519 secret (32)`, 65 bytes.
  /// Local only: never sent, logged or put in a backup (PROTOCOL.md
  /// section 3). The caller must overwrite the list with zeros as soon as it
  /// is stored.
  Uint8List toStorageBytes() {
    final out = Uint8List(storageLength)..[0] = storageFormatVersion;
    final seed = _signing.secretKey.extractBytes();
    final dh = _dh.secretKey.extractBytes();
    out
      ..setAll(1, seed)
      ..setAll(33, dh);
    seed.fillRange(0, seed.length, 0);
    dh.fillRange(0, dh.length, 0);
    return out;
  }

  /// Whether [dispose] was called.
  bool get isDisposed => _signing.secretKey.isDisposed;

  /// Wipes both private keys. Safe to call more than once.
  void dispose() {
    _signing.dispose();
    _dh.dispose();
  }

  @override
  String toString() =>
      'DeviceIdentity(${deviceId.toBase64Url()}, private keys redacted)';

  static Uint8List _take(RandomSource random, int length) {
    final bytes = random.nextBytes(length);
    if (bytes.length != length) {
      final got = bytes.length;
      bytes.fillRange(0, got, 0);
      throw StateError('RandomSource returned $got bytes, expected $length');
    }
    return bytes;
  }
}

/// A device ID, 16 bytes (PROTOCOL.md section 3):
/// `SHA-256("mawaddah/v1/inbox" || IKsig_pub)[0..16]`. It is also the relay
/// inbox ID, written as 22 characters of base64url without padding.
final class DeviceId {
  DeviceId._(this.bytes);

  /// The device ID of the device whose signing key is [signingKey].
  factory DeviceId.fromSigningKey(Ed25519PublicKey signingKey) {
    final digest = sha256.convert([..._inboxLabel, ...signingKey.bytes]).bytes;
    return DeviceId._(
      Uint8List.fromList(digest.sublist(0, byteLength)).asUnmodifiableView(),
    );
  }

  /// Parses the base64url form (22 characters, no padding). Throws
  /// [FormatException] for any other text.
  factory DeviceId.parse(String text) {
    if (text.length != base64UrlLength ||
        !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(text)) {
      throw FormatException('not a base64url device ID', text);
    }
    final bytes = base64Url.decode('$text==');
    final id = DeviceId._(Uint8List.fromList(bytes).asUnmodifiableView());
    // Reject non-canonical text (unused low bits of the last character set).
    if (id.toBase64Url() != text) {
      throw FormatException('not a canonical base64url device ID', text);
    }
    return id;
  }

  static const byteLength = 16;
  static const base64UrlLength = 22;
  static final _inboxLabel = ascii.encode('mawaddah/v1/inbox');

  /// The 16 ID bytes (read-only).
  final Uint8List bytes;

  /// Base64url without padding, as used in JSON and relay URLs.
  String toBase64Url() => base64Url.encode(bytes).replaceAll('=', '');

  @override
  bool operator ==(Object other) {
    if (other is! DeviceId) return false;
    for (var i = 0; i < byteLength; i++) {
      if (bytes[i] != other.bytes[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);

  @override
  String toString() => 'DeviceId(${toBase64Url()})';
}

/// The safety number of a pair (PROTOCOL.md section 5): 20 ASCII digits,
/// the same whichever order [a] and [b] are given in.
///
/// ```
/// K  = IKsig || IKdh for each device; (K1, K2) = both, sorted, smaller first
/// H  = BLAKE2b-256("mawaddah/v1/safety-number" || K1 || K2)
/// group[g] = u40(H[5g .. 5g+5]) mod 10000, 4 digits with leading zeros
/// ```
///
/// Shown to people as 5 groups of 4 ([safetyNumberGroups]), left to right.
String safetyNumber(Crypto crypto, PublicIdentity a, PublicIdentity b) {
  final ka = a._safetyNumberInput;
  final kb = b._safetyNumberInput;
  final aFirst = _compareBytes(ka, kb) <= 0;
  final h = crypto.blake2b(
    Uint8List.fromList([
      ..._safetyNumberLabel,
      ...(aFirst ? ka : kb),
      ...(aFirst ? kb : ka),
    ]),
    length: 32,
  );
  final out = StringBuffer();
  for (var g = 0; g < safetyNumberGroupCount; g++) {
    var u40 = 0;
    for (var i = 5 * g; i < 5 * g + 5; i++) {
      u40 = u40 * 256 + h[i];
    }
    out.write((u40 % 10000).toString().padLeft(4, '0'));
  }
  return out.toString();
}

/// [digits] (a [safetyNumber]) split into its 5 groups of 4, for display.
List<String> safetyNumberGroups(String digits) {
  if (!RegExp(r'^[0-9]{20}$').hasMatch(digits)) {
    throw ArgumentError.value(digits, 'digits', 'must be 20 ASCII digits');
  }
  return [
    for (var g = 0; g < safetyNumberGroupCount; g++)
      digits.substring(4 * g, 4 * g + 4),
  ];
}

/// Number of 4-digit groups in a safety number.
const safetyNumberGroupCount = 5;

final _safetyNumberLabel = ascii.encode('mawaddah/v1/safety-number');

/// Unsigned lexicographic order of two equal-length byte strings.
int _compareBytes(Uint8List x, Uint8List y) {
  for (var i = 0; i < x.length; i++) {
    if (x[i] != y[i]) return x[i] - y[i];
  }
  return 0;
}
