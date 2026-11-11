// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

part of 'crypto.dart';

// --- Public values ---------------------------------------------------------

/// Fixed-length public bytes (keys, signatures, nonces). Compared by value.
abstract base class _PublicBytes {
  _PublicBytes(Uint8List bytes, int length, String what)
      : bytes = _checkedCopy(bytes, length, what);

  /// A read-only copy of the bytes.
  final Uint8List bytes;

  static Uint8List _checkedCopy(Uint8List bytes, int length, String what) {
    if (bytes.length != length) {
      throw ArgumentError.value(
          bytes.length, what, 'must be $length bytes long');
    }
    return Uint8List.fromList(bytes).asUnmodifiableView();
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other.runtimeType != runtimeType) return false;
    final o = (other as _PublicBytes).bytes;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != o[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(runtimeType, Object.hashAll(bytes));

  @override
  String toString() {
    final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return '$runtimeType($hex)';
  }
}

/// X25519 public key (32 bytes, RFC 7748 u-coordinate).
final class X25519PublicKey extends _PublicBytes {
  X25519PublicKey(Uint8List bytes)
      : super(bytes, byteLength, 'X25519PublicKey');

  static const byteLength = 32;
}

/// Ed25519 public key (32 bytes, RFC 8032 encoding).
final class Ed25519PublicKey extends _PublicBytes {
  Ed25519PublicKey(Uint8List bytes)
      : super(bytes, byteLength, 'Ed25519PublicKey');

  static const byteLength = 32;
}

/// Ed25519 detached signature (64 bytes).
final class Ed25519Signature extends _PublicBytes {
  Ed25519Signature(Uint8List bytes)
      : super(bytes, byteLength, 'Ed25519Signature');

  static const byteLength = 64;
}

/// XChaCha20-Poly1305 nonce (24 bytes). Never reuse one with the same key.
final class AeadNonce extends _PublicBytes {
  AeadNonce(Uint8List bytes) : super(bytes, byteLength, 'AeadNonce');

  static const byteLength = 24;
}

// --- Secret values -----------------------------------------------------------

/// Secret bytes held in libsodium guarded memory (locked against swapping,
/// read/write-protected while not in use, wiped when freed).
///
/// Call [dispose] as soon as the secret is no longer needed; using it after
/// that throws a [StateError]. Equality is identity: compare secrets only
/// through the protocol's constant-time checks.
abstract base class _Secret {
  _Secret(this._sodium, this._key, int? length, String what) {
    if (length != null && _key.length != length) {
      final actual = _key.length;
      _key.dispose();
      throw ArgumentError.value(actual, what, 'must be $length bytes long');
    }
  }

  final na.SodiumSumo _sodium;
  final na.SecureKey _key;
  bool _disposed = false;

  /// Number of secret bytes.
  int get length => _key.length;

  /// Whether [dispose] was called.
  bool get isDisposed => _disposed;

  na.SecureKey get _live {
    if (_disposed) throw StateError('$runtimeType used after dispose()');
    return _key;
  }

  /// Runs [action] with a read-only view of the secret bytes. The view is
  /// valid only inside [action]; do not keep or copy it.
  T _use<T>(T Function(Uint8List bytes) action) =>
      _live.runUnlockedSync(action);

  /// A copy of the secret bytes in an ordinary Dart list, for writing to the
  /// platform keystore. The caller must overwrite it with zeros
  /// (`fillRange(0, length, 0)`) as soon as it is stored.
  Uint8List extractBytes() => _live.extractBytes();

  /// Wipes and frees the secret. Safe to call more than once.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _key.dispose();
  }

  @override
  String toString() =>
      '$runtimeType(${_disposed ? 'disposed' : '$length bytes'})';
}

/// Secret key material of any length: Diffie-Hellman outputs, HKDF outputs,
/// root and chain keys.
final class SecretBytes extends _Secret {
  SecretBytes._(na.SodiumSumo sodium, na.SecureKey key)
      : super(sodium, key, null, 'SecretBytes');

  /// Bytes [start] to [end] (exclusive) as a new secret. This secret is kept.
  SecretBytes slice(int start, [int? end]) {
    final stop = RangeError.checkValidRange(start, end, length);
    return SecretBytes._(
      _sodium,
      _use((b) => _sodium.secureCopy(Uint8List.sublistView(b, start, stop))),
    );
  }
}

/// X25519 secret key (32 bytes, clamped by libsodium on use).
final class X25519SecretKey extends _Secret {
  X25519SecretKey._(na.SodiumSumo sodium, na.SecureKey key)
      : super(sodium, key, byteLength, 'X25519SecretKey');

  static const byteLength = 32;
}

/// Ed25519 secret key. Held in libsodium's 64-byte form (seed followed by
/// the public key); [extractBytes] returns only the 32-byte seed, which is
/// what [Crypto.importEd25519KeyPair] takes back.
final class Ed25519SecretKey extends _Secret {
  Ed25519SecretKey._(na.SodiumSumo sodium, na.SecureKey key)
      : super(sodium, key, _libsodiumLength, 'Ed25519SecretKey');

  /// Length of the seed returned by [extractBytes].
  static const seedLength = 32;
  static const _libsodiumLength = 64;

  @override
  Uint8List extractBytes() =>
      _use((b) => Uint8List.fromList(Uint8List.sublistView(b, 0, seedLength)));
}

/// XChaCha20-Poly1305 key (32 bytes).
final class AeadKey extends _Secret {
  AeadKey._(na.SodiumSumo sodium, na.SecureKey key)
      : super(sodium, key, byteLength, 'AeadKey');

  static const byteLength = 32;
}

// --- Key pairs ---------------------------------------------------------------

/// An X25519 key pair. [dispose] wipes the secret key.
final class X25519KeyPair {
  X25519KeyPair._(this.publicKey, this.secretKey);

  final X25519PublicKey publicKey;
  final X25519SecretKey secretKey;

  void dispose() => secretKey.dispose();
}

/// An Ed25519 key pair. [dispose] wipes the secret key.
final class Ed25519KeyPair {
  Ed25519KeyPair._(this.publicKey, this.secretKey);

  final Ed25519PublicKey publicKey;
  final Ed25519SecretKey secretKey;

  void dispose() => secretKey.dispose();
}
