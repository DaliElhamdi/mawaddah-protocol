// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Cryptographic primitives for the protocol (PROTOCOL.md section 2).
///
/// Every operation is a libsodium function reached through the `sodium`
/// package (sumo build). Nothing here is a new construction: this library
/// only gives the libsodium calls typed keys, so a key made for one primitive
/// cannot be passed to another, and secret bytes stay in libsodium's guarded
/// memory instead of ordinary Dart lists.
library;

import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart' as na;

import '../random_source.dart';

part 'keys.dart';
part 'sodium_crypto.dart';

/// The primitives the protocol uses. Implemented by [SodiumCrypto].
///
/// Methods that take a `Uint8List` holding secret bytes (`import*`) copy it
/// into guarded memory and then overwrite the caller's list with zeros.
///
/// Errors: a value of the wrong size or out of range is a programming error
/// and throws [ArgumentError] or [RangeError]; a secret used after `dispose()`
/// throws [StateError]. Only data received from outside raises a
/// [CryptoException] (failed decryption, a small-order public key).
/// Signature checks return `false` instead of throwing.
abstract interface class Crypto {
  // --- X25519 (RFC 7748) -------------------------------------------------

  /// New X25519 key pair; the 32 secret bytes come from the [RandomSource].
  X25519KeyPair generateX25519KeyPair();

  /// Key pair for a stored 32-byte X25519 secret. Zeroes [secretKey].
  X25519KeyPair importX25519KeyPair(Uint8List secretKey);

  /// X25519(secret, public): the raw 32-byte Diffie-Hellman output.
  ///
  /// Throws [InvalidPublicKeyException] when the result is all zeros (a
  /// small-order [publicKey], RFC 7748 section 6.1).
  SecretBytes x25519(X25519SecretKey secretKey, X25519PublicKey publicKey);

  // --- Ed25519 (RFC 8032, pure) ------------------------------------------

  /// New Ed25519 key pair; the 32-byte seed comes from the [RandomSource].
  Ed25519KeyPair generateEd25519KeyPair();

  /// Key pair for a stored 32-byte Ed25519 seed. Zeroes [seed].
  Ed25519KeyPair importEd25519KeyPair(Uint8List seed);

  /// Detached signature over [message].
  Ed25519Signature sign(Ed25519SecretKey secretKey, Uint8List message);

  /// Whether [signature] is a valid signature by [publicKey] over [message].
  bool verify(
    Ed25519PublicKey publicKey,
    Uint8List message,
    Ed25519Signature signature,
  );

  // --- XChaCha20-Poly1305 (IETF AEAD) ------------------------------------

  /// New random AEAD key from the [RandomSource].
  AeadKey generateAeadKey();

  /// AEAD key from 32 stored bytes. Zeroes [key].
  AeadKey importAeadKey(Uint8List key);

  /// AEAD key from the first 32 bytes of derived key material, for example
  /// an HKDF output (PROTOCOL.md section 6, `ENCRYPT`).
  AeadKey aeadKeyFrom(SecretBytes keyMaterial);

  /// New random 24-byte nonce from the [RandomSource].
  AeadNonce generateAeadNonce();

  /// Ciphertext followed by the 16-byte Poly1305 tag.
  Uint8List encrypt({
    required AeadKey key,
    required AeadNonce nonce,
    required Uint8List plaintext,
    Uint8List? associatedData,
  });

  /// Plaintext, or [DecryptionFailedException] when the tag does not match
  /// (wrong key, nonce, associated data, or a changed byte).
  Uint8List decrypt({
    required AeadKey key,
    required AeadNonce nonce,
    required Uint8List ciphertext,
    Uint8List? associatedData,
  });

  // --- BLAKE2b (RFC 7693) ------------------------------------------------

  /// BLAKE2b digest of [message], [length] bytes (16 to 64), optionally
  /// keyed with 16 to 64 bytes of [key].
  Uint8List blake2b(Uint8List message, {int length = 32, SecretBytes? key});

  // --- HKDF-SHA-256 (RFC 5869) -------------------------------------------

  /// HKDF-Extract. A missing [salt] means the RFC's default (32 zero bytes).
  SecretBytes hkdfExtract({SecretBytes? salt, required SecretBytes ikm});

  /// HKDF-Expand of [prk] ([hkdfPrkLength] bytes) with an ASCII label as
  /// `info` (PROTOCOL.md section 1), [length] bytes (1 to [hkdfMaxLength]).
  ///
  /// `info` is a String because the `sodium` API takes it that way; binary
  /// `info` is not supported (the protocol has none).
  SecretBytes hkdfExpand({
    required SecretBytes prk,
    required String info,
    required int length,
  });

  /// HKDF-Extract followed by HKDF-Expand (the full RFC 5869 HKDF).
  SecretBytes hkdf({
    SecretBytes? salt,
    required SecretBytes ikm,
    required String info,
    required int length,
  });

  // --- HMAC-SHA-512-256 (libsodium crypto_auth) ---------------------------

  /// HMAC-SHA-512 truncated to 256 bits (libsodium `crypto_auth`; RFC 2104
  /// over SHA-512). [key] must be [hmacKeyLength] bytes. Returns
  /// [hmacLength] bytes.
  Uint8List hmac(SecretBytes key, Uint8List message);

  /// Constant-time check of an [hmac] tag. A tag of the wrong length is
  /// simply not valid (`false`); a key of the wrong size is a programming
  /// error.
  bool verifyHmac(SecretBytes key, Uint8List message, Uint8List tag);

  // --- Padding -----------------------------------------------------------

  /// ISO/IEC 7816-4 padding (libsodium `sodium_pad`): appends `0x80` and
  /// then zeros up to the next multiple of [blockSize]. Always adds at least
  /// one byte. Returns a new list; [data] is not changed.
  Uint8List pad(Uint8List data, int blockSize);

  /// Removes [pad]'s padding (libsodium `sodium_unpad`). Throws
  /// [InvalidPaddingException] when [data] is empty, not a multiple of
  /// [blockSize] long, or does not end with valid padding.
  Uint8List unpad(Uint8List data, int blockSize);

  // --- Secretstream ------------------------------------------------------

  /// Encrypts [plaintext] with libsodium secretstream XChaCha20-Poly1305 and
  /// returns the 24-byte stream header followed by the encrypted chunks.
  /// The plaintext is cut into [chunkSize]-byte chunks; the last one (the
  /// only one, for an empty or short input) may be shorter, may be empty only
  /// when [plaintext] is empty, and carries the `FINAL` tag. Every other
  /// chunk carries the `MESSAGE` tag. [key] is not disposed. No size limit
  /// is applied here (the 10 MiB cap is `AttachmentCipher`'s).
  Future<Uint8List> streamEncrypt({
    required SecretBytes key,
    required Uint8List plaintext,
    required int chunkSize,
  });

  /// Reverses [streamEncrypt]. Throws [DecryptionFailedException], and
  /// returns nothing, when the header is missing, any chunk fails
  /// authentication, a chunk is not full size before the last one, a `FINAL`
  /// tag is missing or comes early, a non-final chunk has any tag but
  /// `MESSAGE`, or bytes follow the final chunk. Plaintext of a refused
  /// stream is zeroed.
  Future<Uint8List> streamDecrypt({
    required SecretBytes key,
    required Uint8List ciphertext,
    required int chunkSize,
  });

  // --- Secret bytes ------------------------------------------------------

  /// Copies [bytes] into guarded memory and zeroes [bytes].
  SecretBytes importSecret(Uint8List bytes);

  /// The concatenation of [parts] (for example the X3DH input `F || DH1 || ...`).
  SecretBytes concat(List<SecretBytes> parts);
}

/// Size of an HKDF-SHA-256 pseudorandom key (the SHA-256 output length).
const hkdfPrkLength = 32;

/// Key and tag size of [Crypto.hmac] (libsodium `crypto_auth`).
const hmacKeyLength = 32;
const hmacLength = 32;

/// Largest HKDF-SHA-256 output: 255 blocks of 32 bytes (RFC 5869 section 2.3).
const hkdfMaxLength = 255 * 32;

/// Base of every error raised by [Crypto].
sealed class CryptoException implements Exception {
  const CryptoException(this.message);

  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// AEAD decryption failed: the data is not authentic for this key, nonce and
/// associated data. Never use any part of it.
final class DecryptionFailedException extends CryptoException {
  const DecryptionFailedException() : super('authentication tag mismatch');
}

/// An X25519 public key gave the all-zero shared secret (small order).
final class InvalidPublicKeyException extends CryptoException {
  const InvalidPublicKeyException() : super('X25519 result is all zeros');
}

/// [Crypto.unpad] found no valid ISO/IEC 7816-4 padding.
final class InvalidPaddingException extends CryptoException {
  const InvalidPaddingException() : super('invalid padding');
}
