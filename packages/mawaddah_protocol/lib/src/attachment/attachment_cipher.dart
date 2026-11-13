// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import '../crypto/crypto.dart';
import '../random_source.dart';

/// Size of an attachment key.
const attachmentKeyLength = 32;

/// Size of a `blob_id`.
const blobIdLength = 16;

/// Plaintext bytes in one secretstream chunk (PROTOCOL.md section 12).
const attachmentChunkSize = 65536;

/// Header size plus the 17 bytes each chunk adds.
const attachmentHeaderLength = 24;
const attachmentChunkOverhead = 17;

/// The relay's limit for one blob (10 MiB of ciphertext).
const maxAttachmentCiphertext = 10 * 1024 * 1024;

/// Largest file that fits [maxAttachmentCiphertext]: 10,483,016 bytes.
const maxAttachmentPlaintext = 10483016;

/// A file refused because it is larger than the relay accepts.
final class AttachmentTooLargeException implements Exception {
  const AttachmentTooLargeException();

  @override
  String toString() => 'AttachmentTooLargeException: over the 10 MiB limit';
}

/// The size of the ciphertext for a file of [plaintextLength] bytes.
int attachmentCiphertextLength(int plaintextLength) {
  final chunks = plaintextLength == 0
      ? 1
      : (plaintextLength + attachmentChunkSize - 1) ~/ attachmentChunkSize;
  return attachmentHeaderLength +
      plaintextLength +
      chunks * attachmentChunkOverhead;
}

/// Encrypts and decrypts a whole attachment (PROTOCOL.md section 12) with
/// libsodium secretstream XChaCha20-Poly1305.
///
/// The file is cut into 65,536-byte chunks; the last chunk (the only one for
/// an empty file) is tagged `FINAL`. Decryption returns the whole file or
/// throws; no partial output is ever returned.
final class AttachmentCipher {
  AttachmentCipher(this._crypto, this._random);

  final Crypto _crypto;
  final RandomSource _random;

  /// A new random 32-byte key. The caller disposes it.
  SecretBytes generateKey() => _crypto.importSecret(
    _checked(_random.nextBytes(attachmentKeyLength), attachmentKeyLength),
  );

  /// A new random 16-byte blob ID.
  Uint8List generateBlobId() =>
      _checked(_random.nextBytes(blobIdLength), blobIdLength);

  /// Encrypts [plaintext] under [key] (not disposed). Throws
  /// [AttachmentTooLargeException] if the result would exceed
  /// [maxAttachmentCiphertext].
  Future<Uint8List> encrypt({
    required SecretBytes key,
    required Uint8List plaintext,
  }) async {
    if (plaintext.length > maxAttachmentPlaintext) {
      throw const AttachmentTooLargeException();
    }
    return _crypto.streamEncrypt(
      key: key,
      plaintext: plaintext,
      chunkSize: attachmentChunkSize,
    );
  }

  /// Decrypts [ciphertext] under [key] (not disposed). Throws
  /// [AttachmentTooLargeException] for input over the limit, and
  /// [DecryptionFailedException] for anything that is not exactly what
  /// [encrypt] produced.
  Future<Uint8List> decrypt({
    required SecretBytes key,
    required Uint8List ciphertext,
  }) async {
    if (ciphertext.length > maxAttachmentCiphertext) {
      throw const AttachmentTooLargeException();
    }
    return _crypto.streamDecrypt(
      key: key,
      ciphertext: ciphertext,
      chunkSize: attachmentChunkSize,
    );
  }

  static Uint8List _checked(Uint8List bytes, int length) {
    if (bytes.length != length) {
      bytes.fillRange(0, bytes.length, 0);
      throw StateError('RandomSource returned ${bytes.length} bytes');
    }
    return bytes;
  }
}
