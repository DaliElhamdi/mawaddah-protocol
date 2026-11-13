// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

part of 'crypto.dart';

/// [Crypto] over libsodium 1.0.22 (sumo), through the `sodium` package.
///
/// libsodium is compiled and linked by the `sodium` build hook, so plain
/// `dart test`, the Flutter app and the partner bot all use the same library
/// with no system install (ADR 0005, ADR 0006 point 1).
final class SodiumCrypto implements Crypto {
  /// Uses an already initialised libsodium [sodium] (the app passes the
  /// instance it loaded, for example inside an isolate). Random bytes for
  /// keys and nonces come from [random]; without one, libsodium's own CSPRNG
  /// (`randombytes_buf`) is used. Tests pass a `SeededRandom` to get
  /// repeatable keys.
  SodiumCrypto(na.SodiumSumo sodium, {RandomSource? random})
    : _sodium = sodium,
      _random = random ?? SodiumRandomSource(sodium);

  /// Loads the libsodium built by the `sodium` build hook, then
  /// [SodiumCrypto.new].
  static Future<SodiumCrypto> load({RandomSource? random}) async =>
      SodiumCrypto(await na.SodiumSumoInit.init(), random: random);

  final na.SodiumSumo _sodium;
  final RandomSource _random;

  /// The libsodium version in use, for example `1.0.22` (debug screens).
  String get libsodiumVersion => _sodium.version.toString();

  // --- helpers -----------------------------------------------------------

  na.SecureKey _randomSecret(int length) {
    final bytes = _random.nextBytes(length);
    if (bytes.length != length) {
      final got = bytes.length;
      bytes.fillRange(0, got, 0);
      throw StateError('RandomSource returned $got bytes, expected $length');
    }
    return _importBytes(bytes);
  }

  na.SecureKey _importBytes(Uint8List bytes) {
    if (bytes.isEmpty) throw ArgumentError.value(bytes, 'bytes', 'is empty');
    try {
      return _sodium.secureCopy(bytes);
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  Uint8List? _ad(Uint8List? associatedData) =>
      (associatedData == null || associatedData.isEmpty)
      ? null
      : associatedData;

  // --- X25519 ------------------------------------------------------------

  @override
  X25519KeyPair generateX25519KeyPair() =>
      _x25519Pair(_randomSecret(X25519SecretKey.byteLength));

  @override
  X25519KeyPair importX25519KeyPair(Uint8List secretKey) {
    if (secretKey.length != X25519SecretKey.byteLength) {
      secretKey.fillRange(0, secretKey.length, 0);
      throw ArgumentError.value(
        secretKey.length,
        'secretKey',
        'must be ${X25519SecretKey.byteLength} bytes long',
      );
    }
    return _x25519Pair(_importBytes(secretKey));
  }

  X25519KeyPair _x25519Pair(na.SecureKey secret) {
    final sk = X25519SecretKey._(_sodium, secret);
    try {
      final pk = X25519PublicKey(_sodium.crypto.scalarmult.base(n: sk._live));
      return X25519KeyPair._(pk, sk);
    } catch (_) {
      sk.dispose();
      rethrow;
    }
  }

  @override
  SecretBytes x25519(X25519SecretKey secretKey, X25519PublicKey publicKey) {
    final na.SecureKey out;
    try {
      out = _sodium.crypto.scalarmult(n: secretKey._live, p: publicKey.bytes);
    } on na.SodiumException {
      // crypto_scalarmult fails only when the result is all zeros.
      throw const InvalidPublicKeyException();
    }
    return SecretBytes._(_sodium, out);
  }

  // --- Ed25519 -----------------------------------------------------------

  @override
  Ed25519KeyPair generateEd25519KeyPair() =>
      _ed25519Pair(_randomSecret(Ed25519SecretKey.seedLength));

  @override
  Ed25519KeyPair importEd25519KeyPair(Uint8List seed) {
    if (seed.length != Ed25519SecretKey.seedLength) {
      seed.fillRange(0, seed.length, 0);
      throw ArgumentError.value(
        seed.length,
        'seed',
        'must be ${Ed25519SecretKey.seedLength} bytes long',
      );
    }
    return _ed25519Pair(_importBytes(seed));
  }

  Ed25519KeyPair _ed25519Pair(na.SecureKey seed) {
    try {
      final kp = _sodium.crypto.sign.seedKeyPair(seed);
      return Ed25519KeyPair._(
        Ed25519PublicKey(kp.publicKey),
        Ed25519SecretKey._(_sodium, kp.secretKey),
      );
    } finally {
      seed.dispose();
    }
  }

  @override
  Ed25519Signature sign(Ed25519SecretKey secretKey, Uint8List message) =>
      Ed25519Signature(
        _sodium.crypto.sign.detached(
          message: message,
          secretKey: secretKey._live,
        ),
      );

  @override
  bool verify(
    Ed25519PublicKey publicKey,
    Uint8List message,
    Ed25519Signature signature,
  ) => _sodium.crypto.sign.verifyDetached(
    message: message,
    signature: signature.bytes,
    publicKey: publicKey.bytes,
  );

  // --- XChaCha20-Poly1305 ------------------------------------------------

  na.Aead get _aead => _sodium.crypto.aeadXChaCha20Poly1305IETF;

  @override
  AeadKey generateAeadKey() =>
      AeadKey._(_sodium, _randomSecret(AeadKey.byteLength));

  @override
  AeadKey importAeadKey(Uint8List key) {
    if (key.length != AeadKey.byteLength) {
      key.fillRange(0, key.length, 0);
      throw ArgumentError.value(
        key.length,
        'key',
        'must be ${AeadKey.byteLength} bytes long',
      );
    }
    return AeadKey._(_sodium, _importBytes(key));
  }

  @override
  AeadKey aeadKeyFrom(SecretBytes keyMaterial) {
    if (keyMaterial.length < AeadKey.byteLength) {
      throw ArgumentError.value(
        keyMaterial.length,
        'keyMaterial',
        'must be at least ${AeadKey.byteLength} bytes long',
      );
    }
    return AeadKey._(
      _sodium,
      keyMaterial._use(
        (b) =>
            _sodium.secureCopy(Uint8List.sublistView(b, 0, AeadKey.byteLength)),
      ),
    );
  }

  @override
  AeadNonce generateAeadNonce() =>
      AeadNonce(_random.nextBytes(AeadNonce.byteLength));

  @override
  Uint8List encrypt({
    required AeadKey key,
    required AeadNonce nonce,
    required Uint8List plaintext,
    Uint8List? associatedData,
  }) => _aead.encrypt(
    message: plaintext,
    nonce: nonce.bytes,
    key: key._live,
    additionalData: _ad(associatedData),
  );

  @override
  Uint8List decrypt({
    required AeadKey key,
    required AeadNonce nonce,
    required Uint8List ciphertext,
    Uint8List? associatedData,
  }) {
    final live = key._live;
    if (ciphertext.length < _aead.aBytes) {
      throw const DecryptionFailedException();
    }
    try {
      return _aead.decrypt(
        cipherText: ciphertext,
        nonce: nonce.bytes,
        key: live,
        additionalData: _ad(associatedData),
      );
    } on na.SodiumException {
      throw const DecryptionFailedException();
    }
  }

  // --- Secretstream ------------------------------------------------------

  @override
  Future<Uint8List> streamEncrypt({
    required SecretBytes key,
    required Uint8List plaintext,
    required int chunkSize,
  }) async {
    RangeError.checkValueInInterval(chunkSize, 1, 1 << 24, 'chunkSize');
    final live = key._live;
    final count = plaintext.isEmpty
        ? 1
        : (plaintext.length + chunkSize - 1) ~/ chunkSize;
    Stream<na.SecretStreamPlainMessage> messages() async* {
      for (var i = 0; i < count; i++) {
        final start = i * chunkSize;
        final end = (start + chunkSize).clamp(0, plaintext.length);
        yield na.SecretStreamPlainMessage(
          Uint8List.sublistView(plaintext, start, end),
          tag: i == count - 1
              ? na.SecretStreamMessageTag.finalPush
              : na.SecretStreamMessageTag.message,
        );
      }
    }

    final out = BytesBuilder(copy: false);
    await for (final m in _sodium.crypto.secretStream.pushEx(
      messageStream: messages(),
      key: live,
    )) {
      out.add(m.message);
    }
    return out.takeBytes();
  }

  @override
  Future<Uint8List> streamDecrypt({
    required SecretBytes key,
    required Uint8List ciphertext,
    required int chunkSize,
  }) async {
    RangeError.checkValueInInterval(chunkSize, 1, 1 << 24, 'chunkSize');
    final live = key._live;
    final stream = _sodium.crypto.secretStream;
    final header = stream.headerBytes;
    final frame = chunkSize + stream.aBytes;
    // A well-formed stream is the header plus at least one chunk, every chunk
    // but the last full size: the cut points follow from the length.
    if (ciphertext.length < header + stream.aBytes) {
      throw const DecryptionFailedException();
    }
    final body = ciphertext.length - header;
    final count = (body + frame - 1) ~/ frame;
    // The last chunk must at least hold its tag.
    if (body - (count - 1) * frame < stream.aBytes) {
      throw const DecryptionFailedException();
    }

    Stream<na.SecretStreamCipherMessage> messages() async* {
      yield na.SecretStreamCipherMessage(
        Uint8List.sublistView(ciphertext, 0, header),
      );
      for (var i = 0; i < count; i++) {
        final start = header + i * frame;
        final end = (start + frame).clamp(0, ciphertext.length);
        yield na.SecretStreamCipherMessage(
          Uint8List.sublistView(ciphertext, start, end),
        );
      }
    }

    final out = BytesBuilder(copy: false);
    var seen = 0;
    var finalSeen = false;
    try {
      await for (final m in stream.pullEx(
        cipherStream: messages(),
        key: live,
      )) {
        final isLast = seen == count - 1;
        final isFinal = m.tag == na.SecretStreamMessageTag.finalPush;
        if (finalSeen || isFinal != isLast) {
          throw const DecryptionFailedException();
        }
        finalSeen = isFinal;
        seen++;
        out.add(m.message);
      }
    } on na.SodiumException {
      throw const DecryptionFailedException();
    } on na.StreamClosedEarlyException {
      throw const DecryptionFailedException();
    }
    if (!finalSeen || seen != count) throw const DecryptionFailedException();
    return out.takeBytes();
  }

  // --- Padding -----------------------------------------------------------

  @override
  Uint8List pad(Uint8List data, int blockSize) {
    RangeError.checkValueInInterval(blockSize, 1, 1 << 16, 'blockSize');
    return Uint8List.fromList(_sodium.pad(data, blockSize));
  }

  @override
  Uint8List unpad(Uint8List data, int blockSize) {
    RangeError.checkValueInInterval(blockSize, 1, 1 << 16, 'blockSize');
    if (data.isEmpty || data.length % blockSize != 0) {
      throw const InvalidPaddingException();
    }
    try {
      return Uint8List.fromList(_sodium.unpad(data, blockSize));
    } on na.SodiumException {
      throw const InvalidPaddingException();
    }
  }

  // --- BLAKE2b -----------------------------------------------------------

  @override
  Uint8List blake2b(Uint8List message, {int length = 32, SecretBytes? key}) =>
      _sodium.crypto.genericHash(
        message: message,
        outLen: length,
        key: key?._live,
      );

  // --- HKDF-SHA-256 ------------------------------------------------------

  na.KdfHkdf get _hkdf => _sodium.crypto.kdfHkdfSha256;

  @override
  SecretBytes hkdfExtract({SecretBytes? salt, required SecretBytes ikm}) {
    final prk = ikm._use(
      (i) => salt == null
          ? _hkdf.extract(ikm: i)
          : salt._use((s) => _hkdf.extract(salt: s, ikm: i)),
    );
    return SecretBytes._(_sodium, prk);
  }

  @override
  SecretBytes hkdfExpand({
    required SecretBytes prk,
    required String info,
    required int length,
  }) {
    // libsodium takes `info` as a C string from a Dart String (UTF-8). The
    // protocol's labels are ASCII (PROTOCOL.md section 1), so the bytes are
    // exactly the label; anything else is refused rather than re-encoded.
    for (final unit in info.codeUnits) {
      if (unit > 0x7f) {
        throw ArgumentError.value(info, 'info', 'must be ASCII');
      }
    }
    if (prk.length != hkdfPrkLength) {
      throw ArgumentError.value(
        prk.length,
        'prk',
        'must be $hkdfPrkLength bytes long',
      );
    }
    RangeError.checkValueInInterval(length, 1, hkdfMaxLength, 'length');
    return SecretBytes._(
      _sodium,
      _hkdf.expand(masterKey: prk._live, context: info, outLen: length),
    );
  }

  @override
  SecretBytes hkdf({
    SecretBytes? salt,
    required SecretBytes ikm,
    required String info,
    required int length,
  }) {
    final prk = hkdfExtract(salt: salt, ikm: ikm);
    try {
      return hkdfExpand(prk: prk, info: info, length: length);
    } finally {
      prk.dispose();
    }
  }

  // --- HMAC-SHA-512-256 --------------------------------------------------

  void _checkHmacKey(SecretBytes key) {
    if (key.length != hmacKeyLength) {
      throw ArgumentError.value(
        key.length,
        'key',
        'must be $hmacKeyLength bytes long',
      );
    }
  }

  @override
  Uint8List hmac(SecretBytes key, Uint8List message) {
    _checkHmacKey(key);
    return _sodium.crypto.auth(message: message, key: key._live);
  }

  @override
  bool verifyHmac(SecretBytes key, Uint8List message, Uint8List tag) {
    _checkHmacKey(key);
    if (tag.length != hmacLength) return false;
    return _sodium.crypto.auth.verify(
      tag: tag,
      message: message,
      key: key._live,
    );
  }

  // --- Secret bytes ------------------------------------------------------

  @override
  SecretBytes importSecret(Uint8List bytes) =>
      SecretBytes._(_sodium, _importBytes(bytes));

  @override
  SecretBytes concat(List<SecretBytes> parts) {
    final total = parts.fold<int>(0, (n, p) => n + p._live.length);
    if (total == 0) throw ArgumentError.value(parts, 'parts', 'are empty');
    final out = _sodium.secureAlloc(total);
    out.runUnlockedSync((dst) {
      var offset = 0;
      for (final p in parts) {
        p._use((src) => dst.setAll(offset, src));
        offset += p.length;
      }
    }, writable: true);
    return SecretBytes._(_sodium, out);
  }
}

/// [RandomSource] backed by libsodium's CSPRNG (`randombytes_buf`, which
/// reads the operating system's generator). The production source.
final class SodiumRandomSource implements RandomSource {
  SodiumRandomSource(this._sodium);

  final na.Sodium _sodium;

  @override
  Uint8List nextBytes(int length) {
    if (length < 0) throw RangeError.value(length, 'length');
    if (length == 0) return Uint8List(0);
    return _sodium.randombytes.buf(length);
  }
}
