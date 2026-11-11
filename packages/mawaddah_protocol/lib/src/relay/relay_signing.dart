// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

import '../clock.dart';
import '../crypto/crypto.dart';
import '../identity/identity.dart';
import '../random_source.dart';

/// Signs relay requests with the device's `IKsig` (PROTOCOL.md section 13).
///
/// The relay client (protocol #24) adds the returned headers to every
/// request except `GET /v1/pairing-slot/{slot_id or code}` and `GET /health`.
final class RelayRequestSigner {
  RelayRequestSigner({
    required this.crypto,
    required this.identity,
    required this.clock,
    required this.random,
  });

  final Crypto crypto;

  /// The device whose `IKsig` signs. The signer does not own it: the caller
  /// disposes it.
  final DeviceIdentity identity;
  final Clock clock;
  final RandomSource random;

  /// First line of every signing input.
  static const label = 'MAWADDAH-RELAY-V1';

  /// Size of the random nonce, in bytes.
  static const nonceLength = 16;

  static const keyHeader = 'Maw-Key';
  static const timestampHeader = 'Maw-Timestamp';
  static const nonceHeader = 'Maw-Nonce';
  static const signatureHeader = 'Maw-Signature';

  /// The four signing headers for one request. [pathAndQuery] is the path
  /// and query exactly as they will be sent (for example
  /// `/v1/inbox/AbC.../envelopes?after=17`); [body] is the exact body bytes
  /// (empty for a request without a body). A fresh nonce is drawn each call.
  Map<String, String> sign({
    required String method,
    required String pathAndQuery,
    required Uint8List body,
  }) {
    final nonce = random.nextBytes(nonceLength);
    if (nonce.length != nonceLength) {
      throw StateError('RandomSource returned ${nonce.length} bytes');
    }
    final timestamp =
        clock.now().toUtc().millisecondsSinceEpoch ~/
        Duration.millisecondsPerSecond;
    final nonceText = _b64(nonce);
    final input = signingInput(
      method: method,
      pathAndQuery: pathAndQuery,
      body: body,
      timestamp: timestamp,
      nonce: nonceText,
    );
    final signature = crypto.sign(identity.signingSecretKey, input);
    return {
      keyHeader: _b64(identity.publicIdentity.signingKey.bytes),
      timestampHeader: '$timestamp',
      nonceHeader: nonceText,
      signatureHeader: _b64(signature.bytes),
    };
  }

  /// The bytes that are signed: six lines joined by `\n`, no final newline.
  ///
  /// Throws [ArgumentError] for a [method] that is not uppercase letters, a
  /// negative [timestamp], a [nonce] that is not 22 base64url characters,
  /// or a [pathAndQuery] the relay would not rebuild the same way: it must
  /// start with `/` and use only base64url characters and `/` in the path,
  /// then optionally `?` and a non-empty query of base64url characters, `=`
  /// and `&` (PROTOCOL.md section 13). That rules out `.` segments,
  /// percent-escapes, `#`, `\` and an empty `?`, which URL parsing changes.
  static Uint8List signingInput({
    required String method,
    required String pathAndQuery,
    required Uint8List body,
    required int timestamp,
    required String nonce,
  }) {
    if (!_method.hasMatch(method)) {
      throw ArgumentError.value(method, 'method', 'must be uppercase letters');
    }
    if (!_path.hasMatch(pathAndQuery)) {
      throw ArgumentError.value(
        pathAndQuery,
        'pathAndQuery',
        'must be / and base64url characters, then an optional ?query',
      );
    }
    if (timestamp < 0) {
      throw ArgumentError.value(timestamp, 'timestamp', 'must not be negative');
    }
    if (!_nonce.hasMatch(nonce)) {
      throw ArgumentError.value(nonce, 'nonce', 'must be 22 base64url chars');
    }
    final text = [
      label,
      method,
      pathAndQuery,
      sha256.convert(body).toString(),
      '$timestamp',
      nonce,
    ].join('\n');
    return Uint8List.fromList(ascii.encode(text));
  }

  static final _method = RegExp(r'^[A-Z]+$');
  static final _path = RegExp(r'^/[A-Za-z0-9_/-]*(\?[A-Za-z0-9_=&-]+)?$');
  static final _nonce = RegExp(r'^[A-Za-z0-9_-]{22}$');

  static String _b64(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');
}
