// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// The three pairing messages: the initiator bundle, the QR payload and the
/// joiner reply (PROTOCOL.md sections 4.1 to 4.3).
///
/// None of them carries a name, gender or mode: the partner profile travels
/// later, inside the encrypted channel (section 4.5).
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/crypto.dart';
import '../identity/identity.dart';

/// Format version of the bundle, QR and reply in protocol v1.
const pairingFormatVersion = 1;

/// How long a pairing slot and its code are valid (PROTOCOL.md section 14).
const pairingSlotLifetime = Duration(minutes: 10);

/// Size of the one-time QR secret `S`.
const pairingSecretLength = 16;

/// Size of the relay's pairing slot ID.
const pairingSlotIdLength = 16;

/// How the joiner got the initiator's bundle (PROTOCOL.md section 4.3).
enum PairingPath {
  /// Scanned the QR code: the one-time secret `S` is part of the key material.
  qr(0x01, 'qr'),

  /// Typed the 6-digit code: `S'` is 16 zero bytes, so the safety number
  /// must be compared by the two people.
  code(0x02, 'code');

  const PairingPath(this.byte, this.wireName);

  /// `path_byte` in the transcript hash.
  final int byte;

  /// Value of the reply's `path` field.
  final String wireName;

  static PairingPath fromWireName(String name) => switch (name) {
    'qr' => qr,
    'code' => code,
    _ => throw FormatException('unknown pairing path', name),
  };
}

// --- encoding helpers ------------------------------------------------------

final _base64UrlChars = RegExp(r'^[A-Za-z0-9_-]*$');

String _encode(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

/// Strict base64url without padding: canonical text only.
Uint8List _decode(String text, String what) {
  if (!_base64UrlChars.hasMatch(text) || text.length % 4 == 1) {
    throw FormatException('$what is not base64url', text);
  }
  final bytes = base64Url.decode(text + '=' * ((4 - text.length % 4) % 4));
  if (_encode(bytes) != text) {
    throw FormatException('$what is not canonical base64url', text);
  }
  return Uint8List.fromList(bytes);
}

Uint8List _field(Map<String, Object?> json, String name, int length) {
  final value = json[name];
  if (value is! String) throw FormatException('missing or invalid "$name"');
  final bytes = _decode(value, name);
  if (bytes.length != length) {
    throw FormatException('"$name" must be $length bytes, got ${bytes.length}');
  }
  return bytes;
}

void _checkVersion(Map<String, Object?> json) {
  final v = json['v'];
  if (v is! int) throw const FormatException('missing or invalid "v"');
  if (v != pairingFormatVersion) {
    throw FormatException('unsupported pairing format version $v');
  }
}

Uint8List _bytes(List<List<int>> parts) {
  final out = BytesBuilder(copy: false);
  for (final p in parts) {
    out.add(p);
  }
  return out.toBytes();
}

final _bundleLabel = ascii.encode('mawaddah/v1/bundle');
final _replyLabel = ascii.encode('mawaddah/v1/reply');

// --- bundle ----------------------------------------------------------------

/// The initiator's signed key bundle, stored in the relay pairing slot
/// (section 4.1). It never contains the QR secret `S`.
final class PairingBundle {
  PairingBundle({
    required this.signingKey,
    required this.dhKey,
    required this.ephemeralKey,
    required this.signature,
  });

  /// Signs a bundle for [identity] and the fresh ephemeral key [ephemeralKey].
  factory PairingBundle.sign(
    Crypto crypto,
    DeviceIdentity identity,
    X25519PublicKey ephemeralKey,
  ) {
    final pub = identity.publicIdentity;
    final message = _signedBytes(pub.signingKey, pub.dhKey, ephemeralKey);
    return PairingBundle(
      signingKey: pub.signingKey,
      dhKey: pub.dhKey,
      ephemeralKey: ephemeralKey,
      signature: crypto.sign(identity.signingSecretKey, message),
    );
  }

  /// Reads the bundle JSON. Throws [FormatException] for a missing field, a
  /// wrong size, non-canonical base64url or an unknown version. Does not
  /// check the signature: call [verify].
  factory PairingBundle.fromJson(Map<String, Object?> json) {
    _checkVersion(json);
    return PairingBundle(
      signingKey: Ed25519PublicKey(_field(json, 'sig_pub', 32)),
      dhKey: X25519PublicKey(_field(json, 'dh_pub', 32)),
      ephemeralKey: X25519PublicKey(_field(json, 'ek_pub', 32)),
      signature: Ed25519Signature(_field(json, 'sig', 64)),
    );
  }

  /// `IKsig_i`.
  final Ed25519PublicKey signingKey;

  /// `IKdh_i`.
  final X25519PublicKey dhKey;

  /// `EKi`.
  final X25519PublicKey ephemeralKey;

  /// Ed25519 signature by [signingKey] over the bundle (section 4.1).
  final Ed25519Signature signature;

  /// The initiator's public identity.
  PublicIdentity get identity =>
      PublicIdentity(signingKey: signingKey, dhKey: dhKey);

  static Uint8List _signedBytes(
    Ed25519PublicKey sig,
    X25519PublicKey dh,
    X25519PublicKey ek,
  ) => _bytes([
    _bundleLabel,
    [pairingFormatVersion],
    sig.bytes,
    dh.bytes,
    ek.bytes,
  ]);

  /// Whether [signature] is valid for these keys.
  bool verify(Crypto crypto) => crypto.verify(
    signingKey,
    _signedBytes(signingKey, dhKey, ephemeralKey),
    signature,
  );

  Map<String, Object?> toJson() => {
    'v': pairingFormatVersion,
    'sig_pub': _encode(signingKey.bytes),
    'dh_pub': _encode(dhKey.bytes),
    'ek_pub': _encode(ephemeralKey.bytes),
    'sig': _encode(signature.bytes),
  };
}

// --- QR payload ------------------------------------------------------------

/// The QR payload (section 4.2): the initiator's three public keys, the
/// one-time secret `S` and the slot ID. It is a bearer secret shown only on
/// the initiator's screen; it carries no signature.
final class PairingQr {
  PairingQr({
    required this.signingKey,
    required this.dhKey,
    required this.ephemeralKey,
    required Uint8List secret,
    required Uint8List slotId,
  }) : secret = _sized(secret, pairingSecretLength, 'secret'),
       slotId = _sized(slotId, pairingSlotIdLength, 'slotId');

  /// Reads the text of a scanned QR. Throws [FormatException] for another
  /// prefix, a decoded length other than 129 bytes, non-canonical base64url
  /// or an unknown version byte.
  factory PairingQr.decode(String text) {
    if (!text.startsWith(prefix)) {
      throw const FormatException('not a Mawaddah pairing code');
    }
    final bytes = _decode(text.substring(prefix.length), 'payload');
    if (bytes.length != byteLength) {
      throw FormatException('pairing payload must be $byteLength bytes');
    }
    if (bytes[0] != pairingFormatVersion) {
      throw FormatException('unsupported pairing version ${bytes[0]}');
    }
    Uint8List part(int from, int to) =>
        Uint8List.fromList(Uint8List.sublistView(bytes, from, to));
    return PairingQr(
      signingKey: Ed25519PublicKey(part(1, 33)),
      dhKey: X25519PublicKey(part(33, 65)),
      ephemeralKey: X25519PublicKey(part(65, 97)),
      secret: part(97, 113),
      slotId: part(113, 129),
    );
  }

  /// Text before the base64url payload.
  static const prefix = 'MAWADDAH:';

  /// Size of the binary payload.
  static const byteLength = 129;

  final Ed25519PublicKey signingKey;
  final X25519PublicKey dhKey;
  final X25519PublicKey ephemeralKey;

  /// `S`. Overwrite it with zeros ([wipe]) when pairing ends.
  final Uint8List secret;

  /// The relay's pairing slot ID.
  final Uint8List slotId;

  /// The initiator's public identity.
  PublicIdentity get identity =>
      PublicIdentity(signingKey: signingKey, dhKey: dhKey);

  /// `MAWADDAH:` followed by the base64url payload (181 characters).
  String encode() =>
      prefix +
      _encode(
        _bytes([
          [pairingFormatVersion],
          signingKey.bytes,
          dhKey.bytes,
          ephemeralKey.bytes,
          secret,
          slotId,
        ]),
      );

  /// Overwrites [secret] with zeros.
  void wipe() => secret.fillRange(0, secret.length, 0);

  static Uint8List _sized(Uint8List bytes, int length, String what) {
    if (bytes.length != length) {
      throw ArgumentError.value(bytes.length, what, 'must be $length bytes');
    }
    return bytes;
  }
}

// --- reply -----------------------------------------------------------------

/// The joiner's reply, posted to the slot (section 4.3).
final class PairingReply {
  PairingReply({
    required this.path,
    required this.signingKey,
    required this.dhKey,
    required this.ephemeralKey,
    required this.confirm,
    required this.signature,
  });

  /// Reads the reply JSON. Throws [FormatException] like
  /// [PairingBundle.fromJson]; does not check the signature or `confirm`.
  factory PairingReply.fromJson(Map<String, Object?> json) {
    _checkVersion(json);
    final path = json['path'];
    if (path is! String) throw const FormatException('missing "path"');
    return PairingReply(
      path: PairingPath.fromWireName(path),
      signingKey: Ed25519PublicKey(_field(json, 'sig_pub', 32)),
      dhKey: X25519PublicKey(_field(json, 'dh_pub', 32)),
      ephemeralKey: X25519PublicKey(_field(json, 'ek_pub', 32)),
      confirm: _field(json, 'confirm', hmacLength),
      signature: Ed25519Signature(_field(json, 'sig', 64)),
    );
  }

  final PairingPath path;

  /// `IKsig_j`.
  final Ed25519PublicKey signingKey;

  /// `IKdh_j`.
  final X25519PublicKey dhKey;

  /// `EKj`.
  final X25519PublicKey ephemeralKey;

  /// Key confirmation (section 4.4), 32 bytes.
  final Uint8List confirm;

  /// Ed25519 signature by [signingKey] over `"mawaddah/v1/reply" || TH ||
  /// confirm`.
  final Ed25519Signature signature;

  /// The joiner's public identity.
  PublicIdentity get identity =>
      PublicIdentity(signingKey: signingKey, dhKey: dhKey);

  /// The bytes the reply signature covers.
  static Uint8List signedBytes(Uint8List transcriptHash, Uint8List confirm) =>
      _bytes([_replyLabel, transcriptHash, confirm]);

  Map<String, Object?> toJson() => {
    'v': pairingFormatVersion,
    'path': path.wireName,
    'sig_pub': _encode(signingKey.bytes),
    'dh_pub': _encode(dhKey.bytes),
    'ek_pub': _encode(ephemeralKey.bytes),
    'confirm': _encode(confirm),
    'sig': _encode(signature.bytes),
  };
}
