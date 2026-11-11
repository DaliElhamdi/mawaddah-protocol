// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Writes the generated test-vector files in test/vectors/ (PROTOCOL.md
// section 15). Run from the package root:
//
//   dart run tool/gen_vectors.dart
//
// Random bytes come from SeededRandom and are written into each case's
// `input`, so another implementation can reproduce every output without
// this tool. Regenerate only together with a protocol change and its ADR:
// a changed vector means the wire format changed.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';

const _generatedBy = 'packages/mawaddah_protocol/tool/gen_vectors.dart';

Future<void> main() async {
  final crypto = await SodiumCrypto.load();
  _write('identity', _identityCases(crypto));
  _write('safety_number', _safetyNumberCases(crypto));
  _write('pairing', _pairingCases(crypto));
}

void _write(String file, List<Map<String, Object?>> cases) {
  final json = {
    'file': file,
    'protocol_version': 1,
    'generated_by': _generatedBy,
    'cases': cases,
  };
  final text = '${const JsonEncoder.withIndent('  ').convert(json)}\n';
  File('test/vectors/$file.json').writeAsStringSync(text);
  stdout.writeln('wrote test/vectors/$file.json (${cases.length} cases)');
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// The 64 random bytes [DeviceIdentity.generate] would draw from
/// `SeededRandom(seed)`: Ed25519 seed, then X25519 secret.
({Uint8List sigSeed, Uint8List dhSecret}) _secrets(int seed) {
  final random = SeededRandom(seed);
  return (sigSeed: random.nextBytes(32), dhSecret: random.nextBytes(32));
}

DeviceIdentity _identity(Crypto crypto, int seed) =>
    DeviceIdentity.generate(crypto, SeededRandom(seed));

Map<String, Object?> _identityInput(int seed) {
  final s = _secrets(seed);
  return {'sig_seed': _hex(s.sigSeed), 'dh_secret': _hex(s.dhSecret)};
}

Map<String, Object?> _publicJson(PublicIdentity p) => {
  'sig_pub': _hex(p.signingKey.bytes),
  'dh_pub': _hex(p.dhKey.bytes),
};

// --- identity.json -----------------------------------------------------------

List<Map<String, Object?>> _identityCases(Crypto crypto) => [
  for (final seed in [1, 2, 3, 4])
    () {
      final id = _identity(crypto, seed);
      final p = id.publicIdentity;
      final c = {
        'name': 'SeededRandom($seed): 32-byte Ed25519 seed, then X25519 secret',
        'input': _identityInput(seed),
        'output': {
          ..._publicJson(p),
          'device_id': _hex(p.deviceId.bytes),
          'device_id_base64url': p.deviceId.toBase64Url(),
        },
      };
      id.dispose();
      return c;
    }(),
];

// --- safety_number.json ------------------------------------------------------

List<Map<String, Object?>> _safetyNumberCases(Crypto crypto) {
  final cases = <Map<String, Object?>>[];

  Map<String, Object?> hashed(
    String name,
    Map<String, Object?> aJson,
    PublicIdentity a,
    Map<String, Object?> bJson,
    PublicIdentity b,
  ) {
    final digits = safetyNumber(crypto, a, b);
    // The hash, for implementers who need to debug the digit mapping.
    final ka = [...a.signingKey.bytes, ...a.dhKey.bytes];
    final kb = [...b.signingKey.bytes, ...b.dhKey.bytes];
    final aFirst = _hex(ka).compareTo(_hex(kb)) <= 0;
    final h = crypto.blake2b(
      Uint8List.fromList([
        ...ascii.encode('mawaddah/v1/safety-number'),
        ...(aFirst ? ka : kb),
        ...(aFirst ? kb : ka),
      ]),
    );
    return {
      'name': name,
      'input': {'a': aJson, 'b': bJson},
      'output': {'hash': _hex(h), 'safety_number': digits},
    };
  }

  Map<String, Object?> seeded(int seedA, int seedB, String name) {
    final a = _identity(crypto, seedA);
    final b = _identity(crypto, seedB);
    final c = hashed(
      name,
      {..._identityInput(seedA), ..._publicJson(a.publicIdentity)},
      a.publicIdentity,
      {..._identityInput(seedB), ..._publicJson(b.publicIdentity)},
      b.publicIdentity,
    );
    a.dispose();
    b.dispose();
    return c;
  }

  cases
    ..add(seeded(1, 2, 'SeededRandom(1) and SeededRandom(2)'))
    ..add(seeded(3, 4, 'SeededRandom(3) and SeededRandom(4)'));

  // A pair whose number has a group with leading zeros (formatting check).
  for (var s = 10; ; s += 2) {
    final c = seeded(s, s + 1, 'SeededRandom($s) and SeededRandom(${s + 1})');
    final digits = (c['output']! as Map)['safety_number'] as String;
    if (safetyNumberGroups(digits).any((g) => g.startsWith('00'))) {
      cases.add({...c, 'name': '${c['name']}: a group with leading zeros'});
      break;
    }
  }

  // Public keys given directly: the order depends on the X25519 half when
  // the Ed25519 halves are equal (the whole 64 bytes are compared).
  PublicIdentity fixed(int sig, int dh) => PublicIdentity(
    signingKey: Ed25519PublicKey(Uint8List(32)..fillRange(0, 32, sig)),
    dhKey: X25519PublicKey(Uint8List(32)..fillRange(0, 32, dh)),
  );
  final same1 = fixed(0x11, 0x80);
  final same2 = fixed(0x11, 0x7f);
  cases.add(
    hashed(
      'equal Ed25519 keys, ordered by the X25519 key (fixed public bytes)',
      _publicJson(same1),
      same1,
      _publicJson(same2),
      same2,
    ),
  );
  // Unsigned order: 0xff sorts after 0x00 (a signed comparison would not).
  final high = fixed(0xff, 0x01);
  final low = fixed(0x00, 0xfe);
  cases.add(
    hashed(
      'bytes compared unsigned: 0xff... sorts after 0x00... (fixed public bytes)',
      _publicJson(high),
      high,
      _publicJson(low),
      low,
    ),
  );
  return cases;
}

// --- pairing.json --------------------------------------------------------------

/// The bytes the initiator draws from `SeededRandom(seed)`: Ed25519 seed,
/// X25519 secret, `EKi` secret, then the QR secret `S`.
Map<String, Object?> _initiatorInput(int seed, Uint8List slotId) {
  final r = SeededRandom(seed);
  return {
    'sig_seed': _hex(r.nextBytes(32)),
    'dh_secret': _hex(r.nextBytes(32)),
    'ek_secret': _hex(r.nextBytes(32)),
    'secret': _hex(r.nextBytes(16)),
    'slot_id': _hex(slotId),
  };
}

/// The bytes the joiner draws: Ed25519 seed, X25519 secret, `EKj` secret.
Map<String, Object?> _joinerInput(int seed) {
  final r = SeededRandom(seed);
  return {
    'sig_seed': _hex(r.nextBytes(32)),
    'dh_secret': _hex(r.nextBytes(32)),
    'ek_secret': _hex(r.nextBytes(32)),
  };
}

Uint8List _slotId(int n) => Uint8List.fromList(List.generate(16, (i) => n + i));

List<int> _ascii(String s) => ascii.encode(s);

Uint8List _bytes(List<List<int>> parts) =>
    Uint8List.fromList([for (final p in parts) ...p]);

/// Pairing run for one path, checked against a second, independent
/// derivation written straight from PROTOCOL.md section 4.4.
Map<String, Object?> _pairingSuccess(
  Crypto crypto,
  String name,
  PairingPath path,
  int iSeed,
  int jSeed,
  int slotN,
) {
  final slot = _slotId(slotN);
  final init = PairingInitiator.start(
    crypto: crypto,
    random: SeededRandom(iSeed),
    clock: FakeClock(),
  );
  final qr = init.qr(slot);
  final bundle = PairingBundle.fromJson(init.bundle.toJson());
  final joiner = path == PairingPath.qr
      ? PairingJoiner.fromQr(
          crypto: crypto,
          random: SeededRandom(jSeed),
          qrText: qr.encode(),
        )
      : PairingJoiner.fromCode(
          crypto: crypto,
          random: SeededRandom(jSeed),
          bundle: bundle,
          slotId: slot,
        );
  final reply = PairingReply.fromJson(joiner.reply.toJson());
  final result = init.acceptReply(reply);

  // Independent derivation.
  final ri = SeededRandom(iSeed);
  final ii = DeviceIdentity.generate(crypto, ri);
  final eki = crypto.importX25519KeyPair(ri.nextBytes(32));
  final secret = ri.nextBytes(16);
  final rj = SeededRandom(jSeed);
  final ji = DeviceIdentity.generate(crypto, rj);
  final ekj = crypto.importX25519KeyPair(rj.nextBytes(32));
  final sPrime = path == PairingPath.qr ? secret : Uint8List(16);

  Uint8List dh(X25519SecretKey sk, X25519PublicKey pk) {
    final out = crypto.x25519(sk, pk);
    final b = out.extractBytes();
    out.dispose();
    return b;
  }

  final dh1 = dh(ji.dhSecretKey, eki.publicKey);
  final dh2 = dh(ekj.secretKey, ii.publicIdentity.dhKey);
  final dh3 = dh(ekj.secretKey, eki.publicKey);
  final ikm = crypto.importSecret(
    _bytes([Uint8List(32)..fillRange(0, 32, 0xff), dh1, dh2, dh3, sPrime]),
  );
  final prk = crypto.hkdfExtract(
    salt: crypto.importSecret(Uint8List(32)),
    ikm: ikm,
  );
  final sk = crypto.hkdfExpand(
    prk: prk,
    info: 'mawaddah/v1/pairing/sk',
    length: 32,
  );
  final kc = crypto.hkdfExpand(
    prk: prk,
    info: 'mawaddah/v1/pairing/confirm',
    length: 32,
  );
  final iPub = ii.publicIdentity;
  final jPub = ji.publicIdentity;
  final th = crypto.blake2b(
    _bytes([
      _ascii('mawaddah/v1/transcript'),
      [1, path.byte],
      iPub.signingKey.bytes,
      iPub.dhKey.bytes,
      eki.publicKey.bytes,
      jPub.signingKey.bytes,
      jPub.dhKey.bytes,
      ekj.publicKey.bytes,
    ]),
  );
  final confirm = crypto.hmac(kc, _bytes([_ascii('mawaddah/v1/confirm'), th]));
  final ad = _bytes([
    jPub.signingKey.bytes,
    jPub.dhKey.bytes,
    iPub.signingKey.bytes,
    iPub.dhKey.bytes,
  ]);

  final skBytes = sk.extractBytes();
  if (_hex(skBytes) != _hex(result.rootKey.extractBytes()) ||
      _hex(skBytes) != _hex(joiner.result.rootKey.extractBytes()) ||
      _hex(confirm) != _hex(reply.confirm) ||
      _hex(ad) != _hex(result.associatedData) ||
      result.safetyNumber != joiner.result.safetyNumber) {
    throw StateError(
      '$name: the package and the independent derivation differ',
    );
  }

  final out = {
    'name': name,
    'input': {
      'path': path.wireName,
      'initiator': _initiatorInput(iSeed, slot),
      'joiner': _joinerInput(jSeed),
    },
    'output': {
      'bundle': init.bundle.toJson(),
      if (path == PairingPath.qr) 'qr': qr.encode(),
      'reply': reply.toJson(),
      'dh1': _hex(dh1),
      'dh2': _hex(dh2),
      'dh3': _hex(dh3),
      'sk': _hex(skBytes),
      'kc': _hex(kc.extractBytes()),
      'th': _hex(th),
      'confirm': _hex(confirm),
      'ad': _hex(ad),
      'safety_number': result.safetyNumber,
      'safety_number_required': path == PairingPath.code,
    },
  };
  for (final d in [ii, ji]) {
    d.dispose();
  }
  for (final k in [eki, ekj]) {
    k.dispose();
  }
  for (final x in [ikm, prk, sk, kc, result.rootKey, joiner.result.rootKey]) {
    x.dispose();
  }
  return out;
}

Map<String, Object?> _initiatorFailure(
  String name,
  int iSeed,
  int slotN,
  Map<String, Object?> reply,
  String error, {
  int attempts = 1,
}) => {
  'name': name,
  'input': {
    'side': 'initiator',
    'initiator': _initiatorInput(iSeed, _slotId(slotN)),
    'reply': reply,
    if (attempts != 1) 'accept_attempts': attempts,
  },
  'error': error,
};

List<Map<String, Object?>> _pairingCases(Crypto crypto) {
  final cases = <Map<String, Object?>>[
    _pairingSuccess(crypto, 'qr path', PairingPath.qr, 11, 12, 1),
    _pairingSuccess(crypto, 'code path', PairingPath.code, 13, 14, 2),
  ];

  // A QR path run, from which the failing cases are made.
  PairingInitiator initiatorFor(int seed) => PairingInitiator.start(
    crypto: crypto,
    random: SeededRandom(seed),
    clock: FakeClock(),
  );
  Map<String, Object?> replyFor(
    PairingInitiator init,
    int slotN,
    int jSeed, {
    Uint8List? secretOverride,
  }) {
    final qr = init.qr(_slotId(slotN));
    final shown = secretOverride == null
        ? qr
        : PairingQr(
            signingKey: qr.signingKey,
            dhKey: qr.dhKey,
            ephemeralKey: qr.ephemeralKey,
            secret: secretOverride,
            slotId: qr.slotId,
          );
    return PairingJoiner.fromQr(
      crypto: crypto,
      random: SeededRandom(jSeed),
      qrText: shown.encode(),
    ).reply.toJson();
  }

  // wrong secret: the joiner scanned a QR whose S differs from the initiator's
  final wrongSecret = replyFor(
    initiatorFor(15),
    3,
    16,
    secretOverride: Uint8List(16)..fillRange(0, 16, 0x42),
  );
  cases.add(
    _initiatorFailure(
      'wrong secret S: key confirmation does not match',
      15,
      3,
      wrongSecret,
      'confirm_mismatch',
    ),
  );

  final good = replyFor(initiatorFor(17), 4, 18);
  String flip(String b64, int index) {
    final bytes = base64Url.decode(_pad(b64));
    bytes[index] ^= 1;
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  cases
    ..add(
      _initiatorFailure(
        'confirm changed by one bit: reply signature fails',
        17,
        4,
        {...good, 'confirm': flip(good['confirm']! as String, 31)},
        'bad_reply_signature',
      ),
    )
    ..add(
      _initiatorFailure(
        'reply made for another initiator (wrong slot)',
        19,
        5,
        good,
        'bad_reply_signature',
      ),
    )
    ..add(
      _initiatorFailure('path changed from qr to code in transit', 17, 4, {
        ...good,
        'path': 'code',
      }, 'bad_reply_signature'),
    )
    ..add(
      _initiatorFailure(
        'the same reply offered a second time',
        17,
        4,
        good,
        'already_used',
        attempts: 2,
      ),
    );

  // code path: a bundle whose signature is wrong
  final init = initiatorFor(20);
  final bundleJson = init.bundle.toJson();
  cases.add({
    'name': 'code path: bundle signature changed by one bit',
    'input': {
      'side': 'joiner',
      'initiator': _initiatorInput(20, _slotId(6)),
      'joiner': _joinerInput(21),
      'bundle': {...bundleJson, 'sig': flip(bundleJson['sig']! as String, 0)},
    },
    'error': 'bad_bundle_signature',
  });

  // QR texts a reader must refuse
  final validQr = init.qr(_slotId(6)).encode();
  Uint8List payload() {
    final b64 = validQr.substring(PairingQr.prefix.length);
    return Uint8List.fromList(base64Url.decode(_pad(b64)));
  }

  String text(Uint8List b) =>
      PairingQr.prefix + base64Url.encode(b).replaceAll('=', '');
  final badVersion = payload()..[0] = 2;
  final tooLong = Uint8List(130)..setAll(0, payload());
  final tooShort = payload().sublist(0, 128);
  for (final (name, qrText) in [
    ('QR with another prefix', 'MAWADDAH-X:${validQr.substring(9)}'),
    ('QR with an unknown version byte', text(badVersion)),
    ('QR payload one byte too long', text(tooLong)),
    ('QR payload one byte too short', text(tooShort)),
    ('QR payload with padding characters', '$validQr=='),
  ]) {
    cases.add({
      'name': name,
      'input': {'side': 'qr', 'qr': qrText},
      'error': 'format',
    });
  }
  return cases;
}

String _pad(String b64) => b64 + '=' * ((4 - b64.length % 4) % 4);
