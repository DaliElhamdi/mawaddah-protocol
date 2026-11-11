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
  _write('ratchet', _ratchetCases(crypto));
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

// --- ratchet.json --------------------------------------------------------------
//
// Scripted conversations: one in order per direction (turn changes and
// crossing messages), one out of order (skipped message keys in the current
// and in a previous chain, messages opened from stored skipped keys). Every
// output is derived twice: by RatchetSession, and by the reference below
// written straight from PROTOCOL.md section 6 on raw bytes; the generator
// stops if they differ.

/// Random bytes one side's RandomSource hands out, 32 per GENERATE_DH.
class _Draws implements RandomSource {
  _Draws(int seed) : _random = SeededRandom(seed);
  final SeededRandom _random;
  final drawn = <Uint8List>[];

  @override
  Uint8List nextBytes(int length) {
    final b = _random.nextBytes(length);
    drawn.add(Uint8List.fromList(b));
    return b;
  }
}

/// PROTOCOL.md section 6 on plain byte lists, one side.
class _RefSide {
  _RefSide(this.crypto, this.ad);
  final Crypto crypto;
  final Uint8List ad;
  late Uint8List dhsSecret;
  late Uint8List dhsPub;
  Uint8List? dhr;
  late Uint8List rk;
  Uint8List? cks;
  Uint8List? ckr;
  var ns = 0, nr = 0, pn = 0;

  /// MKSKIPPED: "hex(dh_pub):n" -> message key, in the order stored.
  final skipped = <String, Uint8List>{};

  /// Signal 3.5 SkipMessageKeys(until) on the receiving chain; returns the
  /// keys it stored, for the vector output.
  List<Map<String, Object?>> skip(int until) {
    final out = <Map<String, Object?>>[];
    if (ckr == null) return out;
    while (nr < until) {
      final (ck, mk) = kdfCk(ckr!);
      skipped['${_hex(dhr!)}:$nr'] = mk;
      out.add({'dh_pub': _hex(dhr!), 'n': nr, 'message_key': _hex(mk)});
      ckr = ck;
      nr += 1;
    }
    return out;
  }

  Uint8List _s(SecretBytes b) {
    final out = b.extractBytes();
    b.dispose();
    return out;
  }

  SecretBytes _imp(Uint8List b) => crypto.importSecret(Uint8List.fromList(b));

  Uint8List pub(Uint8List secret) =>
      crypto.importX25519KeyPair(Uint8List.fromList(secret)).publicKey.bytes;

  Uint8List dh(Uint8List secret, Uint8List pub) {
    final pair = crypto.importX25519KeyPair(Uint8List.fromList(secret));
    final out = _s(crypto.x25519(pair.secretKey, X25519PublicKey(pub)));
    pair.dispose();
    return out;
  }

  (Uint8List, Uint8List) kdfRk(Uint8List rk, Uint8List dhOut) {
    final out = _s(
      crypto.hkdf(
        salt: _imp(rk),
        ikm: _imp(dhOut),
        info: 'mawaddah/v1/ratchet/rk',
        length: 64,
      ),
    );
    return (out.sublist(0, 32), out.sublist(32));
  }

  (Uint8List, Uint8List) kdfCk(Uint8List ck) => (
    _s(
      crypto.hkdfExpand(
        prk: _imp(ck),
        info: 'mawaddah/v1/ratchet/ck',
        length: 32,
      ),
    ),
    _s(
      crypto.hkdfExpand(
        prk: _imp(ck),
        info: 'mawaddah/v1/ratchet/mk',
        length: 32,
      ),
    ),
  );

  Uint8List aeadKm(Uint8List mk) => _s(
    crypto.hkdfExpand(
      prk: _imp(mk),
      info: 'mawaddah/v1/ratchet/aead',
      length: 56,
    ),
  );

  Uint8List header(int pn, int n) {
    final h = Uint8List(40)..setAll(0, dhsPub);
    ByteData.sublistView(h)
      ..setUint32(32, pn)
      ..setUint32(36, n);
    return h;
  }

  Uint8List aead(
    Uint8List km,
    Uint8List data,
    Uint8List fullAd, {
    required bool seal,
  }) {
    final key = crypto.importAeadKey(km.sublist(0, 32));
    final nonce = AeadNonce(km.sublist(32, 56));
    final out = seal
        ? crypto.encrypt(
            key: key,
            nonce: nonce,
            plaintext: data,
            associatedData: fullAd,
          )
        : crypto.decrypt(
            key: key,
            nonce: nonce,
            ciphertext: data,
            associatedData: fullAd,
          );
    key.dispose();
    return out;
  }
}

Map<String, Object?> _ratchetConversation(
  Crypto crypto, {
  required String name,
  required int seed,
  required List<(String, String, String)> script,
}) {
  final setup = SeededRandom(seed);
  final sk = setup.nextBytes(32);
  final ad = setup.nextBytes(128);
  final bobSecret = setup.nextBytes(32);

  final aliceDraws = _Draws(seed + 1);
  final bobDraws = _Draws(seed + 2);
  final bobPair = crypto.importX25519KeyPair(Uint8List.fromList(bobSecret));
  final bobPub = bobPair.publicKey.bytes;
  final alice = RatchetSession.initAlice(
    crypto: crypto,
    random: aliceDraws,
    clock: FakeClock(),
    rootKey: crypto.importSecret(Uint8List.fromList(sk)),
    associatedData: ad,
    remoteRatchetKey: X25519PublicKey(bobPub),
  );
  final bob = RatchetSession.initBob(
    crypto: crypto,
    random: bobDraws,
    clock: FakeClock(),
    rootKey: crypto.importSecret(Uint8List.fromList(sk)),
    associatedData: ad,
    ratchetKeyPair: bobPair,
  );

  // Reference sides (Signal 3.3 init), drawing the same bytes.
  final refRandom = {
    'alice': SeededRandom(seed + 1),
    'bob': SeededRandom(seed + 2),
  };
  final ra = _RefSide(crypto, ad)
    ..dhsSecret = refRandom['alice']!.nextBytes(32);
  ra
    ..dhsPub = ra.pub(ra.dhsSecret)
    ..dhr = bobPub;
  final (rk0, cks0) = ra.kdfRk(sk, ra.dh(ra.dhsSecret, bobPub));
  ra
    ..rk = rk0
    ..cks = cks0;
  final rb = _RefSide(crypto, ad)
    ..dhsSecret = bobSecret
    ..rk = sk;
  rb.dhsPub = rb.pub(bobSecret);
  final ref = {'alice': ra, 'bob': rb};
  final real = {'alice': alice, 'bob': bob};

  final sent = <String, ({Uint8List prefix, Uint8List header, Uint8List ct})>{};
  final counters = {'alice': 0, 'bob': 0};
  final steps = <Map<String, Object?>>[];
  String h(List<int> b) => _hex(b);
  void same(List<int> a, List<int> b, String what) {
    if (_hex(a) != _hex(b)) {
      throw StateError('ratchet reference differs: $what');
    }
  }

  for (final (op, side, id) in script) {
    final r = ref[side]!;
    if (op == 'send') {
      final counter = counters[side]! + 1;
      counters[side] = counter;
      final prefix = Uint8List(50)
        ..[0] = 1
        ..[1] = 1;
      ByteData.sublistView(prefix)
        ..setUint64(34, counter)
        ..setUint64(42, 1000 + steps.length);
      final plaintext = Uint8List.fromList(utf8.encode('message $id'));
      // Reference RatchetEncrypt (Signal 3.4).
      final (ck, mk) = r.kdfCk(r.cks!);
      final header = r.header(r.pn, r.ns);
      final km = r.aeadKm(mk);
      final fullAd = _bytes([ad, prefix, header]);
      final ct = r.aead(km, plaintext, fullAd, seal: true);
      r
        ..cks = ck
        ..ns += 1;

      final m = real[side]!.encrypt(plaintext, envelopePrefix: prefix);
      same(m.header.encode(), header, '$id header');
      same(m.ciphertext, ct, '$id ciphertext');
      sent[id] = (prefix: prefix, header: header, ct: ct);
      steps.add({
        'op': 'send',
        'side': side,
        'message': id,
        'plaintext': h(plaintext),
        'envelope_prefix': h(prefix),
        'header': h(header),
        'chain_key': h(ck),
        'message_key': h(mk),
        'aead_key': h(km.sublist(0, 32)),
        'aead_nonce': h(km.sublist(32)),
        'ciphertext': h(ct),
      });
    } else {
      final s = sent[id]!;
      final hdrPub = s.header.sublist(0, 32);
      final hdrPn = ByteData.sublistView(s.header).getUint32(32);
      final hdrN = ByteData.sublistView(s.header).getUint32(36);
      final step = <String, Object?>{
        'op': 'receive',
        'side': side,
        'message': id,
      };
      final hadSkipped = r.skipped.isNotEmpty;
      final Uint8List mk;
      final Uint8List? ck;
      // Reference RatchetDecrypt (Signal 3.4/3.5).
      if (r.skipped.remove('${_hex(hdrPub)}:$hdrN') case final stored?) {
        // TrySkippedMessageKeys.
        mk = stored;
        ck = null;
        step['from_skipped_key'] = true;
      } else {
        final created = <Map<String, Object?>>[];
        if (r.dhr == null || _hex(hdrPub) != _hex(r.dhr!)) {
          created.addAll(r.skip(hdrPn));
          r
            ..pn = r.ns
            ..ns = 0
            ..nr = 0
            ..dhr = hdrPub;
          final (rk1, ckr1) = r.kdfRk(r.rk, r.dh(r.dhsSecret, hdrPub));
          r
            ..ckr = ckr1
            ..dhsSecret = refRandom[side]!.nextBytes(32);
          r.dhsPub = r.pub(r.dhsSecret);
          final (rk2, cks2) = r.kdfRk(rk1, r.dh(r.dhsSecret, hdrPub));
          r
            ..rk = rk2
            ..cks = cks2;
          step['dh_ratchet'] = {
            'new_ratchet_secret': h(r.dhsSecret),
            'new_ratchet_pub': h(r.dhsPub),
            'root_key': h(r.rk),
            'receiving_chain_key': h(r.ckr!),
            'sending_chain_key': h(r.cks!),
          };
        }
        created.addAll(r.skip(hdrN));
        if (created.length > 1000) throw StateError('MAX_SKIP at $id');
        if (created.isNotEmpty) step['skipped_keys'] = created;
        final (ck1, mk1) = r.kdfCk(r.ckr!);
        (ck, mk) = (ck1, mk1);
        r
          ..ckr = ck1
          ..nr += 1;
      }
      final km = r.aeadKm(mk);
      final pt = r.aead(
        km,
        s.ct,
        _bytes([ad, s.prefix, s.header]),
        seal: false,
      );

      final got = real[side]!.decrypt(
        RatchetHeader.decode(s.header),
        s.ct,
        envelopePrefix: s.prefix,
      );
      same(got, pt, '$id plaintext');
      if (real[side]!.skippedKeyCount != r.skipped.length) {
        throw StateError('ratchet reference differs: $id skipped keys');
      }
      if (ck != null) step['chain_key'] = h(ck);
      step
        ..['message_key'] = h(mk)
        ..['plaintext'] = h(pt);
      if (hadSkipped || r.skipped.isNotEmpty) {
        step['skipped_key_count'] = r.skipped.length;
      }
      steps.add(step);
    }
  }
  alice.dispose();
  bob.dispose();

  return {
    'name': name,
    'input': {
      'root_key': h(sk),
      'associated_data': h(ad),
      'bob_ratchet_secret': h(bobSecret),
      'alice_random': [for (final d in aliceDraws.drawn) h(d)],
      'bob_random': [for (final d in bobDraws.drawn) h(d)],
      'script': [
        for (final (op, side, id) in script)
          {'op': op, 'side': side, 'message': id},
      ],
    },
    'output': {
      'bob_ratchet_pub': h(bobPub),
      'alice_initial_ratchet_pub': h(ra.pub(aliceDraws.drawn.first)),
      'steps': steps,
    },
  };
}

List<Map<String, Object?>> _ratchetCases(Crypto crypto) => [
  // Script: (op, side, message id). Messages are delivered in order per
  // direction; a2/b2 cross (both are sent before either is read).
  _ratchetConversation(
    crypto,
    name: 'conversation in order with turn changes and crossing messages',
    seed: 100,
    script: const [
      ('send', 'alice', 'a0'),
      ('send', 'alice', 'a1'),
      ('recv', 'bob', 'a0'),
      ('recv', 'bob', 'a1'),
      ('send', 'bob', 'b0'),
      ('send', 'bob', 'b1'),
      ('recv', 'alice', 'b0'),
      ('recv', 'alice', 'b1'),
      ('send', 'alice', 'a2'),
      ('send', 'bob', 'b2'),
      ('recv', 'bob', 'a2'),
      ('recv', 'alice', 'b2'),
      ('send', 'bob', 'b3'),
      ('recv', 'alice', 'b3'),
      ('send', 'alice', 'a3'),
      ('recv', 'bob', 'a3'),
    ],
  ),
  // Out of order: Bob's first message is n = 2 (a0, a1 skipped before his
  // first DH step); b2 is skipped inside the current chain; b6 is skipped
  // from the previous chain through pn at a turn; a1, b0, b2, b6 open later
  // from stored keys; b3 and a3 cross.
  _ratchetConversation(
    crypto,
    name: 'conversation out of order with skipped message keys',
    seed: 200,
    script: const [
      ('send', 'alice', 'a0'),
      ('send', 'alice', 'a1'),
      ('send', 'alice', 'a2'),
      ('recv', 'bob', 'a2'),
      ('recv', 'bob', 'a0'),
      ('send', 'bob', 'b0'),
      ('send', 'bob', 'b1'),
      ('send', 'bob', 'b2'),
      ('recv', 'alice', 'b1'),
      ('send', 'alice', 'a3'),
      ('send', 'bob', 'b3'),
      ('recv', 'bob', 'a3'),
      ('recv', 'alice', 'b3'),
      ('send', 'bob', 'b4'),
      ('recv', 'alice', 'b4'),
      ('recv', 'alice', 'b2'),
      ('recv', 'alice', 'b0'),
      ('recv', 'bob', 'a1'),
      ('send', 'alice', 'a4'),
      ('recv', 'bob', 'a4'),
      ('send', 'bob', 'b5'),
      ('send', 'bob', 'b6'),
      ('recv', 'alice', 'b5'),
      ('send', 'alice', 'a5'),
      ('recv', 'bob', 'a5'),
      ('send', 'bob', 'b7'),
      ('recv', 'alice', 'b7'),
      ('recv', 'alice', 'b6'),
    ],
  ),
];
