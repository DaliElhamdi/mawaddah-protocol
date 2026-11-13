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
  _write('envelope', _envelopeCases(crypto));
  _write('hlc', _hlcCases());
  _write('uuid7', _uuid7Cases());
  _write('event', await _eventCases());
  _write('relay_signing', _relaySigningCases(crypto));
  _write('attachment', await _attachmentCases(crypto));
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

// --- envelope.json -------------------------------------------------------------
//
// The joiner (Alice, sends first) seals her first message to the initiator
// (Bob). Each success case has its own identities and ratchet keys, so no
// message key is used twice across the file. Every output is derived twice:
// by Envelope.seal, and by the reference below written straight from
// PROTOCOL.md sections 6 and 7 on raw bytes; the generator stops if they
// differ. Failing cases change one thing in the first case's envelope (or
// in Bob's state) and name the error Envelope.open must give.

final _envelopeLabel = ascii.encode('mawaddah/v1/envelope');

/// Inputs of one sealing: both identities and the ratchet start.
Map<String, Object?> _envelopeSetup(int seed) {
  final setup = SeededRandom(seed);
  return {
    'alice': _identityInput(seed + 1),
    'bob': _identityInput(seed + 2),
    'root_key': _hex(setup.nextBytes(32)),
    'associated_data': _hex(setup.nextBytes(128)),
    'bob_ratchet_secret': _hex(setup.nextBytes(32)),
    'alice_random': _hex(SeededRandom(seed + 3).nextBytes(32)),
    'bob_random': _hex(SeededRandom(seed + 4).nextBytes(32)),
  };
}

Uint8List _unhex(Object? s) {
  final t = s! as String;
  return Uint8List.fromList([
    for (var i = 0; i < t.length; i += 2)
      int.parse(t.substring(i, i + 2), radix: 16),
  ]);
}

DeviceIdentity _identityFrom(Crypto crypto, Map<String, Object?> json) =>
    DeviceIdentity.fromStorageBytes(
      crypto,
      Uint8List.fromList([
        1,
        ..._unhex(json['sig_seed']),
        ..._unhex(json['dh_secret']),
      ]),
    );

/// Both sides of [setup], with Bob's receiving state.
({
  DeviceIdentity alice,
  DeviceIdentity bob,
  RatchetSession aliceSession,
  RatchetSession bobSession,
})
_envelopeSides(Crypto crypto, Map<String, Object?> setup, Clock clock) {
  final bobPair = crypto.importX25519KeyPair(
    _unhex(setup['bob_ratchet_secret']),
  );
  final bobPub = bobPair.publicKey;
  return (
    alice: _identityFrom(crypto, setup['alice']! as Map<String, Object?>),
    bob: _identityFrom(crypto, setup['bob']! as Map<String, Object?>),
    aliceSession: RatchetSession.initAlice(
      crypto: crypto,
      random: _FixedRandom(_unhex(setup['alice_random'])),
      clock: clock,
      rootKey: crypto.importSecret(_unhex(setup['root_key'])),
      associatedData: _unhex(setup['associated_data']),
      remoteRatchetKey: bobPub,
    ),
    bobSession: RatchetSession.initBob(
      crypto: crypto,
      random: _FixedRandom(_unhex(setup['bob_random'])),
      clock: clock,
      rootKey: crypto.importSecret(_unhex(setup['root_key'])),
      associatedData: _unhex(setup['associated_data']),
      ratchetKeyPair: bobPair,
    ),
  );
}

/// A RandomSource that hands out the given bytes once.
class _FixedRandom implements RandomSource {
  _FixedRandom(this._bytes);
  final Uint8List _bytes;
  var _at = 0;

  @override
  Uint8List nextBytes(int length) {
    if (_at + length > _bytes.length) throw StateError('random exhausted');
    return Uint8List.fromList(_bytes.sublist(_at, _at += length));
  }
}

Map<String, Object?> _envelopeSuccess(
  Crypto crypto, {
  required String name,
  required int seed,
  required int counter,
  required Hlc hlc,
  required int receiverNowMs,
  required String plaintext,
}) {
  final setup = _envelopeSetup(seed);
  final clock = FakeClock(
    DateTime.fromMillisecondsSinceEpoch(receiverNowMs, isUtc: true),
  );
  final sides = _envelopeSides(crypto, setup, clock);
  final text = Uint8List.fromList(utf8.encode(plaintext));
  final bytes = Envelope.seal(
    crypto: crypto,
    sender: sides.alice,
    recipient: sides.bob.deviceId,
    counter: counter,
    hlc: hlc,
    session: sides.aliceSession,
    plaintext: text,
  );

  // Reference: PROTOCOL.md sections 6 and 7 on raw bytes.
  final ref = _RefSide(crypto, _unhex(setup['associated_data']));
  final aliceRatchet = _unhex(setup['alice_random']);
  final bobPub = ref.pub(_unhex(setup['bob_ratchet_secret']));
  final (_, cks) = ref.kdfRk(
    _unhex(setup['root_key']),
    ref.dh(aliceRatchet, bobPub),
  );
  final (_, mk) = ref.kdfCk(cks);
  final km = ref.aeadKm(mk);
  final padLen = (text.length ~/ 256 + 1) * 256;
  final padded = Uint8List(padLen)
    ..setAll(0, text)
    ..[text.length] = 0x80;
  final prefix = Uint8List(50)
    ..[0] = 1
    ..[1] = 1
    ..setAll(2, sides.alice.deviceId.bytes)
    ..setAll(18, sides.bob.deviceId.bytes)
    ..setAll(42, hlc.toBytes());
  ByteData.sublistView(prefix)
    ..setUint32(34, counter ~/ 0x100000000)
    ..setUint32(38, counter % 0x100000000);
  ref
    ..dhsSecret = aliceRatchet
    ..dhsPub = ref.pub(aliceRatchet);
  final header = ref.header(0, 0);
  final ciphertext = ref.aead(
    km,
    padded,
    Uint8List.fromList([...ref.ad, ...prefix, ...header]),
    seal: true,
  );
  final signed = Uint8List.fromList([...prefix, ...header, ...ciphertext]);
  final signature = crypto.sign(
    sides.alice.signingSecretKey,
    Uint8List.fromList([..._envelopeLabel, ...signed]),
  );
  final expected = [...signed, ...signature.bytes];
  if (_hex(expected) != _hex(bytes)) {
    throw StateError('$name: envelope differs from the reference');
  }

  // Bob opens it.
  final opened = Envelope.open(
    crypto: crypto,
    bytes: bytes,
    self: sides.bob.deviceId,
    partner: sides.alice.publicIdentity,
    session: sides.bobSession,
    window: ReplayWindow(),
    clock: HlcClock(clock),
  );
  if (_hex(opened.plaintext) != _hex(text)) {
    throw StateError('$name: opened plaintext differs');
  }

  return {
    'name': name,
    'input': {
      ...setup,
      'counter': counter,
      'hlc': hlc.toHex(),
      'plaintext': plaintext,
      'receiver_now_ms': receiverNowMs,
    },
    'output': {
      'alice_device_id': _hex(sides.alice.deviceId.bytes),
      'bob_device_id': _hex(sides.bob.deviceId.bytes),
      'alice_ratchet_pub': _hex(ref.dhsPub),
      'bob_ratchet_pub': _hex(bobPub),
      'padded_plaintext': _hex(padded),
      'message_key': _hex(mk),
      'aead_key': _hex(km.sublist(0, 32)),
      'aead_nonce': _hex(km.sublist(32)),
      'prefix': _hex(prefix),
      'header': _hex(header),
      'ciphertext': _hex(ciphertext),
      'signature': _hex(signature.bytes),
      'envelope': _hex(bytes),
    },
  };
}

String _envelopeFailureName(EnvelopeFailure f) => switch (f) {
  EnvelopeFailure.malformed => 'malformed',
  EnvelopeFailure.unknownVersion => 'unknown_version',
  EnvelopeFailure.wrongRecipient => 'wrong_recipient',
  EnvelopeFailure.unknownSender => 'unknown_sender',
  EnvelopeFailure.badSignature => 'bad_signature',
  EnvelopeFailure.replayed => 'replayed',
  EnvelopeFailure.fromTheFuture => 'from_the_future',
  EnvelopeFailure.tooOld => 'too_old',
  EnvelopeFailure.undecryptable => 'undecryptable',
};

/// A failing case: Bob, in the state of [base] changed by the arguments,
/// opens [envelope] and must fail with [error] (checked here).
Map<String, Object?> _envelopeFailure(
  Crypto crypto, {
  required String name,
  required Map<String, Object?> base,
  required Uint8List envelope,
  required String error,
  int? receiverNowMs,
  List<int> windowAccepted = const [],
}) {
  final input = base['input']! as Map<String, Object?>;
  final now = receiverNowMs ?? input['receiver_now_ms']! as int;
  final clock = FakeClock(
    DateTime.fromMillisecondsSinceEpoch(now, isUtc: true),
  );
  final sides = _envelopeSides(crypto, input, clock);
  final window = ReplayWindow();
  for (final c in windowAccepted) {
    window.mark(c);
  }
  try {
    Envelope.open(
      crypto: crypto,
      bytes: envelope,
      self: sides.bob.deviceId,
      partner: sides.alice.publicIdentity,
      session: sides.bobSession,
      window: window,
      clock: HlcClock(clock),
    );
    throw StateError('$name: opened');
  } on EnvelopeException catch (e) {
    if (_envelopeFailureName(e.failure) != error) {
      throw StateError('$name: got ${e.failure}, want $error');
    }
  }
  return {
    'name': name,
    'input': {
      for (final MapEntry(:key, :value) in input.entries)
        if (key != 'plaintext' && key != 'counter' && key != 'hlc') key: value,
      'receiver_now_ms': now,
      'window_accepted': windowAccepted,
      'envelope': _hex(envelope),
    },
    'error': error,
  };
}

List<Map<String, Object?>> _envelopeCases(Crypto crypto) {
  const now = 1762862400000; // 2025-11-11T12:00:00Z
  final first = _envelopeSuccess(
    crypto,
    name: 'first message, short plaintext',
    seed: 300,
    counter: 1,
    hlc: Hlc(now - 5000, 0),
    receiverNowMs: now,
    plaintext:
        '{"events":[{"event_id":"019a72d3-6a38-7cc1-9a2e-3f6d4b8c1e07",'
        '"entity_type":"message","entity_id":'
        '"019a72d3-6a38-7cc1-9a2e-3f6d4b8c1e08","op":"create",'
        '"payload":{"text":"Salam"},"hlc":"019a72d36a380000",'
        '"author_device":"AAAAAAAAAAAAAAAAAAAAAA","protocol_version":1,'
        '"schema_version":1}]}',
  );
  final sizes = <Map<String, Object?>>[
    _envelopeSuccess(
      crypto,
      name: '255-byte plaintext (one block), counter above 2^32',
      seed: 310,
      counter: 0x100000001,
      hlc: Hlc(now, 0xffff),
      receiverNowMs: now,
      plaintext: '{"events":[${'"x",' * 48}"${'y' * 48}"]}',
    ),
    _envelopeSuccess(
      crypto,
      name: '256-byte plaintext (two blocks)',
      seed: 320,
      counter: 7,
      hlc: Hlc(now - 1000, 3),
      receiverNowMs: now,
      plaintext: '{"events":[${'"x",' * 48}"${'y' * 49}"]}',
    ),
  ];
  for (final (c, length) in [(sizes[0], 255), (sizes[1], 256)]) {
    final text = (c['input']! as Map<String, Object?>)['plaintext']! as String;
    if (text.length != length) throw StateError('${c['name']}: $length');
  }
  final out = [first, ...sizes];
  final good = _unhex((first['output']! as Map<String, Object?>)['envelope']);
  final input = first['input']! as Map<String, Object?>;
  final hlcMs = Hlc.parse(input['hlc']! as String).physicalMs;
  Uint8List flipped(int i) => Uint8List.fromList(good)..[i] ^= 1;

  // Re-signed by Alice after changing a ciphertext byte: the signature
  // checks, the ratchet cannot open it.
  final alice = _identityFrom(crypto, input['alice']! as Map<String, Object?>);
  final body = flipped(100).sublist(0, good.length - 64);
  final resigned = Uint8List.fromList([
    ...body,
    ...crypto
        .sign(
          alice.signingSecretKey,
          Uint8List.fromList([..._envelopeLabel, ...body]),
        )
        .bytes,
  ]);
  // Sealed by Alice to a third device.
  final setup = Map<String, Object?>.from(input);
  final sides = _envelopeSides(
    crypto,
    setup,
    FakeClock(DateTime.fromMillisecondsSinceEpoch(now, isUtc: true)),
  );
  final elsewhere = Envelope.seal(
    crypto: crypto,
    sender: sides.alice,
    recipient: _identity(crypto, 399).deviceId,
    counter: 1,
    hlc: Hlc(now - 5000, 0),
    session: sides.aliceSession,
    plaintext: Uint8List.fromList(utf8.encode('{"events":[]}')),
  );

  out.addAll([
    _envelopeFailure(
      crypto,
      name: 'tampered ciphertext byte',
      base: first,
      envelope: flipped(100),
      error: 'bad_signature',
    ),
    _envelopeFailure(
      crypto,
      name: 'tampered HLC byte',
      base: first,
      envelope: flipped(49),
      error: 'bad_signature',
    ),
    _envelopeFailure(
      crypto,
      name: 'tampered signature byte',
      base: first,
      envelope: flipped(good.length - 1),
      error: 'bad_signature',
    ),
    _envelopeFailure(
      crypto,
      name: 'replayed counter',
      base: first,
      envelope: good,
      windowAccepted: [1],
      error: 'replayed',
    ),
    _envelopeFailure(
      crypto,
      name: 'counter behind the window (highest accepted 1025)',
      base: first,
      envelope: good,
      windowAccepted: [1025],
      error: 'replayed',
    ),
    _envelopeFailure(
      crypto,
      name: 'HLC more than 1 hour ahead of the receiver',
      base: first,
      envelope: good,
      receiverNowMs: hlcMs - 3600000 - 1,
      error: 'from_the_future',
    ),
    _envelopeFailure(
      crypto,
      name: 'HLC more than 31 days behind the receiver',
      base: first,
      envelope: good,
      receiverNowMs: hlcMs + 31 * 86400000 + 1,
      error: 'too_old',
    ),
    _envelopeFailure(
      crypto,
      name: 'wrong recipient',
      base: first,
      envelope: elsewhere,
      error: 'wrong_recipient',
    ),
    _envelopeFailure(
      crypto,
      name: 'unknown sender',
      base: first,
      envelope: flipped(2),
      error: 'unknown_sender',
    ),
    _envelopeFailure(
      crypto,
      name: 'unknown version',
      base: first,
      envelope: Uint8List.fromList(good)..[0] = 2,
      error: 'unknown_version',
    ),
    _envelopeFailure(
      crypto,
      name: 'one byte short',
      base: first,
      envelope: good.sublist(0, good.length - 1),
      error: 'malformed',
    ),
    _envelopeFailure(
      crypto,
      name: 'counter 0',
      base: first,
      envelope: flipped(41),
      error: 'malformed',
    ),
    _envelopeFailure(
      crypto,
      name: 'signed by the sender but not decryptable',
      base: first,
      envelope: resigned,
      error: 'undecryptable',
    ),
  ]);
  return out;
}

// --- hlc.json --------------------------------------------------------------------

List<Map<String, Object?>> _hlcCases() {
  const ms = 1762862400000;
  Map<String, Object?> run(
    String name,
    Hlc start,
    List<(String, int, Hlc?)> ops,
  ) {
    var nowMs = 0;
    final clock = _MsClock(() => nowMs);
    final hlc = HlcClock(clock, last: start);
    final values = <String>[];
    for (final (op, now, remote) in ops) {
      nowMs = now;
      values.add((op == 'send' ? hlc.send() : hlc.receive(remote!)).toHex());
    }
    return {
      'name': name,
      'input': {
        'start': start.toHex(),
        'ops': [
          for (final (op, now, remote) in ops)
            {'op': op, 'now_ms': now, 'remote': ?remote?.toHex()},
        ],
      },
      'output': {'values': values},
    };
  }

  return [
    run('send on a still, a moving and a backward clock', Hlc.zero, [
      ('send', ms, null),
      ('send', ms, null),
      ('send', ms, null),
      ('send', ms + 5, null),
      ('send', ms - 3600000, null),
      ('send', ms - 3600000, null),
      ('send', ms + 6, null),
    ]),
    run('receive: the four cases', Hlc(ms + 100, 4), [
      ('receive', ms, Hlc(ms + 100, 9)), // l' == l == l_m
      ('receive', ms, Hlc(ms + 50, 99)), // l' == l
      ('receive', ms, Hlc(ms + 200, 7)), // l' == l_m
      ('receive', ms + 300, Hlc(ms + 250, 7)), // now is largest
      ('send', ms + 300, null),
    ]),
    run('a full counter moves the physical part on by 1 ms', Hlc(ms, 0xfffe), [
      ('send', ms, null),
      ('send', ms, null),
      ('send', ms, null),
      ('receive', ms, Hlc(ms + 60000, 0xffff)),
      ('receive', ms, Hlc(ms + 60001, 0xffff)),
    ]),
  ];
}

class _MsClock implements Clock {
  _MsClock(this._ms);
  final int Function() _ms;

  @override
  DateTime now() => DateTime.fromMillisecondsSinceEpoch(_ms(), isUtc: true);
}

// --- uuid7.json ------------------------------------------------------------------

List<Map<String, Object?>> _uuid7Cases() => [
  for (final (name, ms, random) in [
    ('all-zero random bytes', 1762862400000, Uint8List(10)),
    (
      'all-one random bytes',
      1762862400000,
      Uint8List(10)..fillRange(0, 10, 0xff),
    ),
    ('SeededRandom(500)', 1762862400123, SeededRandom(500).nextBytes(10)),
    ('time 0', 0, SeededRandom(501).nextBytes(10)),
    ('largest 48-bit time', 0xffffffffffff, SeededRandom(502).nextBytes(10)),
  ])
    {
      'name': name,
      'input': {'now_ms': ms, 'random': _hex(random)},
      'output': {
        'uuid': Uuid7.generate(
          _MsClock(() => ms),
          _FixedRandom(Uint8List.fromList(random)),
        ),
      },
    },
];

// --- event.json -------------------------------------------------------------------

String _reasonName(UnappliedReason r) => switch (r) {
  UnappliedReason.newerProtocol => 'newer_protocol',
  UnappliedReason.unknownEntityType => 'unknown_entity_type',
  UnappliedReason.unknownOp => 'unknown_op',
  UnappliedReason.newerSchema => 'newer_schema',
  UnappliedReason.invalidPayload => 'invalid_payload',
  UnappliedReason.rejected => 'rejected',
};

String _eventFailureName(EventFailure f) => switch (f) {
  EventFailure.malformed => 'malformed',
  EventFailure.wrongAuthor => 'wrong_author',
};

/// Makes events for one device: clock from [startMs], UUIDs from
/// SeededRandom([seed]).
class _EventMaker {
  _EventMaker(int b, int seed, int startMs)
    : device = DeviceId.fromBytes(Uint8List(16)..fillRange(0, 16, b)),
      _ms = startMs {
    factory = EventFactory(
      hlc: HlcClock(_MsClock(() => _ms)),
      random: SeededRandom(seed),
      author: device,
    );
  }

  final DeviceId device;
  int _ms;
  late final EventFactory factory;

  void advance(int ms) => _ms += ms;

  Event make(String type, String id, String op, [JsonMap payload = const {}]) =>
      factory.make(entityType: type, entityId: id, op: op, payload: payload);

  String newId() => factory.newEntityId();
}

Map<String, Object?> _stateJson(EntityState s) => {
  'entity_type': s.entityType,
  'entity_id': s.entityId,
  'fields': {
    for (final k in s.fields.keys.toList()..sort())
      k: {'value': s.fields[k]!.value, 'event_id': s.fields[k]!.stamp.eventId},
  },
  'created': s.created?.eventId,
  'deleted': s.deleted?.eventId,
};

Future<List<Map<String, Object?>>> _eventCases() async {
  const t0 = 1762862400000;
  final a = _EventMaker(0x0a, 600, t0);
  final b = _EventMaker(0x0b, 601, t0 + 250);
  final cases = <Map<String, Object?>>[];

  // Encoding: the plaintext bytes for a list of events.
  final profile = a.newId();
  final hello = a.make('device', a.newId(), EventOp.update, {
    'protocol_version': 1,
    'min_supported_protocol': 1,
    'envelope_versions': [1],
  });
  final named = a.make('profile', profile, EventOp.update, {
    'first_name': 'أمينة',
    'gender': 'female',
    'mode': 'engaged',
  });
  final msg = a.newId();
  final text = a.make('message', msg, EventOp.create, {
    'text': 'salam "quoted" \\ line\nbreak \u0001 é 😊',
  });
  for (final (name, events) in [
    ('the hello', [hello]),
    ('a profile with an Arabic name', [named]),
    (
      'three events; escapes, control and non-ASCII characters',
      [hello, named, text],
    ),
  ]) {
    cases.add({
      'name': 'encode: $name',
      'input': {
        'events': [for (final e in events) e.toJson()],
      },
      'output': {'plaintext': _hex(EventBatch.encode(events))},
    });
  }

  // Decoding: refused plaintexts (nothing is applied).
  final good = named.toJson();
  List<int> raw(Object json) => utf8.encode(jsonEncode(json));
  for (final (name, bytes, sender) in [
    ('not UTF-8', [0xff, 0xfe], a.device),
    ('not JSON', utf8.encode('{"events": ['), a.device),
    ('empty event list', raw({'events': <Object?>[]}), a.device),
    (
      'extra top-level key',
      raw({
        'events': [good],
        'v': 1,
      }),
      a.device,
    ),
    (
      'extra event field',
      raw({
        'events': [
          {...good, 'extra': true},
        ],
      }),
      a.device,
    ),
    (
      'protocol_version as a float',
      raw({
        'events': [
          {...good, 'protocol_version': 1.0},
        ],
      }),
      a.device,
    ),
    (
      'delete with a payload',
      raw({
        'events': [
          {...good, 'op': 'delete'},
        ],
      }),
      a.device,
    ),
    (
      'one good event, one with a bad hlc',
      raw({
        'events': [
          good,
          {...good, 'hlc': '0123'},
        ],
      }),
      a.device,
    ),
    (
      'newer event without event_id',
      raw({
        'events': [
          {'protocol_version': 2},
        ],
      }),
      a.device,
    ),
    (
      'author is not the sender',
      raw({
        'events': [good],
      }),
      b.device,
    ),
  ]) {
    Object? error;
    try {
      EventBatch.decode(Uint8List.fromList(bytes), sender: sender);
    } on EventException catch (e) {
      error = _eventFailureName(e.failure);
    }
    if (error == null) throw StateError('decode case "$name" was accepted');
    cases.add({
      'name': 'decode: $name',
      'input': {'plaintext': _hex(bytes), 'sender': _hex(sender.bytes)},
      'error': error,
    });
  }

  // Applying: a set of events in batches; any order of the batches, any
  // repeats, gives the output state.
  Future<Map<String, Object?>> applyCase(
    String name,
    DeviceId local,
    List<(DeviceId, List<Object?>)> batches,
  ) async {
    final store = InMemoryEventStore();
    final applier = Applier(store, localDevice: local);
    for (final (sender, events) in batches) {
      await applier.applyReceived(
        Uint8List.fromList(raw({'events': events})),
        sender: sender,
      );
    }
    final entities = [...store.entities]
      ..sort(
        (x, y) => '${x.entityType}/${x.entityId}'.compareTo(
          '${y.entityType}/${y.entityId}',
        ),
      );
    final log = store.events.keys.toList()..sort();
    return {
      'name': 'apply: $name',
      'input': {
        'local_device': _hex(local.bytes),
        'batches': [
          for (final (sender, events) in batches)
            {'sender': _hex(sender.bytes), 'events': events},
        ],
      },
      'output': {
        'entities': [for (final s in entities) _stateJson(s)],
        'log': [
          for (final id in log)
            {
              'event_id': id,
              'payload_purged':
                  store.events[id]!.payload.isEmpty &&
                  store.events[id]!.op != EventOp.delete,
            },
        ],
        'unapplied': [
          for (final u in await store.unapplied())
            {'event_id': u.eventId, 'reason': _reasonName(u.reason)},
        ],
      },
    };
  }

  final c = _EventMaker(0x0c, 602, t0);

  // Field-level last-writer-wins with clock skew and an HLC tie.
  final p = a.newId();
  a.advance(1000);
  final a1 = a.make('profile', p, EventOp.update, {
    'first_name': 'Amina',
    'gender': 'female',
    'mode': 'engaged',
  });
  b.advance(1000); // Bob's clock is 250 ms ahead: his edit wins "mode".
  final b1 = b.make('profile', p, EventOp.update, {'mode': 'contracted'});
  a.advance(100);
  final a2 = a.make('profile', p, EventOp.update, {'first_name': 'Aminah'});
  // Bob edits the same field with exactly Alice's hlc: the higher author
  // bytes (Bob, 0x0b...) win.
  final bTie = Event.fromJson({
    ...a2.toJson(),
    'event_id': b.newId(),
    'author_device': b.device.toBase64Url(),
    'payload': {'first_name': 'Amna'},
  });
  cases.add(
    await applyCase('last-writer-wins per field, HLC tie', c.device, [
      (b.device, [b1.toJson(), bTie.toJson()]),
      (a.device, [a2.toJson(), a1.toJson()]),
    ]),
  );

  // Append-only and tombstones: delete before create, a second create, a
  // repeat.
  final m1 = a.newId(), m2 = b.newId();
  a.advance(10);
  final c1 = a.make('message', m1, EventOp.create, {'text': 'first'});
  b.advance(10);
  final c2 = b.make('message', m2, EventOp.create, {'text': 'kept'});
  final c2b = b.make('message', m2, EventOp.create, {'text': 'kept, again'});
  final d1 = b.make('message', m1, EventOp.delete);
  cases.add(
    await applyCase('append-only, tombstone before create', c.device, [
      (b.device, [d1.toJson(), c2.toJson()]),
      (a.device, [c1.toJson()]),
      (b.device, [c2b.toJson(), c2.toJson()]),
    ]),
  );

  // Unapplied: newer protocol, unknown type, op, schema, invalid payload.
  b.advance(10);
  final v2 = {
    'event_id': b.newId(),
    'protocol_version': 2,
    'hlc': b.factory.hlc.send().toHex(),
    'shape': 'unknown',
  };
  final unknownType = b.make('note', b.newId(), EventOp.update, {'t': 1});
  final unknownOp = b.make('message', m2, EventOp.update, {'text': 'x'});
  final newerSchema = Event.fromJson({
    ...b.make('profile', p, EventOp.update, {'mode': 'married_cohab'}).toJson(),
    'schema_version': 2,
  });
  final invalid = b.make('profile', p, EventOp.update, {'gender': 'x'});
  cases.add(
    await applyCase('unapplied events are kept, in HLC order', a.device, [
      (
        b.device,
        [
          invalid.toJson(),
          newerSchema.toJson(),
          unknownOp.toJson(),
          unknownType.toJson(),
          v2,
        ],
      ),
    ]),
  );
  return cases;
}

// --- relay_signing.json ----------------------------------------------------------

List<Map<String, Object?>> _relaySigningCases(Crypto crypto) {
  final noise = SeededRandom(1900);
  Map<String, Object?> one(
    String name, {
    required int seed,
    required String method,
    required String Function(String inbox, String key) path,
    required Uint8List Function(String inbox, String key) body,
    required int timestamp,
  }) {
    final identity = _identity(crypto, seed);
    final key = base64Url
        .encode(identity.publicIdentity.signingKey.bytes)
        .replaceAll('=', '');
    final inbox = identity.deviceId.toBase64Url();
    final nonce = noise.nextBytes(RelayRequestSigner.nonceLength);
    final p = path(inbox, key);
    final b = body(inbox, key);
    final headers = RelayRequestSigner(
      crypto: crypto,
      identity: identity,
      clock: _MsClock(() => timestamp * 1000 + 999),
      random: _FixedRandom(nonce),
    ).sign(method: method, pathAndQuery: p, body: b);
    final input = RelayRequestSigner.signingInput(
      method: method,
      pathAndQuery: p,
      body: b,
      timestamp: timestamp,
      nonce: headers[RelayRequestSigner.nonceHeader]!,
    );
    final signature = base64Url.decode(
      '${headers[RelayRequestSigner.signatureHeader]!}==',
    );
    identity.dispose();
    return {
      'name': name,
      'input': {
        'sig_seed': _hex(_secrets(seed).sigSeed),
        'method': method,
        'path': p,
        'body': _hex(b),
        'timestamp': timestamp,
        'nonce': _hex(nonce),
      },
      'output': {
        'inbox_id': inbox,
        'body_sha256': ascii.decode(input).split('\n')[3],
        'signing_input': ascii.decode(input),
        'signature': _hex(signature),
        'headers': headers,
      },
    };
  }

  const t = 1762862400;
  return [
    one(
      'POST /v1/inbox: registration, signed with the key it registers',
      seed: 1,
      method: 'POST',
      path: (_, _) => '/v1/inbox',
      body: (_, key) => Uint8List.fromList(
        utf8.encode(
          jsonEncode({
            'signing_key': key,
            'push_token': 'example-fcm-token',
            'platform': 'android',
          }),
        ),
      ),
      timestamp: t,
    ),
    one(
      'GET with a query and an empty body (hash of zero bytes)',
      seed: 1,
      method: 'GET',
      path: (inbox, _) => '/v1/inbox/$inbox/envelopes?after=17',
      body: (_, _) => Uint8List(0),
      timestamp: t + 1,
    ),
    one(
      'PUT with a binary body, the other device',
      seed: 2,
      method: 'PUT',
      path: (inbox, _) => '/v1/inbox/$inbox/envelopes',
      body: (_, _) => noise.nextBytes(300),
      timestamp: t + 299,
    ),
    one(
      'DELETE at timestamp 0 (written "0")',
      seed: 2,
      method: 'DELETE',
      path: (inbox, _) => '/v1/inbox/$inbox',
      body: (_, _) => Uint8List(0),
      timestamp: 0,
    ),
  ];
}

/// Byte `i` of a pattern file: `(i * 7 + 3) mod 256`.
Uint8List _pattern(int length) =>
    Uint8List.fromList([for (var i = 0; i < length; i++) (i * 7 + 3) & 0xff]);

/// Attachment vectors (PROTOCOL.md section 12). libsodium draws the stream
/// header itself, so the ciphertexts were produced once by this generator and
/// are recorded; the tests and an independent PyNaCl script check that they
/// decrypt, and that the refused mutations are refused.
Future<List<Map<String, Object?>>> _attachmentCases(Crypto crypto) async {
  final cipher = AttachmentCipher(crypto, SeededRandom(900));
  final key = _hex(SeededRandom(901).nextBytes(32));
  final other = _hex(SeededRandom(902).nextBytes(32));
  Future<String> enc(int length) async {
    final k = crypto.importSecret(_unhex(key));
    final ct = await cipher.encrypt(key: k, plaintext: _pattern(length));
    k.dispose();
    return _hex(ct);
  }

  return [
    for (final length in [0, 5, 65536, 65537])
      {
        'name': 'valid, $length bytes',
        'input': {'key': key, 'pattern_length': length},
        'output': {'ciphertext': await enc(length), 'verdict': 'ok'},
      },
    for (final (name, mutation, k) in [
      ('drop the final chunk', 'drop_last_chunk', key),
      ('cut 5 bytes off the end', 'cut_5', key),
      ('drop the first chunk', 'drop_first_chunk', key),
      ('swap the two chunks', 'swap_chunks', key),
      ('one byte after the end', 'append_byte', key),
      ('flip a bit in the header', 'flip_header', key),
      ('flip a bit in the first chunk', 'flip_first_chunk', key),
      ('flip a bit in the final chunk', 'flip_last_chunk', key),
      ('header only', 'header_only', key),
      ('23 bytes', 'short_header', key),
      ('nothing', 'empty', key),
      ('wrong key', 'none', other),
    ])
      {
        'name': 'refused: $name',
        'input': {'key': k, 'base': 'valid, 65537 bytes', 'mutation': mutation},
        'output': {'verdict': 'refused'},
      },
  ];
}
