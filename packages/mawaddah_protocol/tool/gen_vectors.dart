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
