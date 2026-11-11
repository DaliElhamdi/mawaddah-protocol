// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late Crypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  Matcher fails(RatchetFailure f) =>
      throwsA(isA<RatchetException>().having((e) => e.failure, 'failure', f));

  /// Sends one message from [from] and opens it on [to].
  String roundTrip(
    RatchetSession from,
    RatchetSession to,
    String message,
    int counter,
  ) {
    final m = from.encrypt(text(message), envelopePrefix: prefix(counter));
    final header = RatchetHeader.decode(m.header.encode());
    return utf8.decode(
      to.decrypt(header, m.ciphertext, envelopePrefix: prefix(counter)),
    );
  }

  group('RatchetHeader', () {
    test('encodes dh_pub || u32 pn || u32 n and decodes back', () {
      final key = X25519PublicKey(
        Uint8List.fromList(List.generate(32, (i) => i)),
      );
      final h = RatchetHeader(dhPub: key, pn: 0x01020304, n: 0xFFFFFFFF);
      final bytes = h.encode();
      expect(bytes.length, 40);
      expect(bytes.sublist(0, 32), key.bytes);
      expect(bytes.sublist(32), [1, 2, 3, 4, 255, 255, 255, 255]);
      expect(RatchetHeader.decode(bytes), h);
    });

    test('rejects a wrong length and out-of-range counters', () {
      expect(() => RatchetHeader.decode(Uint8List(39)), throwsFormatException);
      expect(() => RatchetHeader.decode(Uint8List(41)), throwsFormatException);
      final key = X25519PublicKey(Uint8List(32));
      expect(() => RatchetHeader(dhPub: key, pn: -1, n: 0), throwsRangeError);
      expect(
        () => RatchetHeader(dhPub: key, pn: 0, n: 0x100000000),
        throwsRangeError,
      );
    });
  });

  group('initialisation from pairing', () {
    test('the joiner can send at once, the initiator only after', () {
      final s = sessions(crypto);
      expect(s.alice.canSend, isTrue);
      expect(s.bob.canSend, isFalse);
      expect(
        () => s.bob.encrypt(text('x'), envelopePrefix: prefix(1)),
        throwsStateError,
      );
      expect(roundTrip(s.alice, s.bob, 'salam', 1), 'salam');
      expect(s.bob.canSend, isTrue);
      expect(roundTrip(s.bob, s.alice, 'wa alaykum', 1), 'wa alaykum');
    });

    test('takes over the pairing secrets', () {
      final p = pair(crypto);
      final bobPair = p.initiator.initiatorRatchetKeyPair!;
      final alice = RatchetSession.fromPairing(
        crypto: crypto,
        random: SeededRandom(3),
        clock: FakeClock(),
        pairing: p.joiner,
      );
      final bob = RatchetSession.fromPairing(
        crypto: crypto,
        random: SeededRandom(4),
        clock: FakeClock(),
        pairing: p.initiator,
      );
      expect(p.joiner.rootKey.isDisposed, isTrue);
      expect(p.initiator.rootKey.isDisposed, isTrue);
      // The initiator's EKi is Bob's first DHs ...
      expect(bob.ratchetPublicKey, p.initiator.initiatorRatchetKey);
      expect(bobPair.secretKey.isDisposed, isFalse);
      roundTrip(alice, bob, 'hello', 1);
      // ... and the first DH ratchet step replaces and wipes it.
      expect(bobPair.secretKey.isDisposed, isTrue);
      expect(bob.ratchetPublicKey, isNot(p.initiator.initiatorRatchetKey));
      // The identity keys are still the pairing's to manage.
      expect(p.initiator.identity.toString(), isNot(contains('disposed')));
    });

    test('rejects associated data of the wrong length', () {
      expect(
        () => RatchetSession.initAlice(
          crypto: crypto,
          random: SeededRandom(1),
          clock: FakeClock(),
          rootKey: crypto.importSecret(Uint8List(32)),
          associatedData: Uint8List(127),
          remoteRatchetKey: crypto.generateX25519KeyPair().publicKey,
        ),
        throwsArgumentError,
      );
    });
  });

  group('in-order conversation', () {
    test('100-message ping-pong decrypts on both sides', () {
      final s = sessions(crypto);
      var aliceCounter = 0;
      var bobCounter = 0;
      for (var i = 0; i < 100; i++) {
        final msg = 'message $i';
        if (i.isEven) {
          expect(roundTrip(s.alice, s.bob, msg, ++aliceCounter), msg);
        } else {
          expect(roundTrip(s.bob, s.alice, msg, ++bobCounter), msg);
        }
      }
    });

    test('runs of messages in each direction, in random turn lengths', () {
      final s = sessions(crypto);
      final rnd = math.Random(7);
      var counter = 0;
      var aliceTurn = true;
      for (var i = 0; i < 300;) {
        final run = 1 + rnd.nextInt(6);
        for (var j = 0; j < run; j++, i++) {
          final (from, to) = aliceTurn ? (s.alice, s.bob) : (s.bob, s.alice);
          expect(roundTrip(from, to, '#$i', ++counter), '#$i');
        }
        aliceTurn = !aliceTurn;
      }
    });

    test(
      'a DH ratchet step happens on every turn change, not inside a run',
      () {
        final s = sessions(crypto);
        final a1 = s.alice.encrypt(text('1'), envelopePrefix: prefix(1));
        final a2 = s.alice.encrypt(text('2'), envelopePrefix: prefix(2));
        expect(a1.header.dhPub, a2.header.dhPub);
        expect((a1.header.pn, a1.header.n, a2.header.n), (0, 0, 1));
        s.bob.decrypt(a1.header, a1.ciphertext, envelopePrefix: prefix(1));
        s.bob.decrypt(a2.header, a2.ciphertext, envelopePrefix: prefix(2));

        final b1 = s.bob.encrypt(text('3'), envelopePrefix: prefix(1));
        expect(b1.header.dhPub, isNot(a1.header.dhPub));
        expect((b1.header.pn, b1.header.n), (0, 0));
        s.alice.decrypt(b1.header, b1.ciphertext, envelopePrefix: prefix(1));

        final a3 = s.alice.encrypt(text('4'), envelopePrefix: prefix(3));
        expect(a3.header.dhPub, isNot(a1.header.dhPub));
        expect((a3.header.pn, a3.header.n), (2, 0));
      },
    );

    test('crossing messages (both send before reading) decrypt', () {
      final s = sessions(crypto);
      roundTrip(s.alice, s.bob, 'a1', 1);
      roundTrip(s.bob, s.alice, 'b1', 1);
      // Both write at the same time.
      final a = s.alice.encrypt(text('a2'), envelopePrefix: prefix(2));
      final b = s.bob.encrypt(text('b2'), envelopePrefix: prefix(2));
      expect(
        utf8.decode(
          s.bob.decrypt(a.header, a.ciphertext, envelopePrefix: prefix(2)),
        ),
        'a2',
      );
      expect(
        utf8.decode(
          s.alice.decrypt(b.header, b.ciphertext, envelopePrefix: prefix(2)),
        ),
        'b2',
      );
      expect(roundTrip(s.bob, s.alice, 'b3', 3), 'b3');
      expect(roundTrip(s.alice, s.bob, 'a3', 3), 'a3');
    });

    test('an empty plaintext works', () {
      final s = sessions(crypto);
      final m = s.alice.encrypt(Uint8List(0), envelopePrefix: prefix(1));
      expect(m.ciphertext.length, 16);
      expect(
        s.bob.decrypt(m.header, m.ciphertext, envelopePrefix: prefix(1)),
        isEmpty,
      );
    });
  });

  group('header and envelope bytes are authenticated', () {
    late ({RatchetSession alice, RatchetSession bob}) s;
    late RatchetMessage m;

    setUp(() {
      s = sessions(crypto);
      roundTrip(s.alice, s.bob, 'first', 1);
      roundTrip(s.bob, s.alice, 'reply', 1);
      m = s.alice.encrypt(text('secret'), envelopePrefix: prefix(2));
    });

    /// After a rejected try the genuine message still opens: the failure
    /// did not change the session.
    void genuineStillOpens() => expect(
      utf8.decode(
        s.bob.decrypt(m.header, m.ciphertext, envelopePrefix: prefix(2)),
      ),
      'secret',
    );

    test('a changed envelope prefix byte', () {
      for (final at in [0, 2, 34, 49]) {
        final p = prefix(2);
        p[at] ^= 1;
        expect(
          () => s.bob.decrypt(m.header, m.ciphertext, envelopePrefix: p),
          fails(RatchetFailure.decryptionFailed),
          reason: 'offset $at',
        );
      }
      genuineStillOpens();
    });

    test('a changed pn', () {
      final h = RatchetHeader(dhPub: m.header.dhPub, pn: 0, n: m.header.n);
      expect(m.header.pn, isNot(0));
      expect(
        () => s.bob.decrypt(h, m.ciphertext, envelopePrefix: prefix(2)),
        fails(RatchetFailure.decryptionFailed),
      );
      genuineStillOpens();
    });

    test('a changed ratchet key (turn step computed, then discarded)', () {
      final other = crypto.generateX25519KeyPair().publicKey;
      final h = RatchetHeader(dhPub: other, pn: m.header.pn, n: m.header.n);
      expect(
        () => s.bob.decrypt(h, m.ciphertext, envelopePrefix: prefix(2)),
        fails(RatchetFailure.decryptionFailed),
      );
      genuineStillOpens();
    });

    test('a changed ciphertext or tag byte', () {
      for (final at in [0, m.ciphertext.length - 1]) {
        final c = Uint8List.fromList(m.ciphertext);
        c[at] ^= 0x80;
        expect(
          () => s.bob.decrypt(m.header, c, envelopePrefix: prefix(2)),
          fails(RatchetFailure.decryptionFailed),
        );
      }
      genuineStillOpens();
    });

    test('a message from another pair (different AD and keys)', () {
      final other = sessions(crypto, seed: 50);
      expect(
        () => other.bob.decrypt(
          m.header,
          m.ciphertext,
          envelopePrefix: prefix(2),
        ),
        fails(RatchetFailure.decryptionFailed),
      );
    });

    test('a small-order ratchet key is refused', () {
      final zero = X25519PublicKey(Uint8List(32));
      expect(
        () => s.bob.decrypt(
          RatchetHeader(dhPub: zero, pn: 0, n: 0),
          m.ciphertext,
          envelopePrefix: prefix(2),
        ),
        fails(RatchetFailure.invalidKey),
      );
      genuineStillOpens();
    });

    test('the prefix must be 50 bytes', () {
      expect(
        () => s.alice.encrypt(text('x'), envelopePrefix: Uint8List(49)),
        throwsArgumentError,
      );
      expect(
        () => s.bob.decrypt(
          m.header,
          m.ciphertext,
          envelopePrefix: Uint8List(51),
        ),
        throwsArgumentError,
      );
    });
  });

  group('order', () {
    test('a repeated message is refused and the session goes on', () {
      final s = sessions(crypto);
      final m = s.alice.encrypt(text('once'), envelopePrefix: prefix(1));
      s.bob.decrypt(m.header, m.ciphertext, envelopePrefix: prefix(1));
      expect(
        () => s.bob.decrypt(m.header, m.ciphertext, envelopePrefix: prefix(1)),
        fails(RatchetFailure.oldMessage),
      );
      expect(roundTrip(s.alice, s.bob, 'next', 2), 'next');
    });
  });

  group('dispose', () {
    test('wipes the keys; use afterwards throws', () {
      final s = sessions(crypto);
      roundTrip(s.alice, s.bob, 'x', 1);
      s.alice.dispose();
      s.alice.dispose();
      expect(s.alice.canSend, isFalse);
      expect(
        () => s.alice.encrypt(text('x'), envelopePrefix: prefix(2)),
        throwsStateError,
      );
      final m = s.bob.encrypt(text('y'), envelopePrefix: prefix(1));
      expect(
        () =>
            s.alice.decrypt(m.header, m.ciphertext, envelopePrefix: prefix(1)),
        throwsStateError,
      );
    });
  });
}
