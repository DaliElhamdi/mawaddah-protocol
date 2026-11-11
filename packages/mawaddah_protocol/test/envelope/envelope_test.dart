// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late Crypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  group('seal and open', () {
    test('a conversation in both directions opens in order', () {
      final (:alice, :bob, :clock) = paired(crypto);
      for (var i = 0; i < 20; i++) {
        expect(bob.open(alice.send('a$i')), 'a$i');
        clock.advance(const Duration(seconds: 1));
        expect(alice.open(bob.send('b$i')), 'b$i');
        if (i.isEven) expect(bob.open(alice.send('a$i+')), 'a$i+');
      }
      expect(bob.window.highest, 30);
      expect(alice.window.highest, 20);
    });

    test('the parsed fields are the ones sealed', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      final hlc = Hlc(1762862400000, 7);
      final bytes = alice.send('{"events":[]}', counter: 5, hlc: hlc);
      final e = Envelope.parse(bytes);
      expect(e.senderId, alice.identity.deviceId);
      expect(e.recipientId, bob.identity.deviceId);
      expect(e.counter, 5);
      expect(e.hlc, hlc);
      expect(e.header.n, 0);
      expect(e.header.pn, 0);
      expect(e.header.dhPub, alice.session.ratchetPublicKey);
      expect(bytes[0], envelopeVersion);
      expect(bytes[1], envelopeTypeRatchetMessage);
      expect(e.ciphertext.length, 272);
      expect(e.bytes.length, minEnvelopeLength);
      expect(
        crypto.verify(
          alice.identity.publicIdentity.signingKey,
          Uint8List.fromList([
            ...ascii.encode('mawaddah/v1/envelope'),
            ...bytes.sublist(0, bytes.length - 64),
          ]),
          e.signature,
        ),
        isTrue,
      );
    });

    test('opening merges the sender HLC into the receiver clock', () {
      final (:alice, :bob, :clock) = paired(crypto);
      final ahead = Hlc(clock.now().millisecondsSinceEpoch + 60000, 3);
      bob.open(alice.send('x', hlc: ahead));
      expect(bob.hlc.last, Hlc(ahead.physicalMs, 4));
      expect(bob.hlc.send() > ahead, isTrue);
    });

    test('padding: sizes are 256-byte blocks plus header, tag, signature', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      for (final (len, total) in [
        (0, 426),
        (255, 426),
        (256, 682),
        (511, 682),
        (512, 938),
        (maxEnvelopePlaintextLength, 65450),
      ]) {
        final text = 'x' * len;
        final bytes = alice.send(text);
        expect(bytes.length, total, reason: '$len bytes');
        expect(bob.open(bytes), text);
      }
      expect(maxEnvelopePlaintextLength, 65279);
    });

    test('seal refuses a bad counter, a long plaintext, a session that '
        'cannot send', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      expect(() => alice.send('x', counter: 0), throwsRangeError);
      expect(() => alice.send('x', counter: -1), throwsRangeError);
      expect(
        () => alice.send('x' * (maxEnvelopePlaintextLength + 1)),
        throwsArgumentError,
      );
      // The initiator cannot send before the joiner's first message.
      expect(() => bob.send('x'), throwsStateError);
      // The largest counter is accepted.
      expect(bob.open(alice.send('x', counter: maxEnvelopeCounter)), 'x');
    });

    test('the failure flags say what the app does', () {
      for (final f in EnvelopeFailure.values) {
        expect(f.acknowledge, f != EnvelopeFailure.fromTheFuture, reason: '$f');
        expect(
          f.keepUnapplied,
          f == EnvelopeFailure.unknownVersion ||
              f == EnvelopeFailure.undecryptable,
          reason: '$f',
        );
      }
    });
  });

  group('rejects', () {
    test('every single changed bit, and nothing changes', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      final genuine = alice.send('hello');
      final n = genuine.length;
      for (var i = 0; i < n; i++) {
        final f = failureOf(() => bob.open(flip(genuine, i)));
        final expected = switch (i) {
          0 || 1 => EnvelopeFailure.unknownVersion,
          < 18 => EnvelopeFailure.unknownSender,
          < 34 => EnvelopeFailure.wrongRecipient,
          // Counter 1 with its lowest bit flipped is 0.
          41 => EnvelopeFailure.malformed,
          _ => EnvelopeFailure.badSignature,
        };
        expect(f, expected, reason: 'byte $i');
      }
      expect(bob.window.highest, 0);
      expect(bob.hlc.last, Hlc.zero);
      expect(bob.open(genuine), 'hello');
    });

    test('a replay, and accepts out-of-order envelopes inside the window', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      final sent = [for (var i = 1; i <= 5; i++) alice.send('m$i')];
      for (final i in [3, 1, 5, 2, 4]) {
        expect(bob.open(sent[i - 1]), 'm$i');
      }
      for (final s in sent) {
        expect(failureOf(() => bob.open(s)), EnvelopeFailure.replayed);
      }
      final next = alice.send('m6');
      expect(bob.open(next), 'm6');
    });

    test('a counter that fell behind the window', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      final old = alice.send('old', counter: 1);
      final edge = alice.send('edge', counter: 1025);
      final last = alice.send('last', counter: 2048);
      expect(bob.open(last), 'last');
      expect(bob.open(edge), 'edge'); // 2048 - 1023
      expect(failureOf(() => bob.open(old)), EnvelopeFailure.replayed);
    });

    test('an HLC more than 1 hour ahead, until the clock catches up', () {
      final (:alice, :bob, :clock) = paired(crypto);
      final now = clock.now().millisecondsSinceEpoch;
      const hour = 3600000;
      final edge = alice.send('edge', hlc: Hlc(now + hour, 0));
      final ahead = alice.send('ahead', hlc: Hlc(now + hour + 1, 0));
      expect(failureOf(() => bob.open(ahead)), EnvelopeFailure.fromTheFuture);
      expect(bob.window.highest, 0);
      expect(bob.open(edge), 'edge');
      clock.advance(const Duration(milliseconds: 1));
      expect(bob.open(ahead), 'ahead');
    });

    test('an HLC more than 31 days behind', () {
      final (:alice, :bob, :clock) = paired(crypto);
      final now = clock.now().millisecondsSinceEpoch;
      const days31 = 31 * 86400000;
      final edge = alice.send('edge', hlc: Hlc(now - days31, 0));
      final old = alice.send('old', hlc: Hlc(now - days31 - 1, 0));
      expect(failureOf(() => bob.open(old)), EnvelopeFailure.tooOld);
      expect(bob.open(edge), 'edge');
    });

    test('an envelope for another device', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      final other = DeviceIdentity.generate(crypto, SeededRandom(99));
      final bytes = Envelope.seal(
        crypto: crypto,
        sender: alice.identity,
        recipient: other.deviceId,
        counter: 1,
        hlc: alice.hlc.send(),
        session: alice.session,
        plaintext: utf8.encode('x'),
      );
      expect(failureOf(() => bob.open(bytes)), EnvelopeFailure.wrongRecipient);
    });

    test('an envelope from a device that is not the partner', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      final other = DeviceIdentity.generate(crypto, SeededRandom(99));
      final bytes = alice.send('x');
      expect(
        failureOf(
          () => Envelope.open(
            crypto: crypto,
            bytes: bytes,
            self: bob.identity.deviceId,
            partner: other.publicIdentity,
            session: bob.session,
            window: bob.window,
            clock: bob.hlc,
          ),
        ),
        EnvelopeFailure.unknownSender,
      );
    });

    test('a signature by another key', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      final other = DeviceIdentity.generate(crypto, SeededRandom(99));
      final bytes = alice.send('x');
      final body = bytes.sublist(0, bytes.length - 64);
      final forged = crypto.sign(
        other.signingSecretKey,
        Uint8List.fromList([...ascii.encode('mawaddah/v1/envelope'), ...body]),
      );
      final out = Uint8List.fromList([...body, ...forged.bytes]);
      expect(failureOf(() => bob.open(out)), EnvelopeFailure.badSignature);
      // A signature without the label does not verify either.
      final unlabelled = crypto.sign(alice.identity.signingSecretKey, body);
      expect(
        failureOf(
          () => bob.open(Uint8List.fromList([...body, ...unlabelled.bytes])),
        ),
        EnvelopeFailure.badSignature,
      );
      expect(bob.open(bytes), 'x');
    });

    test('malformed structures and unknown versions', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      final genuine = alice.send('x');
      Uint8List resized(int n) {
        final out = Uint8List(n);
        out.setAll(0, genuine.length > n ? genuine.sublist(0, n) : genuine);
        return out;
      }

      for (final n in [0, 1, 425, 427, 426 + 255, 65537]) {
        final b = Uint8List.fromList(resized(n));
        if (n >= 2) {
          b
            ..[0] = 1
            ..[1] = 1;
        }
        expect(
          failureOf(() => Envelope.parse(b)),
          EnvelopeFailure.malformed,
          reason: '$n bytes',
        );
      }
      expect(
        failureOf(() => Envelope.parse(Uint8List.fromList([2, 1]))),
        EnvelopeFailure.unknownVersion,
      );
      expect(
        failureOf(() => Envelope.parse(Uint8List.fromList([1, 2, 0]))),
        EnvelopeFailure.unknownVersion,
      );
      // Oversize is malformed whatever the version.
      expect(
        failureOf(() => Envelope.parse(Uint8List(65537)..[0] = 2)),
        EnvelopeFailure.malformed,
      );
      // Counter 0, and counters of 2^63 and above.
      for (final high in [0x00, 0x80, 0xff]) {
        final b = Uint8List.fromList(genuine);
        b.fillRange(34, 42, 0);
        b[34] = high;
        expect(
          failureOf(() => Envelope.parse(b)),
          EnvelopeFailure.malformed,
          reason: 'counter high byte $high',
        );
      }
      expect(bob.open(genuine), 'x');
    });

    test('undecryptable: signed by the partner but not openable', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      final genuine = alice.send('x');
      final body = Uint8List.fromList(genuine.sublist(0, genuine.length - 64));
      body[100] ^= 1; // a ciphertext byte
      final resigned = crypto.sign(
        alice.identity.signingSecretKey,
        Uint8List.fromList([...ascii.encode('mawaddah/v1/envelope'), ...body]),
      );
      final bytes = Uint8List.fromList([...body, ...resigned.bytes]);
      try {
        bob.open(bytes);
        fail('opened');
      } on EnvelopeException catch (e) {
        expect(e.failure, EnvelopeFailure.undecryptable);
        expect(e.ratchetFailure, RatchetFailure.decryptionFailed);
      }
      // The counter is used up; the session is unchanged.
      expect(bob.window.highest, 1);
      expect(failureOf(() => bob.open(bytes)), EnvelopeFailure.replayed);
      expect(failureOf(() => bob.open(genuine)), EnvelopeFailure.replayed);
      expect(bob.hlc.last, Hlc.zero);
      expect(bob.open(alice.send('y')), 'y');
    });

    test('undecryptable: decrypted bytes without valid padding', () {
      final (:alice, :bob, clock: _) = paired(crypto);
      // Seal by hand, encrypting 256 zero bytes (no 0x80 marker).
      final prefix = Uint8List(50)
        ..[0] = 1
        ..[1] = 1
        ..setAll(2, alice.identity.deviceId.bytes)
        ..setAll(18, bob.identity.deviceId.bytes)
        ..[41] = 1
        ..setAll(42, alice.hlc.send().toBytes());
      final m = alice.session.encrypt(Uint8List(256), envelopePrefix: prefix);
      final body = Uint8List.fromList([
        ...prefix,
        ...m.header.encode(),
        ...m.ciphertext,
      ]);
      final sig = crypto.sign(
        alice.identity.signingSecretKey,
        Uint8List.fromList([...ascii.encode('mawaddah/v1/envelope'), ...body]),
      );
      try {
        bob.open(Uint8List.fromList([...body, ...sig.bytes]));
        fail('opened');
      } on EnvelopeException catch (e) {
        expect(e.failure, EnvelopeFailure.undecryptable);
        expect(e.ratchetFailure, isNull);
      }
      expect(bob.window.highest, 1);
      expect(bob.open(alice.send('y', counter: 2)), 'y');
    });

    test('checks run in the order of PROTOCOL.md section 8', () {
      final (:alice, :bob, :clock) = paired(crypto);
      final now = clock.now().millisecondsSinceEpoch;
      // Replayed and from the future: the replay check comes first.
      final future = alice.send('f', hlc: Hlc(now + 7200000, 0));
      clock.advance(const Duration(hours: 2));
      expect(bob.open(future), 'f');
      clock.advance(const Duration(hours: -2));
      expect(failureOf(() => bob.open(future)), EnvelopeFailure.replayed);
      // Bad signature and too old: the signature comes first.
      final old = alice.send('o', hlc: Hlc(now - 40 * 86400000, 0));
      expect(
        failureOf(() => bob.open(flip(old, old.length - 1))),
        EnvelopeFailure.badSignature,
      );
      expect(failureOf(() => bob.open(old)), EnvelopeFailure.tooOld);
      // A too-old envelope does not use up its counter.
      expect(bob.window.accepts(Envelope.parse(old).counter), isTrue);
    });
  });
}
