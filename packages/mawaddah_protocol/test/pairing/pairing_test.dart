// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import '../crypto/support.dart';
import 'support.dart';

void main() {
  late SodiumCrypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  Uint8List slot([int n = 1]) =>
      Uint8List.fromList(List.generate(16, (i) => n + i));

  group('pairing.json', () {
    for (final c in loadPairingCases()) {
      test(c.name, () {
        final input = c.input;
        if (c.output != null) {
          _checkSuccess(crypto, c);
          return;
        }
        switch (input['side']) {
          case 'initiator':
            final init = startInitiator(crypto, input['initiator']! as Json);
            final reply = PairingReply.fromJson(input['reply']! as Json);
            final attempts = (input['accept_attempts'] as int?) ?? 1;
            PairingException? failure;
            for (var n = 0; n < attempts; n++) {
              try {
                init.acceptReply(reply).dispose();
                failure = null;
              } on PairingException catch (e) {
                failure = e;
              }
            }
            expect(failure, isNotNull, reason: 'the reply must be refused');
            expect(failureName(failure!.failure), c.error);
          case 'joiner':
            expect(
              () => PairingJoiner.fromCode(
                crypto: crypto,
                random: joinerRandom(input['joiner']! as Json),
                bundle: PairingBundle.fromJson(input['bundle']! as Json),
                slotId: hex((input['initiator']! as Json)['slot_id']),
              ),
              throwsA(
                isA<PairingException>().having(
                  (e) => failureName(e.failure),
                  'failure',
                  c.error,
                ),
              ),
            );
          case 'qr':
            expect(c.error, 'format');
            expect(
              () => PairingQr.decode(input['qr']! as String),
              throwsFormatException,
            );
        }
      });
    }
  });

  group('a normal run', () {
    for (final path in PairingPath.values) {
      test('both sides agree, ${path.name} path (secure random)', () {
        final init = PairingInitiator.start(
          crypto: crypto,
          random: SecureTestRandom(),
          clock: FakeClock(),
        );
        final joiner = path == PairingPath.qr
            ? PairingJoiner.fromQr(
                crypto: crypto,
                random: SecureTestRandom(),
                qrText: init.qr(slot()).encode(),
              )
            : PairingJoiner.fromCode(
                crypto: crypto,
                random: SecureTestRandom(),
                bundle: init.bundle,
                slotId: slot(),
              );
        final a = init.acceptReply(joiner.reply);
        final b = joiner.result;

        expect(a.rootKey.extractBytes(), b.rootKey.extractBytes());
        expect(a.associatedData, b.associatedData);
        expect(a.associatedData, hasLength(128));
        expect(a.safetyNumber, b.safetyNumber);
        expect(a.safetyNumber, matches(RegExp(r'^[0-9]{20}$')));
        expect(a.partner, b.identity.publicIdentity);
        expect(b.partner, a.identity.publicIdentity);
        expect(a.path, path);
        expect(b.path, path);
        expect(a.isInitiator, isTrue);
        expect(b.isInitiator, isFalse);
        // The initiator keeps EKi's pair as its first ratchet key.
        expect(a.initiatorRatchetKeyPair!.publicKey, a.initiatorRatchetKey);
        expect(b.initiatorRatchetKey, a.initiatorRatchetKey);
        expect(b.initiatorRatchetKeyPair, isNull);
        a.dispose();
        b.dispose();
      });
    }

    test('two runs share nothing', () {
      PairingResult run() {
        final init = PairingInitiator.start(
          crypto: crypto,
          random: SecureTestRandom(),
          clock: FakeClock(),
        );
        final j = PairingJoiner.fromQr(
          crypto: crypto,
          random: SecureTestRandom(),
          qrText: init.qr(slot()).encode(),
        );
        return init.acceptReply(j.reply);
      }

      final x = run();
      final y = run();
      expect(x.rootKey.extractBytes(), isNot(y.rootKey.extractBytes()));
      expect(x.safetyNumber, isNot(y.safetyNumber));
    });
  });

  group('safety number confirmation', () {
    PairingResult pair(PairingPath path, {bool joinerSide = false}) {
      final init = PairingInitiator.start(
        crypto: crypto,
        random: SecureTestRandom(),
        clock: FakeClock(),
      );
      final joiner = path == PairingPath.qr
          ? PairingJoiner.fromQr(
              crypto: crypto,
              random: SecureTestRandom(),
              qrText: init.qr(slot()).encode(),
            )
          : PairingJoiner.fromCode(
              crypto: crypto,
              random: SecureTestRandom(),
              bundle: init.bundle,
              slotId: slot(),
            );
      final a = init.acceptReply(joiner.reply);
      return joinerSide ? joiner.result : a;
    }

    test('code path: required on both phones until confirmed', () {
      for (final side in [false, true]) {
        final r = pair(PairingPath.code, joinerSide: side);
        expect(r.safetyNumberCheck, SafetyNumberCheck.required);
        expect(r.requiresSafetyNumberConfirmation, isTrue);
        expect(r.mayExchangeProfile, isFalse);
        r.confirmSafetyNumber();
        expect(r.safetyNumberCheck, SafetyNumberCheck.confirmed);
        expect(r.requiresSafetyNumberConfirmation, isFalse);
        expect(r.mayExchangeProfile, isTrue);
      }
    });

    test('QR path: recommended, not required', () {
      for (final side in [false, true]) {
        final r = pair(PairingPath.qr, joinerSide: side);
        expect(r.safetyNumberCheck, SafetyNumberCheck.recommended);
        expect(r.requiresSafetyNumberConfirmation, isFalse);
        expect(r.mayExchangeProfile, isTrue);
      }
    });

    test('a code-path reply makes the initiator require it, always', () {
      // The initiator expected a scan (it showed a QR), but the reply says
      // "code": the check is required.
      final init = PairingInitiator.start(
        crypto: crypto,
        random: SecureTestRandom(),
        clock: FakeClock(),
      );
      final joiner = PairingJoiner.fromCode(
        crypto: crypto,
        random: SecureTestRandom(),
        bundle: init.bundle,
        slotId: slot(),
      );
      init.qr(slot());
      expect(
        init.acceptReply(joiner.reply).requiresSafetyNumberConfirmation,
        isTrue,
      );
    });
  });

  group('failures', () {
    PairingInitiator newInitiator([Clock? clock]) => PairingInitiator.start(
      crypto: crypto,
      random: SecureTestRandom(),
      clock: clock ?? FakeClock(),
    );

    void expectFailure(void Function() f, PairingFailure failure) => expect(
      f,
      throwsA(
        isA<PairingException>().having((e) => e.failure, 'failure', failure),
      ),
    );

    test('a relay that never saw the QR cannot answer for the joiner', () {
      // The relay knows the bundle (it stores it) but not S. It plays the
      // joiner with the code path (S' = zeros) and claims the QR path.
      final init = newInitiator();
      final forged = PairingJoiner.fromCode(
        crypto: crypto,
        random: SecureTestRandom(),
        bundle: init.bundle,
        slotId: slot(),
      ).reply;
      // As sent (path = code): accepted, but the safety number is required.
      // Relabelled as the QR path: refused.
      final relabelled = PairingReply.fromJson({
        ...forged.toJson(),
        'path': 'qr',
      });
      expectFailure(
        () => init.acceptReply(relabelled),
        PairingFailure.badReplySignature,
      );
    });

    test('a joiner with the wrong secret gets a confirm mismatch', () {
      final init = newInitiator();
      final qr = init.qr(slot());
      final other = Uint8List.fromList(qr.secret)..[0] ^= 0xff;
      final joiner = PairingJoiner.fromQr(
        crypto: crypto,
        random: SecureTestRandom(),
        qrText: PairingQr(
          signingKey: qr.signingKey,
          dhKey: qr.dhKey,
          ephemeralKey: qr.ephemeralKey,
          secret: other,
          slotId: qr.slotId,
        ).encode(),
      );
      expectFailure(
        () => init.acceptReply(joiner.reply),
        PairingFailure.confirmMismatch,
      );
    });

    test('a second reply is refused, also after a failure', () {
      final init = newInitiator();
      final good = PairingJoiner.fromQr(
        crypto: crypto,
        random: SecureTestRandom(),
        qrText: init.qr(slot()).encode(),
      );
      final bad = PairingReply.fromJson({
        ...good.reply.toJson(),
        'confirm': 'A' * 43,
      });
      expectFailure(
        () => init.acceptReply(bad),
        PairingFailure.badReplySignature,
      );
      expectFailure(
        () => init.acceptReply(good.reply),
        PairingFailure.alreadyUsed,
      );
    });

    test('the attempt ends after 10 minutes', () {
      final clock = FakeClock();
      final init = newInitiator(clock);
      final joiner = PairingJoiner.fromQr(
        crypto: crypto,
        random: SecureTestRandom(),
        qrText: init.qr(slot()).encode(),
      );
      expect(init.expiresAt, clock.now().add(const Duration(minutes: 10)));
      clock.advance(const Duration(minutes: 10, seconds: 1));
      expectFailure(
        () => init.acceptReply(joiner.reply),
        PairingFailure.expired,
      );
    });

    test('a reply exactly at the limit is still accepted', () {
      final clock = FakeClock();
      final init = newInitiator(clock);
      final joiner = PairingJoiner.fromQr(
        crypto: crypto,
        random: SecureTestRandom(),
        qrText: init.qr(slot()).encode(),
      );
      clock.advance(const Duration(minutes: 10));
      init.acceptReply(joiner.reply).dispose();
    });

    test('a small-order ephemeral key in the QR is refused', () {
      final init = newInitiator();
      final qr = init.qr(slot());
      final text = PairingQr(
        signingKey: qr.signingKey,
        dhKey: qr.dhKey,
        ephemeralKey: X25519PublicKey(Uint8List(32)),
        secret: Uint8List.fromList(qr.secret),
        slotId: qr.slotId,
      ).encode();
      expectFailure(
        () => PairingJoiner.fromQr(
          crypto: crypto,
          random: SecureTestRandom(),
          qrText: text,
        ),
        PairingFailure.invalidKey,
      );
    });

    test(
      'on the code path nothing is generated before the bundle is checked',
      () {
        final init = newInitiator();
        final json = init.bundle.toJson();
        final bad = PairingBundle.fromJson({...json, 'ek_pub': 'A' * 43});
        expectFailure(
          () => PairingJoiner.fromCode(
            crypto: crypto,
            random: ReplayRandom([]), // would throw StateError if asked
            bundle: bad,
            slotId: slot(),
          ),
          PairingFailure.badBundleSignature,
        );
      },
    );

    test('abandon erases the attempt and ends it', () {
      final init = newInitiator();
      final joiner = PairingJoiner.fromQr(
        crypto: crypto,
        random: SecureTestRandom(),
        qrText: init.qr(slot()).encode(),
      );
      init.abandon();
      init.abandon();
      expect(() => init.qr(slot()), throwsStateError);
      expectFailure(
        () => init.acceptReply(joiner.reply),
        PairingFailure.alreadyUsed,
      );
      joiner.abandon();
      expect(joiner.result.identity.isDisposed, isTrue);
      expect(joiner.result.rootKey.isDisposed, isTrue);
    });

    test('the QR secret is erased after the attempt', () {
      final init = newInitiator();
      final joiner = PairingJoiner.fromQr(
        crypto: crypto,
        random: SecureTestRandom(),
        qrText: init.qr(slot()).encode(),
      );
      init.acceptReply(joiner.reply).dispose();
      expect(() => init.qr(slot()), throwsStateError);
    });
  });

  group('formats', () {
    test('QR text is 181 characters and 129 bytes', () {
      final init = PairingInitiator.start(
        crypto: crypto,
        random: SecureTestRandom(),
        clock: FakeClock(),
      );
      final text = init.qr(slot()).encode();
      expect(text, startsWith('MAWADDAH:'));
      expect(text, hasLength(181));
      final back = PairingQr.decode(text);
      expect(back.encode(), text);
      expect(back.slotId, slot());
    });

    test('bundle, reply and QR carry no profile data', () {
      final init = PairingInitiator.start(
        crypto: crypto,
        random: SecureTestRandom(),
        clock: FakeClock(),
      );
      final joiner = PairingJoiner.fromQr(
        crypto: crypto,
        random: SecureTestRandom(),
        qrText: init.qr(slot()).encode(),
      );
      expect(
        init.bundle.toJson().keys,
        unorderedEquals(['v', 'sig_pub', 'dh_pub', 'ek_pub', 'sig']),
      );
      expect(
        joiner.reply.toJson().keys,
        unorderedEquals([
          'v', 'path', 'sig_pub', 'dh_pub', 'ek_pub', 'confirm', 'sig', //
        ]),
      );
    });

    test('bundle and reply JSON are read strictly', () {
      final init = PairingInitiator.start(
        crypto: crypto,
        random: SecureTestRandom(),
        clock: FakeClock(),
      );
      final good = init.bundle.toJson();
      PairingBundle.fromJson({...good, 'extra': 1}); // unknown fields ignored
      for (final bad in <Json>[
        {...good}..remove('sig'),
        {...good, 'v': 2},
        {...good, 'v': '1'},
        {...good, 'dh_pub': 'AAAA'},
        {...good, 'dh_pub': 5},
        {...good, 'ek_pub': '${good['ek_pub']}='},
        {...good, 'ek_pub': '+${(good['ek_pub']! as String).substring(1)}'},
      ]) {
        expect(() => PairingBundle.fromJson(bad), throwsFormatException);
      }
      expect(
        () => PairingReply.fromJson({
          ...good,
          'path': 'both',
          'confirm': good['sig'],
        }),
        throwsFormatException,
      );
    });
  });

  group('PairingProfile', () {
    test('round trip', () {
      final p = PairingProfile(
        firstName: 'Amina',
        gender: ProfileGender.female,
        mode: RelationshipMode.marriedRemote,
      );
      expect(p.toJson(), {
        'first_name': 'Amina',
        'gender': 'female',
        'mode': 'married_remote',
      });
      final back = PairingProfile.fromJson(p.toJson());
      expect(back.firstName, 'Amina');
      expect(back.gender, ProfileGender.female);
      expect(back.mode, RelationshipMode.marriedRemote);
    });

    test('invalid profiles are refused', () {
      for (final bad in <Json>[
        {'first_name': '', 'gender': 'male', 'mode': 'engaged'},
        {'first_name': ' Ali', 'gender': 'male', 'mode': 'engaged'},
        {'first_name': 'A\nB', 'gender': 'male', 'mode': 'engaged'},
        {'first_name': 'A' * 51, 'gender': 'male', 'mode': 'engaged'},
        {'first_name': 'Ali', 'gender': 'other', 'mode': 'engaged'},
        {'first_name': 'Ali', 'gender': 'male', 'mode': 'sulh'},
        {'gender': 'male', 'mode': 'engaged'},
      ]) {
        expect(() => PairingProfile.fromJson(bad), throwsFormatException);
      }
    });
  });
}

void _checkSuccess(SodiumCrypto crypto, PairingCase c) {
  final input = c.input;
  final out = c.output!;
  final path = PairingPath.values.firstWhere(
    (p) => p.wireName == input['path'],
  );
  final iIn = input['initiator']! as Json;
  final init = startInitiator(crypto, iIn);
  final slotId = hex(iIn['slot_id']);
  expect(init.bundle.toJson(), out['bundle']);
  final qr = init.qr(slotId);
  if (path == PairingPath.qr) expect(qr.encode(), out['qr']);

  final jRandom = joinerRandom(input['joiner']! as Json);
  final joiner = path == PairingPath.qr
      ? PairingJoiner.fromQr(
          crypto: crypto,
          random: jRandom,
          qrText: out['qr']! as String,
        )
      : PairingJoiner.fromCode(
          crypto: crypto,
          random: jRandom,
          bundle: PairingBundle.fromJson(out['bundle']! as Json),
          slotId: slotId,
        );
  expect(joiner.reply.toJson(), out['reply']);

  final result = init.acceptReply(PairingReply.fromJson(out['reply']! as Json));
  expect(toHex(result.rootKey.extractBytes()), out['sk']);
  expect(toHex(joiner.result.rootKey.extractBytes()), out['sk']);
  expect(toHex(result.associatedData), out['ad']);
  expect(toHex(joiner.result.associatedData), out['ad']);
  expect(result.safetyNumber, out['safety_number']);
  expect(joiner.result.safetyNumber, out['safety_number']);
  expect(
    result.requiresSafetyNumberConfirmation,
    out['safety_number_required'],
  );
  expect(
    joiner.result.requiresSafetyNumberConfirmation,
    out['safety_number_required'],
  );
  result.dispose();
  joiner.result.dispose();
}
