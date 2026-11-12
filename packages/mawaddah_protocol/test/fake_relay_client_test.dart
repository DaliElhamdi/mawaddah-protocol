// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

Matcher _code(RelayErrorCode code) =>
    throwsA(isA<RelayException>().having((e) => e.code, 'code', code));

String _id(int byte) => encodeRelayId(Uint8List(16)..fillRange(0, 16, byte));

/// The checked [FakeRelayClient] follows relay/README.md.
void main() {
  late Crypto crypto;
  late DeviceIdentity a, b, c;
  late FakeClock clock;
  late FakeRelayClient alice, bob, carol;
  late String aliceInbox, bobInbox;
  setUpAll(() async => crypto = await SodiumCrypto.load());
  setUp(() async {
    a = DeviceIdentity.generate(crypto, SeededRandom(1));
    b = DeviceIdentity.generate(crypto, SeededRandom(2));
    c = DeviceIdentity.generate(crypto, SeededRandom(3));
    clock = FakeClock(DateTime.utc(2026, 11, 11, 12));
    alice = FakeRelayClient(
      signingKey: a.publicIdentity.signingKey,
      clock: clock,
      pageSize: 3,
    );
    bob = alice.as(b.publicIdentity.signingKey);
    carol = alice.as(c.publicIdentity.signingKey);
    aliceInbox = await alice.registerInbox(
      pushToken: 't1',
      platform: RelayPlatform.android,
    );
    bobInbox = await bob.registerInbox(
      pushToken: null,
      platform: RelayPlatform.ios,
    );
  });
  tearDown(() {
    a.dispose();
    b.dispose();
    c.dispose();
  });

  Uint8List key(DeviceIdentity d) => d.publicIdentity.signingKey.bytes;

  test('register: the ID is the device ID; again updates', () async {
    expect(aliceInbox, a.deviceId.toBase64Url());
    expect(alice.pushTokenOf(aliceInbox), 't1');
    expect(alice.platformOf(bobInbox), RelayPlatform.ios);
    expect(
      await alice.registerInbox(pushToken: 't2', platform: RelayPlatform.ios),
      aliceInbox,
    );
    expect(alice.pushTokenOf(aliceInbox), 't2');
    await alice.setPushToken(aliceInbox, null);
    expect(alice.pushTokenOf(aliceInbox), isNull);
  });

  test('owner, allowed sender and missing inboxes', () async {
    await expectLater(
      alice.fetch(bobInbox),
      _code(RelayErrorCode.notInboxOwner),
    );
    await expectLater(
      alice.setPushToken(bobInbox, 'x'),
      _code(RelayErrorCode.notInboxOwner),
    );
    await expectLater(
      alice.deposit(bobInbox, Uint8List(1)),
      _code(RelayErrorCode.senderNotAllowed),
    );
    await bob.allowSender(bobInbox, key(a));
    await bob.allowSender(bobInbox, key(a)); // a retry
    await expectLater(
      bob.allowSender(bobInbox, key(c)),
      _code(RelayErrorCode.allowConflict),
    );
    await expectLater(
      carol.deposit(bobInbox, Uint8List(1)),
      _code(RelayErrorCode.senderNotAllowed),
    );
    await alice.deposit(bobInbox, Uint8List(1), wake: true);
    expect(alice.wakesFor(bobInbox), [true]);
    await expectLater(
      alice.deposit(_id(9), Uint8List(1)),
      _code(RelayErrorCode.inboxNotFound),
    );
    await expectLater(
      alice.deposit(bobInbox, Uint8List(0)),
      _code(RelayErrorCode.malformedRequest),
    );
    await expectLater(
      alice.deposit(bobInbox, Uint8List(maxEnvelopeLength + 1)),
      _code(RelayErrorCode.bodyTooLarge),
    );

    await expectLater(
      alice.deleteInbox(bobInbox),
      _code(RelayErrorCode.notInboxOwner),
    );
    await bob.deleteInbox(bobInbox);
    await bob.deleteInbox(bobInbox); // already gone: fine
    expect(alice.hasInbox(bobInbox), isFalse);
    await expectLater(
      alice.deposit(bobInbox, Uint8List(1)),
      _code(RelayErrorCode.inboxNotFound),
    );
  });

  test('pages, cursors and the cumulative ACK', () async {
    await bob.allowSender(bobInbox, key(a));
    for (var i = 1; i <= 7; i++) {
      await alice.deposit(bobInbox, Uint8List.fromList([i]));
    }
    final p1 = await bob.fetch(bobInbox);
    expect([for (final e in p1.envelopes) e.body.single], [1, 2, 3]);
    expect(p1.more, isTrue);
    final p2 = await bob.fetch(bobInbox, after: p1.envelopes.last.cursor);
    expect([for (final e in p2.envelopes) e.body.single], [4, 5, 6]);
    final p3 = await bob.fetch(bobInbox, after: p2.envelopes.last.cursor);
    expect([for (final e in p3.envelopes) e.body.single], [7]);
    expect(p3.more, isFalse);
    // Cursors are decimal, increasing, never reused.
    final cursors = [
      for (final p in [p1, p2, p3])
        for (final e in p.envelopes) int.parse(e.cursor),
    ];
    expect(cursors, orderedEquals([...cursors]..sort()));
    expect(cursors.toSet(), hasLength(7));

    await bob.ack(bobInbox, p2.envelopes.first.cursor);
    expect(
      [for (final e in (await bob.fetch(bobInbox)).envelopes) e.body.single],
      [5, 6, 7],
    );
    final beyond = '${int.parse(p3.envelopes.last.cursor) + 1}';
    await expectLater(
      bob.ack(bobInbox, beyond),
      _code(RelayErrorCode.invalidCursor),
    );
    await expectLater(
      bob.fetch(bobInbox, after: beyond),
      _code(RelayErrorCode.invalidCursor),
    );
    await expectLater(
      bob.fetch(bobInbox, after: '01'),
      _code(RelayErrorCode.malformedRequest),
    );
    await bob.ack(bobInbox, p3.envelopes.last.cursor);
    expect((await bob.fetch(bobInbox)).envelopes, isEmpty);
  });

  test('a page holds at most 1 MiB, but always one envelope', () async {
    final big = FakeRelayClient();
    for (var i = 0; i < 20; i++) {
      await big.deposit('i', Uint8List(maxEnvelopeLength));
    }
    final page = await big.fetch('i');
    expect(page.envelopes, hasLength(16));
    expect(page.more, isTrue);
  });

  group('pairing slots', () {
    late PairingInitiator initiator;
    late FakeRelayClient init;
    late PairingSlot slot;
    setUp(() async {
      initiator = PairingInitiator.start(
        crypto: crypto,
        random: SeededRandom(5),
        clock: clock,
      );
      init = alice.as(initiator.publicIdentity.signingKey);
      await expectLater(
        init.createPairingSlot(initiator.bundle),
        _code(RelayErrorCode.inboxRequired),
      );
      await init.registerInbox(
        pushToken: null,
        platform: RelayPlatform.android,
      );
      slot = await init.createPairingSlot(initiator.bundle);
    });
    tearDown(() => initiator.abandon());

    PairingJoiner join(PairingSlotLookup found, int seed) =>
        PairingJoiner.fromCode(
          crypto: crypto,
          random: SeededRandom(seed),
          bundle: found.bundle,
          slotId: found.slotIdBytes,
        );

    test('the whole flow, once', () async {
      expect(slot.code, matches(RegExp(r'^\d{6}$')));
      expect(slot.expiresAt, clock.now().add(pairingSlotLifetime));
      // A retry gets the same slot; another key's bundle is a mismatch.
      expect(
        (await init.createPairingSlot(initiator.bundle)).slotId,
        slot.slotId,
      );
      await expectLater(
        alice.createPairingSlot(initiator.bundle),
        _code(RelayErrorCode.keyMismatch),
      );

      final found = await bob.lookupPairingSlot(slot.code);
      expect(found.slotId, slot.slotId);
      expect(found.bundle.toJson(), initiator.bundle.toJson());
      expect((await bob.lookupPairingSlot(slot.slotId)).slotId, slot.slotId);

      final joiner = join(found, 6);
      addTearDown(joiner.result.identity.dispose);
      final j = alice.as(joiner.result.identity.publicIdentity.signingKey);
      await expectLater(
        j.replyToPairingSlot(slot.slotId, joiner.reply),
        _code(RelayErrorCode.inboxRequired),
      );
      await j.registerInbox(pushToken: null, platform: RelayPlatform.android);
      await expectLater(
        bob.replyToPairingSlot(slot.slotId, joiner.reply),
        _code(RelayErrorCode.keyMismatch),
      );
      expect(await init.readPairingReply(slot.slotId), isNull);
      await j.replyToPairingSlot(slot.slotId, joiner.reply);
      await j.replyToPairingSlot(slot.slotId, joiner.reply); // a retry
      await expectLater(
        bob.lookupPairingSlot(slot.code),
        _code(RelayErrorCode.slotUsed),
      );
      await expectLater(
        bob.readPairingReply(slot.slotId),
        _code(RelayErrorCode.slotNotFound),
      );

      final reply = await init.readPairingReply(slot.slotId);
      expect(reply!.toJson(), joiner.reply.toJson());
      expect(initiator.acceptReply(reply).safetyNumber, isNotEmpty);
      await expectLater(
        init.readPairingReply(slot.slotId),
        _code(RelayErrorCode.slotUsed),
      );
      await expectLater(
        j.replyToPairingSlot(slot.slotId, joiner.reply),
        _code(RelayErrorCode.slotUsed),
      );
    });

    test('the first reply wins; slots end after 10 minutes', () async {
      final found = await bob.lookupPairingSlot(slot.code);
      final first = join(found, 6);
      final second = join(found, 7);
      addTearDown(first.result.identity.dispose);
      addTearDown(second.result.identity.dispose);
      for (final j in [first, second]) {
        await alice
            .as(j.result.identity.publicIdentity.signingKey)
            .registerInbox(pushToken: null, platform: RelayPlatform.android);
      }
      await alice
          .as(first.result.identity.publicIdentity.signingKey)
          .replyToPairingSlot(slot.slotId, first.reply);
      await expectLater(
        alice
            .as(second.result.identity.publicIdentity.signingKey)
            .replyToPairingSlot(slot.slotId, second.reply),
        _code(RelayErrorCode.slotUsed),
      );

      clock.advance(pairingSlotLifetime);
      await expectLater(
        bob.lookupPairingSlot(slot.code),
        _code(RelayErrorCode.slotNotFound),
      );
      await expectLater(
        init.readPairingReply(slot.slotId),
        _code(RelayErrorCode.slotNotFound),
      );
    });

    test('another bundle from the same key is a conflict', () async {
      final other = PairingBundle.fromJson({
        ...initiator.bundle.toJson(),
        'ek_pub': base64Url.encode(Uint8List(32)..[0] = 9).replaceAll('=', ''),
      });
      await expectLater(
        init.createPairingSlot(other),
        _code(RelayErrorCode.slotConflict),
      );
    });
  });

  group('blobs', () {
    setUp(() => bob.allowSender(bobInbox, key(a)));
    final blob = _id(1);

    Future<void> put(int size, int chunk, Uint8List bytes, [String? id]) =>
        alice.putBlobChunk(
          bobInbox,
          id ?? blob,
          size: size,
          chunk: chunk,
          bytes: bytes,
        );

    test('order, repeats, conflicts and incomplete blobs', () async {
      const size = relayBlobChunkLength + 2;
      final c0 = Uint8List(relayBlobChunkLength)..[0] = 1;
      final c1 = Uint8List.fromList([2, 3]);
      await expectLater(
        put(size, 1, c1),
        throwsA(
          isA<RelayException>()
              .having((e) => e.code, 'code', RelayErrorCode.chunkOutOfOrder)
              .having((e) => e.nextChunk, 'next', 0),
        ),
      );
      await put(size, 0, c0);
      await put(size, 0, c0); // a retry
      await expectLater(
        put(size, 0, Uint8List(relayBlobChunkLength)),
        _code(RelayErrorCode.blobConflict),
      );
      await expectLater(
        put(size + 1, 0, c0),
        _code(RelayErrorCode.blobConflict),
      );
      await expectLater(
        bob.getBlobChunk(bobInbox, blob, 0),
        _code(RelayErrorCode.blobIncomplete),
      );
      await put(size, 1, c1);
      final got = await bob.getBlobChunk(bobInbox, blob, 1);
      expect(got.bytes, c1);
      expect(got.blobSize, size);
      await expectLater(
        alice.getBlobChunk(bobInbox, blob, 0),
        _code(RelayErrorCode.notInboxOwner),
      );
      await expectLater(
        bob.getBlobChunk(bobInbox, blob, 2),
        _code(RelayErrorCode.malformedRequest),
      );
      await expectLater(
        carol.deleteBlob(bobInbox, blob),
        _code(RelayErrorCode.senderNotAllowed),
      );
      await alice.deleteBlob(bobInbox, blob); // the sender may
      await bob.deleteBlob(bobInbox, blob); // already gone: fine
      await expectLater(
        bob.getBlobChunk(bobInbox, blob, 0),
        _code(RelayErrorCode.blobNotFound),
      );
    });

    test('a chunk past the next one names the next one', () async {
      const size = 3 * relayBlobChunkLength;
      await put(size, 0, Uint8List(relayBlobChunkLength), _id(2));
      await expectLater(
        put(size, 2, Uint8List(relayBlobChunkLength), _id(2)),
        throwsA(
          isA<RelayException>()
              .having((e) => e.code, 'code', RelayErrorCode.chunkOutOfOrder)
              .having((e) => e.nextChunk, 'next', 1),
        ),
      );
    });

    test('sizes and the 100 MiB quota', () async {
      await expectLater(
        put(maxRelayBlobLength + 1, 0, Uint8List(relayBlobChunkLength)),
        _code(RelayErrorCode.blobTooLarge),
      );
      await expectLater(
        put(10, 0, Uint8List(9)),
        _code(RelayErrorCode.malformedRequest),
      );
      for (var i = 0; i < 10; i++) {
        await put(
          maxRelayBlobLength,
          0,
          Uint8List(relayBlobChunkLength),
          _id(i + 10),
        );
      }
      await expectLater(
        put(1, 0, Uint8List(1), _id(30)),
        _code(RelayErrorCode.blobQuotaExceeded),
      );
      await bob.deleteBlob(bobInbox, _id(10));
      await put(1, 0, Uint8List(1), _id(30));
    });
  });

  test('failNext makes the next calls fail, on any client', () async {
    alice.failNext(
      const RelayException(RelayErrorCode.rateLimited, status: 429),
      times: 2,
    );
    await expectLater(bob.fetch(bobInbox), _code(RelayErrorCode.rateLimited));
    await expectLater(
      alice.fetch(aliceInbox),
      _code(RelayErrorCode.rateLimited),
    );
    expect((await bob.fetch(bobInbox)).envelopes, isEmpty);
  });

  test('an unchecked client cannot use the routes that need a key', () async {
    final plain = FakeRelayClient();
    expect(
      () => plain.registerInbox(pushToken: null, platform: RelayPlatform.ios),
      throwsStateError,
    );
    expect(() => plain.readPairingReply(_id(1)), throwsStateError);
  });
}
