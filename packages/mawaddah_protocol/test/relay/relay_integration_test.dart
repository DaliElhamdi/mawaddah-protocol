// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// [HttpRelayClient] against a real relay: the Worker in wrangler's local
/// runtime, started by `scripts/relay-integration.sh`, which sets
/// `MAWADDAH_RELAY_URL`. Without it these tests are skipped (a plain
/// `dart test`); the script fails if any is skipped.
library;

import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:sodium/sodium_sumo.dart' as na;
import 'package:test/test.dart';

import '../sync/sync_support.dart' show pairedDevice;

final _url = Platform.environment['MAWADDAH_RELAY_URL'];

/// These tests create inboxes and use up rate limits: only ever against a
/// relay on this computer, never staging or production.
bool get _local {
  final host = Uri.tryParse(_url ?? '')?.host;
  return host == '127.0.0.1' || host == 'localhost' || host == '::1';
}

/// The real time: the relay refuses requests more than 300 s off its clock.
final class _Now implements Clock {
  _Now([this.offset = Duration.zero]);
  final Duration offset;
  @override
  DateTime now() => DateTime.now().toUtc().add(offset);
}

/// Sends every request as if from [ip]. The local runtime takes the
/// `cf-connecting-ip` header as given (Cloudflare's edge sets it in
/// production), so each test has its own rate-limit buckets.
final class _From extends http.BaseClient {
  _From(this.ip);
  final String ip;
  final _inner = http.Client();
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    request.headers['cf-connecting-ip'] = ip;
    return _inner.send(request);
  }

  @override
  void close() => _inner.close();
}

void main() {
  late Crypto crypto;
  late RandomSource random;
  setUpAll(() async {
    final sodium = await na.SodiumSumoInit.init();
    crypto = SodiumCrypto(sodium);
    random = SodiumRandomSource(sodium);
  });

  var network = 0;

  /// A client from a new address; signs as [identity] if given.
  HttpRelayClient client(
    String ip, [
    DeviceIdentity? identity,
    Duration clockOffset = Duration.zero,
  ]) {
    final http = _From(ip);
    addTearDown(http.close);
    return HttpRelayClient(
      baseUrl: Uri.parse(_url!),
      httpClient: http,
      signer: identity == null
          ? null
          : RelayRequestSigner(
              crypto: crypto,
              identity: identity,
              clock: _Now(clockOffset),
              random: random,
            ),
      retryDelays: const [],
    );
  }

  String newIp() => '198.51.100.${++network}';

  Matcher code(RelayErrorCode c) =>
      throwsA(isA<RelayException>().having((e) => e.code, 'code', c));

  group(
    'local relay',
    skip: _url == null
        ? 'MAWADDAH_RELAY_URL not set'
        : _local
        ? false
        : 'MAWADDAH_RELAY_URL must be a relay on this computer',
    () {
      test('code path: pair, chat both ways, blobs, errors, delete', () async {
        final ip = newIp();

        // --- initiator: inbox and slot (PROTOCOL.md 4.5 step 1) ------------
        final initiator = PairingInitiator.start(
          crypto: crypto,
          random: random,
          clock: _Now(),
        );
        final bob = client(ip, initiator.identity);
        final bobInbox = await bob.registerInbox(
          pushToken: 'push-token-bob',
          platform: RelayPlatform.android,
        );
        expect(bobInbox, initiator.publicIdentity.deviceId.toBase64Url());
        final slot = await bob.createPairingSlot(initiator.bundle);
        expect(slot.code, matches(RegExp(r'^\d{6}$')));
        expect(
          slot.expiresAt.difference(DateTime.now().toUtc()).inMinutes,
          inInclusiveRange(9, 10),
        );
        expect(
          (await bob.createPairingSlot(initiator.bundle)).slotId,
          slot.slotId,
          reason: 'a retry gets the same slot',
        );
        expect(await bob.readPairingReply(slot.slotId), isNull);

        // --- joiner: code lookup (unsigned), keys, inbox, reply -------------
        final found = await client(ip).lookupPairingSlot(slot.code);
        expect(found.slotId, slot.slotId);
        expect(found.bundle.toJson(), initiator.bundle.toJson());
        final joiner = PairingJoiner.fromCode(
          crypto: crypto,
          random: random,
          bundle: found.bundle,
          slotId: found.slotIdBytes,
        );
        final alice = client(ip, joiner.result.identity);
        final aliceInbox = await alice.registerInbox(
          pushToken: null,
          platform: RelayPlatform.android,
        );
        await alice.replyToPairingSlot(slot.slotId, joiner.reply);
        await alice.replyToPairingSlot(slot.slotId, joiner.reply); // a retry

        // --- initiator reads the reply once (step 3) ------------------------
        final reply = await bob.readPairingReply(slot.slotId);
        expect(reply!.toJson(), joiner.reply.toJson());
        await expectLater(
          bob.readPairingReply(slot.slotId),
          code(RelayErrorCode.slotUsed),
        );
        await expectLater(
          client(ip).lookupPairingSlot(slot.code),
          code(RelayErrorCode.slotUsed),
        );
        final bobResult = initiator.acceptReply(reply);
        expect(bobResult.safetyNumber, joiner.result.safetyNumber);

        // --- both allow the partner (step 4) --------------------------------
        // Before Bob allows her, Alice's deposit is refused (retryable).
        await expectLater(
          alice.deposit(bobInbox, Uint8List(1)),
          throwsA(
            isA<RelayException>()
                .having((e) => e.code, 'code', RelayErrorCode.senderNotAllowed)
                .having((e) => e.retryable, 'retryable', isTrue),
          ),
        );
        await bob.allowSender(bobInbox, joiner.reply.signingKey.bytes);
        await alice.allowSender(aliceInbox, initiator.bundle.signingKey.bytes);
        await alice.allowSender(aliceInbox, initiator.bundle.signingKey.bytes);
        await expectLater(
          alice.allowSender(aliceInbox, Uint8List(32)..[0] = 1),
          code(RelayErrorCode.allowConflict),
        );

        // --- two sync engines over HTTP (step 5) -----------------------------
        final now = DateTime.now().toUtc();
        final a = await pairedDevice(
          crypto,
          name: 'alice',
          pairing: joiner.result,
          relay: alice,
          start: now,
          seed: 20,
        );
        final b = await pairedDevice(
          crypto,
          name: 'bob',
          pairing: bobResult,
          relay: bob,
          start: now,
          seed: 21,
        );
        for (var i = 0; i < 3; i++) {
          await a.say('salam $i');
        }
        final sent = await a.sync();
        expect(sent.relayError, isNull);
        expect(sent.envelopesSent, greaterThan(0));
        final got = await b.sync();
        expect(got.relayError, isNull);
        expect(got.complete, isTrue);
        expect(b.messages(), ['salam 0', 'salam 1', 'salam 2']);
        await b.say('wa alaykum salam');
        expect((await b.sync()).relayError, isNull);
        expect((await a.sync()).relayError, isNull);
        expect(a.messages().last, 'wa alaykum salam');
        expect((await alice.fetch(aliceInbox)).envelopes, isEmpty);

        // --- pages: more than 100 envelopes wait ----------------------------
        for (var i = 0; i < 103; i++) {
          await alice.deposit(bobInbox, Uint8List.fromList([i, 1, 2]));
        }
        final p1 = await bob.fetch(bobInbox);
        expect(p1.envelopes, hasLength(100));
        expect(p1.more, isTrue);
        final p2 = await bob.fetch(bobInbox, after: p1.envelopes.last.cursor);
        expect([for (final e in p2.envelopes) e.body[0]], [100, 101, 102]);
        expect(p2.more, isFalse);
        await expectLater(
          bob.ack(bobInbox, '${int.parse(p2.envelopes.last.cursor) + 1}'),
          code(RelayErrorCode.invalidCursor),
        );
        await bob.ack(bobInbox, p2.envelopes.last.cursor);
        expect((await bob.fetch(bobInbox)).envelopes, isEmpty);

        // --- a 64 KiB envelope of every byte value --------------------------
        final full = Uint8List.fromList(
          List.generate(maxEnvelopeLength, (i) => i & 255),
        );
        await alice.deposit(bobInbox, full, wake: true);
        final big = (await bob.fetch(bobInbox)).envelopes.single;
        expect(big.body, full);
        await bob.ack(bobInbox, big.cursor);

        // --- blobs: two chunks, every byte value ----------------------------
        final blobId = encodeRelayId(random.nextBytes(16));
        final file = Uint8List.fromList(
          List.generate(relayBlobChunkLength + 3, (i) => (i * 31 + 7) & 255),
        );
        await alice.uploadBlob(bobInbox, blobId, file);
        await alice.uploadBlob(bobInbox, blobId, file); // repeats are fine
        expect(await bob.downloadBlob(bobInbox, blobId), file);
        await bob.deleteBlob(bobInbox, blobId);
        await bob.deleteBlob(bobInbox, blobId); // already gone: fine
        await expectLater(
          bob.getBlobChunk(bobInbox, blobId, 0),
          code(RelayErrorCode.blobNotFound),
        );
        // Out of order: the relay names the chunk it expects.
        final other = encodeRelayId(random.nextBytes(16));
        await expectLater(
          alice.putBlobChunk(
            bobInbox,
            other,
            size: file.length,
            chunk: 1,
            bytes: Uint8List(3),
          ),
          throwsA(
            isA<RelayException>()
                .having((e) => e.code, 'code', RelayErrorCode.chunkOutOfOrder)
                .having((e) => e.nextChunk, 'next', 0),
          ),
        );
        await expectLater(
          alice.putBlobChunk(
            bobInbox,
            other,
            size: maxRelayBlobLength + 1,
            chunk: 0,
            bytes: Uint8List(relayBlobChunkLength),
          ),
          throwsRangeError,
          reason: 'refused before sending',
        );

        // --- push token, refusals ------------------------------------------
        await bob.setPushToken(bobInbox, 'push-token-bob-2');
        await bob.setPushToken(bobInbox, null);
        await expectLater(
          alice.fetch(bobInbox),
          code(RelayErrorCode.notInboxOwner),
        );
        await expectLater(
          bob.deposit(bobInbox, Uint8List(1)),
          code(RelayErrorCode.senderNotAllowed),
        );
        final skewed = client(
          ip,
          joiner.result.identity,
          const Duration(hours: 1),
        );
        try {
          await skewed.fetch(aliceInbox);
          fail('clock_skew expected');
        } on RelayException catch (e) {
          expect(e.code, RelayErrorCode.clockSkew);
          expect(
            e.serverTime!.difference(DateTime.now().toUtc()).inSeconds.abs(),
            lessThan(60),
          );
          expect(e.retryable, isFalse);
        }

        // --- delete (unpair) -------------------------------------------------
        await alice.deleteInbox(aliceInbox);
        await alice.deleteInbox(aliceInbox); // already gone: fine
        await expectLater(
          bob.deposit(aliceInbox, Uint8List(1)),
          code(RelayErrorCode.inboxNotFound),
        );
        await bob.deleteInbox(bobInbox);
        for (final r in [bobResult, joiner.result]) {
          r.identity.dispose();
        }
      });

      test('QR path: the joiner needs no lookup', () async {
        final ip = newIp();
        final initiator = PairingInitiator.start(
          crypto: crypto,
          random: random,
          clock: _Now(),
        );
        final bob = client(ip, initiator.identity);
        await bob.registerInbox(pushToken: null, platform: RelayPlatform.ios);
        final slot = await bob.createPairingSlot(initiator.bundle);
        final joiner = PairingJoiner.fromQr(
          crypto: crypto,
          random: random,
          qrText: initiator.qr(slot.slotIdBytes).encode(),
        );
        final alice = client(ip, joiner.result.identity);
        await alice.registerInbox(pushToken: null, platform: RelayPlatform.ios);
        await alice.replyToPairingSlot(slot.slotId, joiner.reply);
        final reply = await bob.readPairingReply(slot.slotId);
        final result = initiator.acceptReply(reply!);
        expect(result.path, PairingPath.qr);
        expect(result.safetyNumber, joiner.result.safetyNumber);
        await bob.deleteInbox(result.identity.deviceId.toBase64Url());
        await alice.deleteInbox(joiner.result.identity.deviceId.toBase64Url());
        result.identity.dispose();
        joiner.result.identity.dispose();
      });

      test('rate limits: registrations and wrong codes, per network', () async {
        final ip = newIp();
        final ids = [
          for (var i = 0; i < 6; i++) DeviceIdentity.generate(crypto, random),
        ];
        addTearDown(() {
          for (final d in ids) {
            d.dispose();
          }
        });
        for (final d in ids.take(5)) {
          await client(
            ip,
            d,
          ).registerInbox(pushToken: null, platform: RelayPlatform.android);
        }
        // Registering an existing inbox again is not counted.
        await client(
          ip,
          ids.first,
        ).registerInbox(pushToken: 'x', platform: RelayPlatform.android);
        try {
          await client(
            ip,
            ids.last,
          ).registerInbox(pushToken: null, platform: RelayPlatform.android);
          fail('rate_limited expected');
        } on RelayException catch (e) {
          expect(e.code, RelayErrorCode.rateLimited);
          expect(e.status, 429);
          expect(e.retryAfter!.inSeconds, inInclusiveRange(1, 3600));
          expect(e.retryable, isTrue);
        }
        // Another network is not limited.
        await client(
          newIp(),
          ids.last,
        ).registerInbox(pushToken: null, platform: RelayPlatform.android);

        final lookups = client(newIp());
        for (var i = 0; i < 5; i++) {
          await expectLater(
            lookups.lookupPairingSlot('00000$i'),
            code(RelayErrorCode.slotNotFound),
          );
        }
        try {
          await lookups.lookupPairingSlot('000009');
          fail('rate_limited expected');
        } on RelayException catch (e) {
          expect(e.code, RelayErrorCode.rateLimited);
          expect(e.retryAfter!.inSeconds, inInclusiveRange(1, 600));
        }
        for (final d in ids) {
          await client(newIp(), d).deleteInbox(d.deviceId.toBase64Url());
        }
      });

      test('unknown routes and bad bodies get stable codes', () async {
        // Straight HTTP: things the client never sends.
        final base = Uri.parse(_url!);
        final h = _From(newIp());
        addTearDown(h.close);
        final r = await h.get(base.replace(path: '/v1/nothing'));
        expect(r.statusCode, 404);
        expect(jsonDecode(r.body), {'error': 'not_found'});
        final health = await h.get(base.replace(path: '/health'));
        expect(jsonDecode(health.body), {'ok': true});
      });
    },
  );
}
