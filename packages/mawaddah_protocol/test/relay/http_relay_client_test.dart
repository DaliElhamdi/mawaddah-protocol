// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

String _b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');

/// A relay ID made of one repeated byte.
String _id(int byte) => encodeRelayId(Uint8List(16)..fillRange(0, 16, byte));

http.Response _json(Object body, [int status = 200, Map<String, String>? h]) =>
    http.Response(
      jsonEncode(body),
      status,
      headers: {'content-type': 'application/json', ...?h},
    );

http.Response _err(String code, int status, [Map<String, Object?>? extra]) =>
    _json({'error': code, ...?extra}, status);

void main() {
  late Crypto crypto;
  late DeviceIdentity identity;
  late FakeClock clock;
  late String inbox;
  setUpAll(() async => crypto = await SodiumCrypto.load());
  setUp(() {
    identity = DeviceIdentity.generate(crypto, SeededRandom(1));
    inbox = identity.deviceId.toBase64Url();
    clock = FakeClock(DateTime.utc(2026, 11, 11, 12));
  });
  tearDown(() => identity.dispose());

  final base = Uri.parse('https://relay.example');

  /// A client whose transport is [handler]; every request is recorded.
  ({HttpRelayClient client, List<http.Request> sent, List<Duration> slept})
  make(
    FutureOr<http.Response> Function(http.Request) handler, {
    bool signed = true,
    Duration timeout = const Duration(seconds: 30),
  }) {
    final sent = <http.Request>[];
    final slept = <Duration>[];
    final client = HttpRelayClient(
      baseUrl: base,
      signer: signed
          ? RelayRequestSigner(
              crypto: crypto,
              identity: identity,
              clock: clock,
              random: SeededRandom(9),
            )
          : null,
      httpClient: MockClient((r) async {
        sent.add(r);
        return handler(r);
      }),
      timeout: timeout,
      sleep: (d) async => slept.add(d),
    );
    return (client: client, sent: sent, slept: slept);
  }

  /// Checks [r] carries a valid signature by [identity] over exactly what
  /// was sent.
  void expectSigned(http.Request r) {
    final h = r.headers;
    expect(h['Maw-Key'], _b64(identity.publicIdentity.signingKey.bytes));
    expect(h['Maw-Timestamp'], '${clock.now().millisecondsSinceEpoch ~/ 1000}');
    final input = RelayRequestSigner.signingInput(
      method: r.method,
      pathAndQuery: r.url.hasQuery
          ? '${r.url.path}?${r.url.query}'
          : r.url.path,
      body: r.bodyBytes,
      timestamp: int.parse(h['Maw-Timestamp']!),
      nonce: h['Maw-Nonce']!,
    );
    final sig = base64Url.decode(base64Url.normalize(h['Maw-Signature']!));
    expect(
      crypto.verify(
        identity.publicIdentity.signingKey,
        input,
        Ed25519Signature(Uint8List.fromList(sig)),
      ),
      isTrue,
    );
  }

  group('base URL', () {
    HttpRelayClient at(String url) => HttpRelayClient(
      baseUrl: Uri.parse(url),
      httpClient: MockClient((_) {
        throw StateError('no request expected');
      }),
    );

    test('an https origin, or plain http to this computer only', () {
      for (final ok in [
        'https://relay.example',
        'https://relay.example/',
        'https://relay.example:8443',
        'http://localhost:8787',
        'http://127.0.0.1:8787',
        'http://[::1]:8787',
        'http://10.0.2.2:8787',
      ]) {
        expect(() => at(ok), returnsNormally, reason: ok);
      }
      // The error shows the scheme and host only.
      try {
        at('ftp://user:pw@relay.example/?k=v');
        fail('refused expected');
      } on ArgumentError catch (e) {
        expect('$e', contains('ftp://relay.example'));
        expect('$e', isNot(contains('pw')));
        expect('$e', isNot(contains('k=v')));
      }
      for (final bad in [
        'http://relay.example',
        'http://192.168.1.10:8787',
        'ftp://relay.example',
        'https://relay.example/v1',
        'https://relay.example/?a=b',
        'https://relay.example/#x',
        'https://user:pw@relay.example',
        'relay.example',
      ]) {
        expect(() => at(bad), throwsArgumentError, reason: bad);
      }
    });

    test('requests go to the origin with the exact signed path', () async {
      final t = make((_) => _json({'envelopes': <Object?>[], 'more': false}));
      await t.client.fetch(inbox, after: '17');
      expect(
        t.sent.single.url.toString(),
        'https://relay.example/v1/inbox/$inbox/envelopes?after=17',
      );
      expectSigned(t.sent.single);
    });
  });

  group('routes', () {
    test('registerInbox: body, signature, and the ID is checked', () async {
      final t = make((_) => _json({'inbox_id': inbox}, 201));
      expect(
        await t.client.registerInbox(
          pushToken: 'tok',
          platform: RelayPlatform.android,
        ),
        inbox,
      );
      final r = t.sent.single;
      expect(r.method, 'POST');
      expect(r.url.path, '/v1/inbox');
      expect(r.headers['content-type'], startsWith('application/json'));
      expect(jsonDecode(r.body), {
        'signing_key': _b64(identity.publicIdentity.signingKey.bytes),
        'push_token': 'tok',
        'platform': 'android',
      });
      expectSigned(r);

      // A relay that answers another ID would misroute the envelopes.
      final lying = make((_) => _json({'inbox_id': _id(7)}, 201));
      await expectLater(
        lying.client.registerInbox(
          pushToken: null,
          platform: RelayPlatform.ios,
        ),
        throwsA(_code(RelayErrorCode.invalidResponse)),
      );
      expect(jsonDecode(lying.sent.first.body)['push_token'], isNull);
    });

    test('pairing slot: create, lookup (unsigned), reply, read', () async {
      final initiator = PairingInitiator.start(
        crypto: crypto,
        random: SeededRandom(2),
        clock: clock,
      );
      addTearDown(initiator.abandon);
      final bundle = initiator.bundle.toJson();
      final slotId = _id(3);

      var t = make(
        (_) => _json({'slot_id': slotId, 'code': '004217', 'expires_at': 99}),
      );
      final slot = await t.client.createPairingSlot(initiator.bundle);
      expect(slot.slotId, slotId);
      expect(slot.code, '004217');
      expect(slot.expiresAt, DateTime.utc(1970, 1, 1, 0, 1, 39));
      expect(slot.slotIdBytes, hasLength(16));
      expect(t.sent.single.url.path, '/v1/pairing-slot');
      expect(jsonDecode(t.sent.single.body), bundle);
      expectSigned(t.sent.single);

      t = make(
        (_) => _json({'slot_id': slotId, 'bundle': bundle}),
        signed: false,
      );
      final found = await t.client.lookupPairingSlot('004217');
      expect(found.slotId, slotId);
      expect(found.bundle.toJson(), bundle);
      expect(t.sent.single.method, 'GET');
      expect(t.sent.single.url.path, '/v1/pairing-slot/004217');
      expect(
        t.sent.single.headers.keys.where((k) => k.startsWith('Maw-')),
        isEmpty,
      );

      final joiner = PairingJoiner.fromCode(
        crypto: crypto,
        random: SeededRandom(4),
        bundle: found.bundle,
        slotId: found.slotIdBytes,
      );
      addTearDown(joiner.result.identity.dispose);
      t = make((_) => _json({}, 201));
      await t.client.replyToPairingSlot(slotId, joiner.reply);
      expect(t.sent.single.url.path, '/v1/pairing-slot/$slotId/reply');
      expect(jsonDecode(t.sent.single.body), joiner.reply.toJson());
      expectSigned(t.sent.single);

      t = make((_) => _json({'reply': null}));
      expect(await t.client.readPairingReply(slotId), isNull);
      expect(t.sent.single.method, 'GET');
      expectSigned(t.sent.single);
      t = make((_) => _json({'reply': joiner.reply.toJson()}));
      expect(
        (await t.client.readPairingReply(slotId))!.toJson(),
        joiner.reply.toJson(),
      );
    });

    test('pairing answers that do not fit are bad responses', () async {
      final initiator = PairingInitiator.start(
        crypto: crypto,
        random: SeededRandom(2),
        clock: clock,
      );
      addTearDown(initiator.abandon);
      final bundle = initiator.bundle.toJson();
      for (final body in [
        {'slot_id': _id(3), 'code': '12345', 'expires_at': 1},
        {'slot_id': 'short', 'code': '123456', 'expires_at': 1},
        {'slot_id': _id(3), 'code': '123456', 'expires_at': '1'},
      ]) {
        await expectLater(
          make((_) => _json(body)).client.createPairingSlot(initiator.bundle),
          throwsA(_code(RelayErrorCode.invalidResponse)),
          reason: '$body',
        );
      }
      for (final body in [
        {'slot_id': _id(3)},
        {
          'slot_id': _id(3),
          'bundle': {...bundle, 'sig': 'AA'},
        },
        // Looked up by slot ID: the answer must be that slot.
        {'slot_id': _id(4), 'bundle': bundle},
      ]) {
        await expectLater(
          make(
            (_) => _json(body),
            signed: false,
          ).client.lookupPairingSlot(_id(3)),
          throwsA(_code(RelayErrorCode.invalidResponse)),
          reason: '$body',
        );
      }
      for (final body in [
        <String, Object?>{},
        {'reply': 'x'},
        {
          'reply': {'v': 1},
        },
      ]) {
        await expectLater(
          make((_) => _json(body)).client.readPairingReply(_id(3)),
          throwsA(_code(RelayErrorCode.invalidResponse)),
          reason: '$body',
        );
      }
    });

    test('allow, ack, push token, delete inbox: method, path, body', () async {
      final t = make((_) => _json({}));
      final key = Uint8List(32)..[0] = 1;
      await t.client.allowSender(inbox, key);
      await t.client.ack(inbox, '42');
      await t.client.setPushToken(inbox, 'new');
      await t.client.setPushToken(inbox, null);
      await t.client.deleteInbox(inbox);
      expect(
        [for (final r in t.sent) '${r.method} ${r.url.path}'],
        [
          'POST /v1/inbox/$inbox/allow',
          'POST /v1/inbox/$inbox/ack',
          'POST /v1/inbox/$inbox/push-token',
          'POST /v1/inbox/$inbox/push-token',
          'DELETE /v1/inbox/$inbox',
        ],
      );
      expect(
        [for (final r in t.sent.take(4)) jsonDecode(r.body)],
        [
          {'sender_key': _b64(key)},
          {'cursor': '42'},
          {'push_token': 'new'},
          {'push_token': null},
        ],
      );
      expect(t.sent.last.bodyBytes, isEmpty);
      t.sent.forEach(expectSigned);
    });

    test('deposit: raw bytes and the wake header', () async {
      final t = make((_) => _json({}, 201));
      final partner = _id(5);
      final body = Uint8List.fromList(List.generate(256, (i) => i));
      await t.client.deposit(partner, body, wake: true);
      await t.client.deposit(partner, body);
      for (final (i, r) in t.sent.indexed) {
        expect(r.method, 'PUT');
        expect(r.url.path, '/v1/inbox/$partner/envelopes');
        expect(r.headers['content-type'], 'application/octet-stream');
        expect(r.bodyBytes, body);
        expect(r.headers['Maw-Wake'], i == 0 ? '1' : '0');
        expectSigned(r);
      }
      await expectLater(
        t.client.deposit(partner, Uint8List(0)),
        throwsArgumentError,
      );
      await expectLater(
        t.client.deposit(partner, Uint8List(maxEnvelopeLength + 1)),
        throwsArgumentError,
      );
      expect(t.sent, hasLength(2));
    });

    test('fetch: decodes the page and checks it', () async {
      final a = Uint8List.fromList([1, 2, 3]);
      final b = Uint8List.fromList(List.filled(65536, 255));
      final t = make(
        (_) => _json({
          'envelopes': [
            {'cursor': '9', 'body': _b64(a)},
            {'cursor': '10', 'body': _b64(b)},
          ],
          'more': true,
        }),
      );
      final page = await t.client.fetch(inbox);
      expect(t.sent.single.url.hasQuery, isFalse);
      expect([for (final e in page.envelopes) e.cursor], ['9', '10']);
      expect(page.envelopes[0].body, a);
      expect(page.envelopes[1].body, b);
      expect(page.more, isTrue);

      for (final body in <Object>[
        {'envelopes': <Object?>[]},
        {'envelopes': <Object?>[], 'more': true}, // "more" with nothing
        {
          'envelopes': [
            {'cursor': '10', 'body': 'AQ'},
            {'cursor': '9', 'body': 'AQ'}, // goes back
          ],
          'more': false,
        },
        {
          'envelopes': [
            {'cursor': '5', 'body': 'AQ'}, // not after "after"
          ],
          'more': false,
        },
        {
          'envelopes': [
            {'cursor': '09', 'body': 'AQ'},
          ],
          'more': false,
        },
        {
          'envelopes': [
            {'cursor': '11', 'body': 'AQ=='}, // padded
          ],
          'more': false,
        },
        {
          'envelopes': [
            {'cursor': '11', 'body': 'AR'}, // not canonical
          ],
          'more': false,
        },
        {
          'envelopes': [
            {'cursor': '11', 'body': ''},
          ],
          'more': false,
        },
        {
          'envelopes': [
            {'cursor': '11', 'body': _b64(Uint8List(65537))},
          ],
          'more': false,
        },
      ]) {
        await expectLater(
          make((_) => _json(body)).client.fetch(inbox, after: '5'),
          throwsA(_code(RelayErrorCode.invalidResponse)),
          reason: '$body',
        );
      }
    });

    test('an answer that is not a JSON object is a bad response', () async {
      await expectLater(
        make((_) => _json(<Object?>[])).client.fetch(inbox),
        throwsA(_code(RelayErrorCode.badResponse)),
      );
    });

    test('blob chunks: path, query, raw bytes and the size header', () async {
      final blob = _id(6);
      final partner = _id(5);
      final t = make(
        (r) => r.method == 'GET'
            ? http.Response.bytes(
                [7, 8, 9],
                200,
                headers: {'maw-blob-size': '1048579'},
              )
            : _json({}, 201),
      );
      await t.client.putBlobChunk(
        partner,
        blob,
        size: relayBlobChunkLength + 3,
        chunk: 1,
        bytes: Uint8List.fromList([1, 2, 3]),
      );
      final got = await t.client.getBlobChunk(inbox, blob, 1);
      await t.client.deleteBlob(inbox, blob);
      expect(
        [for (final r in t.sent) '${r.method} ${r.url}'],
        [
          'PUT https://relay.example/v1/inbox/$partner/blobs/$blob'
              '?size=1048579&chunk=1',
          'GET https://relay.example/v1/inbox/$inbox/blobs/$blob?chunk=1',
          'DELETE https://relay.example/v1/inbox/$inbox/blobs/$blob',
        ],
      );
      expect(t.sent.first.bodyBytes, [1, 2, 3]);
      expect(t.sent.first.headers['content-type'], 'application/octet-stream');
      t.sent.forEach(expectSigned);
      expect(got.bytes, [7, 8, 9]);
      expect(got.blobSize, relayBlobChunkLength + 3);

      // A chunk of the wrong length is refused before sending.
      await expectLater(
        t.client.putBlobChunk(
          partner,
          blob,
          size: relayBlobChunkLength + 3,
          chunk: 0,
          bytes: Uint8List(3),
        ),
        throwsArgumentError,
      );
      // A blob of 1 MiB + 3: chunk 0 must be a full 1 MiB, chunk 1 exactly
      // 3 bytes; there is no chunk 2.
      for (final (index, length) in [
        (0, relayBlobChunkLength - 1),
        (1, 2),
        (1, 4),
        (2, 3),
      ]) {
        await expectLater(
          make(
            (_) => http.Response.bytes(
              Uint8List(length),
              200,
              headers: {'maw-blob-size': '${relayBlobChunkLength + 3}'},
            ),
          ).client.getBlobChunk(inbox, blob, index),
          throwsA(_code(RelayErrorCode.invalidResponse)),
          reason: 'chunk $index of $length bytes',
        );
      }
      for (final body in [Uint8List(0), Uint8List(relayBlobChunkLength + 1)]) {
        await expectLater(
          make(
            (_) => http.Response.bytes(
              body,
              200,
              headers: {'maw-blob-size': '$maxRelayBlobLength'},
            ),
          ).client.getBlobChunk(inbox, blob, 0),
          throwsA(_code(RelayErrorCode.invalidResponse)),
          reason: '${body.length} bytes',
        );
      }
      for (final size in [null, '0', '010', '10485761', 'x']) {
        await expectLater(
          make(
            (_) => http.Response.bytes(
              [1],
              200,
              headers: {'maw-blob-size': ?size},
            ),
          ).client.getBlobChunk(inbox, blob, 0),
          throwsA(_code(RelayErrorCode.invalidResponse)),
          reason: '$size',
        );
      }
    });

    test('bad IDs and cursors are refused before sending', () async {
      final t = make((_) => _json({}));
      for (final call in <Future<void> Function()>[
        () => t.client.fetch('short'),
        () => t.client.fetch(inbox, after: '01'),
        () => t.client.fetch(inbox, after: '-1'),
        () => t.client.ack(inbox, '1&x=2'),
        () => t.client.deposit('../x', Uint8List(1)),
        () => t.client.allowSender(inbox, Uint8List(31)),
        () => t.client.deleteBlob(inbox, '${'A' * 21}B'),
        () => t.client.lookupPairingSlot('12345'),
        () => t.client.lookupPairingSlot('../inbox'),
        () => t.client.readPairingReply('x'),
      ]) {
        await expectLater(call(), throwsArgumentError);
      }
      // The error names the parameter, never the value (a code, an ID).
      for (final call in <Future<void> Function()>[
        () => t.client.lookupPairingSlot('12345'),
        () => t.client.fetch('${_id(1)}x'),
        () => t.client.ack(inbox, '0123'),
      ]) {
        try {
          await call();
          fail('ArgumentError expected');
        } on ArgumentError catch (e) {
          expect('$e', isNot(contains('12345')));
          expect('$e', isNot(contains(_id(1))));
          expect('$e', isNot(contains('0123')));
        }
      }
      expect(t.sent, isEmpty);
    });

    test('signed routes need a signer; the lookup does not', () async {
      final t = make((_) => _json({}), signed: false);
      await expectLater(t.client.deleteInbox(inbox), throwsStateError);
      await expectLater(
        t.client.registerInbox(pushToken: null, platform: RelayPlatform.ios),
        throwsStateError,
      );
      expect(t.sent, isEmpty);
    });
  });

  group('errors', () {
    test('every relay code maps to its RelayErrorCode', () async {
      final relayCodes = RelayErrorCode.values.where(
        (c) => !{
          RelayErrorCode.unknown,
          RelayErrorCode.network,
          RelayErrorCode.timeout,
          RelayErrorCode.badResponse,
          RelayErrorCode.invalidResponse,
        }.contains(c),
      );
      // The relay's table (relay/README.md, "Errors"): 30 codes.
      expect(relayCodes, hasLength(30));
      for (final c in relayCodes) {
        final t = make((_) => _err(c.wireName, 409));
        try {
          await t.client.deleteInbox(inbox);
          fail('no error');
        } on RelayException catch (e) {
          expect(e.code, c);
          expect(e.status, 409);
        }
      }
    });

    test('extra fields: retry_after, server_time, next_chunk', () async {
      RelayException? caught;
      Future<void> run(http.Response r) async {
        try {
          await make((_) => r).client.deleteInbox(inbox);
        } on RelayException catch (e) {
          caught = e;
        }
      }

      await run(_err('rate_limited', 429, {'retry_after': 600}));
      expect(caught!.retryAfter, const Duration(minutes: 10));
      expect(caught!.retryable, isTrue);
      await run(_json({'error': 'rate_limited'}, 429, {'retry-after': '30'}));
      expect(caught!.retryAfter, const Duration(seconds: 30));
      // A wait longer than any relay window is capped.
      await run(_err('rate_limited', 429, {'retry_after': 86400}));
      expect(caught!.retryAfter, HttpRelayClient.maxRetryAfter);
      await run(_err('clock_skew', 401, {'server_time': 1800000000}));
      expect(caught!.serverTime, DateTime.utc(2027, 1, 15, 8));
      expect(caught!.retryable, isFalse);
      await run(_err('chunk_out_of_order', 409, {'next_chunk': 3}));
      expect(caught!.nextChunk, 3);
    });

    test('unknown codes, non-JSON and redirects', () async {
      Future<RelayException> run(http.Response r) async {
        try {
          await make((_) => r).client.ack(inbox, '1');
        } on RelayException catch (e) {
          return e;
        }
        throw StateError('no error');
      }

      var e = await run(_err('brand_new_code', 409));
      expect(e.code, RelayErrorCode.unknown);
      expect(e.retryable, isFalse);
      e = await run(_err('brand_new_code', 503));
      expect(e.retryable, isTrue);
      e = await run(http.Response('<html>Bad gateway</html>', 502));
      expect(e.code, RelayErrorCode.badResponse);
      expect(e.status, 502);
      e = await run(
        http.Response('', 302, headers: {'location': 'https://elsewhere'}),
      );
      expect(e.code, RelayErrorCode.badResponse);
      // A 200 that is not the JSON object the route returns.
      e = await run(http.Response('[]', 200));
      expect(e.code, RelayErrorCode.badResponse);
    });

    test('redirects are never followed', () async {
      final t = make((_) => _json({}));
      await t.client.ack(inbox, '1');
      expect(t.sent.single.followRedirects, isFalse);
    });

    test('the exception names no URL, ID or body', () async {
      final e = RelayException(
        RelayErrorCode.rateLimited,
        status: 429,
        retryAfter: const Duration(seconds: 5),
      );
      expect('$e', 'RelayException(rate_limited, status 429, retry after 5 s)');
      final t = make((_) => throw http.ClientException('boom', base));
      try {
        await t.client.deleteInbox(inbox);
      } on RelayException catch (e) {
        expect(e.code, RelayErrorCode.network);
        expect('$e', isNot(contains('relay.example')));
        expect('$e', isNot(contains(inbox)));
      }
    });

    test('retryable says which refusals may pass later', () {
      bool r(RelayErrorCode c, [int? s]) =>
          RelayException(c, status: s).retryable;
      for (final c in [
        RelayErrorCode.senderNotAllowed,
        RelayErrorCode.inboxFull,
        RelayErrorCode.blobQuotaExceeded,
        RelayErrorCode.blobIncomplete,
        RelayErrorCode.rateLimited,
        RelayErrorCode.slotsFull,
        RelayErrorCode.internalError,
        RelayErrorCode.nonceReused,
        RelayErrorCode.network,
        RelayErrorCode.timeout,
        RelayErrorCode.badResponse,
      ]) {
        expect(r(c), isTrue, reason: c.name);
      }
      for (final c in [
        RelayErrorCode.keyMismatch,
        RelayErrorCode.malformedRequest,
        RelayErrorCode.notInboxOwner,
        RelayErrorCode.allowConflict,
        RelayErrorCode.invalidCursor,
        RelayErrorCode.inboxConflict,
        RelayErrorCode.slotConflict,
        RelayErrorCode.slotUsed,
        RelayErrorCode.slotNotFound,
        RelayErrorCode.inboxNotFound,
        RelayErrorCode.blobConflict,
        RelayErrorCode.blobTooLarge,
        RelayErrorCode.blobNotFound,
        RelayErrorCode.clockSkew,
        RelayErrorCode.badSignature,
        RelayErrorCode.invalidResponse,
      ]) {
        expect(r(c), isFalse, reason: c.name);
      }
      expect(r(RelayErrorCode.unknown, 500), isTrue);
      expect(r(RelayErrorCode.unknown, 409), isFalse);
      expect(r(RelayErrorCode.unknown), isFalse);
    });
  });

  group('retries', () {
    test('a passing fault is tried again, with a fresh signature', () async {
      var n = 0;
      final t = make((_) {
        n++;
        if (n == 1) throw http.ClientException('connection reset');
        if (n == 2) return _err('internal_error', 500);
        return _json({});
      });
      clock.advance(Duration.zero);
      await t.client.ack(inbox, '3');
      expect(t.sent, hasLength(3));
      expect(t.slept, [const Duration(seconds: 1), const Duration(seconds: 3)]);
      final nonces = {for (final r in t.sent) r.headers['Maw-Nonce']};
      expect(nonces, hasLength(3));
      t.sent.forEach(expectSigned);
    });

    test('gives up after the last delay with the last error', () async {
      final t = make((_) => http.Response('oops', 503));
      await expectLater(
        t.client.deleteInbox(inbox),
        throwsA(_code(RelayErrorCode.badResponse)),
      );
      expect(t.sent, hasLength(3));
    });

    test('refusals are not retried here: the caller decides', () async {
      for (final code in [
        'rate_limited',
        'inbox_full',
        'sender_not_allowed',
        'slots_full',
        'clock_skew',
      ]) {
        final t = make((_) => _err(code, 409));
        await expectLater(
          t.client.deleteInbox(inbox),
          throwsA(isA<RelayException>()),
        );
        expect(t.sent, hasLength(1), reason: code);
        expect(t.slept, isEmpty);
      }
    });

    test('deposit is tried once (the engine resends the same bytes)', () async {
      final t = make((_) => throw http.ClientException('dropped'));
      await expectLater(
        t.client.deposit(_id(5), Uint8List(1)),
        throwsA(_code(RelayErrorCode.network)),
      );
      expect(t.sent, hasLength(1));
    });

    test('a code lookup is tried once; a slot-ID lookup is retried', () async {
      var t = make((_) => throw http.ClientException('dropped'), signed: false);
      await expectLater(
        t.client.lookupPairingSlot('123456'),
        throwsA(_code(RelayErrorCode.network)),
      );
      expect(t.sent, hasLength(1));
      t = make((_) => throw http.ClientException('dropped'), signed: false);
      await expectLater(
        t.client.lookupPairingSlot(_id(3)),
        throwsA(_code(RelayErrorCode.network)),
      );
      expect(t.sent, hasLength(3));
    });

    test('an invalid answer is not retried', () async {
      final t = make((_) => _json({'inbox_id': _id(7)}, 201));
      await expectLater(
        t.client.registerInbox(pushToken: null, platform: RelayPlatform.ios),
        throwsA(_code(RelayErrorCode.invalidResponse)),
      );
      expect(t.sent, hasLength(1));
    });

    test(
      'readPairingReply is tried once (the reply can be read once)',
      () async {
        final t = make((_) => throw http.ClientException('dropped'));
        await expectLater(
          t.client.readPairingReply(_id(3)),
          throwsA(_code(RelayErrorCode.network)),
        );
        expect(t.sent, hasLength(1));
      },
    );

    test('no retry delays: one try', () async {
      final sent = <http.Request>[];
      final client = HttpRelayClient(
        baseUrl: base,
        signer: RelayRequestSigner(
          crypto: crypto,
          identity: identity,
          clock: clock,
          random: SeededRandom(9),
        ),
        httpClient: MockClient((r) async {
          sent.add(r);
          throw http.ClientException('down');
        }),
        retryDelays: const [],
      );
      await expectLater(
        client.deleteInbox(inbox),
        throwsA(_code(RelayErrorCode.network)),
      );
      expect(sent, hasLength(1));
    });

    test('a try that takes too long is a timeout, and is retried', () async {
      final never = Completer<http.Response>();
      final t = make(
        (_) => never.future,
        timeout: const Duration(milliseconds: 20),
      );
      await expectLater(
        t.client.deleteInbox(inbox),
        throwsA(_code(RelayErrorCode.timeout)),
      );
      expect(t.sent, hasLength(3));
    });

    test('a JSON answer over the size limit is refused', () async {
      String page(int pad) =>
          jsonEncode({'envelopes': <Object?>[], 'more': false, 'x': 'a' * pad});
      final limit = HttpRelayClient.maxResponseLength;
      final fits = page(0).length;
      expect(
        (await make((_) => http.Response(page(limit - fits), 200)).client
                .fetch(inbox))
            .envelopes,
        isEmpty,
      );
      await expectLater(
        make((_) => http.Response(page(limit - fits + 1), 200)).client
            .fetch(inbox),
        throwsA(_code(RelayErrorCode.badResponse)),
      );
    });

    test('an answer over the size limit is refused', () async {
      final t = make(
        (_) => http.Response.bytes(
          Uint8List(HttpRelayClient.maxResponseLength + 1),
          200,
          headers: {'maw-blob-size': '1'},
        ),
      );
      await expectLater(
        t.client.getBlobChunk(inbox, _id(6), 0),
        throwsA(_code(RelayErrorCode.badResponse)),
      );
    });
  });

  group('whole blobs (over the fake relay)', () {
    late FakeRelayClient alice, bob;
    late String bobInbox;
    late DeviceIdentity bobId;
    setUp(() async {
      bobId = DeviceIdentity.generate(crypto, SeededRandom(11));
      alice = FakeRelayClient(signingKey: identity.publicIdentity.signingKey);
      bob = alice.as(bobId.publicIdentity.signingKey);
      bobInbox = await bob.registerInbox(
        pushToken: null,
        platform: RelayPlatform.android,
      );
      await bob.allowSender(bobInbox, identity.publicIdentity.signingKey.bytes);
    });
    tearDown(() => bobId.dispose());

    Uint8List file(int n) =>
        Uint8List.fromList(List.generate(n, (i) => (i * 7 + i ~/ 256) & 255));

    for (final n in [1, relayBlobChunkLength, relayBlobChunkLength + 3]) {
      test('$n bytes: upload, download, delete', () async {
        final data = file(n);
        await alice.uploadBlob(bobInbox, _id(1), data);
        expect(await bob.downloadBlob(bobInbox, _id(1)), data);
        await bob.deleteBlob(bobInbox, _id(1));
        expect(alice.blobIdsOf(bobInbox), isEmpty);
      });
    }

    test('an upload cut off part-way resumes where the relay is', () async {
      final data = file(3 * relayBlobChunkLength + 5);
      await alice.putBlobChunk(
        bobInbox,
        _id(2),
        size: data.length,
        chunk: 0,
        bytes: Uint8List.sublistView(data, 0, relayBlobChunkLength),
      );
      await alice.putBlobChunk(
        bobInbox,
        _id(2),
        size: data.length,
        chunk: 1,
        bytes: Uint8List.sublistView(
          data,
          relayBlobChunkLength,
          2 * relayBlobChunkLength,
        ),
      );
      await alice.uploadBlob(bobInbox, _id(2), data);
      expect(await bob.downloadBlob(bobInbox, _id(2)), data);
    });

    test('a blob lost mid-upload is uploaded again from chunk 0', () async {
      final data = file(3 * relayBlobChunkLength);
      final losing = _LosesBlobAfter(alice, bob, chunk: 1);
      await losing.uploadBlob(bobInbox, _id(7), data);
      expect(losing.puts, [0, 1, 2, 0, 1, 2]);
      expect(await bob.downloadBlob(bobInbox, _id(7)), data);
    });

    test('other failures stop the upload', () async {
      final data = file(10);
      await alice.uploadBlob(bobInbox, _id(3), data);
      await expectLater(
        alice.uploadBlob(bobInbox, _id(3), file(11)),
        throwsA(_code(RelayErrorCode.blobConflict)),
      );
      await expectLater(
        alice.uploadBlob(bobInbox, _id(4), Uint8List(maxRelayBlobLength + 1)),
        throwsRangeError,
      );
    });

    test('a relay that keeps sending the upload back is given up', () async {
      final looping = _Looping(alice);
      await expectLater(
        looping.uploadBlob(bobInbox, _id(5), file(2 * relayBlobChunkLength)),
        throwsA(_code(RelayErrorCode.invalidResponse)),
      );
      expect(looping.puts, lessThanOrEqualTo(7));
    });

    test('a download whose chunks do not add up is refused', () async {
      await alice.uploadBlob(bobInbox, _id(6), file(relayBlobChunkLength + 1));
      await expectLater(
        _Shrinking(bob).downloadBlob(bobInbox, _id(6)),
        throwsA(_code(RelayErrorCode.invalidResponse)),
      );
    });
  });
}

Matcher _code(RelayErrorCode code) =>
    isA<RelayException>().having((e) => e.code, 'code', code);

/// Every chunk after the first answers "send chunk 0 next".
final class _Looping extends _Delegate {
  _Looping(super.inner);
  var puts = 0;
  @override
  Future<void> putBlobChunk(
    String inboxId,
    String blobId, {
    required int size,
    required int chunk,
    required Uint8List bytes,
  }) async {
    puts++;
    if (chunk > 0) {
      throw const RelayException(
        RelayErrorCode.chunkOutOfOrder,
        status: 409,
        nextChunk: 0,
      );
    }
    await inner.putBlobChunk(
      inboxId,
      blobId,
      size: size,
      chunk: chunk,
      bytes: bytes,
    );
  }
}

/// Once chunk [chunk] is stored, the blob disappears (the receiver deleted
/// it, or it expired): the next chunk gets `chunk_out_of_order` / 0.
final class _LosesBlobAfter extends _Delegate {
  _LosesBlobAfter(super.inner, this.owner, {required this.chunk});
  final FakeRelayClient owner;
  final int chunk;
  final puts = <int>[];
  var _lost = false;
  @override
  Future<void> putBlobChunk(
    String inboxId,
    String blobId, {
    required int size,
    required int chunk,
    required Uint8List bytes,
  }) async {
    puts.add(chunk);
    await inner.putBlobChunk(
      inboxId,
      blobId,
      size: size,
      chunk: chunk,
      bytes: bytes,
    );
    if (chunk == this.chunk && !_lost) {
      _lost = true;
      await owner.deleteBlob(inboxId, blobId);
    }
  }
}

/// The last chunk comes back one byte short.
final class _Shrinking extends _Delegate {
  _Shrinking(super.inner);
  @override
  Future<RelayBlobChunk> getBlobChunk(
    String inboxId,
    String blobId,
    int chunk,
  ) async {
    final c = await inner.getBlobChunk(inboxId, blobId, chunk);
    return chunk == 0
        ? c
        : RelayBlobChunk(
            bytes: Uint8List.sublistView(c.bytes, 1),
            blobSize: c.blobSize,
          );
  }
}

class _Delegate implements RelayClient {
  _Delegate(this.inner);
  final RelayClient inner;
  @override
  dynamic noSuchMethod(Invocation i) => Function.apply(
    switch (i.memberName) {
      #putBlobChunk => inner.putBlobChunk,
      #getBlobChunk => inner.getBlobChunk,
      _ => throw UnimplementedError('${i.memberName}'),
    },
    i.positionalArguments,
    i.namedArguments,
  );
}
