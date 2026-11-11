// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../envelope/envelope.dart' show maxEnvelopeLength;
import '../pairing/messages.dart';
import '../relay_client.dart';
import 'relay_signing.dart';

/// [RelayClient] over HTTPS (spec 4.5, `relay/README.md`).
///
/// - The relay's address is injected ([baseUrl]); the package names none.
/// - Every request except the pairing-slot lookup is signed by [signer]
///   (PROTOCOL.md section 13), with a fresh timestamp and nonce for each
///   try. Without a signer only [lookupPairingSlot] works: the joiner's code
///   path looks the code up before its keys exist.
/// - Redirects are not followed (they would change the signed path).
/// - An answer is checked before it is used; one that does not fit the
///   route is [RelayErrorCode.badResponse], never a crash.
/// - **Retries:** a try that gets no answer, times out, or meets a passing
///   server fault (`internal_error`, a 5xx without a known code, an answer
///   that is not JSON) is tried again after each of [retryDelays], so a
///   short network drop does not fail a sync. Not repeated here:
///   [deposit] (a lost answer would store the envelope twice; the sync
///   engine resends the same bytes on its next run), [readPairingReply]
///   (the reply can be read once) and a code lookup (a repeat could use up
///   one of the network's wrong guesses). Everything else (`rate_limited`,
///   `inbox_full`, `sender_not_allowed`, …) is thrown at once: the caller
///   decides when to try again, with [RelayException.retryable] and its
///   own back-off (PROTOCOL.md section 17). One call takes at most
///   3 × [timeout] plus the delays.
/// - An answer that parses but breaks the route's rules (an inbox ID that
///   is not the key's, cursors that do not increase, a chunk of the wrong
///   length, …) is `invalid_response`: a broken or hostile relay, never
///   retried.
final class HttpRelayClient implements RelayClient {
  /// [baseUrl] is the relay's origin, e.g. `https://relay.example`: HTTPS,
  /// no path, query or user info. Plain `http` is accepted only for
  /// `localhost`, `127.0.0.1`, `[::1]` and `10.0.2.2` (the Android
  /// emulator's name for the computer it runs on), for local tests. The
  /// package cannot tell a release build from a debug one: the app makes
  /// sure its release builds use the HTTPS production address.
  ///
  /// [httpClient] defaults to a new `http.Client`, closed by [close]; a
  /// client passed in is left open.
  HttpRelayClient({
    required Uri baseUrl,
    this.signer,
    http.Client? httpClient,
    this.timeout = const Duration(seconds: 30),
    this.retryDelays = const [Duration(seconds: 1), Duration(seconds: 3)],
    Future<void> Function(Duration)? sleep,
  }) : _origin = _checkBaseUrl(baseUrl),
       _client = httpClient ?? http.Client(),
       _ownsClient = httpClient == null,
       _sleep = sleep ?? _defaultSleep;

  /// Signs every request but the slot lookup; see the class comment.
  final RelayRequestSigner? signer;

  /// Limit for one try, from sending to the last byte of the answer.
  final Duration timeout;

  /// Waits before the 2nd, 3rd, … try of a request that met a passing
  /// fault. Empty: one try only.
  final List<Duration> retryDelays;

  final String _origin;
  final http.Client _client;
  final bool _ownsClient;
  final Future<void> Function(Duration) _sleep;

  /// Largest answer read: a fetch page holds at most 1 MiB of envelopes
  /// (base64url: 4/3 of that) plus JSON, a blob chunk 1 MiB.
  static const maxResponseLength = 2 * 1024 * 1024;

  static const _wakeHeader = 'Maw-Wake';
  static const _blobSizeHeader = 'Maw-Blob-Size';

  /// Closes the HTTP client if this object created it.
  void close() {
    if (_ownsClient) _client.close();
  }

  // --- routes ----------------------------------------------------------------

  @override
  Future<String> registerInbox({
    required String? pushToken,
    required RelayPlatform platform,
  }) async {
    final s = _signer;
    final key = s.identity.publicIdentity.signingKey.bytes;
    final json = await _json(
      'POST',
      '/v1/inbox',
      body: {
        'signing_key': _b64(key),
        'push_token': pushToken,
        'platform': platform.wireName,
      },
    );
    final id = json['inbox_id'];
    // The relay computes the ID from the key (PROTOCOL.md section 3); one
    // that does not match would send the partner's envelopes elsewhere.
    if (id is! String || id != s.identity.deviceId.toBase64Url()) {
      throw _invalid;
    }
    return id;
  }

  @override
  Future<PairingSlot> createPairingSlot(PairingBundle bundle) async {
    final json = await _json('POST', '/v1/pairing-slot', body: bundle.toJson());
    final slotId = json['slot_id'];
    final code = json['code'];
    final expiresAt = json['expires_at'];
    if (slotId is! String ||
        !isRelayId(slotId) ||
        code is! String ||
        !_code.hasMatch(code) ||
        expiresAt is! int ||
        expiresAt < 0) {
      throw _invalid;
    }
    return PairingSlot(
      slotId: slotId,
      code: code,
      expiresAt: DateTime.fromMillisecondsSinceEpoch(
        expiresAt * 1000,
        isUtc: true,
      ),
    );
  }

  @override
  Future<PairingSlotLookup> lookupPairingSlot(String handle) async {
    if (!_code.hasMatch(handle) && !isRelayId(handle)) {
      // The handle is a pairing code: never quoted in the error.
      throw ArgumentError('not a 6-digit code or a slot ID', 'handle');
    }
    final json = await _json(
      'GET',
      '/v1/pairing-slot/$handle',
      signed: false,
      // A code lookup that found nothing counts against the network's 5
      // wrong guesses: never spend one on a repeat.
      retry: isRelayId(handle),
    );
    final slotId = json['slot_id'];
    final bundle = json['bundle'];
    if (slotId is! String ||
        !isRelayId(slotId) ||
        (isRelayId(handle) && slotId != handle) ||
        bundle is! Map<String, Object?>) {
      throw _invalid;
    }
    try {
      return PairingSlotLookup(
        slotId: slotId,
        bundle: PairingBundle.fromJson(bundle),
      );
    } on FormatException {
      throw _invalid;
    }
  }

  @override
  Future<void> replyToPairingSlot(String slotId, PairingReply reply) async {
    _id(slotId, 'slotId');
    await _json('POST', '/v1/pairing-slot/$slotId/reply', body: reply.toJson());
  }

  @override
  Future<PairingReply?> readPairingReply(String slotId) async {
    _id(slotId, 'slotId');
    final json = await _json(
      'GET',
      '/v1/pairing-slot/$slotId/reply',
      retry: false,
    );
    if (!json.containsKey('reply')) throw _invalid;
    final reply = json['reply'];
    if (reply == null) return null;
    if (reply is! Map<String, Object?>) throw _invalid;
    try {
      return PairingReply.fromJson(reply);
    } on FormatException {
      throw _invalid;
    }
  }

  @override
  Future<void> allowSender(String inboxId, Uint8List senderKey) async {
    _id(inboxId, 'inboxId');
    if (senderKey.length != 32) {
      throw ArgumentError.value(senderKey.length, 'senderKey', 'not 32 bytes');
    }
    await _json(
      'POST',
      '/v1/inbox/$inboxId/allow',
      body: {'sender_key': _b64(senderKey)},
    );
  }

  @override
  Future<void> deposit(
    String inboxId,
    Uint8List body, {
    bool wake = false,
  }) async {
    _id(inboxId, 'inboxId');
    if (body.isEmpty || body.length > maxEnvelopeLength) {
      throw ArgumentError.value(body.length, 'body', 'not 1..65536 bytes');
    }
    await _send(
      'PUT',
      '/v1/inbox/$inboxId/envelopes',
      body: body,
      contentType: _octets,
      extraHeaders: {_wakeHeader: wake ? '1' : '0'},
      // Not repeated here: a lost answer would store the envelope twice
      // and send a second wake-up. The sync engine deposits the same bytes
      // again on its next run (PROTOCOL.md section 17).
      retry: false,
    );
  }

  @override
  Future<RelayPage> fetch(String inboxId, {String? after}) async {
    _id(inboxId, 'inboxId');
    if (after != null) _cursor(after);
    final query = after == null ? '' : '?after=$after';
    final json = await _json('GET', '/v1/inbox/$inboxId/envelopes$query');
    final list = json['envelopes'];
    final more = json['more'];
    if (list is! List<Object?> || more is! bool) throw _invalid;
    final envelopes = <RelayEnvelope>[];
    var last = after == null ? BigInt.zero : BigInt.parse(after);
    for (final item in list) {
      if (item is! Map<String, Object?>) throw _invalid;
      final cursor = item['cursor'];
      final body = item['body'];
      if (cursor is! String || !_decimal.hasMatch(cursor) || body is! String) {
        throw _invalid;
      }
      // Cursors increase; one that does not would make the next fetch, or
      // the cumulative ACK, skip envelopes.
      final position = BigInt.parse(cursor);
      if (position <= last) throw _invalid;
      last = position;
      final bytes = _unb64(body);
      if (bytes == null || bytes.isEmpty || bytes.length > maxEnvelopeLength) {
        throw _invalid;
      }
      envelopes.add(RelayEnvelope(cursor: cursor, body: bytes));
    }
    if (envelopes.isEmpty && more) throw _invalid;
    return RelayPage(envelopes: envelopes, more: more);
  }

  @override
  Future<void> ack(String inboxId, String cursor) async {
    _id(inboxId, 'inboxId');
    _cursor(cursor);
    await _json('POST', '/v1/inbox/$inboxId/ack', body: {'cursor': cursor});
  }

  @override
  Future<void> putBlobChunk(
    String inboxId,
    String blobId, {
    required int size,
    required int chunk,
    required Uint8List bytes,
  }) async {
    _id(inboxId, 'inboxId');
    _id(blobId, 'blobId');
    final count = relayBlobChunkCount(size);
    if (chunk < 0 || chunk >= count) {
      throw RangeError.range(chunk, 0, count - 1, 'chunk');
    }
    final expected = chunk == count - 1
        ? size - chunk * relayBlobChunkLength
        : relayBlobChunkLength;
    if (bytes.length != expected) {
      throw ArgumentError.value(bytes.length, 'bytes', 'chunk is $expected');
    }
    await _send(
      'PUT',
      '/v1/inbox/$inboxId/blobs/$blobId?size=$size&chunk=$chunk',
      body: bytes,
      contentType: _octets,
    );
  }

  @override
  Future<RelayBlobChunk> getBlobChunk(
    String inboxId,
    String blobId,
    int chunk,
  ) async {
    _id(inboxId, 'inboxId');
    _id(blobId, 'blobId');
    if (chunk < 0) throw RangeError.value(chunk, 'chunk');
    final a = await _send(
      'GET',
      '/v1/inbox/$inboxId/blobs/$blobId?chunk=$chunk',
    );
    final sizeText = a.headers[_blobSizeHeader.toLowerCase()];
    final size = sizeText != null && _decimal.hasMatch(sizeText)
        ? int.tryParse(sizeText)
        : null;
    if (size == null || size < 1 || size > maxRelayBlobLength) throw _invalid;
    final count = relayBlobChunkCount(size);
    final expected = chunk == count - 1
        ? size - chunk * relayBlobChunkLength
        : relayBlobChunkLength;
    // A chunk index past the end, or a chunk cut short or padded.
    if (chunk >= count || a.body.length != expected) throw _invalid;
    return RelayBlobChunk(bytes: a.body, blobSize: size);
  }

  @override
  Future<void> deleteBlob(String inboxId, String blobId) async {
    _id(inboxId, 'inboxId');
    _id(blobId, 'blobId');
    await _send('DELETE', '/v1/inbox/$inboxId/blobs/$blobId');
  }

  @override
  Future<void> setPushToken(String inboxId, String? pushToken) async {
    _id(inboxId, 'inboxId');
    await _json(
      'POST',
      '/v1/inbox/$inboxId/push-token',
      body: {'push_token': pushToken},
    );
  }

  @override
  Future<void> deleteInbox(String inboxId) async {
    _id(inboxId, 'inboxId');
    await _send('DELETE', '/v1/inbox/$inboxId');
  }

  // --- transport -------------------------------------------------------------

  RelayRequestSigner get _signer =>
      signer ??
      (throw StateError('this relay call is signed: give the client a signer'));

  Future<Map<String, Object?>> _json(
    String method,
    String pathAndQuery, {
    Map<String, Object?>? body,
    bool signed = true,
    bool retry = true,
  }) async {
    final a = await _send(
      method,
      pathAndQuery,
      body: body == null ? null : utf8.encode(jsonEncode(body)),
      contentType: body == null ? null : 'application/json',
      signed: signed,
      retry: retry,
    );
    final json = _decodeObject(a.body);
    if (json == null) throw _bad;
    return json;
  }

  Future<_Answer> _send(
    String method,
    String pathAndQuery, {
    Uint8List? body,
    String? contentType,
    Map<String, String> extraHeaders = const {},
    bool signed = true,
    bool retry = true,
  }) async {
    final s = signed ? _signer : null;
    final bytes = body ?? Uint8List(0);
    for (var attempt = 0; ; attempt++) {
      try {
        final a = await _once(
          method,
          pathAndQuery,
          bytes,
          contentType,
          extraHeaders,
          s,
        );
        if (a.status == 200 || a.status == 201) return a;
        throw _error(a);
      } on RelayException catch (e) {
        if (!retry || attempt >= retryDelays.length || !_passing(e)) rethrow;
        await _sleep(retryDelays[attempt]);
      }
    }
  }

  /// Faults that usually clear within seconds.
  static bool _passing(RelayException e) => switch (e.code) {
    RelayErrorCode.network ||
    RelayErrorCode.timeout ||
    RelayErrorCode.badResponse ||
    RelayErrorCode.internalError => true,
    RelayErrorCode.unknown => (e.status ?? 0) >= 500,
    _ => false,
  };

  Future<_Answer> _once(
    String method,
    String pathAndQuery,
    Uint8List body,
    String? contentType,
    Map<String, String> extraHeaders,
    RelayRequestSigner? s,
  ) async {
    final abort = Completer<void>();
    final request =
        http.AbortableRequest(
            method,
            Uri.parse('$_origin$pathAndQuery'),
            abortTrigger: abort.future,
          )
          ..followRedirects = false
          ..persistentConnection = true;
    if (s != null) {
      request.headers.addAll(
        s.sign(method: method, pathAndQuery: pathAndQuery, body: body),
      );
    }
    request.headers.addAll(extraHeaders);
    if (contentType != null) request.headers['content-type'] = contentType;
    if (body.isNotEmpty) request.bodyBytes = body;
    try {
      return await _exchange(request).timeout(timeout);
    } on TimeoutException {
      throw const RelayException(RelayErrorCode.timeout);
    } on RelayException {
      rethrow;
    } on Exception {
      // ClientException (socket, DNS, TLS, connection closed) and anything
      // else the HTTP client throws. Its message may hold the URL, so it is
      // not kept.
      throw const RelayException(RelayErrorCode.network);
    } finally {
      if (!abort.isCompleted) abort.complete();
    }
  }

  Future<_Answer> _exchange(http.BaseRequest request) async {
    final response = await _client.send(request);
    final out = BytesBuilder(copy: false);
    await for (final part in response.stream) {
      out.add(part);
      if (out.length > maxResponseLength) throw _bad;
    }
    return _Answer(response.statusCode, response.headers, out.takeBytes());
  }

  static RelayException _error(_Answer a) {
    final json = _decodeObject(a.body);
    final code = json?['error'];
    if (json == null || code is! String) {
      return RelayException(RelayErrorCode.badResponse, status: a.status);
    }
    final retryAfter = json['retry_after'];
    final header = a.headers['retry-after'];
    final headerSeconds = header != null && _decimal.hasMatch(header)
        ? int.tryParse(header)
        : null;
    final serverTime = json['server_time'];
    final nextChunk = json['next_chunk'];
    return RelayException(
      RelayErrorCode.fromWire(code),
      status: a.status,
      retryAfter: _waitOf(
        retryAfter is int && retryAfter >= 0 ? retryAfter : headerSeconds,
      ),
      serverTime: serverTime is int && serverTime >= 0
          ? DateTime.fromMillisecondsSinceEpoch(serverTime * 1000, isUtc: true)
          : null,
      nextChunk: nextChunk is int && nextChunk >= 0 ? nextChunk : null,
    );
  }

  // --- helpers ---------------------------------------------------------------

  /// Longest wait taken from the relay: its limits use windows of at most
  /// one hour, so a longer wait is a fault, not a reason to stop for days.
  static const maxRetryAfter = Duration(hours: 1);

  static Duration? _waitOf(int? seconds) {
    if (seconds == null) return null;
    final d = Duration(seconds: seconds);
    return d > maxRetryAfter ? maxRetryAfter : d;
  }

  static const _octets = 'application/octet-stream';
  static const _bad = RelayException(RelayErrorCode.badResponse);
  static const _invalid = RelayException(RelayErrorCode.invalidResponse);
  static final _code = RegExp(r'^[0-9]{6}$');
  static final _decimal = RegExp(r'^(0|[1-9][0-9]{0,30})$');

  static void _id(String id, String name) {
    if (!isRelayId(id)) {
      // IDs are not quoted: errors end up in crash reports and logs.
      throw ArgumentError('not a 22-character relay ID', name);
    }
  }

  static void _cursor(String cursor) {
    if (!_decimal.hasMatch(cursor)) {
      throw ArgumentError('not a relay cursor', 'cursor');
    }
  }

  static Map<String, Object?>? _decodeObject(Uint8List body) {
    try {
      final v = jsonDecode(utf8.decode(body));
      return v is Map<String, Object?> ? v : null;
    } on FormatException {
      return null;
    }
  }

  static String _b64(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  /// Canonical unpadded base64url, or null.
  static Uint8List? _unb64(String text) {
    if (!_base64Url.hasMatch(text) || text.length % 4 == 1) return null;
    try {
      final bytes = base64Url.decode(base64Url.normalize(text));
      return _b64(bytes) == text ? bytes : null;
    } on FormatException {
      return null;
    }
  }

  static final _base64Url = RegExp(r'^[A-Za-z0-9_-]*$');

  static String _checkBaseUrl(Uri url) {
    const localHosts = {'localhost', '127.0.0.1', '::1', '10.0.2.2'};
    final okScheme =
        url.scheme == 'https' ||
        (url.scheme == 'http' && localHosts.contains(url.host));
    if (!okScheme ||
        url.host.isEmpty ||
        url.userInfo.isNotEmpty ||
        url.hasQuery ||
        url.hasFragment ||
        (url.path.isNotEmpty && url.path != '/')) {
      // Scheme and host only: a URL may carry user info or a query.
      throw ArgumentError(
        'must be an https origin, http only for a local relay '
            '(got ${url.scheme}://${url.host})',
        'baseUrl',
      );
    }
    return url.replace(path: '').toString();
  }

  static Future<void> _defaultSleep(Duration d) => Future<void>.delayed(d);
}

final class _Answer {
  const _Answer(this.status, this.headers, this.body);
  final int status;
  final Map<String, String> headers;
  final Uint8List body;
}
