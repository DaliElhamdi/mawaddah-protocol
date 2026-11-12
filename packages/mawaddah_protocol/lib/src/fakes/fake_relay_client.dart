// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import '../clock.dart';
import '../crypto/crypto.dart' show Ed25519PublicKey;
import '../envelope/envelope.dart' show maxEnvelopeLength;
import '../identity/identity.dart' show DeviceId;
import '../pairing/messages.dart';
import '../relay_client.dart';
import 'fake_clock.dart';

/// In-memory relay for tests, following `relay/README.md` without HTTP.
///
/// One [FakeRelayClient] holds the relay's state; [as] gives another client
/// on the same state signing as another device (the partner's phone).
///
/// - **Checked** (made with a signing key): the relay's rules and error
///   codes apply: inbox owner, the one allowed sender, pairing slots (one
///   reply, read once, 10 minutes by [clock]), cursors (`invalid_cursor`),
///   page limits, blob chunk order, conflicts, sizes and quotas.
/// - **Unchecked** (no key): the inbox routes work on any inbox name without
///   registration, owner or sender checks, as a plain mailbox; the routes
///   that need the key (register, slots) throw [StateError].
///
/// Not modelled: signatures, nonces and clock skew (the relay's own tests
/// cover them), rate limits, and the 30-day delete. [failNext] makes the
/// next calls throw a chosen [RelayException] instead.
class FakeRelayClient implements RelayClient {
  FakeRelayClient({this.signingKey, Clock? clock, int pageSize = 100})
    : _s = _State(clock ?? FakeClock(), pageSize);

  FakeRelayClient._(this._s, this.signingKey);

  final _State _s;

  /// The key this client signs with; null for an unchecked client.
  final Ed25519PublicKey? signingKey;

  /// Clock for slot expiry and slot `expires_at`.
  Clock get clock => _s.clock;

  /// Another client on this relay, signing as [key].
  FakeRelayClient as(Ed25519PublicKey key) => FakeRelayClient._(_s, key);

  /// The next [times] calls (on any client of this relay) throw [error]
  /// without doing anything.
  void failNext(RelayException error, {int times = 1}) {
    for (var i = 0; i < times; i++) {
      _s.failures.add(error);
    }
  }

  /// The `wake` flag of each envelope ever deposited into [inboxId] (a
  /// history: not cleared by [ack]).
  List<bool> wakesFor(String inboxId) =>
      List.unmodifiable(_s.wakes[inboxId] ?? const <bool>[]);

  /// Whether a registered inbox [inboxId] exists.
  bool hasInbox(String inboxId) => _s.inboxes[inboxId]?.registered ?? false;

  /// The push token of [inboxId], or null.
  String? pushTokenOf(String inboxId) => _s.inboxes[inboxId]?.pushToken;

  /// The platform [inboxId] registered with, or null.
  RelayPlatform? platformOf(String inboxId) => _s.inboxes[inboxId]?.platform;

  /// IDs of the blobs stored in [inboxId] (complete or not).
  List<String> blobIdsOf(String inboxId) =>
      List.unmodifiable(_s.inboxes[inboxId]?.blobs.keys ?? const <String>[]);

  // --- inbox -----------------------------------------------------------------

  @override
  Future<String> registerInbox({
    required String? pushToken,
    required RelayPlatform platform,
  }) async {
    _step();
    final key = _key;
    final id = _own(key);
    final inbox = _s.inboxes.putIfAbsent(id, _Inbox.new);
    inbox
      ..registered = true
      ..pushToken = pushToken
      ..platform = platform;
    return id;
  }

  @override
  Future<void> allowSender(String inboxId, Uint8List senderKey) async {
    _step();
    final inbox = _owned(inboxId);
    final allowed = inbox.allowed;
    if (allowed == null) {
      inbox.allowed = Uint8List.fromList(senderKey);
    } else if (!_same(allowed, senderKey)) {
      throw _e(RelayErrorCode.allowConflict, 409);
    }
  }

  @override
  Future<void> setPushToken(String inboxId, String? pushToken) async {
    _step();
    _owned(inboxId).pushToken = pushToken;
  }

  @override
  Future<void> deleteInbox(String inboxId) async {
    _step();
    final key = signingKey;
    if (key != null && inboxId != _own(key)) {
      throw _e(RelayErrorCode.notInboxOwner, 403);
    }
    _s.inboxes.remove(inboxId);
  }

  // --- envelopes -------------------------------------------------------------

  @override
  Future<void> deposit(
    String inboxId,
    Uint8List body, {
    bool wake = false,
  }) async {
    _step();
    if (body.isEmpty) throw _e(RelayErrorCode.malformedRequest, 400);
    if (body.length > maxEnvelopeLength) {
      throw _e(RelayErrorCode.bodyTooLarge, 413);
    }
    final inbox = _senderOf(inboxId);
    if (inbox.envelopeBytes + body.length > _inboxQuota) {
      throw _e(RelayErrorCode.inboxFull, 409);
    }
    final cursor = ++_s.counter;
    inbox
      ..envelopes.add((cursor, Uint8List.fromList(body)))
      ..envelopeBytes += body.length
      ..lastCursor = cursor;
    (_s.wakes[inboxId] ??= []).add(wake);
  }

  @override
  Future<RelayPage> fetch(String inboxId, {String? after}) async {
    _step();
    final inbox = _owned(inboxId);
    final from = _cursor(inbox, after);
    final page = <RelayEnvelope>[];
    var bytes = 0;
    var more = false;
    for (final (cursor, body) in inbox.envelopes) {
      if (cursor <= from) continue;
      if (page.length == _s.pageSize ||
          (page.isNotEmpty && bytes + body.length > _pageBytes)) {
        more = true;
        break;
      }
      page.add(
        RelayEnvelope(cursor: '$cursor', body: Uint8List.fromList(body)),
      );
      bytes += body.length;
    }
    return RelayPage(envelopes: page, more: more);
  }

  @override
  Future<void> ack(String inboxId, String cursor) async {
    _step();
    final inbox = _owned(inboxId);
    final upTo = _cursor(inbox, cursor);
    inbox.envelopes.removeWhere((e) {
      if (e.$1 > upTo) return false;
      inbox.envelopeBytes -= e.$2.length;
      return true;
    });
  }

  // --- blobs -----------------------------------------------------------------

  @override
  Future<void> putBlobChunk(
    String inboxId,
    String blobId, {
    required int size,
    required int chunk,
    required Uint8List bytes,
  }) async {
    _step();
    if (size > maxRelayBlobLength) throw _e(RelayErrorCode.blobTooLarge, 413);
    if (bytes.length > relayBlobChunkLength) {
      throw _e(RelayErrorCode.bodyTooLarge, 413);
    }
    if (size < 1 || !isRelayId(blobId)) {
      throw _e(RelayErrorCode.malformedRequest, 400);
    }
    final count = relayBlobChunkCount(size);
    final expected = chunk == count - 1
        ? size - chunk * relayBlobChunkLength
        : relayBlobChunkLength;
    if (chunk < 0 || chunk >= count || bytes.length != expected) {
      throw _e(RelayErrorCode.malformedRequest, 400);
    }
    final inbox = _senderOf(inboxId);
    var blob = inbox.blobs[blobId];
    if (blob == null) {
      if (chunk != 0) throw _outOfOrder(0);
      if (inbox.blobBytes + size > _blobQuota) {
        throw _e(RelayErrorCode.blobQuotaExceeded, 413);
      }
      blob = inbox.blobs[blobId] = _Blob(size);
      inbox.blobBytes += size;
    } else if (blob.size != size) {
      throw _e(RelayErrorCode.blobConflict, 409);
    }
    if (chunk < blob.chunks.length) {
      if (!_same(blob.chunks[chunk], bytes)) {
        throw _e(RelayErrorCode.blobConflict, 409);
      }
      return;
    }
    if (chunk > blob.chunks.length) throw _outOfOrder(blob.chunks.length);
    blob.chunks.add(Uint8List.fromList(bytes));
  }

  @override
  Future<RelayBlobChunk> getBlobChunk(
    String inboxId,
    String blobId,
    int chunk,
  ) async {
    _step();
    final blob = _owned(inboxId).blobs[blobId];
    if (blob == null) throw _e(RelayErrorCode.blobNotFound, 404);
    if (chunk < 0 || chunk >= relayBlobChunkCount(blob.size)) {
      throw _e(RelayErrorCode.malformedRequest, 400);
    }
    if (!blob.complete) throw _e(RelayErrorCode.blobIncomplete, 409);
    return RelayBlobChunk(
      bytes: Uint8List.fromList(blob.chunks[chunk]),
      blobSize: blob.size,
    );
  }

  @override
  Future<void> deleteBlob(String inboxId, String blobId) async {
    _step();
    final inbox = _existing(inboxId);
    final key = signingKey;
    if (key != null &&
        inboxId != _own(key) &&
        !(inbox.allowed != null && _same(inbox.allowed!, key.bytes))) {
      throw _e(RelayErrorCode.senderNotAllowed, 403);
    }
    final blob = inbox.blobs.remove(blobId);
    if (blob != null) inbox.blobBytes -= blob.size;
  }

  // --- pairing slots ---------------------------------------------------------

  @override
  Future<PairingSlot> createPairingSlot(PairingBundle bundle) async {
    _step();
    final key = _key;
    _needInbox(key);
    if (!_same(bundle.signingKey.bytes, key.bytes)) {
      throw _e(RelayErrorCode.keyMismatch, 400);
    }
    _expireSlots();
    final json = jsonEncode(bundle.toJson());
    for (final slot in _s.slots.values) {
      if (_same(slot.creator, key.bytes)) {
        if (slot.bundle != json) throw _e(RelayErrorCode.slotConflict, 409);
        return slot.info;
      }
    }
    final n = ++_s.slotCounter;
    final id = Uint8List(16)..buffer.asByteData().setUint64(8, n);
    final slot = _Slot(
      PairingSlot(
        slotId: encodeRelayId(id),
        code: (n % 1000000).toString().padLeft(6, '0'),
        expiresAt: _wholeSeconds(clock.now().add(pairingSlotLifetime)),
      ),
      Uint8List.fromList(key.bytes),
      json,
    );
    _s.slots[slot.info.slotId] = slot;
    return slot.info;
  }

  @override
  Future<PairingSlotLookup> lookupPairingSlot(String handle) async {
    _step();
    _expireSlots();
    final slot = _s.slots.values
        .where((s) => s.info.slotId == handle || s.info.code == handle)
        .firstOrNull;
    if (slot == null) throw _e(RelayErrorCode.slotNotFound, 404);
    if (slot.reply != null || slot.read) throw _e(RelayErrorCode.slotUsed, 409);
    return PairingSlotLookup(
      slotId: slot.info.slotId,
      bundle: PairingBundle.fromJson(
        jsonDecode(slot.bundle!) as Map<String, Object?>,
      ),
    );
  }

  @override
  Future<void> replyToPairingSlot(String slotId, PairingReply reply) async {
    _step();
    final key = _key;
    _needInbox(key);
    if (!_same(reply.signingKey.bytes, key.bytes)) {
      throw _e(RelayErrorCode.keyMismatch, 400);
    }
    final slot = _slot(slotId);
    final json = jsonEncode(reply.toJson());
    if (slot.read) throw _e(RelayErrorCode.slotUsed, 409);
    if (slot.reply == null) {
      slot.reply = json;
    } else if (slot.reply != json) {
      throw _e(RelayErrorCode.slotUsed, 409);
    }
  }

  @override
  Future<PairingReply?> readPairingReply(String slotId) async {
    _step();
    final key = _key;
    final slot = _slot(slotId);
    if (!_same(slot.creator, key.bytes)) {
      throw _e(RelayErrorCode.slotNotFound, 404);
    }
    if (slot.read) throw _e(RelayErrorCode.slotUsed, 409);
    final reply = slot.reply;
    if (reply == null) return null;
    slot
      ..read = true
      ..reply = null
      ..bundle = null;
    return PairingReply.fromJson(jsonDecode(reply) as Map<String, Object?>);
  }

  // --- helpers ---------------------------------------------------------------

  static const _inboxQuota = 100 * 1024 * 1024;
  static const _blobQuota = 100 * 1024 * 1024;
  static const _pageBytes = 1024 * 1024;

  void _step() {
    if (_s.failures.isNotEmpty) throw _s.failures.removeFirst();
  }

  Ed25519PublicKey get _key =>
      signingKey ?? (throw StateError('this route needs a signing key'));

  static String _own(Ed25519PublicKey key) =>
      DeviceId.fromSigningKey(key).toBase64Url();

  _Inbox _existing(String inboxId) {
    if (signingKey == null) return _s.inboxes.putIfAbsent(inboxId, _Inbox.new);
    final inbox = _s.inboxes[inboxId];
    if (inbox == null || !inbox.registered) {
      throw _e(RelayErrorCode.inboxNotFound, 404);
    }
    return inbox;
  }

  /// The inbox, if this client owns it (checked).
  _Inbox _owned(String inboxId) {
    final inbox = _existing(inboxId);
    final key = signingKey;
    if (key != null && inboxId != _own(key)) {
      throw _e(RelayErrorCode.notInboxOwner, 403);
    }
    return inbox;
  }

  /// The inbox, if this client is its allowed sender (checked).
  _Inbox _senderOf(String inboxId) {
    final inbox = _existing(inboxId);
    final key = signingKey;
    final allowed = inbox.allowed;
    if (key != null && (allowed == null || !_same(allowed, key.bytes))) {
      throw _e(RelayErrorCode.senderNotAllowed, 403);
    }
    return inbox;
  }

  void _needInbox(Ed25519PublicKey key) {
    if (!hasInbox(_own(key))) throw _e(RelayErrorCode.inboxRequired, 403);
  }

  /// [text] as a position: `0`/null is the start; above the inbox's last
  /// cursor is `invalid_cursor`.
  int _cursor(_Inbox inbox, String? text) {
    if (text == null) return 0;
    final n = int.tryParse(text);
    if (n == null || n < 0 || '$n' != text) {
      throw _e(RelayErrorCode.malformedRequest, 400);
    }
    if (n > inbox.lastCursor) throw _e(RelayErrorCode.invalidCursor, 400);
    return n;
  }

  void _expireSlots() {
    final now = clock.now();
    _s.slots.removeWhere((_, s) => !now.isBefore(s.info.expiresAt));
  }

  _Slot _slot(String slotId) {
    _expireSlots();
    return _s.slots[slotId] ?? (throw _e(RelayErrorCode.slotNotFound, 404));
  }

  static DateTime _wholeSeconds(DateTime t) =>
      DateTime.fromMillisecondsSinceEpoch(
        t.millisecondsSinceEpoch ~/ 1000 * 1000,
        isUtc: true,
      );

  static RelayException _e(RelayErrorCode code, int status) =>
      RelayException(code, status: status);

  static RelayException _outOfOrder(int next) => RelayException(
    RelayErrorCode.chunkOutOfOrder,
    status: 409,
    nextChunk: next,
  );

  static bool _same(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

final class _State {
  _State(this.clock, this.pageSize) {
    if (pageSize < 1) throw RangeError.value(pageSize, 'pageSize');
  }
  final Clock clock;
  final int pageSize;
  final inboxes = <String, _Inbox>{};
  final wakes = <String, List<bool>>{};
  final slots = <String, _Slot>{};
  final failures = Queue<RelayException>();
  var counter = 0;
  var slotCounter = 0;
}

final class _Inbox {
  var registered = false;
  String? pushToken;
  RelayPlatform? platform;
  Uint8List? allowed;
  final envelopes = <(int, Uint8List)>[];
  var envelopeBytes = 0;
  var lastCursor = 0;
  final blobs = <String, _Blob>{};
  var blobBytes = 0;
}

final class _Blob {
  _Blob(this.size);
  final int size;
  final chunks = <Uint8List>[];
  bool get complete => chunks.length == relayBlobChunkCount(size);
}

final class _Slot {
  _Slot(this.info, this.creator, this.bundle);
  final PairingSlot info;
  final Uint8List creator;
  String? bundle;
  String? reply;
  var read = false;
}
