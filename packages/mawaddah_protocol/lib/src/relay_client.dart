// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:convert';
import 'dart:typed_data';

import 'pairing/messages.dart';

import 'relay/relay_errors.dart';

export 'relay/relay_errors.dart';

/// One sealed envelope held by the relay.
final class RelayEnvelope {
  const RelayEnvelope({required this.cursor, required this.body});

  /// Opaque, increasing position used to resume fetching.
  final String cursor;

  /// Sealed (already encrypted) bytes. The relay never sees plaintext.
  final Uint8List body;
}

/// One page of `GET /v1/inbox/{id}/envelopes`.
final class RelayPage {
  const RelayPage({required this.envelopes, required this.more});

  /// In deposit order. Empty only when nothing waits.
  final List<RelayEnvelope> envelopes;

  /// Whether more envelopes wait after the last one of this page.
  final bool more;
}

/// The phone's platform, as registered with the inbox.
enum RelayPlatform {
  android('android'),
  ios('ios');

  const RelayPlatform(this.wireName);

  final String wireName;
}

/// A pairing slot opened by `POST /v1/pairing-slot`.
final class PairingSlot {
  const PairingSlot({
    required this.slotId,
    required this.code,
    required this.expiresAt,
  });

  /// 22 base64url characters (16 bytes); goes into the QR.
  final String slotId;

  /// Six digits, possibly starting with zeros.
  final String code;

  /// When the relay deletes the slot (UTC, whole seconds).
  final DateTime expiresAt;

  /// [slotId] as bytes, for [PairingQr] and the pairing state machines.
  Uint8List get slotIdBytes => decodeRelayId(slotId);
}

/// The answer of `GET /v1/pairing-slot/{slot_id or code}`.
final class PairingSlotLookup {
  const PairingSlotLookup({required this.slotId, required this.bundle});

  /// 22 base64url characters.
  final String slotId;

  /// The initiator's bundle. Its signature is **not** checked here: the
  /// joiner checks it (`PairingJoiner.fromCode` does).
  final PairingBundle bundle;

  /// [slotId] as bytes.
  Uint8List get slotIdBytes => decodeRelayId(slotId);
}

/// One chunk of a blob, from `GET /v1/inbox/{id}/blobs/{blob_id}?chunk=`.
final class RelayBlobChunk {
  const RelayBlobChunk({required this.bytes, required this.blobSize});

  final Uint8List bytes;

  /// The whole blob's size in bytes (header `Maw-Blob-Size`).
  final int blobSize;
}

/// Size of one relay blob chunk (the last one of a blob may be shorter).
const relayBlobChunkLength = 1024 * 1024;

/// Largest blob the relay takes, in bytes of ciphertext (PROTOCOL.md 12).
const maxRelayBlobLength = 10 * relayBlobChunkLength;

/// Number of relay chunks of a blob of [size] bytes.
int relayBlobChunkCount(int size) {
  if (size < 1 || size > maxRelayBlobLength) {
    throw RangeError.range(size, 1, maxRelayBlobLength, 'size');
  }
  return (size + relayBlobChunkLength - 1) ~/ relayBlobChunkLength;
}

/// The 22-character base64url form of a 16-byte relay ID (inbox, slot or
/// blob ID).
String encodeRelayId(Uint8List bytes) {
  if (bytes.length != 16) {
    throw ArgumentError.value(bytes.length, 'bytes', 'must be 16 bytes');
  }
  return base64Url.encode(bytes).replaceAll('=', '');
}

/// The 16 bytes of a relay ID. Throws [FormatException] unless [id] is 22
/// canonical base64url characters.
Uint8List decodeRelayId(String id) {
  if (!isRelayId(id)) throw FormatException('not a relay ID', id);
  return base64Url.decode('$id==');
}

/// Whether [id] is the canonical 22-character base64url form of 16 bytes.
bool isRelayId(String id) => _relayId.hasMatch(id);

// 21 free characters, then one whose low 4 bits are zero (16 bytes = 128
// bits = 21 * 6 + 2).
final _relayId = RegExp(r'^[A-Za-z0-9_-]{21}[AQgw]$');

/// The blind relay (spec 4.5; `relay/README.md` lists every route and error
/// code). A client signs as one device: the key that signs is the device's
/// `IKsig`, which also names its inbox.
///
/// Every method throws [RelayException] when the relay refuses the request
/// or cannot be reached; the exception's [RelayException.code] is the
/// relay's stable error code. IDs are 22 base64url characters; a badly
/// formed ID throws [ArgumentError] before anything is sent.
abstract interface class RelayClient {
  /// `POST /v1/inbox`: registers this device's inbox and returns its ID
  /// (computed by the relay from the signing key). Registering again with
  /// the same key returns the same ID and updates the token and platform.
  Future<String> registerInbox({
    required String? pushToken,
    required RelayPlatform platform,
  });

  /// `POST /v1/pairing-slot`: opens a slot for [bundle], which must be
  /// signed by this client's key (`key_mismatch` otherwise). Sending the
  /// same bundle again returns the same slot.
  Future<PairingSlot> createPairingSlot(PairingBundle bundle);

  /// `GET /v1/pairing-slot/{handle}`, unsigned: [handle] is the 6-digit
  /// code or the slot ID. Wrong codes are rate-limited per network
  /// (`rate_limited`).
  Future<PairingSlotLookup> lookupPairingSlot(String handle);

  /// `POST /v1/pairing-slot/{slot_id}/reply`: the joiner posts [reply],
  /// signed by this client's key. The first reply wins (`slot_used`).
  Future<void> replyToPairingSlot(String slotId, PairingReply reply);

  /// `GET /v1/pairing-slot/{slot_id}/reply`, by the slot's creator: `null`
  /// while waiting, then the reply **once** (reading it closes the slot; a
  /// second read gets `slot_used`). Never retried: a lost answer loses the
  /// attempt (PROTOCOL.md 4.5).
  Future<PairingReply?> readPairingReply(String slotId);

  /// `POST /v1/inbox/{inboxId}/allow`: allow the partner's signing key
  /// [senderKey] (32 bytes) to deposit into this device's inbox.
  Future<void> allowSender(String inboxId, Uint8List senderKey);

  /// `PUT /v1/inbox/{inboxId}/envelopes`: deposits one sealed envelope into
  /// the partner's inbox. [wake] asks the relay to send a content-free push.
  Future<void> deposit(String inboxId, Uint8List body, {bool wake = false});

  /// `GET /v1/inbox/{inboxId}/envelopes`: one page of waiting envelopes
  /// after [after] (from the start if null).
  Future<RelayPage> fetch(String inboxId, {String? after});

  /// `POST /v1/inbox/{inboxId}/ack`: deletes every envelope up to and
  /// including [cursor].
  Future<void> ack(String inboxId, String cursor);

  /// `PUT /v1/inbox/{inboxId}/blobs/{blobId}`: uploads chunk [chunk] of a
  /// blob of [size] bytes into the partner's inbox. Chunks go in order; see
  /// [RelayBlobTransfer.uploadBlob] for the whole file.
  Future<void> putBlobChunk(
    String inboxId,
    String blobId, {
    required int size,
    required int chunk,
    required Uint8List bytes,
  });

  /// `GET /v1/inbox/{inboxId}/blobs/{blobId}?chunk=`: one chunk of a
  /// complete blob in this device's inbox.
  Future<RelayBlobChunk> getBlobChunk(String inboxId, String blobId, int chunk);

  /// `DELETE /v1/inbox/{inboxId}/blobs/{blobId}`: the owner's ACK of a blob,
  /// or the sender giving up an upload. Succeeds when already gone.
  Future<void> deleteBlob(String inboxId, String blobId);

  /// `POST /v1/inbox/{inboxId}/push-token`: replaces the push token (null:
  /// none). Call it on every app open and token refresh: the relay drops a
  /// token FCM calls unregistered.
  Future<void> setPushToken(String inboxId, String? pushToken);

  /// `DELETE /v1/inbox/{inboxId}`: deletes this device's inbox, its allowed
  /// sender, envelopes and blobs. Succeeds when already gone.
  Future<void> deleteInbox(String inboxId);
}

/// Whole-blob transfers over [RelayClient]'s chunk calls (PROTOCOL.md 12).
extension RelayBlobTransfer on RelayClient {
  /// Uploads [ciphertext] as blob [blobId] into the partner's inbox, chunk by
  /// chunk in order. A chunk the relay already has with the same bytes is
  /// accepted again, and `chunk_out_of_order` jumps to the chunk the relay
  /// expects, so calling this again after a failure resumes the upload.
  ///
  /// Deposit the envelope that names the blob only after this returns, and
  /// never call this again for the blob once that envelope is deposited.
  Future<void> uploadBlob(
    String inboxId,
    String blobId,
    Uint8List ciphertext,
  ) async {
    final size = ciphertext.length;
    final count = relayBlobChunkCount(size);
    var chunk = 0;
    // Each jump moves forward, except one back to an earlier chunk the relay
    // asks for; bound the loop so a relay that keeps sending us around
    // cannot hold it forever.
    for (var steps = 0; chunk < count; steps++) {
      if (steps > 3 * count) {
        throw const RelayException(RelayErrorCode.badResponse);
      }
      final start = chunk * relayBlobChunkLength;
      final end = start + relayBlobChunkLength < size
          ? start + relayBlobChunkLength
          : size;
      try {
        await putBlobChunk(
          inboxId,
          blobId,
          size: size,
          chunk: chunk,
          bytes: Uint8List.sublistView(ciphertext, start, end),
        );
        chunk++;
      } on RelayException catch (e) {
        final next = e.nextChunk;
        if (e.code != RelayErrorCode.chunkOutOfOrder ||
            next == null ||
            next < 0 ||
            next >= count) {
          rethrow;
        }
        chunk = next;
      }
    }
  }

  /// Downloads blob [blobId] from this device's inbox, chunk by chunk, and
  /// returns the ciphertext. Does not delete it: call [RelayClient.deleteBlob]
  /// once the file is decrypted and stored. `blob_not_found` part-way means
  /// the blob expired (show the attachment as unavailable).
  Future<Uint8List> downloadBlob(String inboxId, String blobId) async {
    final first = await getBlobChunk(inboxId, blobId, 0);
    final size = first.blobSize;
    final int count;
    try {
      count = relayBlobChunkCount(size);
    } on RangeError {
      throw const RelayException(RelayErrorCode.badResponse);
    }
    final out = Uint8List(size);
    var offset = 0;
    for (var chunk = 0; chunk < count; chunk++) {
      final part = chunk == 0
          ? first
          : await getBlobChunk(inboxId, blobId, chunk);
      final expected = chunk == count - 1
          ? size - chunk * relayBlobChunkLength
          : relayBlobChunkLength;
      if (part.blobSize != size || part.bytes.length != expected) {
        throw const RelayException(RelayErrorCode.badResponse);
      }
      out.setRange(offset, offset + expected, part.bytes);
      offset += expected;
    }
    return out;
  }
}
