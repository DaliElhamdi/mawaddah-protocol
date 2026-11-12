// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Why a relay request failed: the relay's stable error codes
/// (`relay/README.md`, "Errors"), plus five client-side reasons.
enum RelayErrorCode {
  malformedRequest('malformed_request'),
  keyMismatch('key_mismatch'),
  invalidCursor('invalid_cursor'),
  inboxRequired('inbox_required'),
  notInboxOwner('not_inbox_owner'),
  senderNotAllowed('sender_not_allowed', true),
  slotNotFound('slot_not_found'),
  inboxNotFound('inbox_not_found'),
  blobNotFound('blob_not_found'),
  authMissing('auth_missing'),
  authMalformed('auth_malformed'),
  clockSkew('clock_skew'),
  badSignature('bad_signature'),
  nonceReused('nonce_reused', true),
  notFound('not_found'),
  methodNotAllowed('method_not_allowed'),
  inboxConflict('inbox_conflict'),
  slotUsed('slot_used'),
  slotConflict('slot_conflict'),
  allowConflict('allow_conflict'),
  inboxFull('inbox_full', true),
  blobConflict('blob_conflict'),
  chunkOutOfOrder('chunk_out_of_order'),
  blobIncomplete('blob_incomplete', true),
  bodyTooLarge('body_too_large'),
  blobTooLarge('blob_too_large'),
  blobQuotaExceeded('blob_quota_exceeded', true),
  rateLimited('rate_limited', true),
  internalError('internal_error', true),
  slotsFull('slots_full', true),

  /// The relay answered with a code this client does not know (a newer
  /// relay). Retryable when the status is 5xx.
  unknown('unknown'),

  /// No answer: no network, DNS or TLS failure, connection dropped.
  network('network', true),

  /// No answer within the client's timeout.
  timeout('timeout', true),

  /// An answer that is not the relay's JSON (a proxy's error page, a body
  /// that does not parse, too large, a redirect). Retryable: usually a
  /// passing fault on the way.
  badResponse('bad_response', true),

  /// An answer that parses but breaks the route's rules (an inbox ID that is
  /// not the key's, cursors that do not increase, a chunk of the wrong
  /// length). A broken or hostile relay: not retryable.
  invalidResponse('invalid_response');

  const RelayErrorCode(this.wireName, [this._retryable = false]);

  /// The `error` value in the relay's JSON (or the client-side name).
  final String wireName;

  final bool _retryable;

  /// The code for [wireName]; [unknown] if there is none.
  static RelayErrorCode fromWire(String wireName) {
    for (final c in values) {
      if (c.wireName == wireName && c._isRelayCode) return c;
    }
    return unknown;
  }

  bool get _isRelayCode =>
      this != unknown &&
      this != network &&
      this != timeout &&
      this != badResponse &&
      this != invalidResponse;
}

/// A relay request failed. Carries only the code, the HTTP status and the
/// documented extra field, never request or response bodies, keys or IDs,
/// so it is safe to show in a debug log.
final class RelayException implements Exception {
  const RelayException(
    this.code, {
    this.status,
    this.retryAfter,
    this.serverTime,
    this.nextChunk,
  });

  final RelayErrorCode code;

  /// HTTP status; null when the relay did not answer.
  final int? status;

  /// `rate_limited`: how long to wait (`retry_after` / `Retry-After`).
  final Duration? retryAfter;

  /// `clock_skew`: the relay's time; the phone's clock is off. Show the
  /// wrong-time card.
  final DateTime? serverTime;

  /// `chunk_out_of_order`: the chunk index the relay expects next.
  final int? nextChunk;

  /// Whether the same request may succeed later without anything else
  /// changing: the caller retries it with its back-off.
  ///
  /// `sender_not_allowed` is retryable because just after pairing the
  /// partner may not have allowed this key yet (PROTOCOL.md 4.5 step 4);
  /// `blob_incomplete` because the sender may still be uploading. Not
  /// retryable: codes that mean a bug or a refused request (`key_mismatch`,
  /// `malformed_request`, `not_inbox_owner`, `allow_conflict`,
  /// `invalid_cursor`, `slot_conflict`, `blob_conflict`, `blob_too_large`),
  /// a pairing attempt that is over (`slot_used`, `slot_not_found`), a
  /// partner who deleted their inbox (`inbox_not_found`), and `clock_skew`
  /// (fix the clock first).
  bool get retryable =>
      code._retryable ||
      (code == RelayErrorCode.unknown && (status ?? 0) >= 500);

  @override
  String toString() {
    final extra = [
      if (status != null) 'status $status',
      if (retryAfter != null) 'retry after ${retryAfter!.inSeconds} s',
      if (nextChunk != null) 'next chunk $nextChunk',
    ];
    return 'RelayException(${code.wireName}'
        '${extra.isEmpty ? '' : ', ${extra.join(', ')}'})';
  }
}
