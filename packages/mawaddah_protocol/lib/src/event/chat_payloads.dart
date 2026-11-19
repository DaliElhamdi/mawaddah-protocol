// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Payload rules of the chat entity types `message`, `reaction` and
/// `receipt` (PROTOCOL.md section 10, registry).
library;

import '../attachment/attachment_cipher.dart';
import '../relay_client.dart';
import 'event.dart';
import 'question_payloads.dart';

/// The longest chat message, in UTF-16 code units (what a text field counts).
const maxMessageLength = 4000;

/// The longest reaction, in UTF-16 code units (a flag or a family emoji is a
/// dozen or so).
const maxReactionLength = 32;

/// The longest voice note: 3 minutes.
const maxVoiceMs = 3 * 60 * 1000;

/// The encoder may run a little over the limit: a voice `ms` is accepted up
/// to [maxVoiceMs] plus this slack.
const voiceSlackMs = 5000;

/// Most bars (loudness values) a voice note carries.
const maxVoiceWave = 64;

/// Largest picture side, in pixels, that the layout hint accepts.
const maxPhotoSide = 20000;

final _entityId = RegExp(
  r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
);

// 32 bytes = 43 characters; the last one carries 4 bits only.
final _keyText = RegExp(r'^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$');

final _blankOrControl = RegExp(r'[\s\x00-\x1f\x7f-\x9f]');

final _hlcText = RegExp(r'^[0-9a-f]{16}$');

/// The `message` payload (op `create`; a `delete` has no payload and is not
/// checked here): `text`, a string of at most [maxMessageLength] units that
/// is not blank unless the message carries an `attachment`; optionally
/// `reply_to`, the entity ID of the message this one answers; optionally
/// `attachment`, a photo or a voice note (see [isValidAttachmentPayload]);
/// optionally `thread_id`, the `entity_id` of the topic thread the message
/// belongs to (none: the general chat); optionally `content_ref`, the
/// question ID of a joke shared in the sender's language ([isQuestionId]).
/// Null counts as absent for the optional fields. Other fields are ignored,
/// so a later release can add some.
bool validateMessagePayload(String op, JsonMap payload) {
  final text = payload['text'];
  if (text is! String || text.length > maxMessageLength) return false;
  final attachment = payload['attachment'];
  if (attachment != null) {
    if (!isValidAttachmentPayload(attachment)) return false;
  } else if (text.trim().isEmpty) {
    return false;
  }
  final replyTo = payload['reply_to'];
  if (replyTo != null && (replyTo is! String || !_entityId.hasMatch(replyTo))) {
    return false;
  }
  final threadId = payload['thread_id'];
  if (threadId != null &&
      (threadId is! String || !_entityId.hasMatch(threadId))) {
    return false;
  }
  final contentRef = payload['content_ref'];
  return contentRef == null || isQuestionId(contentRef);
}

/// Whether [value] is a well-formed `attachment` of a `message`: an object
/// of kind `photo` or `voice` with a canonical `blob_id` (22 characters), a
/// 32-byte `key` in unpadded base64url and a `size` (bytes of ciphertext on
/// the relay) the relay could hold. A photo may carry `w` and `h`, picture
/// sides from 1 to [maxPhotoSide]; a voice note needs `ms`, from 1 to
/// [maxVoiceMs] plus [voiceSlackMs], and may carry `wave`, 1 to
/// [maxVoiceWave] integers from 0 to 255.
bool isValidAttachmentPayload(Object? value) {
  if (value is! Map) return false;
  final kind = value['kind'];
  if (kind != 'photo' && kind != 'voice') return false;
  final blobId = value['blob_id'];
  final key = value['key'];
  final size = value['size'];
  if (blobId is! String || !isRelayId(blobId)) return false;
  if (key is! String || !_keyText.hasMatch(key)) return false;
  if (size is! int ||
      size < attachmentCiphertextLength(0) ||
      size > maxAttachmentCiphertext) {
    return false;
  }
  if (kind == 'photo') {
    for (final side in [value['w'], value['h']]) {
      if (side != null && (side is! int || side < 1 || side > maxPhotoSide)) {
        return false;
      }
    }
    return true;
  }
  final ms = value['ms'];
  if (ms is! int || ms < 1 || ms > maxVoiceMs + voiceSlackMs) return false;
  final wave = value['wave'];
  if (wave == null) return true;
  return wave is List &&
      wave.isNotEmpty &&
      wave.length <= maxVoiceWave &&
      wave.every((v) => v is int && v >= 0 && v <= 255);
}

/// The `reaction` payload: any of `message_id` (the message reacted to, an
/// entity ID) and `emoji` (1 to [maxReactionLength] units with no white
/// space or control characters, or `""` for "removed"), at least one,
/// nothing else.
bool validateReactionPayload(String op, JsonMap payload) {
  if (payload.isEmpty) return false;
  for (final MapEntry(:key, :value) in payload.entries) {
    switch (key) {
      case 'message_id':
        if (value is! String || !_entityId.hasMatch(value)) return false;
      case 'emoji':
        if (value is! String || value.length > maxReactionLength) return false;
        if (value.isNotEmpty && _blankOrControl.hasMatch(value)) return false;
      default:
        return false;
    }
  }
  return true;
}

/// The `receipt` payload: any of `delivered` and `read`, each the HLC (16
/// lowercase hex digits) of the newest message of the other person that this
/// person has received or read, at least one, nothing else.
bool validateReceiptPayload(String op, JsonMap payload) {
  if (payload.isEmpty) return false;
  for (final MapEntry(:key, :value) in payload.entries) {
    if (key != 'delivered' && key != 'read') return false;
    if (value is! String || !_hlcText.hasMatch(value)) return false;
  }
  return true;
}
