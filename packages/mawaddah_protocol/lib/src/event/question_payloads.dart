// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Payload rules of the question entity types: answers and their locks,
/// reveal marks, topic threads, understandings, the daily question, shuffle,
/// blocks, before-the-nikah topics and the pair's settings (PROTOCOL.md
/// section 10, "Question payloads").
///
/// Common rules, for every type here:
/// - A `create` carries every required field. An `update` carries at least
///   one field and none of the type's create-only fields (they name what the
///   entity is about, so a last-writer-wins write can never move an entity
///   to another key).
/// - Each known field present must pass its check; unknown extra fields are
///   ignored, so a later release can add fields.
/// - Lengths count UTF-16 code units.
library;

import 'event.dart';

/// The longest free-text answer, in UTF-16 code units.
const maxAnswerTextLength = 1000;

/// The longest optional `note` of an answer, in UTF-16 code units.
const maxAnswerNoteLength = 140;

/// The longest `origin_id` of a topic thread or `source_id` of an
/// understanding.
const maxOriginIdLength = 128;

typedef _Check = bool Function(Object? value);

final _uuid = RegExp(
  r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
);
final _contentId = RegExp(r'^[a-z][a-z0-9_]{0,63}$');
final _key = RegExp(r'^[a-z][a-z0-9_]{0,31}$');
final _opt = RegExp(r'^[a-z0-9_]{1,16}$');
final _date = RegExp(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})$');
final _yearly = RegExp(r'^--([0-9]{2})-([0-9]{2})$');
final _timezone = RegExp(r'^[A-Za-z0-9_+/-]{1,64}$');

bool _isUuid(Object? v) => v is String && _uuid.hasMatch(v);

/// Whether [v] is a question ID: a content ID (`[a-z][a-z0-9_]{0,63}`) or
/// the UUID-shaped `entity_id` of an own question.
bool isQuestionId(Object? v) =>
    v is String && (_contentId.hasMatch(v) || _isUuid(v));

/// A category or topic key.
bool _isKey(Object? v) => v is String && _key.hasMatch(v);

bool _isOpt(Object? v) => v is String && _opt.hasMatch(v);

bool _isBool(Object? v) => v is bool;

bool _validDay(int year, int month, int day) {
  if (month < 1 || month > 12 || day < 1) return false;
  final leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
  const days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= (month == 2 && leap ? 29 : days[month - 1]);
}

/// `YYYY-MM-DD`, a real day of the Gregorian calendar.
bool _isDate(Object? v) {
  if (v is! String) return false;
  final m = _date.firstMatch(v);
  return m != null &&
      _validDay(int.parse(m[1]!), int.parse(m[2]!), int.parse(m[3]!));
}

/// `--MM-DD`, a day that comes back every year (`--02-29` included).
bool _isYearly(Object? v) {
  if (v is! String) return false;
  final m = _yearly.firstMatch(v);
  return m != null && _validDay(2000, int.parse(m[1]!), int.parse(m[2]!));
}

/// A daily question's date or a quiz session's `entity_id`.
bool _isRound(Object? v) => _isDate(v) || _isUuid(v);

_Check _text(int min, int max) =>
    (v) => v is String && v.length >= min && v.length <= max;

_Check _oneOf(Set<String> values) =>
    (v) => v is String && values.contains(v);

_Check _intIn(int min, int max) =>
    (v) => v is int && v >= min && v <= max;

bool _intAtLeast1(Object? v) => v is int && v >= 1;

/// A list of [min] to [max] distinct items, each passing [item].
_Check _distinct(int min, int max, _Check item) => (v) {
  if (v is! List || v.length < min || v.length > max) return false;
  return v.every(item) && v.toSet().length == v.length;
};

/// The common rules of the library comment: [fields] are the known fields
/// with their checks, [required] must all be in a `create`, [createOnly] may
/// not be in an `update`.
bool _check(
  String op,
  JsonMap payload, {
  required Map<String, _Check> fields,
  Set<String> required = const {},
  Set<String> createOnly = const {},
}) {
  if (op == EventOp.create) {
    if (!required.every(payload.containsKey)) return false;
  } else {
    if (payload.isEmpty || createOnly.any(payload.containsKey)) return false;
  }
  for (final MapEntry(:key, :value) in payload.entries) {
    final check = fields[key];
    if (check != null && !check(value)) return false;
  }
  return true;
}

/// `answer_lock` (`create`): `round`, `question_id` and `skipped` (bool).
/// A lock carries no answer; `skipped: true` is a skip.
bool validateAnswerLockPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {'round': _isRound, 'question_id': isQuestionId, 'skipped': _isBool},
  required: {'round', 'question_id', 'skipped'},
);

const _answerForms = {'choice', 'scale', 'text', 'order', 'gave_up'};

/// `answer` (`create`): `round`, `question_id` and exactly one of `choice`
/// (1 to 12 distinct option IDs), `scale` (an integer from 1 to 10), `text`
/// (1 to [maxAnswerTextLength] units, not only white space), `order` (3 to 6
/// distinct option IDs) or `gave_up` (`true`; a riddle only, which the app
/// checks). Any form may carry an optional `note` (1 to
/// [maxAnswerNoteLength] units, not only white space): a sentence for the
/// spouse, revealed with the answer.
bool validateAnswerPayload(String op, JsonMap payload) {
  if (_answerForms.where(payload.containsKey).length != 1) return false;
  return _check(
    op,
    payload,
    fields: {
      'round': _isRound,
      'question_id': isQuestionId,
      'choice': _distinct(1, 12, _isOpt),
      'scale': _intIn(1, 10),
      'text': (v) =>
          _text(1, maxAnswerTextLength)(v) && (v as String).trim().isNotEmpty,
      'order': _distinct(3, 6, _isOpt),
      'gave_up': (v) => v == true,
      'note': (v) =>
          _text(1, maxAnswerNoteLength)(v) && (v as String).trim().isNotEmpty,
    },
    required: {'round', 'question_id'},
  );
}

/// `reveal_mark` (`create`, `update`): `round` and `question_id`
/// (create-only) and `mark` (`agree`, `discuss` or `none`).
bool validateRevealMarkPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {
    'round': _isRound,
    'question_id': isQuestionId,
    'mark': _oneOf({'agree', 'discuss', 'none'}),
  },
  required: {'round', 'question_id', 'mark'},
  createOnly: {'round', 'question_id'},
);

/// `topic_thread` (`create`, `update`): `origin` (`question`, `nikah` or
/// `manual`) and `origin_id` (0 to [maxOriginIdLength] units), both
/// create-only; `title` (1 to 100 units) and `archived` (bool).
bool validateTopicThreadPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {
    'origin': _oneOf({'question', 'nikah', 'manual'}),
    'origin_id': _text(0, maxOriginIdLength),
    'title': _text(1, 100),
    'archived': _isBool,
  },
  required: {'origin', 'origin_id', 'title', 'archived'},
  createOnly: {'origin', 'origin_id'},
);

/// `understanding` (`create`, `update`, `delete`): `source` (`quiz`,
/// `sulh`, `nikah` or `manual`) and `source_id` (0 to [maxOriginIdLength]
/// units), both create-only; `text` (1 to 500 units); optionally
/// `followup_on` (a date, or null for none).
bool validateUnderstandingPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {
    'source': _oneOf({'quiz', 'sulh', 'nikah', 'manual'}),
    'source_id': _text(0, maxOriginIdLength),
    'text': _text(1, 500),
    'followup_on': (v) => v == null || _isDate(v),
  },
  required: {'source', 'source_id', 'text'},
  createOnly: {'source', 'source_id'},
);

/// `daily_assignment` (`create`, `delete`): `date`, `question_id`, `source`
/// (`pin`, `own` or `random`), `plan_version` and `content_version`
/// (integers of at least 1).
bool validateDailyAssignmentPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {
    'date': _isDate,
    'question_id': isQuestionId,
    'source': _oneOf({'pin', 'own', 'random'}),
    'plan_version': _intAtLeast1,
    'content_version': _intAtLeast1,
  },
  required: {
    'date',
    'question_id',
    'source',
    'plan_version',
    'content_version',
  },
);

/// `daily_pin` (`create`, `update`, `delete`): `on` (a date, or `--MM-DD`
/// for every year), `pin` (`question`, `category` or `own`) and `target`. In
/// a payload with both, `target` matches `pin`: a question ID for
/// `question`, a key for `category`, an own question's `entity_id` for
/// `own`; alone it is a question ID or a key.
bool validateDailyPinPayload(String op, JsonMap payload) {
  final ok = _check(
    op,
    payload,
    fields: {
      'on': (v) => _isDate(v) || _isYearly(v),
      'pin': _oneOf({'question', 'category', 'own'}),
      'target': isQuestionId,
    },
    required: {'on', 'pin', 'target'},
  );
  if (!ok || !payload.containsKey('pin') || !payload.containsKey('target')) {
    return ok;
  }
  final target = payload['target'];
  return switch (payload['pin']) {
    'category' => _isKey(target),
    'own' => _isUuid(target),
    _ => true,
  };
}

const _choiceTypes = {'single_choice', 'multi_choice'};

bool _isOption(Object? v) =>
    v is Map && _isOpt(v['id']) && _text(1, 100)(v['text']);

/// `own_question` (`create`, `update`, `delete`): `text` (1 to 300 units),
/// `type` (`single_choice`, `multi_choice`, `yes_no`, `scale` or
/// `free_text`) and, for the two choice types only, `options` (2 to 6
/// objects with a distinct `id` (option ID) and a `text` of 1 to 100 units);
/// all three create-only. `pooled` (bool).
bool validateOwnQuestionPayload(String op, JsonMap payload) {
  final ok = _check(
    op,
    payload,
    fields: {
      'text': _text(1, 300),
      'type': _oneOf({..._choiceTypes, 'yes_no', 'scale', 'free_text'}),
      'options': (v) {
        if (v is! List || v.length < 2 || v.length > 6) return false;
        if (!v.every(_isOption)) return false;
        return {for (final o in v) (o as Map)['id']}.length == v.length;
      },
      'pooled': _isBool,
    },
    required: {'text', 'type', 'pooled'},
    createOnly: {'text', 'type', 'options'},
  );
  if (!ok || op != EventOp.create) return ok;
  return _choiceTypes.contains(payload['type']) ==
      payload.containsKey('options');
}

/// `shuffle_preset` (`create`, `update`, `delete`): `name` (1 to 40 units),
/// `categories` (1 to 40 distinct keys), `count` (5, 10 or 20), `depth`
/// (`light`, `medium`, `deep` or `any`) and `no_typing` (bool).
bool validateShufflePresetPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {
    'name': _text(1, 40),
    'categories': _distinct(1, 40, _isKey),
    'count': (v) => v is int && const {5, 10, 20}.contains(v),
    'depth': _oneOf({'light', 'medium', 'deep', 'any'}),
    'no_typing': _isBool,
  },
  required: {'name', 'categories', 'count', 'depth', 'no_typing'},
);

/// `quiz_session` (`create`, `update`): `kind` (`shuffle`, `category` or
/// `nikah`) and `question_ids` (1 to 20 distinct question IDs), both
/// create-only; `status` (`open` or `closed`). The `create` is the
/// invitation.
bool validateQuizSessionPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {
    'kind': _oneOf({'shuffle', 'category', 'nikah'}),
    'question_ids': _distinct(1, 20, isQuestionId),
    'status': _oneOf({'open', 'closed'}),
  },
  required: {'kind', 'question_ids', 'status'},
  createOnly: {'kind', 'question_ids'},
);

/// `category_block` (`create`, `update`): `category` (a key, create-only)
/// and `blocked` (bool).
bool validateCategoryBlockPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {'category': _isKey, 'blocked': _isBool},
  required: {'category', 'blocked'},
  createOnly: {'category'},
);

/// `nikah_topic` (`create`, `update`): `topic_id` (a key, create-only) and
/// `state` (`not_yet`, `talked` or `agreed`).
bool validateNikahTopicPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {
    'topic_id': _isKey,
    'state': _oneOf({'not_yet', 'talked', 'agreed'}),
  },
  required: {'topic_id', 'state'},
  createOnly: {'topic_id'},
);

/// `intimacy_opt_in` (`create`, `update`): `enabled` and `adult_married`
/// (bools), both in every event; `enabled: true` needs
/// `adult_married: true`.
bool validateIntimacyOptInPayload(String op, JsonMap payload) {
  final enabled = payload['enabled'];
  final adult = payload['adult_married'];
  return enabled is bool && adult is bool && (!enabled || adult);
}

/// `pair_setting` (`create`, `update`): `daily_timezone`, an IANA zone name
/// of 1 to 64 characters `[A-Za-z0-9_+/-]`.
bool validatePairSettingPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {'daily_timezone': (v) => v is String && _timezone.hasMatch(v)},
  required: {'daily_timezone'},
);

/// `joke_reaction` (`create`, `update`): `question_id` (create-only) and
/// `reaction` (😂, 😄, 🙂 or 😐, or `""` for removed).
bool validateJokeReactionPayload(String op, JsonMap payload) => _check(
  op,
  payload,
  fields: {
    'question_id': isQuestionId,
    'reaction': _oneOf({'😂', '😄', '🙂', '😐', ''}),
  },
  required: {'question_id', 'reaction'},
  createOnly: {'question_id'},
);
