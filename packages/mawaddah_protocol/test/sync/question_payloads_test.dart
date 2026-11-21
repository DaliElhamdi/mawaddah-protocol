// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

const _id = '01a1ca7a-ae00-7c0d-b376-c67aa672a31a';
const _day = '2026-11-19';

typedef _V = bool Function(String op, JsonMap payload);

/// The create payload [good] passes, and every case in [bad] fails.
void _creates(_V check, JsonMap good, Map<String, JsonMap> bad) {
  test('a full create passes', () => expect(check('create', good), isTrue));
  test('unknown fields are ignored', () {
    expect(check('create', {...good, 'later_field': 1}), isTrue);
  });
  test('every required field is needed', () {
    for (final field in good.keys) {
      expect(
        check('create', {...good}..remove(field)),
        isFalse,
        reason: 'without $field',
      );
    }
  });
  for (final MapEntry(:key, :value) in bad.entries) {
    test('refused: $key', () => expect(check('create', value), isFalse));
  }
}

/// [createOnly] fields are refused in an update, [mutable] ones pass.
void _updates(
  _V check, {
  required JsonMap mutable,
  JsonMap createOnly = const {},
}) {
  test('an update of the mutable fields passes', () {
    expect(check('update', mutable), isTrue);
    for (final MapEntry(:key, :value) in mutable.entries) {
      expect(check('update', {key: value}), isTrue, reason: key);
    }
  });
  test('an empty update is refused', () {
    expect(check('update', {}), isFalse);
  });
  test('an update with only later fields passes', () {
    expect(check('update', {'later_field': true}), isTrue);
  });
  for (final MapEntry(:key, :value) in createOnly.entries) {
    test('create-only $key is refused in an update', () {
      expect(check('update', {...mutable, key: value}), isFalse);
    });
  }
}

void main() {
  group('formats', () {
    test('question IDs', () {
      for (final ok in ['a', 'kn_001', 'a${'b' * 63}', _id]) {
        expect(isQuestionId(ok), isTrue, reason: ok);
      }
      for (final bad in [
        '',
        '1abc',
        'Abc',
        'a-b',
        'a${'b' * 64}',
        _id.toUpperCase(),
        7,
        null,
      ]) {
        expect(isQuestionId(bad), isFalse, reason: '$bad');
      }
    });

    test('dates are real days', () {
      bool lock(Object round) => validateAnswerLockPayload('create', {
        'round': round,
        'question_id': 'q',
        'skipped': false,
      });
      for (final ok in ['2026-01-31', '2028-02-29', '2000-02-29', _id]) {
        expect(lock(ok), isTrue, reason: ok);
      }
      for (final bad in [
        '2026-02-29',
        '1900-02-29',
        '2026-13-01',
        '2026-00-10',
        '2026-04-31',
        '2026-1-01',
        '2026-01-01T00:00',
        '20260101',
        '',
      ]) {
        expect(lock(bad), isFalse, reason: bad);
      }
    });
  });

  group('answer_lock', () {
    _creates(
      validateAnswerLockPayload,
      {'round': _day, 'question_id': 'kn_001', 'skipped': false},
      {
        'skipped as text': {'round': _day, 'question_id': 'q', 'skipped': 'no'},
        'bad question': {'round': _day, 'question_id': 'Q', 'skipped': true},
        'round not a date or uuid': {
          'round': 'today',
          'question_id': 'q',
          'skipped': true,
        },
      },
    );
  });

  group('answer', () {
    final base = {'round': _id, 'question_id': 'q1'};
    bool answer(JsonMap more) =>
        validateAnswerPayload('create', {...base, ...more});

    _creates(validateAnswerPayload, {...base, 'scale': 3}, {});

    test('exactly one answer form', () {
      expect(answer({}), isFalse);
      expect(answer({'scale': 3, 'text': 'x'}), isFalse);
      expect(
        answer({
          'gave_up': true,
          'choice': ['a'],
        }),
        isFalse,
      );
    });

    test('choice', () {
      expect(
        answer({
          'choice': ['a'],
        }),
        isTrue,
      );
      expect(
        answer({
          'choice': ['me'],
        }),
        isTrue,
      );
      expect(answer({'choice': List.generate(12, (i) => 'o$i')}), isTrue);
      expect(answer({'choice': List.generate(13, (i) => 'o$i')}), isFalse);
      expect(answer({'choice': <String>[]}), isFalse);
      expect(
        answer({
          'choice': ['a', 'a'],
        }),
        isFalse,
      );
      expect(
        answer({
          'choice': ['A'],
        }),
        isFalse,
      );
      expect(
        answer({
          'choice': ['x' * 17],
        }),
        isFalse,
      );
      expect(answer({'choice': 'a'}), isFalse);
    });

    test('scale', () {
      expect(answer({'scale': 1}), isTrue);
      expect(answer({'scale': 10}), isTrue);
      expect(answer({'scale': 0}), isFalse);
      expect(answer({'scale': 11}), isFalse);
      expect(answer({'scale': 5.0}), isFalse);
    });

    test('text counts UTF-16 units and may not be blank', () {
      expect(answer({'text': 'x' * 1000}), isTrue);
      expect(answer({'text': 'x' * 1001}), isFalse);
      expect(answer({'text': '😊' * 500}), isTrue);
      expect(answer({'text': '😊' * 501}), isFalse);
      expect(answer({'text': ''}), isFalse);
      expect(answer({'text': ' \n'}), isFalse);
    });

    test('order', () {
      expect(
        answer({
          'order': ['a', 'b', 'c'],
        }),
        isTrue,
      );
      expect(answer({'order': List.generate(6, (i) => 'o$i')}), isTrue);
      expect(
        answer({
          'order': ['a', 'b'],
        }),
        isFalse,
      );
      expect(answer({'order': List.generate(7, (i) => 'o$i')}), isFalse);
      expect(
        answer({
          'order': ['a', 'b', 'a'],
        }),
        isFalse,
      );
    });

    test('gave_up is only true', () {
      expect(answer({'gave_up': true}), isTrue);
      expect(answer({'gave_up': false}), isFalse);
      expect(answer({'gave_up': null}), isFalse);
    });

    test('an optional note of 1 to 140 units goes with any form', () {
      expect(answer({'scale': 3, 'note': 'x'}), isTrue);
      expect(
        answer({
          'choice': ['a'],
          'note': 'x' * 140,
        }),
        isTrue,
      );
      expect(answer({'text': 'hi', 'note': '😊' * 70}), isTrue);
      expect(answer({'gave_up': true, 'note': 'x'}), isTrue);
      expect(answer({'scale': 3, 'note': 'x' * 141}), isFalse);
      expect(answer({'scale': 3, 'note': '😊' * 71}), isFalse);
      expect(answer({'scale': 3, 'note': ''}), isFalse);
      expect(answer({'scale': 3, 'note': ' \n'}), isFalse);
      expect(answer({'scale': 3, 'note': 5}), isFalse);
      expect(answer({'scale': 3, 'note': null}), isFalse);
      // A note alone is not an answer.
      expect(answer({'note': 'x'}), isFalse);
    });

    test('the registry allows no update or delete', () {
      expect(EntityRegistry.v1['answer']!.ops, {EventOp.create});
      expect(EntityRegistry.v1['answer_lock']!.ops, {EventOp.create});
    });
  });

  group('reveal_mark', () {
    _creates(
      validateRevealMarkPayload,
      {'round': _day, 'question_id': 'q', 'mark': 'agree'},
      {
        'unknown mark': {'round': _day, 'question_id': 'q', 'mark': 'yes'},
      },
    );
    _updates(
      validateRevealMarkPayload,
      mutable: {'mark': 'discuss'},
      createOnly: {'round': _day, 'question_id': 'q'},
    );
  });

  group('topic_thread', () {
    _creates(
      validateTopicThreadPayload,
      {
        'origin': 'question',
        'origin_id': '$_day/q1',
        'title': 'Money',
        'archived': false,
      },
      {
        'long origin_id': {
          'origin': 'question',
          'origin_id': 'x' * 129,
          'title': 'Money',
          'archived': false,
        },
        'empty title': {
          'origin': 'manual',
          'origin_id': '',
          'title': '',
          'archived': false,
        },
        'long title': {
          'origin': 'manual',
          'origin_id': '',
          'title': 'x' * 101,
          'archived': false,
        },
        'unknown origin': {
          'origin': 'sulh',
          'origin_id': '',
          'title': 't',
          'archived': false,
        },
      },
    );
    test('origin_id may be empty or 128 units', () {
      for (final id in ['', 'x' * 128]) {
        expect(
          validateTopicThreadPayload('create', {
            'origin': 'manual',
            'origin_id': id,
            'title': 't',
            'archived': true,
          }),
          isTrue,
        );
      }
    });
    _updates(
      validateTopicThreadPayload,
      mutable: {'title': 'Our money', 'archived': true},
      createOnly: {'origin': 'manual', 'origin_id': 'x'},
    );
  });

  group('understanding', () {
    _creates(
      validateUnderstandingPayload,
      {'source': 'quiz', 'source_id': '$_day/q1', 'text': 'We save first'},
      {
        'long text': {'source': 'quiz', 'source_id': '', 'text': 'x' * 501},
        'bad follow-up date': {
          'source': 'manual',
          'source_id': '',
          'text': 't',
          'followup_on': '2026-02-30',
        },
      },
    );
    test('followup_on is a date or null', () {
      final base = {'source': 'sulh', 'source_id': '', 'text': 't'};
      expect(
        validateUnderstandingPayload('create', {...base, 'followup_on': _day}),
        isTrue,
      );
      expect(
        validateUnderstandingPayload('update', {'followup_on': null}),
        isTrue,
      );
    });
    _updates(
      validateUnderstandingPayload,
      mutable: {'text': 'changed', 'followup_on': _day},
      createOnly: {'source': 'quiz', 'source_id': 'x'},
    );
  });

  group('daily_assignment', () {
    _creates(
      validateDailyAssignmentPayload,
      {
        'date': _day,
        'question_id': 'kn_001',
        'source': 'random',
        'plan_version': 1,
        'content_version': 3,
      },
      {
        'plan_version 0': {
          'date': _day,
          'question_id': 'q',
          'source': 'pin',
          'plan_version': 0,
          'content_version': 1,
        },
        'content_version as a float': {
          'date': _day,
          'question_id': 'q',
          'source': 'own',
          'plan_version': 1,
          'content_version': 1.0,
        },
        'a uuid as the date': {
          'date': _id,
          'question_id': 'q',
          'source': 'own',
          'plan_version': 1,
          'content_version': 1,
        },
      },
    );
    test('the registry allows create and delete only', () {
      expect(EntityRegistry.v1['daily_assignment']!.ops, {
        EventOp.create,
        EventOp.delete,
      });
    });
  });

  group('daily_pin', () {
    _creates(
      validateDailyPinPayload,
      {'on': '--02-14', 'pin': 'category', 'target': 'love'},
      {
        'a category pin to an own question ID': {
          'on': _day,
          'pin': 'category',
          'target': _id,
        },
        'an own pin to a content ID': {'on': _day, 'pin': 'own', 'target': 'q'},
        'bad yearly day': {'on': '--02-30', 'pin': 'question', 'target': 'q'},
        'long key for a category': {
          'on': _day,
          'pin': 'category',
          'target': 'k' * 33,
        },
      },
    );
    test('targets by pin kind', () {
      bool pin(String kind, String target) => validateDailyPinPayload(
        'create',
        {'on': _day, 'pin': kind, 'target': target},
      );
      expect(pin('question', 'kn_001'), isTrue);
      expect(pin('question', _id), isTrue);
      expect(pin('own', _id), isTrue);
      expect(pin('category', 'faith'), isTrue);
      expect(validateDailyPinPayload('update', {'target': 'q' * 64}), isTrue);
    });
    _updates(
      validateDailyPinPayload,
      mutable: {'on': '2027-01-01', 'pin': 'question', 'target': 'q'},
    );
  });

  group('own_question', () {
    final options = [
      {'id': 'a', 'text': 'Tea'},
      {'id': 'b', 'text': 'Coffee'},
    ];
    _creates(
      validateOwnQuestionPayload,
      {
        'text': 'Tea or coffee?',
        'type': 'single_choice',
        'options': options,
        'pooled': true,
      },
      {
        'one option': {
          'text': 't',
          'type': 'multi_choice',
          'options': [options.first],
          'pooled': true,
        },
        'seven options': {
          'text': 't',
          'type': 'multi_choice',
          'options': List.generate(7, (i) => {'id': 'o$i', 'text': 'x'}),
          'pooled': true,
        },
        'repeated option IDs': {
          'text': 't',
          'type': 'single_choice',
          'options': [options.first, options.first],
          'pooled': true,
        },
        'empty option text': {
          'text': 't',
          'type': 'single_choice',
          'options': [
            options.first,
            {'id': 'b', 'text': ''},
          ],
          'pooled': true,
        },
        'options on a scale question': {
          'text': 't',
          'type': 'scale',
          'options': options,
          'pooled': true,
        },
        'long text': {'text': 'x' * 301, 'type': 'yes_no', 'pooled': true},
        'unknown type': {'text': 't', 'type': 'ranking', 'pooled': true},
      },
    );
    test('non-choice types carry no options', () {
      for (final type in ['yes_no', 'scale', 'free_text']) {
        expect(
          validateOwnQuestionPayload('create', {
            'text': 't',
            'type': type,
            'pooled': false,
          }),
          isTrue,
          reason: type,
        );
      }
    });
    _updates(
      validateOwnQuestionPayload,
      mutable: {'pooled': false},
      createOnly: {'text': 't', 'type': 'yes_no', 'options': options},
    );
  });

  group('shuffle_preset', () {
    _creates(
      validateShufflePresetPayload,
      {
        'name': 'Evening',
        'categories': ['fun', 'faith'],
        'count': 10,
        'depth': 'any',
        'no_typing': false,
      },
      {
        'count 7': {
          'name': 'n',
          'categories': ['fun'],
          'count': 7,
          'depth': 'any',
          'no_typing': false,
        },
        'count 5.0': {
          'name': 'n',
          'categories': ['fun'],
          'count': 5.0,
          'depth': 'any',
          'no_typing': false,
        },
        'no categories': {
          'name': 'n',
          'categories': <String>[],
          'count': 5,
          'depth': 'light',
          'no_typing': false,
        },
        'repeated category': {
          'name': 'n',
          'categories': ['fun', 'fun'],
          'count': 5,
          'depth': 'light',
          'no_typing': false,
        },
        'long name': {
          'name': 'x' * 41,
          'categories': ['fun'],
          'count': 5,
          'depth': 'light',
          'no_typing': false,
        },
      },
    );
    _updates(
      validateShufflePresetPayload,
      mutable: {
        'name': 'Late',
        'categories': List.generate(40, (i) => 'c$i'),
        'count': 20,
        'depth': 'deep',
        'no_typing': true,
      },
    );
  });

  group('quiz_session', () {
    _creates(
      validateQuizSessionPayload,
      {
        'kind': 'shuffle',
        'question_ids': ['q1', _id],
        'status': 'open',
      },
      {
        '21 questions': {
          'kind': 'category',
          'question_ids': List.generate(21, (i) => 'q$i'),
          'status': 'open',
        },
        'repeated question': {
          'kind': 'nikah',
          'question_ids': ['q', 'q'],
          'status': 'open',
        },
        'unknown status': {
          'kind': 'nikah',
          'question_ids': ['q'],
          'status': 'paused',
        },
      },
    );
    _updates(
      validateQuizSessionPayload,
      mutable: {'status': 'closed'},
      createOnly: {
        'kind': 'shuffle',
        'question_ids': ['q'],
      },
    );
  });

  group('category_block', () {
    _creates(
      validateCategoryBlockPayload,
      {'category': 'intimacy', 'blocked': true},
      {
        'blocked as 1': {'category': 'fun', 'blocked': 1},
        'bad key': {'category': 'Fun', 'blocked': true},
      },
    );
    _updates(
      validateCategoryBlockPayload,
      mutable: {'blocked': false},
      createOnly: {'category': 'fun'},
    );
  });

  group('nikah_topic', () {
    _creates(
      validateNikahTopicPayload,
      {'topic_id': 'mahr', 'state': 'not_yet'},
      {
        'unknown state': {'topic_id': 'mahr', 'state': 'done'},
      },
    );
    _updates(
      validateNikahTopicPayload,
      mutable: {'state': 'agreed'},
      createOnly: {'topic_id': 'mahr'},
    );
  });

  group('intimacy_opt_in', () {
    for (final op in ['create', 'update']) {
      test('$op needs both fields, and enabled needs adult_married', () {
        bool v(JsonMap p) => validateIntimacyOptInPayload(op, p);
        expect(v({'enabled': true, 'adult_married': true}), isTrue);
        expect(v({'enabled': false, 'adult_married': true}), isTrue);
        expect(v({'enabled': false, 'adult_married': false}), isTrue);
        expect(v({'enabled': true, 'adult_married': false}), isFalse);
        expect(v({'enabled': false}), isFalse);
        expect(v({'adult_married': true}), isFalse);
        expect(v({'enabled': 'yes', 'adult_married': true}), isFalse);
        expect(v({}), isFalse);
        expect(
          v({'enabled': false, 'adult_married': false, 'later': 1}),
          isTrue,
        );
      });
    }
  });

  group('pair_setting', () {
    _creates(
      validatePairSettingPayload,
      {'daily_timezone': 'Africa/Tunis'},
      {
        'space': {'daily_timezone': 'Africa/ Tunis'},
        'empty': {'daily_timezone': ''},
        'too long': {'daily_timezone': 'x' * 65},
      },
    );
    test('IANA shapes', () {
      for (final z in [
        'Etc/GMT+1',
        'America/Port-au-Prince',
        'UTC',
        'x' * 64,
      ]) {
        expect(
          validatePairSettingPayload('create', {'daily_timezone': z}),
          isTrue,
        );
      }
    });
    _updates(
      validatePairSettingPayload,
      mutable: {'daily_timezone': 'Europe/Paris'},
    );
  });

  group('joke_reaction', () {
    _creates(
      validateJokeReactionPayload,
      {'question_id': 'joke_001', 'reaction': '😂'},
      {
        'another emoji': {'question_id': 'j', 'reaction': '👍'},
        'reaction as a number': {'question_id': 'j', 'reaction': 1},
      },
    );
    test('the four reactions and removed', () {
      for (final r in ['😂', '😄', '🙂', '😐', '']) {
        expect(
          validateJokeReactionPayload('update', {'reaction': r}),
          isTrue,
          reason: r,
        );
      }
    });
    _updates(
      validateJokeReactionPayload,
      mutable: {'reaction': ''},
      createOnly: {'question_id': 'j'},
    );
  });

  group('message thread and joke fields', () {
    bool message(JsonMap p) => validateMessagePayload('create', p);
    test('thread_id is UUID-shaped, content_ref a question ID', () {
      expect(message({'text': 'a', 'thread_id': _id}), isTrue);
      expect(message({'text': 'a', 'thread_id': null}), isTrue);
      expect(message({'text': 'a', 'thread_id': 'general'}), isFalse);
      expect(message({'text': 'a', 'thread_id': 5}), isFalse);
      expect(message({'text': 'a', 'content_ref': 'joke_001'}), isTrue);
      expect(message({'text': 'a', 'content_ref': _id}), isTrue);
      expect(message({'text': 'a', 'content_ref': 'Joke'}), isFalse);
      expect(message({'text': 'a', 'reply_to': _id, 'thread_id': _id}), isTrue);
    });
  });

  group('registry', () {
    const types = {
      'answer_lock': MergeRule.appendOnly,
      'answer': MergeRule.appendOnly,
      'reveal_mark': MergeRule.lastWriterWins,
      'topic_thread': MergeRule.lastWriterWins,
      'understanding': MergeRule.lastWriterWins,
      'daily_assignment': MergeRule.appendOnly,
      'daily_pin': MergeRule.lastWriterWins,
      'own_question': MergeRule.lastWriterWins,
      'shuffle_preset': MergeRule.lastWriterWins,
      'quiz_session': MergeRule.lastWriterWins,
      'category_block': MergeRule.lastWriterWins,
      'nikah_topic': MergeRule.lastWriterWins,
      'intimacy_opt_in': MergeRule.lastWriterWins,
      'pair_setting': MergeRule.lastWriterWins,
      'joke_reaction': MergeRule.lastWriterWins,
    };
    test('every question type has its rule and a check', () {
      for (final MapEntry(key: type, value: merge) in types.entries) {
        final rule = EntityRegistry.v1[type];
        expect(rule, isNotNull, reason: type);
        expect(rule!.merge, merge, reason: type);
        expect(rule.validate, isNotNull, reason: type);
        expect(rule.schemaVersion, 1, reason: type);
      }
    });
    test('delete only where ADR 0014 allows it', () {
      final withDelete = {
        for (final type in types.keys)
          if (EntityRegistry.v1[type]!.ops.contains(EventOp.delete)) type,
      };
      expect(withDelete, {
        'understanding',
        'daily_assignment',
        'daily_pin',
        'own_question',
        'shuffle_preset',
      });
    });
  });
}
