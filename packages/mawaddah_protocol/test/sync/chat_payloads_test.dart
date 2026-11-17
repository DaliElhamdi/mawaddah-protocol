// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

const _blob = 'AAECAwQFBgcICQoLDA0ODw';
const _key = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const _id = '01a1ca7a-ae00-7c0d-b376-c67aa672a31a';
const _hlc = '01a1ca7aae000000';

Map<String, Object?> _photo([Map<String, Object?> more = const {}]) => {
  'kind': 'photo',
  'blob_id': _blob,
  'key': _key,
  'size': 1000,
  ...more,
};

Map<String, Object?> _voice([Map<String, Object?> more = const {}]) => {
  'kind': 'voice',
  'blob_id': _blob,
  'key': _key,
  'size': 1000,
  'ms': 4000,
  ...more,
};

void main() {
  bool message(Map<String, Object?> p) => validateMessagePayload('create', p);

  group('the registry carries the chat checks', () {
    for (final type in ['message', 'reaction', 'receipt']) {
      test(type, () => expect(EntityRegistry.v1[type]!.validate, isNotNull));
    }
  });

  group('message', () {
    test('text limits count UTF-16 units', () {
      expect(message({'text': 'x' * 4000}), isTrue);
      expect(message({'text': 'x' * 4001}), isFalse);
      // 😊 is two units: 2,000 of them fit, 2,001 do not.
      expect(message({'text': '😊' * 2000}), isTrue);
      expect(message({'text': '😊' * 2001}), isFalse);
      expect(message({'text': 5}), isFalse);
      expect(message({}), isFalse);
    });

    test('blank text only with an attachment', () {
      expect(message({'text': ''}), isFalse);
      expect(message({'text': ' \n\t'}), isFalse);
      expect(message({'text': '', 'attachment': _photo()}), isTrue);
      expect(message({'text': '', 'attachment': null}), isFalse);
    });

    test('reply_to must be an entity ID', () {
      expect(message({'text': 'a', 'reply_to': _id}), isTrue);
      expect(message({'text': 'a', 'reply_to': _id.toUpperCase()}), isFalse);
      expect(message({'text': 'a', 'reply_to': 7}), isFalse);
    });

    test('unknown fields are ignored', () {
      expect(message({'text': 'a', 'later': 1}), isTrue);
      expect(
        message({
          'text': '',
          'attachment': _photo({'later': 1}),
        }),
        isTrue,
      );
    });
  });

  group('attachment', () {
    bool ok(Object? a) => isValidAttachmentPayload(a);

    test('photo', () {
      expect(ok(_photo()), isTrue);
      expect(ok(_photo({'w': 1, 'h': 20000})), isTrue);
      expect(ok(_photo({'w': 0})), isFalse);
      expect(ok(_photo({'h': 20001})), isFalse);
      expect(ok(_photo({'w': 1.5})), isFalse);
    });

    test('voice', () {
      expect(ok(_voice()), isTrue);
      expect(ok(_voice({'ms': 185000})), isTrue);
      expect(ok(_voice({'ms': 185001})), isFalse);
      expect(ok(_voice({'ms': 0})), isFalse);
      expect(ok(_voice({'ms': null})), isFalse);
      expect(ok(_voice({'wave': List.filled(64, 255)})), isTrue);
      expect(ok(_voice({'wave': List.filled(65, 1)})), isFalse);
      expect(ok(_voice({'wave': <int>[]})), isFalse);
      expect(
        ok(
          _voice({
            'wave': [-1],
          }),
        ),
        isFalse,
      );
      expect(
        ok(
          _voice({
            'wave': [256],
          }),
        ),
        isFalse,
      );
      expect(ok(_voice({'wave': 'x'})), isFalse);
    });

    test('blob, key, size and kind', () {
      expect(ok(_photo({'size': 41})), isTrue);
      expect(ok(_photo({'size': 40})), isFalse);
      expect(ok(_photo({'size': 10485760})), isTrue);
      expect(ok(_photo({'size': 10485761})), isFalse);
      expect(ok(_photo({'size': 1000.0})), isFalse);
      expect(ok(_photo({'blob_id': _blob.substring(1)})), isFalse);
      expect(ok(_photo({'blob_id': '${_blob.substring(0, 21)}B'})), isFalse);
      expect(ok(_photo({'key': _key.substring(1)})), isFalse);
      // The last character of a 32-byte key carries 4 bits only.
      expect(ok(_photo({'key': '${_key.substring(0, 42)}9'})), isFalse);
      expect(ok(_photo({'key': '$_key='})), isFalse);
      expect(ok(_photo({'kind': 'video'})), isFalse);
      expect(ok('photo'), isFalse);
      expect(ok(null), isFalse);
    });
  });

  group('reaction', () {
    bool r(Map<String, Object?> p) => validateReactionPayload('update', p);

    test('fields', () {
      expect(r({'emoji': '👍'}), isTrue);
      expect(r({'emoji': ''}), isTrue);
      expect(r({'message_id': _id}), isTrue);
      expect(r({'message_id': _id, 'emoji': '❤️'}), isTrue);
      expect(r({}), isFalse);
      expect(r({'emoji': 'a b'}), isFalse);
      expect(r({'emoji': 'a\u0001'}), isFalse);
      expect(r({'emoji': 'x' * 32}), isTrue);
      expect(r({'emoji': 'x' * 33}), isFalse);
      expect(r({'emoji': 1}), isFalse);
      expect(r({'message_id': 'x'}), isFalse);
      expect(r({'emoji': '+', 'other': 1}), isFalse);
    });
  });

  group('receipt', () {
    bool r(Map<String, Object?> p) => validateReceiptPayload('update', p);

    test('fields', () {
      expect(r({'delivered': _hlc}), isTrue);
      expect(r({'read': _hlc, 'delivered': _hlc}), isTrue);
      expect(r({}), isFalse);
      expect(r({'read': '01A1CA7AAE000000'}), isFalse);
      expect(r({'read': '01a1ca7a'}), isFalse);
      expect(r({'read': 5}), isFalse);
      expect(r({'seen': _hlc}), isFalse);
      expect(r({'read': _hlc, 'seen': _hlc}), isFalse);
    });
  });
}
