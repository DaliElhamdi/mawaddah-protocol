// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

Uint8List b(List<int> v) => Uint8List.fromList(v);

void main() {
  group('FakeClock', () {
    test('starts at the given time, in UTC', () {
      expect(
          FakeClock(DateTime.utc(2026, 3, 1)).now(), DateTime.utc(2026, 3, 1));
    });
    test('only moves when told to', () {
      final c = FakeClock(DateTime.utc(2026, 3, 1));
      expect(c.now(), c.now());
      c.advance(const Duration(days: 7));
      expect(c.now(), DateTime.utc(2026, 3, 8));
      c.set(DateTime.utc(2027, 1, 1));
      expect(c.now(), DateTime.utc(2027, 1, 1));
    });
  });

  group('SeededRandom', () {
    test('same seed gives the same bytes', () {
      expect(SeededRandom(7).nextBytes(32), SeededRandom(7).nextBytes(32));
    });
    test('different seeds differ', () {
      expect(
          SeededRandom(1).nextBytes(32), isNot(SeededRandom(2).nextBytes(32)));
    });
    test('returns the requested length and rejects negatives', () {
      expect(SeededRandom(1).nextBytes(0), isEmpty);
      expect(SeededRandom(1).nextBytes(17), hasLength(17));
      expect(() => SeededRandom(1).nextBytes(-1), throwsRangeError);
    });
  });

  group('InMemoryStorage', () {
    test('write, read, overwrite, delete', () async {
      final s = InMemoryStorage();
      expect(await s.read('a'), isNull);
      await s.write('a', b([1]));
      expect(await s.read('a'), b([1]));
      await s.write('a', b([2]));
      expect(await s.read('a'), b([2]));
      await s.delete('a');
      await s.delete('a');
      expect(await s.read('a'), isNull);
    });
    test('keys are filtered by prefix and sorted', () async {
      final s = InMemoryStorage();
      for (final k in ['x/2', 'y/1', 'x/1']) {
        await s.write(k, b([0]));
      }
      expect(await s.keys(prefix: 'x/'), ['x/1', 'x/2']);
      expect(await s.keys(), ['x/1', 'x/2', 'y/1']);
    });
    test('does not alias the caller\'s bytes', () async {
      final s = InMemoryStorage();
      final v = b([1, 2]);
      await s.write('k', v);
      v[0] = 9;
      expect(await s.read('k'), b([1, 2]));
    });
  });

  group('FakeRelayClient', () {
    test('fetch returns envelopes in order; cursor resumes', () async {
      final r = FakeRelayClient();
      await r.deposit('i', b([1]));
      await r.deposit('i', b([2]), wake: true);
      final all = await r.fetch('i');
      expect(all.map((e) => e.body), [
        b([1]),
        b([2])
      ]);
      final rest = await r.fetch('i', after: all.first.cursor);
      expect(rest.map((e) => e.body), [
        b([2])
      ]);
      expect(r.wakesFor('i'), [false, true]);
    });
    test('ack deletes up to the cursor; inboxes are separate', () async {
      final r = FakeRelayClient();
      await r.deposit('i', b([1]));
      await r.deposit('i', b([2]));
      await r.deposit('j', b([3]));
      final all = await r.fetch('i');
      await r.ack('i', all.first.cursor);
      expect((await r.fetch('i')).map((e) => e.body), [
        b([2])
      ]);
      expect((await r.fetch('j')).map((e) => e.body), [
        b([3])
      ]);
      expect(await r.fetch('unknown'), isEmpty);
    });
  });
}
