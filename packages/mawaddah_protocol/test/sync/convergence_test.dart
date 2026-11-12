// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Property test: two phones make random changes to shared entities, then each
// receives the partner's events in a random order, in random batches, with
// repeats, interleaved with its own. Both must end with the same state, and
// so must a third copy that receives everything shuffled.

import 'dart:math';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'support.dart';

/// A type only the newer release knows: Alice stores it unapplied until she
/// updates.
const _note = 'note';
final _newer = EntityRegistry.v1.withRule(
  _note,
  const EntityRule(
    merge: MergeRule.lastWriterWins,
    ops: {EventOp.update, EventOp.delete},
  ),
);

const _names = ['Amina', 'Yusuf', 'Sara', 'Omar'];
const _modes = ['engaged', 'contracted', 'married_cohab', 'married_remote'];

/// The events both phones made, each list in the order its author made them.
({List<Event> a, List<Event> b}) _scenario(Random rnd, int seed) {
  final a = Maker(alice, seed * 2 + 1);
  final b = Maker(bob, seed * 2 + 2);
  // Bob's clock is off by up to 10 minutes either way.
  b.clock.advance(Duration(milliseconds: rnd.nextInt(1200001) - 600000));
  final profiles = [a.newId(), b.newId()];
  final notes = [a.newId(), b.newId()];
  final reactions = [a.newId()];
  final messages = <String>[];
  final made = (a: <Event>[], b: <Event>[]);

  final ops = 10 + rnd.nextInt(40);
  for (var i = 0; i < ops; i++) {
    final isA = rnd.nextBool();
    final m = isA ? a : b;
    final out = isA ? made.a : made.b;
    // Clocks move on, stand still or go back.
    m.clock.advance(Duration(milliseconds: rnd.nextInt(3000) - 500));
    if (rnd.nextInt(5) == 0) {
      // Sometimes this phone has just heard from the partner.
      m.factory.hlc.receive((isA ? b : a).factory.hlc.last);
    }
    T pick<T>(List<T> l) => l[rnd.nextInt(l.length)];
    switch (rnd.nextInt(7)) {
      case 0 || 1:
        out.add(
          m.make('profile', pick(profiles), EventOp.update, {
            if (rnd.nextBool()) 'first_name': pick(_names),
            if (rnd.nextBool()) 'mode': pick(_modes),
            'gender': rnd.nextBool() ? 'male' : 'female',
          }),
        );
      case 2:
        final id = messages.isNotEmpty && rnd.nextInt(6) == 0
            ? pick(messages) // a second create of the same message
            : m.newId();
        messages.add(id);
        out.add(
          m.make('message', id, EventOp.create, {
            'text': 'm$i',
            if (rnd.nextBool()) 'reply_to': pick(messages),
          }),
        );
      case 3:
        if (messages.isNotEmpty) {
          out.add(m.make('message', pick(messages), EventOp.delete));
        }
      case 4:
        out.add(
          m.make('reaction', pick(reactions), EventOp.update, {
            m.device.toBase64Url(): pick(['+1', 'heart', null]),
          }),
        );
      case 5:
        // Only Bob has the newer release.
        b.clock.advance(const Duration(milliseconds: 1));
        made.b.add(
          b.make(_note, pick(notes), EventOp.update, {
            'text': 'n$i',
            'nested': {
              'list': [i, 'x'],
            },
          }),
        );
      case 6:
        if (rnd.nextInt(3) == 0) {
          made.b.add(b.make(_note, pick(notes), EventOp.delete));
        }
    }
  }
  return made;
}

/// Delivers [own] (with applyLocal, in order) and [partner]'s events (with
/// applyReceived: shuffled, in batches of 1 to 4, some batches twice), all
/// interleaved at random. With a [compactor], the log is compacted at random
/// moments too.
Future<void> _deliver(
  Random rnd,
  Applier applier,
  List<Event> own,
  List<Event> partnerEvents,
  DeviceId partner, {
  Compactor? compactor,
}) async {
  final shuffled = [...partnerEvents]..shuffle(rnd);
  final batches = <List<Event>>[];
  for (var i = 0; i < shuffled.length;) {
    final n = min(1 + rnd.nextInt(4), shuffled.length - i);
    batches.add(shuffled.sublist(i, i + n));
    i += n;
  }
  for (final b in [...batches]) {
    if (rnd.nextInt(3) == 0) batches.insert(rnd.nextInt(batches.length), b);
  }
  var nextOwn = 0;
  final work = [
    for (final b in batches) ('received', b),
    for (var i = 0; i < own.length; i++) ('local', null),
  ]..shuffle(rnd);
  for (final (kind, events) in work) {
    if (kind == 'received') {
      // A repeated batch may also carry a repeat of one of its events.
      final list = rnd.nextInt(4) == 0 ? [...events!, events.first] : events!;
      await applier.applyReceived(batch(list), sender: partner);
    } else {
      final e = own[nextOwn++];
      await applier.applyLocal([e]);
      if (rnd.nextInt(5) == 0) await applier.applyLocal([e]); // a second tap
    }
    if (compactor != null && rnd.nextInt(3) == 0) {
      await compactor.compactIfNeeded();
    }
  }
}

/// A compactor for [store] with a low random threshold, so small scenarios
/// compact often.
Compactor _compactor(
  Random rnd,
  InMemoryEventStore store,
  DeviceId device,
  int seed,
  EntityRegistry registry,
) => Compactor(
  store,
  factory: Maker(device, seed).factory,
  registry: registry,
  threshold: 2 + rnd.nextInt(6),
);

void main() {
  test('random order, batches and repeats: both phones end the same', () async {
    await _converge(compact: false);
  });

  test('the same with compaction at random moments', () async {
    await _converge(compact: true);
  });
}

/// Compaction makes each phone's log its own, so with [compact] only the
/// state (entities and unapplied events) is compared.
Future<void> _converge({required bool compact}) async {
  var withNotes = 0, withDeletes = 0, compactions = 0;
  for (var seed = 0; seed < 300; seed++) {
    final rnd = Random(seed);
    final made = _scenario(rnd, seed);
    final reason = 'seed $seed';
    final log = !compact;

    final aliceStore = InMemoryEventStore();
    final bobStore = InMemoryEventStore();
    final aliceApplier = Applier(aliceStore, localDevice: alice);
    final bobApplier = Applier(bobStore, localDevice: bob, registry: _newer);
    final third = InMemoryEventStore();
    Compactor? compactorFor(
      InMemoryEventStore s,
      DeviceId d,
      int n,
      EntityRegistry registry,
    ) => compact ? _compactor(rnd, s, d, seed * 10 + n, registry) : null;
    await _deliver(
      rnd,
      aliceApplier,
      made.a,
      made.b,
      bob,
      compactor: compactorFor(aliceStore, alice, 1, EntityRegistry.v1),
    );
    await _deliver(
      rnd,
      bobApplier,
      made.b,
      made.a,
      alice,
      compactor: compactorFor(bobStore, bob, 2, _newer),
    );

    // Alice's older release keeps Bob's notes unapplied, nothing else.
    final notes = made.b.where((e) => e.entityType == _note).toList();
    final unapplied = await aliceStore.unapplied();
    expect(
      unapplied.map((u) => u.eventId).toSet(),
      notes.map((e) => e.eventId).toSet(),
      reason: reason,
    );
    expect(
      unapplied.every((u) => u.reason == UnappliedReason.unknownEntityType),
      isTrue,
      reason: reason,
    );
    if (notes.isNotEmpty) withNotes++;
    if ([...made.a, ...made.b].any((e) => e.op == EventOp.delete)) {
      withDeletes++;
    }

    // After her update she applies them and matches Bob exactly.
    await Applier(
      aliceStore,
      localDevice: alice,
      registry: _newer,
    ).reapplyUnapplied();
    // She may compact again after the update, with the new types too.
    await compactorFor(aliceStore, alice, 3, _newer)?.compactIfNeeded();
    final bobDump = await dump(bobStore, log: log);
    expect(await dump(aliceStore, log: log), bobDump, reason: reason);

    // A third copy receiving everything shuffled, per author, also matches.
    final thirdCompactor = compactorFor(third, deviceId(0x0c), 4, _newer);
    final thirdApplier = Applier(
      third,
      localDevice: deviceId(0x0c),
      registry: _newer,
    );
    final all = [
      for (final e in made.a) (alice, e),
      for (final e in made.b) (bob, e),
    ]..shuffle(rnd);
    for (final (who, e) in [...all, ...all.take(all.length ~/ 2)]) {
      await thirdApplier.applyReceived(batch([e]), sender: who);
      if (thirdCompactor != null && rnd.nextInt(3) == 0) {
        await thirdCompactor.compactIfNeeded();
      }
    }
    expect(await dump(third, log: log), bobDump, reason: reason);
    if (compact) {
      for (final s in [aliceStore, bobStore, third]) {
        final snapshots = s.events.values.where(
          (e) => e.op == EventOp.snapshot,
        );
        compactions += snapshots.length;
        // Compacted content leaves only snapshot payloads behind.
        for (final e in snapshots) {
          expect(e.payload.keys, ['replaced'], reason: reason);
        }
      }
    }
  }
  // The scenarios did exercise what they are meant to.
  expect(withNotes, greaterThan(100));
  expect(withDeletes, greaterThan(100));
  if (compact) expect(compactions, greaterThan(300));
}
