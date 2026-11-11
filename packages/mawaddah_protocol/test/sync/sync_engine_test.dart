// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:mawaddah_protocol/mawaddah_protocol.dart';
import 'package:test/test.dart';

import 'sync_support.dart';

void main() {
  late Crypto crypto;
  setUpAll(() async => crypto = await SodiumCrypto.load());

  group('sending and receiving', () {
    test('messages reach the partner in order, both ways', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      for (final t in ['salam', 'how was your day?', 'see you at 6']) {
        await alice.say(t);
      }
      final sent = await alice.sync();
      expect(sent.envelopesSent, 1);
      expect(sent.eventsSent, 3);
      expect(sent.complete, isTrue);
      expect(await alice.store.outbox(), isEmpty);
      expect(await alice.store.sealedEnvelopes(), isEmpty);

      final got = await bob.sync();
      expect(got.envelopesOpened, 1);
      expect(got.eventsApplied, 3);
      expect(bob.messages(), ['salam', 'how was your day?', 'see you at 6']);
      expect(await relay.pending(bob.inbox), 0, reason: 'acknowledged');

      await bob.say('wa alaikum salam');
      await bob.sync();
      await alice.sync();
      expect(alice.messages(), [
        'salam',
        'how was your day?',
        'see you at 6',
        'wa alaikum salam',
      ]);
    });

    test('the initiator waits for the first message before sending', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      await bob.say('first from bob');
      final waiting = await bob.sync();
      expect(waiting.waitingForPartner, isTrue);
      expect(waiting.complete, isTrue, reason: 'a push will wake it');
      expect(await bob.store.outbox(), hasLength(1));
      expect(relay.deposited, isEmpty);

      await alice.say('first from alice');
      await alice.sync();
      // One run: receive first (now the session can send), then send.
      final r = await bob.sync();
      expect(r.envelopesOpened, 1);
      expect(r.envelopesSent, 1);
      await alice.sync();
      expect(alice.messages(), ['first from alice', 'first from bob']);
    });

    test('a local event is applied at once, offline', () async {
      final (:alice, bob: _, :relay) = await couple(crypto);
      relay.online = false;
      await alice.say('written offline');
      expect(alice.messages(), ['written offline']);
      expect(await alice.store.outbox(), hasLength(1));
      expect(await alice.store.hlc(), alice.engine.hlc.last);
    });

    test('an event already stored is not queued again', () async {
      final (:alice, bob: _, relay: _) = await couple(crypto);
      final e = alice.message('once');
      await alice.engine.commitLocal([e]);
      final again = await alice.engine.commitLocal([e]);
      expect(again.duplicates, 1);
      expect(await alice.store.outbox(), hasLength(1));
      await alice.sync();
      // Also after it was sent: a repeated Done tap sends nothing.
      expect((await alice.engine.commitLocal([e])).duplicates, 1);
      expect(await alice.store.outbox(), isEmpty);
    });

    test('a store failure in commitLocal keeps nothing', () async {
      final (:alice, bob: _, relay: _) = await couple(crypto);
      alice.store.onWrite = (m) {
        if (m == 'addToOutbox') throw StateError('disk full');
      };
      await expectLater(alice.say('lost'), throwsStateError);
      expect(alice.messages(), isEmpty);
      expect(await alice.store.outbox(), isEmpty);
    });

    test('no session: syncOnce throws StateError', () async {
      final events = InMemoryEventStore();
      final (:alice, bob: _, :relay) = await couple(crypto);
      final engine = SyncEngine(
        crypto: crypto,
        random: SeededRandom(1),
        relay: relay,
        store: InMemorySyncStore(events),
        applier: Applier(events, localDevice: alice.identity.deviceId),
        identity: alice.identity,
        partner: alice.pairing.partner,
        hlc: HlcClock(alice.clock),
      );
      await expectLater(engine.syncOnce(), throwsStateError);
    });

    test('an applier for another device is refused', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      expect(
        () => SyncEngine(
          crypto: crypto,
          random: SeededRandom(1),
          relay: relay,
          store: alice.store,
          applier: Applier(alice.events, localDevice: bob.identity.deviceId),
          identity: alice.identity,
          partner: alice.pairing.partner,
          hlc: HlcClock(alice.clock),
        ),
        throwsArgumentError,
      );
    });
  });

  group('outbox batches', () {
    test('a large outbox is split into envelopes that fit', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      final texts = [for (var i = 0; i < 20; i++) '$i:${'x' * 10000}'];
      for (final t in texts) {
        await alice.say(t);
      }
      final r = await alice.sync();
      expect(r.eventsSent, 20);
      expect(r.envelopesSent, greaterThan(1));
      for (final (_, bytes) in relay.deposited) {
        expect(bytes.length, lessThanOrEqualTo(maxEnvelopeLength));
      }
      await bob.sync();
      expect(bob.messages(), texts);
    });

    test('an event of exactly the largest size is sent; one byte more is '
        'refused', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      Event sized(int extra) {
        final probe = alice.message('');
        final base = EventBatch.encode([probe]).length;
        return alice.factory.make(
          entityType: 'message',
          entityId: probe.entityId,
          op: EventOp.create,
          payload: {'text': 'y' * (maxEnvelopePlaintextLength - base + extra)},
        );
      }

      final big = sized(0);
      expect(EventBatch.encode([big]).length, maxEnvelopePlaintextLength);
      final tooBig = sized(1);
      expect(() => alice.engine.commitLocal([tooBig]), throwsArgumentError);
      expect(await alice.store.outbox(), isEmpty);

      await alice.engine.commitLocal([big]);
      await alice.say('small after');
      final r = await alice.sync();
      expect(r.envelopesSent, 2, reason: 'the big one fills an envelope');
      // 90 + 65,280 + 16 + 64: the largest padded plaintext.
      expect(relay.deposited.first.$2.length, 65450);
      await bob.sync();
      expect(bob.messages(), hasLength(2));
    });

    for (final (extra, envelopes) in [(0, 1), (1, 2)]) {
      test(
        'two events that need ${extra == 0 ? 'exactly' : 'one byte more '
                  'than'} the largest plaintext go in $envelopes envelope(s)',
        () async {
          final (:alice, :bob, :relay) = await couple(crypto);
          final a = alice.message('a');
          final probe = alice.message('');
          final base = EventBatch.encode([a, probe]).length;
          final b = alice.factory.make(
            entityType: 'message',
            entityId: probe.entityId,
            op: EventOp.create,
            payload: {
              'text': 'b' * (maxEnvelopePlaintextLength - base + extra),
            },
          );
          expect(
            EventBatch.encode([a, b]).length,
            maxEnvelopePlaintextLength + extra,
          );
          await alice.engine.commitLocal([a, b]);
          expect((await alice.sync()).envelopesSent, envelopes);
          await bob.sync();
          expect(bob.messages(), hasLength(2));
          expect(relay.deposited, hasLength(envelopes));
        },
      );
    }
  });

  group('wake flag', () {
    test('one table decides by entity type and op', () {
      const p = WakePolicy.v1;
      final m = Maker();
      expect(p.wakes(m.make('message', EventOp.create)), isTrue);
      expect(p.wakes(m.make('message', EventOp.delete)), isFalse);
      expect(p.wakes(m.make('receipt', EventOp.update)), isFalse);
      expect(p.wakes(m.make('reaction', EventOp.update)), isFalse);
      expect(p.wakes(m.make('profile', EventOp.update)), isFalse);
      expect(p.wakes(m.make('device', EventOp.update)), isFalse);
      expect(p.wakes(m.make('unknown_type', EventOp.create)), isFalse);
      expect(
        p.wakesAny([
          m.make('receipt', EventOp.update),
          m.make('message', EventOp.create),
        ]),
        isTrue,
      );
    });

    test(
      'the deposit asks for a push only when an event deserves it',
      () async {
        final (:alice, :bob, :relay) = await couple(crypto);
        await alice.say('hi');
        await alice.sync();
        await alice.engine.commitLocal([
          alice.factory.make(
            entityType: 'profile',
            entityId: alice.factory.newEntityId(),
            op: EventOp.update,
            payload: {'first_name': 'Amina'},
          ),
        ]);
        await alice.sync();
        final msg = alice.factory.make(
          entityType: 'message',
          entityId: alice.factory.newEntityId(),
          op: EventOp.create,
          payload: {'text': 'deleted soon'},
        );
        await alice.engine.commitLocal([msg]);
        await alice.sync();
        await alice.engine.commitLocal([
          alice.factory.make(
            entityType: 'message',
            entityId: msg.entityId,
            op: EventOp.delete,
          ),
        ]);
        await alice.sync();
        expect(relay.inner.wakesFor(bob.inbox), [true, false, true, false]);
      },
    );
  });

  group('offline', () {
    test('7 days offline then reconnect: everything arrives once, and the '
        'retries use no extra ratchet keys', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      relay.online = false;
      final texts = <String>[];
      final retries = <Duration>[];
      for (var h = 0; h < 7 * 24; h++) {
        final t = 'hour $h';
        texts.add(t);
        await alice.say(t);
        final r = await alice.sync();
        expect(r.complete, isFalse);
        expect(r.relayError, 'RelayDown');
        retries.add(r.retryAt!.difference(alice.clock.now()));
        // Never more than one sealed envelope waiting.
        expect(await alice.store.sealedEnvelopes(), hasLength(1));
        advanceBoth(alice, bob, const Duration(hours: 1));
      }
      // Back-off grows to the cap and stays there.
      expect(retries.first, const Duration(seconds: 5));
      expect(retries[1], const Duration(seconds: 10));
      expect(retries.last, const Duration(minutes: 15));
      // One envelope sealed at the start, sealed again once a day.
      expect(await alice.store.lastCounter(), lessThanOrEqualTo(8));

      relay.online = true;
      final r = await alice.sync();
      expect(r.complete, isTrue);
      expect(r.retryAt, isNull);
      expect(r.eventsSent, 7 * 24);
      expect(await alice.store.outbox(), isEmpty);
      final got = await bob.sync();
      expect(got.envelopeFailures, isEmpty);
      expect(bob.messages(), texts);
    });

    test('the partner offline 7 days receives a week of envelopes', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      final texts = <String>[];
      for (var d = 0; d < 7; d++) {
        for (var i = 0; i < 3; i++) {
          texts.add('day $d #$i');
          await alice.say(texts.last);
          expect((await alice.sync()).envelopesSent, 1);
          advanceBoth(alice, bob, const Duration(hours: 8));
        }
      }
      expect(await relay.pending(bob.inbox), 21);
      final r = await bob.sync();
      expect(r.envelopesOpened, 21);
      expect(r.envelopeFailures, isEmpty);
      expect(bob.messages(), texts);
      expect(await relay.pending(bob.inbox), 0);
    });

    test('a relay refusal is reported by its code only', () async {
      final (:alice, bob: _, :relay) = await couple(crypto);
      await alice.say('hi');
      relay.inner.failNext(
        const RelayException(RelayErrorCode.inboxFull, status: 409),
        times: 2,
      );
      final r = await alice.sync();
      expect(r.relayError, 'inbox_full');
      expect(r.complete, isFalse);
      expect(r.retryAt, isNotNull);
      expect((await alice.sync()).envelopesSent, 1);
    });

    test('fetching stops when the relay says nothing more waits', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      for (var i = 0; i < 5; i++) {
        await alice.say('m$i');
        await alice.sync();
      }
      relay.pageSize = 2; // pages of 2, 2, 1; "more" on the first two
      final before = relay.fetches;
      final r = await bob.sync();
      expect(r.envelopesOpened, 5);
      expect(r.complete, isTrue);
      expect(relay.fetches - before, 3, reason: 'no empty fetch at the end');
      expect(await relay.pending(bob.inbox), 0);
    });
  });

  group('duplicates, partial failures and lost ACKs', () {
    test(
      'the relay returns duplicates and old envelopes: applied once',
      () async {
        final (:alice, :bob, :relay) = await couple(crypto);
        for (var i = 0; i < 5; i++) {
          await alice.say('m$i');
          await alice.sync();
        }
        relay.duplicates = true; // each one twice, and old ones again
        relay.dropAcks = true; // the relay keeps them
        final first = await bob.sync();
        expect(first.envelopesOpened, 5);
        // Page 1: 5 opened + 5 repeats; page 2 ("more") brings all 10
        // again, which moves the cursor nowhere, so receiving stops.
        expect(first.envelopeFailures, {EnvelopeFailure.replayed: 15});
        expect(first.complete, isTrue);
        final second = await bob.sync();
        expect(second.envelopesOpened, 0);
        expect(second.envelopeFailures, {EnvelopeFailure.replayed: 10});
        expect(second.eventsApplied, 0);
        relay
          ..dropAcks = false
          ..duplicates = false;
        // The engine believes its ACK went through; a restart repeats it.
        await bob.restart();
        await bob.sync();
        expect(bob.messages(), ['m0', 'm1', 'm2', 'm3', 'm4']);
        expect(await relay.pending(bob.inbox), 0);
      },
    );

    test('a deposit fails mid-outbox: the rest waits, the sealed envelope is '
        'sent again as the same bytes', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      final texts = [for (var i = 0; i < 20; i++) '$i:${'z' * 10000}'];
      for (final t in texts) {
        await alice.say(t);
      }
      // First deposit works, second fails.
      final inner = relay.inner;
      final flaky = _FailNth(inner, fail: 2);
      final engine = SyncEngine(
        crypto: crypto,
        random: SeededRandom(99),
        relay: flaky,
        store: alice.store,
        applier: Applier(alice.events, localDevice: alice.identity.deviceId),
        identity: alice.identity,
        partner: alice.pairing.partner,
        hlc: alice.engine.hlc,
      );
      final r = await engine.syncOnce();
      expect(r.envelopesSent, 1);
      expect(r.relayError, isNotNull);
      final waiting = await alice.store.sealedEnvelopes();
      expect(waiting, hasLength(1));
      expect(waiting.single.counter, 2);
      final waitingBytes = Uint8List.fromList(waiting.single.bytes);

      final again = await alice.sync();
      expect(again.complete, isTrue);
      expect(again.resealed, 0);
      expect(relay.deposited.first.$2, waitingBytes);
      expect(await alice.store.outbox(), isEmpty);
      final counters = [
        for (final e in (await inner.fetch(bob.inbox)).envelopes)
          Envelope.parse(e.body).counter,
      ];
      expect(counters, [for (var i = 1; i <= counters.length; i++) i]);
      await bob.sync();
      expect(bob.messages(), texts);
    });

    test('a store failure while sealing: the envelope never leaves, and the '
        'next run seals from the stored session', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      await alice.say('one');
      alice.store.onWrite = (m) {
        if (m == 'putSealedEnvelope') throw StateError('disk full');
      };
      await expectLater(alice.sync(), throwsStateError);
      expect(relay.deposited, isEmpty);
      expect(await alice.store.lastCounter(), 1, reason: 'counter used up');
      alice.store.onWrite = null;
      await alice.restart();
      await alice.sync();
      expect(relay.deposited, hasLength(1));
      expect(Envelope.parse(relay.deposited.single.$2).counter, 2);
      await bob.sync();
      expect(bob.messages(), ['one']);
    });

    test('a store failure mid-fetch keeps the envelopes before it and '
        'acknowledges nothing after', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      for (var i = 0; i < 4; i++) {
        await alice.say('m$i');
        await alice.sync();
      }
      var cursors = 0;
      bob.store.onWrite = (m) {
        if (m == 'putCursor' && ++cursors == 3) throw StateError('disk full');
      };
      await expectLater(bob.sync(), throwsStateError);
      expect(bob.messages(), ['m0', 'm1']);
      expect(await relay.pending(bob.inbox), 4, reason: 'no ACK sent');

      bob.store.onWrite = null;
      await bob.restart();
      final r = await bob.sync();
      // The stored cursor is acked again first, so the first two are gone.
      expect(r.envelopeFailures, isEmpty);
      expect(r.envelopesOpened, 2);
      expect(bob.messages(), ['m0', 'm1', 'm2', 'm3']);
      expect(await relay.pending(bob.inbox), 0);
    });

    test('ACK answer lost: events stay stored, the ACK is repeated, nothing is '
        'applied twice', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      await alice.say('m0');
      await alice.sync();
      relay.loseAckAnswers = 1;
      final r = await bob.sync();
      expect(r.eventsApplied, 1);
      expect(r.relayError, 'RelayDown');
      expect(r.retryAt, isNotNull);
      expect(bob.messages(), ['m0']);

      final acksBefore = relay.acks;
      final again = await bob.sync();
      expect(relay.acks, acksBefore + 1, reason: 'stored cursor acked again');
      expect(again.complete, isTrue);
      expect(again.eventsApplied, 0);
      expect(bob.messages(), ['m0']);
    });

    test('ACK never reached the relay, app restarted: the envelope is acked '
        'at the next start and not applied twice', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      await alice.say('m0');
      await alice.sync();
      relay.failAcks = 1;
      await bob.sync();
      expect(await relay.pending(bob.inbox), 1);
      await bob.restart();
      relay.duplicates = true; // and the relay ignores the cursor
      final r = await bob.sync();
      expect(await relay.pending(bob.inbox), 0);
      expect(r.eventsApplied, 0);
      expect(bob.messages(), ['m0']);
    });
  });

  group('more review cases', () {
    test('a failed repeat of a lost ACK does not stop fetching', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      await alice.say('m0');
      await alice.sync();
      relay.loseAckAnswers = 1;
      await bob.sync();
      await alice.say('m1');
      await alice.sync();
      relay.failAcks = 1; // the repeated ACK fails
      final r = await bob.sync();
      expect(r.relayError, 'RelayDown');
      expect(r.envelopesOpened, 1);
      expect(bob.messages(), ['m0', 'm1']);
      expect(await relay.pending(bob.inbox), 0, reason: 'page ACK covers it');
    });

    test(
      'the page limit leaves the run incomplete; the next run goes on',
      () async {
        final (alice: _, :bob, :relay) = await couple(crypto);
        relay.pageSize = 1;
        for (var i = 0; i < maxFetchPagesPerSync + 1; i++) {
          await relay.inner.deposit(
            bob.inbox,
            Uint8List(500)
              ..[0] = 1
              ..[1] = 1,
          );
        }
        final first = await bob.sync();
        expect(first.envelopeFailures, {
          EnvelopeFailure.malformed: maxFetchPagesPerSync,
        });
        expect(first.complete, isFalse);
        expect(first.relayError, isNull);
        final second = await bob.sync();
        expect(second.envelopeFailures, {EnvelopeFailure.malformed: 1});
        expect(second.complete, isTrue);
        expect(await relay.pending(bob.inbox), 0);
      },
    );

    test('a store failure after the deposit: the same bytes go again and the '
        'partner refuses the copy as a replay', () async {
      final (:alice, :bob, :relay) = await couple(crypto);
      await alice.say('once');
      alice.store.onWrite = (m) {
        if (m == 'removeFromOutbox') throw StateError('disk full');
      };
      await expectLater(alice.sync(), throwsStateError);
      expect(relay.deposited, hasLength(1));
      alice.store.onWrite = null;
      await alice.restart();
      expect((await alice.sync()).envelopesSent, 1);
      expect(relay.deposited, hasLength(2));
      expect(relay.deposited[1].$2, relay.deposited[0].$2);
      final r = await bob.sync();
      expect(r.envelopeFailures, {EnvelopeFailure.replayed: 1});
      expect(bob.messages(), ['once']);
    });
  });

  group('envelopes that do not open', () {
    test('garbage is acknowledged and discarded', () async {
      final (alice: _, :bob, :relay) = await couple(crypto);
      await relay.inner.deposit(
        bob.inbox,
        Uint8List(500)
          ..[0] = 1
          ..[1] = 1,
      );
      final r = await bob.sync();
      expect(r.envelopeFailures, {EnvelopeFailure.malformed: 1});
      expect(r.envelopesKept, 0);
      expect(await bob.store.unappliedEnvelopes(), isEmpty);
      expect(await relay.pending(bob.inbox), 0);
    });

    test('unknown versions are kept, at most 100, oldest dropped', () async {
      final (alice: _, :bob, :relay) = await couple(crypto);
      for (var i = 0; i < 102; i++) {
        await relay.inner.deposit(
          bob.inbox,
          Uint8List(600)
            ..[0] = 2
            ..[1] = i,
        );
      }
      final r = await bob.sync();
      expect(r.envelopesKept, 102);
      final kept = await bob.store.unappliedEnvelopes();
      expect(kept, hasLength(SyncStore.maxKeptEnvelopes));
      expect(kept.every((e) => e.reason.needsUpdate), isTrue);
      expect(kept.first.bytes[1], 2, reason: 'the first two were dropped');
      expect(await relay.pending(bob.inbox), 0);
    });

    test(
      'a refused plaintext is kept, and the session still moves on',
      () async {
        final (:alice, :bob, :relay) = await couple(crypto);
        await alice.sendRaw(utf8.encode('{"events":[]}'));
        final r = await bob.sync();
        expect(r.envelopesOpened, 1);
        expect(r.envelopesKept, 1);
        final kept = await bob.store.unappliedEnvelopes();
        expect(kept.single.reason, UnappliedEnvelopeReason.refused);
        expect(kept.single.reason.needsUpdate, isFalse);
        expect(await relay.pending(bob.inbox), 0);

        await alice.say('after');
        await alice.sync();
        await bob.sync();
        expect(bob.messages(), ['after']);
        await bob.say('reply');
        await bob.sync();
        await alice.sync();
        expect(alice.messages(), ['after', 'reply']);
      },
    );

    test(
      'an envelope ahead of the clock stays on the relay; after 24 h the '
      'wrong-time warning shows; it opens once the clock catches up',
      () async {
        final (:alice, :bob, :relay) = await couple(crypto);
        alice.clock.advance(const Duration(hours: 30));
        await alice.say('from the future');
        await alice.sync();
        await alice.say('also ahead');
        await alice.sync();

        final first = await bob.sync();
        expect(first.leftOnRelay, 1);
        expect(first.envelopeFailures, {EnvelopeFailure.fromTheFuture: 1});
        expect(first.clockWarning, isFalse);
        expect(first.retryAt, isNotNull);
        expect(await relay.pending(bob.inbox), 2, reason: 'nothing acked');
        expect(await bob.store.clockAheadSince(), bob.clock.now());

        bob.clock.advance(const Duration(hours: 25));
        final late = await bob.sync();
        expect(late.clockWarning, isTrue);
        expect(bob.messages(), isEmpty);

        bob.clock.advance(const Duration(hours: 4)); // 29 h: within 1 h
        final caughtUp = await bob.sync();
        expect(caughtUp.envelopesOpened, 2);
        expect(caughtUp.clockWarning, isFalse);
        expect(await bob.store.clockAheadSince(), isNull);
        expect(bob.messages(), ['from the future', 'also ahead']);
      },
    );
  });

  group('single runner', () {
    test(
      'calls during a run share one follow-up run; runs never overlap',
      () async {
        final (:alice, :bob, :relay) = await couple(crypto);
        await alice.say('before');
        relay.gate = Completer<void>();
        final first = alice.sync();
        await Future<void>.delayed(Duration.zero);
        final second = alice.sync();
        final third = alice.sync();
        expect(identical(second, third), isTrue);
        expect(identical(first, second), isFalse);
        await alice.say('during'); // committed while the first run waits
        relay.gate!.complete();
        relay.gate = null;
        final r1 = await first;
        final r2 = await second;
        expect(relay.maxActive, 1);
        expect(r1.eventsSent + r2.eventsSent, 2);
        expect(await alice.store.outbox(), isEmpty);
        await bob.sync();
        expect(bob.messages(), ['before', 'during']);
        // After both finished, a new call starts a new run.
        final next = alice.sync();
        expect(identical(next, second), isFalse);
        await next;
      },
    );

    test('a failed run does not block the next one', () async {
      final (:alice, bob: _, relay: _) = await couple(crypto);
      await alice.say('x');
      alice.store.onWrite = (m) {
        if (m == 'putSealedEnvelope') throw StateError('disk full');
      };
      final failing = alice.sync();
      final queued = alice.sync();
      await expectLater(failing, throwsStateError);
      await expectLater(queued, throwsStateError);
      alice.store.onWrite = null;
      await alice.restart();
      expect((await alice.sync()).eventsSent, 1);
    });
  });

  group('back-off', () {
    test('doubles from 5 s up to 15 min', () {
      const b = BackOff();
      expect(
        [for (var i = 1; i <= 10; i++) b.after(i).inSeconds],
        [5, 10, 20, 40, 80, 160, 320, 640, 900, 900],
      );
      expect(b.after(1000), const Duration(minutes: 15));
    });

    test('a run that finishes resets it', () async {
      final (:alice, bob: _, :relay) = await couple(crypto);
      relay.online = false;
      await alice.say('x');
      await alice.sync();
      final second = await alice.sync();
      expect(second.retryAt!.difference(alice.clock.now()).inSeconds, 10);
      relay.online = true;
      expect((await alice.sync()).retryAt, isNull);
      relay.online = false;
      final again = await alice.sync();
      expect(again.retryAt!.difference(alice.clock.now()).inSeconds, 5);
    });
  });
}

/// A relay whose [fail]th deposit fails (counting from 1).
final class _FailNth extends DelegatingRelay {
  _FailNth(super.inner, {required this.fail});
  final int fail;
  var _n = 0;

  @override
  Future<void> deposit(String inboxId, Uint8List body, {bool wake = false}) {
    if (++_n == fail) throw const RelayDown('deposit');
    return inner.deposit(inboxId, body, wake: wake);
  }
}

/// Makes events of a throwaway device, for the wake table.
final class Maker {
  final _f = EventFactory(
    hlc: HlcClock(FakeClock(DateTime.utc(2026, 11, 11))),
    random: SeededRandom(5),
    author: DeviceId.fromBytes(Uint8List(16)),
  );

  Event make(String type, String op) =>
      _f.make(entityType: type, entityId: _f.newEntityId(), op: op);
}
