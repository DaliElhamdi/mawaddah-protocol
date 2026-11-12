// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// The outbox and the fetch/ack sync loop (spec 4.6 and 8.7, PROTOCOL.md
/// sections 8 and 17).
library;

import 'dart:convert';
import 'dart:typed_data';

import '../clock.dart';
import '../crypto/crypto.dart';
import '../envelope/envelope.dart';
import '../envelope/hlc.dart';
import '../envelope/replay_window.dart';
import '../event/applier.dart';
import '../event/compactor.dart';
import '../event/event.dart';
import '../identity/identity.dart';
import '../random_source.dart';
import '../ratchet/ratchet.dart';
import '../relay_client.dart';
import 'sync_store.dart';
import 'wake_policy.dart';

/// A sealed envelope older than this is not deposited any more: its events
/// are sealed again in a new one. With the relay keeping envelopes for at
/// most 30 days, a deposited envelope is never more than 31 days old when
/// the partner opens it ([maxEnvelopeAge], PROTOCOL.md section 17).
const maxSealedAge = Duration(days: 1);

/// After this long with an envelope from the partner left on the relay
/// because its time is ahead of this phone's clock, the app shows "One of
/// your phones has the wrong date or time" (PROTOCOL.md section 8 step 5).
const clockWarningAfter = Duration(hours: 24);

/// At most this many fetches per [SyncEngine.syncOnce]; the next call goes
/// on from the stored cursor.
const maxFetchPagesPerSync = 100;

/// How long to wait before the next automatic try after failed runs:
/// [first], doubled after every further failure, at most [max].
final class BackOff {
  const BackOff({
    this.first = const Duration(seconds: 5),
    this.max = const Duration(minutes: 15),
  });

  final Duration first;
  final Duration max;

  /// The wait after [failures] runs in a row did not finish (from 1).
  Duration after(int failures) {
    var d = first;
    for (var i = 1; i < failures && d < max; i++) {
      d *= 2;
    }
    return d < max ? d : max;
  }
}

/// What one [SyncEngine.syncOnce] did. Counts only; never any content.
final class SyncReport {
  const SyncReport({
    required this.envelopesSent,
    required this.eventsSent,
    required this.resealed,
    required this.envelopesOpened,
    required this.eventsApplied,
    required this.eventsUnapplied,
    required this.duplicates,
    required this.envelopeFailures,
    required this.envelopesKept,
    required this.leftOnRelay,
    required this.waitingForPartner,
    required this.clockWarning,
    required this.relayError,
    required this.retryAt,
    this.eventsCompacted = 0,
    this.envelopesDropped = 0,
  });

  /// Envelopes the relay took, and the outbox events they carried.
  final int envelopesSent, eventsSent;

  /// Sealed envelopes older than [maxSealedAge] whose events were sealed
  /// again.
  final int resealed;

  /// Envelopes from the partner that opened (their plaintext may still have
  /// been refused: see [envelopesKept]).
  final int envelopesOpened;

  /// Events applied, stored unapplied, and skipped as already stored.
  final int eventsApplied, eventsUnapplied, duplicates;

  /// Received envelopes that did not open, by failure: for the debug log.
  final Map<EnvelopeFailure, int> envelopeFailures;

  /// Received envelopes kept as raw bytes ([UnappliedEnvelope]).
  final int envelopesKept;

  /// Envelopes left on the relay because their time is ahead of this
  /// phone's clock (tried again at the next sync).
  final int leftOnRelay;

  /// The outbox is not empty but the session cannot send until the
  /// partner's first message arrives (the initiator after pairing).
  final bool waitingForPartner;

  /// Show "One of your phones has the wrong date or time".
  final bool clockWarning;

  /// The first relay failure of this run (debug log only), or null: the
  /// relay's error code for a [RelayException] (`network`, `inbox_full`,
  /// …), the type name of anything else. Nothing more is kept: another
  /// error may quote a URL, an inbox ID or a response body.
  final String? relayError;

  /// When to try again automatically, or null when nothing is left to do.
  /// Advisory: the engine never waits; the app schedules the retry. It also
  /// syncs on every push, when the app opens and after a local change, so
  /// [waitingForPartner] needs no retry (the partner's message comes with a
  /// push).
  final DateTime? retryAt;

  /// Logged events replaced by a snapshot at the end of this run
  /// ([Compactor]).
  final int eventsCompacted;

  /// Sealed envelopes not deposited because a delete committed meanwhile
  /// removed one of their events from the outbox (or dropped the envelope
  /// itself); their other events were sealed again (PROTOCOL.md section
  /// 17). A delete committed while an upload is under way cannot stop it:
  /// that envelope counts in [envelopesSent].
  final int envelopesDropped;

  /// Whether everything was sent and fetched.
  bool get complete => retryAt == null;

  @override
  String toString() =>
      'SyncReport(sent: $envelopesSent/$eventsSent, '
      'opened: $envelopesOpened, applied: $eventsApplied, '
      'unapplied: $eventsUnapplied, failures: '
      '${envelopeFailures.map((k, v) => MapEntry(k.name, v))}, '
      'kept: $envelopesKept, leftOnRelay: $leftOnRelay, '
      'compacted: $eventsCompacted, dropped: $envelopesDropped, '
      'retryAt: $retryAt)';
}

/// Sends this device's events to the partner and applies the partner's.
///
/// Local changes go through [commitLocal]: applied and queued in the outbox
/// in one transaction, so the app works fully offline. [syncOnce] then
/// fetches, opens, applies and acknowledges the partner's envelopes, and
/// seals and deposits the outbox (PROTOCOL.md section 17).
///
/// [applier] must work on the `EventStore` whose transaction [store] joins,
/// with [identity]'s device as its local device. [hlc] is the device's one
/// HLC clock: the app's `EventFactory` uses the same object.
///
/// A run ends by compacting the log of each entity type that reached
/// `compactAfter` logged events ([Compactor]), whether or not the relay
/// answered (not after a store failure, which throws).
final class SyncEngine {
  SyncEngine({
    required this.crypto,
    required this.random,
    required this.relay,
    required this.store,
    required this.applier,
    required this.identity,
    required this.partner,
    required this.hlc,
    this.wake = WakePolicy.v1,
    this.backOff = const BackOff(),
    int compactAfter = Compactor.defaultThreshold,
  }) : compactor = Compactor(
         applier.store,
         factory: EventFactory(
           hlc: hlc,
           random: random,
           author: identity.deviceId,
         ),
         registry: applier.registry,
         threshold: compactAfter,
       ) {
    if (applier.localDevice != identity.deviceId) {
      throw ArgumentError.value(applier, 'applier', 'not this device');
    }
  }

  final Crypto crypto;

  /// For new ratchet keys (a cryptographically secure source in the app).
  final RandomSource random;
  final RelayClient relay;
  final SyncStore store;
  final Applier applier;
  final DeviceIdentity identity;
  final PublicIdentity partner;
  final HlcClock hlc;
  final WakePolicy wake;
  final BackOff backOff;

  /// Compacts the log at the end of each run, in a transaction with the HLC
  /// (a snapshot event takes the next HLC value).
  final Compactor compactor;

  Clock get _clock => hlc.clock;
  String get _inbox => identity.deviceId.toBase64Url();
  String get _partnerInbox => partner.deviceId.toBase64Url();

  Future<SyncReport>? _running;
  Future<SyncReport>? _queued;
  String? _ackedCursor;
  var _failures = 0;

  /// Applies [events] (made on this device by its `EventFactory`) and adds
  /// them to the outbox, in one transaction with the HLC. Events already
  /// stored are not queued again.
  ///
  /// Deleted content is never sent (spec 4.6): after a `delete`, the
  /// entity's other events still in the outbox are removed from it, and a
  /// sealed envelope not yet deposited that carries one of them is dropped
  /// (its other events stay queued and are sealed again). An event of an
  /// entity that is already deleted is logged without effect and not
  /// queued (it is still in [ApplyResult.applied]). The delete itself is
  /// sent.
  ///
  /// Throws [ArgumentError] before changing anything for an event that the
  /// applier refuses or that is too large for one envelope.
  Future<ApplyResult> commitLocal(List<Event> events) async {
    for (final e in events) {
      if (_batchLength(e) + _batchOverhead > maxEnvelopePlaintextLength) {
        throw ArgumentError.value(
          e.eventId,
          'events',
          'too large for one envelope',
        );
      }
    }
    return store.transaction(() async {
      final result = await applier.applyLocal(events);
      final deleted = await _deletedEntities(result.applied);
      await store.addToOutbox([
        for (final e in result.applied)
          if (e.op == EventOp.delete ||
              !deleted.contains((e.entityType, e.entityId)))
            e,
      ]);
      await _unqueueDeleted(deleted);
      await store.putHlc(hlc.last);
      return result;
    });
  }

  /// Fetches and applies the partner's envelopes, then sends the outbox.
  ///
  /// Only one run at a time: a call while one runs waits for it and then
  /// starts one more run (shared by every call made meanwhile), so events
  /// committed during a run are sent too.
  ///
  /// Relay failures do not throw: the run stops that half and reports
  /// [SyncReport.relayError] and [SyncReport.retryAt]. A store failure
  /// throws, and nothing of the step that failed is kept.
  Future<SyncReport> syncOnce() {
    // Checked first: between the end of a run and the start of the queued
    // one, [_running] is already null.
    if (_queued case final queued?) return queued;
    final running = _running;
    if (running == null) return _start();
    return _queued = running.then<void>((_) {}, onError: (Object _) {}).then((
      _,
    ) {
      _queued = null;
      return _start();
    });
  }

  Future<SyncReport> _start() {
    final run = _guarded();
    _running = run;
    return run;
  }

  Future<SyncReport> _guarded() async {
    try {
      return await _run();
    } finally {
      _running = null;
    }
  }

  Future<SyncReport> _run() async {
    final sessionBytes = await store.session();
    if (sessionBytes == null) throw StateError('not paired: no session');
    final session = RatchetSession.fromStorageBytes(
      crypto: crypto,
      random: random,
      clock: _clock,
      bytes: sessionBytes,
    );
    final r = _Run();
    try {
      final windowBytes = await store.replayWindow();
      final window = windowBytes == null
          ? ReplayWindow()
          : ReplayWindow.fromStorageBytes(windowBytes);
      try {
        await _receive(session, window, r);
      } on _RelayFailure catch (e) {
        r.relayFailed(e);
      }
      try {
        await _send(session, r);
      } on _RelayFailure catch (e) {
        r.relayFailed(e);
      }
    } finally {
      session.dispose();
    }
    // Counts are read first, so a run with nothing due opens no write
    // transaction.
    final compacted = !await compactor.isDue()
        ? 0
        : await store.transaction(() async {
            final dropped = await compactor.compactIfNeeded();
            if (dropped.isNotEmpty) await store.putHlc(hlc.last);
            return dropped.values.fold(0, (a, b) => a + b);
          });
    final now = _clock.now();
    final since = await store.clockAheadSince();
    final unfinished = r.relayError != null || r.leftOnRelay > 0 || r.morePages;
    _failures = unfinished ? _failures + 1 : 0;
    return SyncReport(
      envelopesSent: r.envelopesSent,
      eventsSent: r.eventsSent,
      resealed: r.resealed,
      envelopesOpened: r.envelopesOpened,
      eventsApplied: r.eventsApplied,
      eventsUnapplied: r.eventsUnapplied,
      duplicates: r.duplicates,
      envelopeFailures: Map.unmodifiable(r.failures),
      envelopesKept: r.kept,
      leftOnRelay: r.leftOnRelay,
      waitingForPartner: r.waitingForPartner,
      clockWarning: since != null && now.difference(since) >= clockWarningAfter,
      relayError: r.relayError,
      retryAt: unfinished ? now.add(backOff.after(_failures)) : null,
      eventsCompacted: compacted,
      envelopesDropped: r.dropped,
    );
  }

  // --- receiving (PROTOCOL.md sections 8 and 17) ----------------------------

  Future<void> _receive(
    RatchetSession session,
    ReplayWindow window,
    _Run r,
  ) async {
    var cursor = await store.cursor();
    // An ACK lost earlier (or not sent before the app stopped): repeat it.
    // If it fails again, fetch all the same: ACKs are cumulative, so the
    // next one covers it.
    if (cursor != null && cursor != _ackedCursor) {
      final c = cursor;
      try {
        await _relay(() => relay.ack(_inbox, c));
        _ackedCursor = c;
      } on _RelayFailure catch (e) {
        r.relayFailed(e);
      }
    }
    var leftOnRelay = false;
    var finished = false;
    for (var page = 0; page < maxFetchPagesPerSync && !leftOnRelay; page++) {
      final before = cursor;
      final fetched = await _relay(() => relay.fetch(_inbox, after: before));
      for (final item in fetched.envelopes) {
        if (!await _handle(item, session, window, r)) {
          leftOnRelay = true;
          break;
        }
        cursor = item.cursor;
      }
      if (cursor != null && cursor != before) {
        final c = cursor;
        await _relay(() => relay.ack(_inbox, c));
        _ackedCursor = c;
      }
      // Nothing more waits, or nothing new came (a page of old envelopes
      // only cannot move the cursor; fetching again would loop).
      if (!leftOnRelay && (!fetched.more || cursor == before)) {
        finished = true;
        break;
      }
    }
    if (!leftOnRelay && !finished) {
      // Page limit reached: more may be waiting; the next run goes on.
      r.morePages = true;
      return;
    }
    // Only a finished fetch tells whether an envelope is still ahead.
    final since = await store.clockAheadSince();
    if (leftOnRelay && since == null) {
      await store.transaction(() => store.putClockAheadSince(_clock.now()));
    } else if (!leftOnRelay && since != null) {
      await store.transaction(() => store.putClockAheadSince(null));
    }
  }

  /// Opens, applies and commits one envelope. Returns false when it must
  /// stay on the relay (and nothing after it may be acknowledged).
  Future<bool> _handle(
    RelayEnvelope item,
    RatchetSession session,
    ReplayWindow window,
    _Run r,
  ) async {
    final OpenedEnvelope opened;
    try {
      opened = Envelope.open(
        crypto: crypto,
        bytes: item.body,
        self: identity.deviceId,
        partner: partner,
        session: session,
        window: window,
        clock: hlc,
      );
    } on EnvelopeException catch (e) {
      final f = e.failure;
      r.failures[f] = (r.failures[f] ?? 0) + 1;
      if (!f.acknowledge) {
        r.leftOnRelay++;
        return false;
      }
      await store.transaction(() async {
        if (f == EnvelopeFailure.undecryptable) {
          // The counter is used up (and the session may have moved on).
          await _saveSession(session);
          await store.putReplayWindow(window.toStorageBytes());
        }
        if (f.keepUnapplied) {
          await _keep(
            item,
            f == EnvelopeFailure.unknownVersion
                ? UnappliedEnvelopeReason.unknownVersion
                : UnappliedEnvelopeReason.undecryptable,
          );
          r.kept++;
        }
        await store.putCursor(item.cursor);
      });
      return true;
    }
    r.envelopesOpened++;
    final plaintext = opened.plaintext;
    try {
      // PROTOCOL.md section 8 step 8: events, session, window and HLC in
      // one transaction, and only then the ACK.
      await store.transaction(() async {
        try {
          final result = await applier.applyReceived(
            plaintext,
            sender: partner.deviceId,
          );
          // The partner deleted it: nothing queued here about it is sent.
          await _unqueueDeleted(
            await _deletedEntities([
              for (final e in result.applied)
                if (e.op == EventOp.delete) e,
            ]),
          );
          r.eventsApplied += result.applied.length;
          r.eventsUnapplied += result.unapplied.length;
          r.duplicates += result.duplicates;
        } on EventException {
          // Refused before changing anything; the envelope opened all the
          // same (PROTOCOL.md section 10).
          await _keep(item, UnappliedEnvelopeReason.refused);
          r.kept++;
        }
        await _saveSession(session);
        await store.putReplayWindow(window.toStorageBytes());
        await store.putHlc(hlc.last);
        await store.putCursor(item.cursor);
      });
    } finally {
      plaintext.fillRange(0, plaintext.length, 0);
    }
    return true;
  }

  Future<void> _keep(RelayEnvelope item, UnappliedEnvelopeReason reason) async {
    // At most [SyncStore.maxKeptEnvelopes] per reason, oldest dropped.
    final kept = (await store.unappliedEnvelopes())
        .where((e) => e.reason == reason && e.id != item.cursor)
        .toList();
    final excess = kept.length - SyncStore.maxKeptEnvelopes + 1;
    for (var i = 0; i < excess; i++) {
      await store.removeUnappliedEnvelope(kept[i].id);
    }
    await store.putUnappliedEnvelope(
      UnappliedEnvelope(
        id: item.cursor,
        bytes: item.body,
        reason: reason,
        receivedAt: _clock.now(),
      ),
    );
  }

  // --- sending (PROTOCOL.md section 17) --------------------------------------

  Future<void> _send(RatchetSession session, _Run r) async {
    // Envelopes sealed earlier go first, as the same bytes.
    for (final s in await store.sealedEnvelopes()) {
      if (_clock.now().difference(s.sealedAt) > maxSealedAge) {
        // Its events stay in the outbox and are sealed again below.
        await store.transaction(() => store.removeSealedEnvelope(s.counter));
        r.resealed++;
        continue;
      }
      await _deposit(s, r);
    }
    // A delete committed while a batch is sealed drops that envelope
    // ([_deposit]); the outbox is then read and split again.
    while (await _sendOutbox(session, r)) {}
  }

  /// Seals and deposits the outbox. Returns true when an envelope was
  /// dropped: the caller then reads and splits the outbox again.
  Future<bool> _sendOutbox(RatchetSession session, _Run r) async {
    final pending = await store.outbox();
    if (pending.isEmpty) return false;
    if (!session.canSend) {
      r.waitingForPartner = true;
      return false;
    }
    for (final batch in _batches(pending)) {
      // The counter is stored before sealing: a crash never reuses it.
      final counter = await store.transaction(() async {
        final c = await store.lastCounter() + 1;
        await store.putLastCounter(c);
        return c;
      });
      final plaintext = EventBatch.encode(batch);
      final Uint8List bytes;
      try {
        bytes = Envelope.seal(
          crypto: crypto,
          sender: identity,
          recipient: partner.deviceId,
          counter: counter,
          hlc: hlc.send(),
          session: session,
          plaintext: plaintext,
        );
      } finally {
        plaintext.fillRange(0, plaintext.length, 0);
      }
      final sealed = SealedEnvelope(
        counter: counter,
        bytes: bytes,
        eventIds: [for (final e in batch) e.eventId],
        wake: wake.wakesAny(batch),
        sealedAt: _clock.now(),
      );
      // The session is saved before the envelope leaves the phone: a
      // session restored from older bytes would reuse a message key. If
      // this fails the envelope never leaves, and the next run starts from
      // the stored session.
      await store.transaction(() async {
        await _saveSession(session);
        await store.putHlc(hlc.last);
        await store.putSealedEnvelope(sealed);
      });
      if (!await _deposit(sealed, r)) return true;
    }
    return false;
  }

  /// Deposits [s] unless a delete committed since it was sealed removed one
  /// of its events from the outbox (or dropped it already): then it is
  /// removed and false returned. The check is a transaction, so it comes
  /// after any delete committed before it; a delete committed once the
  /// upload has started cannot stop it.
  Future<bool> _deposit(SealedEnvelope s, _Run r) async {
    final current = await store.transaction(() async {
      final stored = (await store.sealedEnvelopes()).any(
        (x) => x.counter == s.counter,
      );
      if (stored && await store.outboxContainsAll(s.eventIds)) return true;
      if (stored) await store.removeSealedEnvelope(s.counter);
      return false;
    });
    if (!current) {
      r.dropped++;
      return false;
    }
    await _relay(() => relay.deposit(_partnerInbox, s.bytes, wake: s.wake));
    await store.transaction(() async {
      await store.removeSealedEnvelope(s.counter);
      await store.removeFromOutbox(s.eventIds);
    });
    r.envelopesSent++;
    r.eventsSent += s.eventIds.length;
    return true;
  }

  /// The entities of [events] that are deleted now (looked up once each).
  Future<Set<(String, String)>> _deletedEntities(List<Event> events) async {
    final deleted = <(String, String)>{};
    final checked = <(String, String)>{};
    for (final e in events) {
      final key = (e.entityType, e.entityId);
      if (!checked.add(key)) continue;
      final state = await applier.store.entity(e.entityType, e.entityId);
      if (state?.isDeleted ?? false) deleted.add(key);
    }
    return deleted;
  }

  /// Removes from the outbox every event of the [deleted] entities except
  /// deletes, and drops the sealed envelopes carrying one of them (their
  /// other events stay in the outbox). Runs inside the caller's
  /// transaction. The dropped ratchet message only leaves a skipped key on
  /// the partner's phone (PROTOCOL.md section 6).
  Future<void> _unqueueDeleted(Set<(String, String)> deleted) async {
    if (deleted.isEmpty) return;
    final ids = {
      for (final e in await store.outbox())
        if (e.op != EventOp.delete &&
            deleted.contains((e.entityType, e.entityId)))
          e.eventId,
    };
    if (ids.isEmpty) return;
    for (final s in await store.sealedEnvelopes()) {
      if (s.eventIds.any(ids.contains)) {
        await store.removeSealedEnvelope(s.counter);
      }
    }
    await store.removeFromOutbox(ids);
  }

  /// `{"events":[` and `]}`.
  static const _batchOverhead = 13;

  static int _batchLength(Event e) =>
      utf8.encode(jsonEncode(e.toJson())).length;

  /// [events] in order, split so that each [EventBatch.encode] is at most
  /// [maxEnvelopePlaintextLength] bytes.
  static Iterable<List<Event>> _batches(List<Event> events) sync* {
    var batch = <Event>[];
    var size = _batchOverhead;
    for (final e in events) {
      final n = _batchLength(e);
      if (batch.isNotEmpty && size + 1 + n > maxEnvelopePlaintextLength) {
        yield batch;
        batch = [];
        size = _batchOverhead;
      }
      size += batch.isEmpty ? n : n + 1;
      batch.add(e);
    }
    if (batch.isNotEmpty) yield batch;
  }

  // --- helpers -----------------------------------------------------------------

  Future<void> _saveSession(RatchetSession session) async {
    final bytes = session.toStorageBytes();
    try {
      await store.putSession(bytes);
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  static Future<T> _relay<T>(Future<T> Function() call) async {
    try {
      return await call();
    } on Exception catch (e) {
      throw _RelayFailure(e);
    }
  }
}

/// A relay call failed (network, server); stops one half of a run.
final class _RelayFailure implements Exception {
  const _RelayFailure(this.cause);
  final Object cause;
}

/// Counters of one run.
final class _Run {
  var envelopesSent = 0, eventsSent = 0, resealed = 0;
  var envelopesOpened = 0, eventsApplied = 0, eventsUnapplied = 0;
  var duplicates = 0, kept = 0, leftOnRelay = 0, dropped = 0;
  var waitingForPartner = false, morePages = false;
  final failures = <EnvelopeFailure, int>{};
  String? relayError;

  void relayFailed(_RelayFailure e) => relayError ??= switch (e.cause) {
    final RelayException x => x.code.wireName,
    final other => other.runtimeType.toString(),
  };
}
