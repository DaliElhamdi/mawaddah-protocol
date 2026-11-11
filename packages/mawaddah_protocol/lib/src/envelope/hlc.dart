// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Hybrid logical clock (PROTOCOL.md section 9).
///
/// Follows S. Kulkarni, M. Demirbas et al., *Logical Physical Clocks*,
/// OPODIS 2014: a timestamp is the largest physical time seen so far plus a
/// counter that orders events within the same millisecond.
library;

import 'dart:typed_data';

import '../clock.dart';

/// One HLC timestamp: 64 bits, the high 48 the physical time in
/// milliseconds since the Unix epoch (UTC), the low 16 a logical counter.
///
/// Ordered by ([physicalMs], [logical]), which is the order of the 64-bit
/// number and of the 16-digit hexadecimal form.
final class Hlc implements Comparable<Hlc> {
  /// Throws [RangeError] when a part is outside its bits.
  Hlc(this.physicalMs, this.logical) {
    RangeError.checkValueInInterval(physicalMs, 0, maxPhysicalMs, 'physicalMs');
    RangeError.checkValueInInterval(logical, 0, maxLogical, 'logical');
  }

  const Hlc._(this.physicalMs, this.logical);

  /// Reads the 8 big-endian bytes of the envelope's `hlc` field. Throws
  /// [FormatException] for any other length.
  factory Hlc.fromBytes(Uint8List bytes) {
    if (bytes.length != byteLength) {
      throw FormatException('an HLC is $byteLength bytes');
    }
    final data = ByteData.sublistView(bytes);
    return Hlc._(
      data.getUint32(0) * 0x10000 + data.getUint16(4),
      data.getUint16(6),
    );
  }

  /// Parses the JSON form: exactly 16 lowercase hexadecimal digits. Throws
  /// [FormatException] for any other text.
  factory Hlc.parse(String text) {
    if (!_hexForm.hasMatch(text)) {
      throw FormatException('an HLC is 16 lowercase hex digits', text);
    }
    return Hlc._(
      int.parse(text.substring(0, 12), radix: 16),
      int.parse(text.substring(12), radix: 16),
    );
  }

  /// The smallest value; the start of a clock that has seen nothing.
  static const zero = Hlc._(0, 0);

  static const byteLength = 8;
  static const maxPhysicalMs = 0xFFFFFFFFFFFF; // 2^48 - 1
  static const maxLogical = 0xFFFF;
  static final _hexForm = RegExp(r'^[0-9a-f]{16}$');

  /// Milliseconds since the Unix epoch (UTC), 48 bits.
  final int physicalMs;

  /// Counter within [physicalMs], 16 bits.
  final int logical;

  /// The physical part as a UTC time.
  DateTime get physicalTime =>
      DateTime.fromMillisecondsSinceEpoch(physicalMs, isUtc: true);

  /// The 8 big-endian bytes (envelope offset 42).
  Uint8List toBytes() {
    final out = Uint8List(byteLength);
    ByteData.sublistView(out)
      ..setUint32(0, physicalMs ~/ 0x10000)
      ..setUint16(4, physicalMs % 0x10000)
      ..setUint16(6, logical);
    return out;
  }

  /// The JSON form: 16 lowercase hexadecimal digits, so that string order
  /// equals numeric order.
  String toHex() =>
      physicalMs.toRadixString(16).padLeft(12, '0') +
      logical.toRadixString(16).padLeft(4, '0');

  @override
  int compareTo(Hlc other) => physicalMs != other.physicalMs
      ? physicalMs.compareTo(other.physicalMs)
      : logical.compareTo(other.logical);

  bool operator <(Hlc other) => compareTo(other) < 0;
  bool operator >(Hlc other) => compareTo(other) > 0;
  bool operator <=(Hlc other) => compareTo(other) <= 0;
  bool operator >=(Hlc other) => compareTo(other) >= 0;

  @override
  bool operator ==(Object other) =>
      other is Hlc &&
      other.physicalMs == physicalMs &&
      other.logical == logical;

  @override
  int get hashCode => Object.hash(physicalMs, logical);

  @override
  String toString() => 'Hlc(${toHex()})';
}

/// One device's hybrid logical clock over the injected [Clock].
///
/// Every value it returns is greater than every value it returned or
/// received before, whatever the wall clock does: when the clock goes back,
/// the physical part stays where it was and the counter grows.
///
/// The app saves [last] with the data it orders (for a received envelope, in
/// the same transaction as its events, PROTOCOL.md section 8 step 8) and
/// passes it back when it starts.
final class HlcClock {
  HlcClock(this.clock, {this._last = Hlc.zero});

  /// The wall clock the physical part comes from.
  final Clock clock;

  Hlc _last;

  /// The latest value this clock returned or received.
  Hlc get last => _last;

  /// A new timestamp for a local event or an envelope being sealed:
  /// `l' = max(l, now)`; `c' = c + 1` if `l' == l`, else `0`.
  Hlc send() {
    final now = _nowMs();
    final l = _last.physicalMs;
    return _last = _next(now > l ? now : l, now > l ? 0 : _last.logical + 1);
  }

  /// Merges a timestamp received from the partner and returns the new
  /// value, which is greater than both [remote] and [last]:
  /// `l' = max(l, l_m, now)`; `c'` = `max(c, c_m) + 1` if `l' == l == l_m`,
  /// `c + 1` if `l' == l`, `c_m + 1` if `l' == l_m`, else `0`.
  ///
  /// Does not judge [remote]: the envelope checks its time window (at most
  /// 1 hour ahead) before merging it.
  Hlc receive(Hlc remote) {
    final now = _nowMs();
    final l = _last.physicalMs, c = _last.logical;
    final lm = remote.physicalMs, cm = remote.logical;
    var lNew = l > lm ? l : lm;
    if (now > lNew) lNew = now;
    final int cNew;
    if (lNew == l && lNew == lm) {
      cNew = (c > cm ? c : cm) + 1;
    } else if (lNew == l) {
      cNew = c + 1;
    } else if (lNew == lm) {
      cNew = cm + 1;
    } else {
      cNew = 0;
    }
    return _last = _next(lNew, cNew);
  }

  /// The counter has 16 bits. When it would pass 65,535 the physical part
  /// moves on by 1 ms and the counter restarts at 0: the value waiting for
  /// the next millisecond would give, without blocking, and it also works
  /// when the physical part is ahead of the wall clock (PROTOCOL.md
  /// section 9).
  static Hlc _next(int l, int c) {
    if (c <= Hlc.maxLogical) return Hlc._(l, c);
    if (l >= Hlc.maxPhysicalMs) throw StateError('HLC is at its maximum');
    return Hlc._(l + 1, 0);
  }

  int _nowMs() {
    final ms = clock.now().millisecondsSinceEpoch;
    if (ms < 0) return 0;
    if (ms > Hlc.maxPhysicalMs) {
      throw StateError('clock is past the HLC range (year 10889)');
    }
    return ms;
  }
}
