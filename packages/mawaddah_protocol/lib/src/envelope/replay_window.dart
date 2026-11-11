// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Anti-replay window for envelope counters (PROTOCOL.md section 8, step 4).
///
/// The sliding window of RFC 4303 section 3.4.3 (IPsec ESP): the receiver
/// remembers the highest accepted counter and, for the [ReplayWindow.size]
/// counters ending at it, which ones were accepted. Envelopes may arrive out
/// of order within the window; a repeat, or a counter that fell behind the
/// window, is refused.
library;

import 'dart:typed_data';

/// Which envelope counters from the partner were already accepted.
final class ReplayWindow {
  /// An empty window: nothing accepted yet (counters start at 1).
  ReplayWindow() : _highest = 0, _seen = Uint8List(size ~/ 8);

  ReplayWindow._(this._highest, this._seen);

  /// Reads [toStorageBytes]. Throws [FormatException] on damaged bytes.
  factory ReplayWindow.fromStorageBytes(Uint8List bytes) {
    if (bytes.length != storageLength || bytes[0] != storageFormatVersion) {
      throw const FormatException('not a replay window');
    }
    final data = ByteData.sublistView(bytes);
    final hi = data.getUint32(1), lo = data.getUint32(5);
    if (hi > 0x7FFFFFFF) throw const FormatException('counter out of range');
    final highest = hi * 0x100000000 + lo;
    final seen = Uint8List.fromList(Uint8List.sublistView(bytes, 9));
    final window = ReplayWindow._(highest, seen);
    // Bit 0 is the highest counter itself; bits for counters below 1 are
    // never set.
    if (highest > 0 && !window._bit(0)) {
      throw const FormatException('inconsistent replay window');
    }
    for (var i = highest; i < size; i++) {
      if (window._bit(i)) {
        throw const FormatException('inconsistent replay window');
      }
    }
    return window;
  }

  /// `W` in PROTOCOL.md section 8: how many counters below the highest one
  /// are remembered.
  static const size = 1024;

  static const storageFormatVersion = 1;

  /// Version (1), highest counter (`u64`), [size] bits (bit `i` is the
  /// counter `highest - i`, least significant bit of each byte first).
  static const storageLength = 1 + 8 + size ~/ 8;

  int _highest;

  /// Bit `i` set: counter `_highest - i` was accepted.
  final Uint8List _seen;

  /// The highest counter accepted so far (0 when none).
  int get highest => _highest;

  /// Whether [counter] (at least 1) is new: above the highest accepted, or
  /// inside the window and not yet accepted. Changes nothing.
  bool accepts(int counter) {
    if (counter < 1) return false;
    if (counter > _highest) return true;
    final offset = _highest - counter;
    return offset < size && !_bit(offset);
  }

  /// Records [counter] as accepted, sliding the window forward when it is
  /// the new highest. Throws [StateError] when [accepts] is false.
  void mark(int counter) {
    if (!accepts(counter)) throw StateError('counter $counter not accepted');
    if (counter > _highest) {
      final shift = counter - _highest;
      for (var i = size - 1; i >= 0; i--) {
        _set(i, i >= shift && _bit(i - shift));
      }
      _highest = counter;
      _set(0, true);
    } else {
      _set(_highest - counter, true);
    }
  }

  /// A separate window with the same contents.
  ReplayWindow copy() => ReplayWindow._(_highest, Uint8List.fromList(_seen));

  /// The window as [storageLength] bytes for the app's database (local
  /// only, not part of the wire protocol).
  Uint8List toStorageBytes() {
    final out = Uint8List(storageLength)..[0] = storageFormatVersion;
    ByteData.sublistView(out)
      ..setUint32(1, _highest ~/ 0x100000000)
      ..setUint32(5, _highest % 0x100000000);
    out.setAll(9, _seen);
    return out;
  }

  bool _bit(int i) => _seen[i >> 3] & (1 << (i & 7)) != 0;

  void _set(int i, bool value) {
    if (value) {
      _seen[i >> 3] |= 1 << (i & 7);
    } else {
      _seen[i >> 3] &= ~(1 << (i & 7)) & 0xFF;
    }
  }
}
