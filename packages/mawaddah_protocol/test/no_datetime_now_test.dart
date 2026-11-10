// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:io';

import 'package:test/test.dart';

/// Spec 14b.3: logic code never reads the system clock; time is injected.
void main() {
  test('lib/ never calls DateTime.now()', () {
    final offenders = <String>[];
    for (final f in Directory('lib').listSync(recursive: true)) {
      if (f is! File || !f.path.endsWith('.dart')) continue;
      final lines = f.readAsLinesSync();
      for (var i = 0; i < lines.length; i++) {
        final code = lines[i].split('//').first;
        if (RegExp(r'DateTime\s*\.\s*now\b').hasMatch(code)) {
          offenders.add('${f.path}:${i + 1}');
        }
      }
    }
    expect(offenders, isEmpty, reason: 'use an injected Clock instead');
  });
}
