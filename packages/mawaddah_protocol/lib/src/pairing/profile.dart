// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// The partner profile exchanged right after pairing (PROTOCOL.md section
/// 4.5). It is the payload of the first `profile` events and is sent only
/// inside the end-to-end encrypted channel, never in the bundle, the QR or the
/// reply, and never on the code path before the safety number is confirmed.
library;

enum ProfileGender {
  male,
  female;

  static ProfileGender parse(Object? value) => switch (value) {
    'male' => male,
    'female' => female,
    _ => throw FormatException('unknown gender', value),
  };
}

/// The relationship mode (spec section 3).
enum RelationshipMode {
  engaged('engaged'),
  contracted('contracted'),
  marriedCohab('married_cohab'),
  marriedRemote('married_remote');

  const RelationshipMode(this.wireName);

  final String wireName;

  static RelationshipMode parse(Object? value) {
    for (final m in values) {
      if (m.wireName == value) return m;
    }
    throw FormatException('unknown mode', value);
  }
}

/// First name, gender and mode of one person.
final class PairingProfile {
  PairingProfile({
    required this.firstName,
    required this.gender,
    required this.mode,
  }) {
    final trimmed = firstName.trim();
    if (trimmed.isEmpty ||
        trimmed != firstName ||
        firstName.runes.length > maxFirstNameRunes ||
        firstName.runes.any((r) => r < 0x20 || (r >= 0x7f && r < 0xa0))) {
      throw ArgumentError.value(
        firstName,
        'firstName',
        'must be 1 to $maxFirstNameRunes characters, trimmed, no control '
            'characters',
      );
    }
  }

  /// Reads the event payload. Throws [FormatException] for a missing or
  /// invalid field.
  factory PairingProfile.fromJson(Map<String, Object?> json) {
    final name = json['first_name'];
    if (name is! String) throw const FormatException('missing "first_name"');
    try {
      return PairingProfile(
        firstName: name,
        gender: ProfileGender.parse(json['gender']),
        mode: RelationshipMode.parse(json['mode']),
      );
    } on ArgumentError catch (e) {
      throw FormatException('invalid "first_name": ${e.message}');
    }
  }

  static const maxFirstNameRunes = 50;

  final String firstName;
  final ProfileGender gender;
  final RelationshipMode mode;

  Map<String, Object?> toJson() => {
    'first_name': firstName,
    'gender': gender.name,
    'mode': mode.wireName,
  };
}
