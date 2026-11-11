// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// The entity types this release knows and how their events merge
/// (PROTOCOL.md section 10, registry).
library;

import '../pairing/profile.dart';
import 'event.dart';

/// How the events of one entity type combine.
enum MergeRule {
  /// Field-level last-writer-wins: each payload field keeps the value of the
  /// event with the highest [EventStamp]. `create` and `update` both set
  /// fields.
  lastWriterWins,

  /// Created once; a later `create` of the same entity replaces the whole
  /// payload only if its [EventStamp] is higher (a correct author never sends
  /// two).
  appendOnly,
}

/// Whether [payload] is valid for an event with [op] of a known type and
/// schema version. A payload that is not is stored unapplied.
typedef PayloadValidator = bool Function(String op, JsonMap payload);

/// One known entity type.
final class EntityRule {
  const EntityRule({
    required this.merge,
    required this.ops,
    this.schemaVersion = 1,
    this.validate,
  });

  final MergeRule merge;

  /// The ops this release applies for the type. `delete` (a tombstone) is
  /// allowed only when listed.
  final Set<String> ops;

  /// The highest payload version this release understands.
  final int schemaVersion;

  /// Checks a payload; null accepts any object (the feature that owns the
  /// type adds its check).
  final PayloadValidator? validate;
}

/// The known entity types, by `entity_type`.
final class EntityRegistry {
  const EntityRegistry(this.rules);

  /// The registry of protocol v1 (PROTOCOL.md section 10).
  ///
  /// `message`, `reaction` and `receipt` have no payload check yet: the chat
  /// work adds their payload fields to PROTOCOL.md and passes the check with
  /// [withValidators].
  static const v1 = EntityRegistry({
    'device': EntityRule(
      merge: MergeRule.lastWriterWins,
      ops: {EventOp.update},
      validate: validateDevicePayload,
    ),
    'profile': EntityRule(
      merge: MergeRule.lastWriterWins,
      ops: {EventOp.update},
      validate: validateProfilePayload,
    ),
    'message': EntityRule(
      merge: MergeRule.appendOnly,
      ops: {EventOp.create, EventOp.delete},
    ),
    'reaction': EntityRule(
      merge: MergeRule.lastWriterWins,
      ops: {EventOp.update},
    ),
    'receipt': EntityRule(
      merge: MergeRule.lastWriterWins,
      ops: {EventOp.update},
    ),
  });

  final Map<String, EntityRule> rules;

  EntityRule? operator [](String entityType) => rules[entityType];

  /// The same registry with [validators] set for existing types. Throws
  /// [ArgumentError] for a type it does not have.
  EntityRegistry withValidators(Map<String, PayloadValidator> validators) {
    final out = Map.of(rules);
    validators.forEach((type, check) {
      final rule = rules[type];
      if (rule == null) throw ArgumentError.value(type, 'unknown entity type');
      out[type] = EntityRule(
        merge: rule.merge,
        ops: rule.ops,
        schemaVersion: rule.schemaVersion,
        validate: check,
      );
    });
    return EntityRegistry(Map.unmodifiable(out));
  }

  /// The same registry with [rule] added or replaced for [entityType].
  EntityRegistry withRule(String entityType, EntityRule rule) =>
      EntityRegistry(Map.unmodifiable({...rules, entityType: rule}));
}

/// The `device` payload (the hello of PROTOCOL.md section 11): any of
/// `protocol_version` and `min_supported_protocol` (integers of at least 1)
/// and `envelope_versions` (a non-empty list of integers from 1 to 255), at
/// least one, nothing else.
bool validateDevicePayload(String op, JsonMap payload) {
  if (payload.isEmpty) return false;
  for (final MapEntry(:key, :value) in payload.entries) {
    final ok = switch (key) {
      'protocol_version' ||
      'min_supported_protocol' => value is int && value >= 1,
      'envelope_versions' =>
        value is List &&
            value.isNotEmpty &&
            value.every((v) => v is int && v >= 1 && v <= 255),
      _ => false,
    };
    if (!ok) return false;
  }
  return true;
}

/// The `profile` payload: any of `first_name`, `gender` and `mode` with the
/// rules of [PairingProfile], at least one, nothing else.
bool validateProfilePayload(String op, JsonMap payload) {
  if (payload.isEmpty) return false;
  for (final MapEntry(:key, :value) in payload.entries) {
    try {
      switch (key) {
        case 'first_name':
          if (value is! String) return false;
          PairingProfile(
            firstName: value,
            gender: ProfileGender.male,
            mode: RelationshipMode.engaged,
          );
        case 'gender':
          ProfileGender.parse(value);
        case 'mode':
          RelationshipMode.parse(value);
        default:
          return false;
      }
    } on FormatException {
      return false;
    } on ArgumentError {
      return false;
    }
  }
  return true;
}
