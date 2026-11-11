// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Pure-Dart protocol package for Mawaddah. No Flutter imports.
library;

export 'src/clock.dart';
export 'src/crypto/crypto.dart';
export 'src/envelope/envelope.dart';
export 'src/envelope/hlc.dart';
export 'src/envelope/replay_window.dart';
export 'src/event/applier.dart';
export 'src/event/event.dart';
export 'src/event/event_store.dart';
export 'src/event/registry.dart';
export 'src/event/uuid7.dart';
export 'src/fakes/fake_clock.dart';
export 'src/fakes/fake_relay_client.dart';
export 'src/fakes/in_memory_event_store.dart';
export 'src/fakes/in_memory_storage.dart';
export 'src/fakes/seeded_random.dart';
export 'src/identity/identity.dart';
export 'src/pairing/pairing.dart';
export 'src/random_source.dart';
export 'src/ratchet/ratchet.dart';
export 'src/relay_client.dart';
export 'src/storage.dart';
export 'src/version.dart';
