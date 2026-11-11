// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

/// Protocol versions of this package release (PROTOCOL.md section 11).
library;

/// The protocol this release speaks: the `protocol_version` of the events it
/// makes, and the highest one it applies.
const protocolVersion = 1;

/// The oldest protocol a partner may speak for this release to work with it.
const minSupportedProtocol = 1;
