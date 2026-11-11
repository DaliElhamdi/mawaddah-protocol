# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `PROTOCOL.md`: the v1 wire format (draft, implemented in v0.1.0): identity keys and device ID, pairing (X3DH adapted, QR payload, code path), safety number, Double Ratchet parameters, envelope layout and receive checks, HLC, event schema and versioning, attachments, relay request signing, constants, test-vector layout and known limits.
- `Crypto` interface and `SodiumCrypto` in `packages/mawaddah_protocol`: X25519, Ed25519, XChaCha20-Poly1305 (IETF), BLAKE2b and HKDF-SHA-256 from libsodium 1.0.22 (sumo) via the `sodium` 4.x package, whose build hook compiles libsodium (no system install). Typed keys; secrets in libsodium guarded memory with `dispose()`; key and nonce randomness from the injected `RandomSource` (`SodiumRandomSource` by default).
- Known-answer tests and vector files `test/vectors/rfc7748_x25519.json`, `rfc8032_ed25519.json`, `rfc5869_hkdf.json`, `rfc7693_blake2b.json`, `xchacha20poly1305.json`.
- Device identity (PROTOCOL.md sections 3 and 5): `DeviceIdentity.generate(crypto, random)` makes the Ed25519 signing key and the X25519 key independently (32 random bytes each, seed first); `toStorageBytes` / `fromStorageBytes` for the app's secure storage (65 bytes, versioned, input zeroed, `toString` redacted); `DeviceId` (`SHA-256("mawaddah/v1/inbox" || IKsig_pub)[0..16]`, base64url, strict `parse`); `safetyNumber` (20 digits, same in both orders) and `safetyNumberGroups`.
- `tool/gen_vectors.dart` and generated vector files `test/vectors/identity.json` and `safety_number.json` (deterministic seeds written into each case).
- Pairing key agreement (PROTOCOL.md section 4): `PairingInitiator` and `PairingJoiner` (injected `Crypto`, `RandomSource`, `Clock`), `PairingBundle`, `PairingQr` (129 bytes, `MAWADDAH:` + base64url, strict decoding), `PairingReply`, the HKDF derivation of `SK`, `KC`, `TH`, `confirm` and `AD`, `PairingResult` (shared keys, safety number, "must be confirmed" state on the code path) and `PairingProfile` for the encrypted profile events. A slot lasts 10 minutes and takes one reply.
- `Crypto.hmac` / `verifyHmac` (HMAC-SHA-512-256, libsodium `crypto_auth`), tested with RFC 4231 cases (`test/vectors/rfc4231_hmac.json`).
- Generated vectors `test/vectors/pairing.json` (13 cases); `.gitleaks.toml` allowlists it and `rfc4231_hmac.json` by exact path.
- Double Ratchet chains (PROTOCOL.md section 6): `RatchetSession.fromPairing` (joiner = Alice, sends first; initiator = Bob, `canSend` only after the joiner's first message), `initAlice` / `initBob`, `encrypt` / `decrypt` with `RatchetHeader` (`dh_pub || pn || n`, 40 bytes) and the 50 envelope bytes before it, so the AEAD authenticates `AD || envelope bytes[0..90]`. A DH ratchet step happens on every turn change; a failed decrypt (`RatchetException`) leaves the session unchanged. In-order delivery per direction only: a message that needs a skipped key is refused (`skippedMessage`) until #14.
- Generated vectors `test/vectors/ratchet.json` (a 16-step conversation with turn changes and crossing messages; every key and ciphertext derived twice in the generator); `.gitleaks.toml` allowlists it by exact path.
- Skipped message keys for the Double Ratchet (PROTOCOL.md section 6, Signal 3.5): messages may arrive out of order or late, also across turns. One message may create at most 1,000 skipped keys (`maxSkip`, both chains of a turn together; more is refused with `tooManySkipped`). At most 1,000 are stored, oldest deleted first. A key older than 30 days (injected `Clock`) is ignored and then deleted, at the next success or by `deleteExpiredSkippedKeys()`. A failed decrypt still changes nothing, including the stored keys.
- Saving a ratchet session: `RatchetSession.toStorageBytes` / `fromStorageBytes` (versioned local format, input zeroed, damaged bytes refused with `FormatException`) and `save` / `load` through `Storage`. `ratchet.json` gains an out-of-order case (28 steps).
- Signed envelopes (PROTOCOL.md sections 7 and 8): `Envelope.seal` (pad to 256-byte blocks, ratchet-encrypt with the 50 envelope bytes as associated data, Ed25519 signature with the `mawaddah/v1/envelope` label) and `Envelope.open`, which checks in the order of section 8: structure, addresses, signature, replay window, time window, decryption, padding. Failures are `EnvelopeException`s whose `EnvelopeFailure` says whether to acknowledge the envelope and whether to keep its raw bytes; only `undecryptable` changes state (the counter is used up). `Envelope.parse` reads the fields.
- `ReplayWindow`: the RFC 4303 sliding window over envelope counters (`W = 1024`), with versioned save/restore bytes (137 bytes, local format).
- Hybrid logical clock (PROTOCOL.md section 9): `Hlc` (48-bit milliseconds + 16-bit counter; 8-byte and 16-hex-digit forms) and `HlcClock` (`send`, `receive`) over the injected `Clock`; always increasing when the clock goes back.
- `Uuid7.generate` / `isValid` (RFC 9562) from the injected `Clock` and `RandomSource`.
- `Crypto.pad` / `unpad` (libsodium `sodium_pad`, ISO/IEC 7816-4) and `InvalidPaddingException`; `DeviceId.fromBytes`.
- Generated vectors `test/vectors/envelope.json` (3 sealed envelopes, 13 rejected cases), `hlc.json` and `uuid7.json`; `.gitleaks.toml` allowlists `envelope.json` by exact path.
- Event model and apply (PROTOCOL.md sections 10 and 11): `Event` with strict v1 JSON, `EventBatch.encode`/`decode` for the envelope plaintext (`EventException`: `malformed`, `wrongAuthor`), `EventStamp` (order `hlc`, author bytes, `event_id`), `EventFactory`, `EntityRegistry.v1` (`device` hello and `profile` payload checks; `message`, `reaction`, `receipt` rules), the `EventStore` interface with `InMemoryEventStore`, and `Applier` (`applyReceived`, `applyLocal`, `reapplyUnapplied`): idempotent, field-level last-writer-wins, append-only, final tombstones that purge payloads, unapplied events with a reason and a stream. `protocolVersion` / `minSupportedProtocol` constants.
- Generated vectors `test/vectors/event.json` (encoding, refused plaintexts, three apply scenarios).

### Changed
- `package:crypto` moved from dev to normal dependencies: the device ID and relay body hashes need SHA-256, which the `sodium` Dart API does not offer (ADR 0006 point 3).
- `RatchetSession.fromPairing`, `initAlice` and `initBob` now take a `Clock`. `RatchetFailure.skippedMessage` is replaced by `tooManySkipped`, because out-of-order messages are now accepted.
- `Storage.write` must not keep a reference to the value it is given (callers zero secrets once it completes).
- `PROTOCOL.md` clarifications from building the envelopes (wire format unchanged): the `version` and `type` bytes are read before the v1 length rules; a v1 envelope whose `L` is not a multiple of 256 plus 16, or whose counter is 0 or above 2^63 − 1, is malformed; bad padding after decryption counts as `undecryptable`; a full HLC counter moves the physical part on by 1 ms instead of waiting; the UUID v7 byte layout is written out.
- `mawaddah_protocol` now needs Dart 3.13 or later (required by `sodium` 4.x) and a C compiler the first time it is built or tested.

## [0.0.1] - 2026-11-10

This first tag is a skeleton for the private app to pin; it contains no cryptography and nothing is deployed.

### Added
- Repository scaffolding, CI skeleton and documentation stubs.
- `packages/mawaddah_protocol` skeleton: `Clock`, `RandomSource`, `Storage` and `RelayClient` interfaces with test fakes (`FakeClock`, `SeededRandom`, `InMemoryStorage`, `FakeRelayClient`). No cryptography yet.
- Check and test that `lib/` never calls `DateTime.now()`.
- `relay/` Worker skeleton (TypeScript, ESLint, Vitest): a `/health` route and its tests. Not deployed.
- CI runs the relay checks; Dart and Node versions are pinned in `.dart-version` and `.node-version`; Dependabot watches pub and npm.
- `protocol-release` workflow: a `vX.Y.Z` tag on `main` runs the checks and tests, then publishes a GitHub Release with the CHANGELOG section as notes (pre-release below 1.0.0). `scripts/release-notes.sh` extracts the section.
