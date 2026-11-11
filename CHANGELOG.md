# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `PROTOCOL.md`: the v1 wire format (draft, implemented in v0.1.0): identity keys and device ID, pairing (X3DH adapted, QR payload, code path), safety number, Double Ratchet parameters, envelope layout and receive checks, HLC, event schema and versioning, attachments, relay request signing, constants, test-vector layout and known limits.
- `Crypto` interface and `SodiumCrypto` in `packages/mawaddah_protocol`: X25519, Ed25519, XChaCha20-Poly1305 (IETF), BLAKE2b and HKDF-SHA-256 from libsodium 1.0.22 (sumo) via the `sodium` 4.x package, whose build hook compiles libsodium (no system install). Typed keys; secrets in libsodium guarded memory with `dispose()`; key and nonce randomness from the injected `RandomSource` (`SodiumRandomSource` by default).
- Known-answer tests and vector files `test/vectors/rfc7748_x25519.json`, `rfc8032_ed25519.json`, `rfc5869_hkdf.json`, `rfc7693_blake2b.json`, `xchacha20poly1305.json`.

### Changed
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
