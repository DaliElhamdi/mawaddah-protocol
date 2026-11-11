# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `PROTOCOL.md`: the v1 wire format (draft, implemented in v0.1.0): identity keys and device ID, pairing (X3DH adapted, QR payload, code path), safety number, Double Ratchet parameters, envelope layout and receive checks, HLC, event schema and versioning, attachments, relay request signing, constants, test-vector layout and known limits.

## [0.0.1] - 2026-11-10

This first tag is a skeleton for the private app to pin; it contains no cryptography and nothing is deployed.

### Added
- Repository scaffolding, CI skeleton and documentation stubs.
- `packages/mawaddah_protocol` skeleton: `Clock`, `RandomSource`, `Storage` and `RelayClient` interfaces with test fakes (`FakeClock`, `SeededRandom`, `InMemoryStorage`, `FakeRelayClient`). No cryptography yet.
- Check and test that `lib/` never calls `DateTime.now()`.
- `relay/` Worker skeleton (TypeScript, ESLint, Vitest): a `/health` route and its tests. Not deployed.
- CI runs the relay checks; Dart and Node versions are pinned in `.dart-version` and `.node-version`; Dependabot watches pub and npm.
- `protocol-release` workflow: a `vX.Y.Z` tag on `main` runs the checks and tests, then publishes a GitHub Release with the CHANGELOG section as notes (pre-release below 1.0.0). `scripts/release-notes.sh` extracts the section.
