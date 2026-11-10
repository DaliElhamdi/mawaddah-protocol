# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Repository scaffolding, CI skeleton and documentation stubs. The protocol package and the relay do not exist yet (planned for Phase 1).
- `packages/mawaddah_protocol` skeleton: `Clock`, `RandomSource`, `Storage` and `RelayClient` interfaces with test fakes (`FakeClock`, `SeededRandom`, `InMemoryStorage`, `FakeRelayClient`). No cryptography yet.
- Check and test that `lib/` never calls `DateTime.now()`.
- `relay/` Worker skeleton (TypeScript, ESLint, Vitest): a `/health` route and its tests. Not deployed.
- CI runs the relay checks; Dart and Node versions are pinned in `.dart-version` and `.node-version`; Dependabot watches pub and npm.
