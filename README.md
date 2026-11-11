# mawaddah-protocol

The public, verifiable half of **Mawaddah** (مودّة), a private two-person app for engaged and married couples. This repository holds the code that carries and protects the couple's data, so anyone can check the privacy claims:

- `packages/mawaddah_protocol/` — pure-Dart package: crypto envelopes, pairing, Double Ratchet, event model, sync engine, relay client (so far: interfaces, fakes and the libsodium primitives)
- `relay/` — the **blind relay** (Cloudflare Workers + Durable Objects, TypeScript): it holds sealed envelopes for at most 30 days and cannot open them (skeleton: a `/health` route only, not deployed)
- [`PROTOCOL.md`](PROTOCOL.md), [`PRIVACY.md`](PRIVACY.md), [`SECURITY.md`](SECURITY.md)

> **Status: scaffolding only.** The package and the relay are built in Phase 1 of the project; nothing here is usable yet, and nothing has been independently reviewed. An independent security review is planned before version 1.0.0.

The Mawaddah app itself is closed source and lives in a separate private repository. Licensed under [Apache-2.0](LICENSE).

## Package interfaces (`packages/mawaddah_protocol`)
Logic code takes its outside world as injected interfaces, so tests can control time, randomness, storage and the relay (no `DateTime.now()` in `lib/`; CI checks this).

| Interface | Purpose | Test fake |
|---|---|---|
| `Clock` | current time (UTC) | `FakeClock` (`set`, `advance`) |
| `RandomSource` | random bytes (secure in the app) | `SeededRandom` (deterministic, **not secure**) |
| `Storage` | async key-value bytes | `InMemoryStorage` |
| `RelayClient` | deposit, fetch, ack sealed envelopes | `FakeRelayClient` |

The real `Clock`, `RandomSource`, `Storage` and `RelayClient` are supplied by the app. `NotificationGateway` lives in the private `core` package. Run the tests with `cd packages/mawaddah_protocol && dart test`.

## Crypto primitives (`packages/mawaddah_protocol/lib/src/crypto`)
`Crypto` (implemented by `SodiumCrypto`) is a typed layer over libsodium 1.0.22 (sumo) through the [`sodium`](https://pub.dev/packages/sodium) package: X25519, Ed25519, XChaCha20-Poly1305 (IETF), BLAKE2b and HKDF-SHA-256 ([`PROTOCOL.md`](PROTOCOL.md) section 2). It adds no cryptography of its own.

- **No system libsodium needed.** The `sodium` build hook compiles the libsodium source shipped inside the package (checked against libsodium's signing key) the first time `dart test` or a build runs; this needs a C compiler (`gcc` or `clang`, plus `make`), not network access.
- **Typed keys.** Keys, nonces and signatures are their own types (`X25519PublicKey`, `Ed25519SecretKey`, `AeadKey`, `AeadNonce`, `SecretBytes`, ...), so a key made for one primitive cannot be passed to another. Secret keys live in libsodium's guarded memory; call `dispose()` to wipe them. Methods that import secret bytes zero the caller's list.
- **Randomness** for keys and nonces comes from the injected `RandomSource` (`SodiumRandomSource` = libsodium's CSPRNG by default; `SeededRandom` only in tests).
- **Loading:** `await SodiumCrypto.load()`, or `SodiumCrypto(sodiumSumo)` to reuse a libsodium instance the app already loaded.
- **Known-answer tests** in `test/crypto/` use the published vectors in `test/vectors/` (RFC 7748, RFC 8032, RFC 5869, RFC 7693, draft-irtf-cfrg-xchacha-03 and libsodium's own XChaCha20-Poly1305 test).

## Toolchain and checks
Pinned versions: Dart in `.dart-version`, Node in `.node-version` (CI reads these files). `scripts/check.sh` = format, analyze, lint, typecheck, secret-file and fork-safety guards; `scripts/test.sh` = `dart test` and the relay's Vitest (the first `dart test` compiles libsodium, about 15 s). CI runs both plus gitleaks (`.gitleaks.toml` keeps the default rules and skips only the published test-vector files, whose "secret" keys are printed in the RFCs). Workflows use `pull_request` only, never `pull_request_target`, and no secrets, so fork PRs cannot reach any.

## Releases
Releases are tags `vX.Y.Z` on `main`. The `protocol-release` workflow runs the checks and tests, then publishes a GitHub Release with the matching CHANGELOG section (add `## [X.Y.Z] - date` first; `scripts/release-notes.sh vX.Y.Z` shows what will be published). The private app depends on the package by tag (`ref: vX.Y.Z`), never by branch.

## Contributing
Conventional Commits (`type(scope): subject`, see `.github/commit-types.txt`), PRs into `main`, CI green. Enable the git hook once per clone: `git config core.hooksPath .githooks`. Report security issues privately (see `SECURITY.md`).
