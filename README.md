# mawaddah-protocol

The public, verifiable half of **Mawaddah** (مودّة), a private two-person app for engaged and married couples. This repository holds the code that carries and protects the couple's data, so anyone can check the privacy claims:

- `packages/mawaddah_protocol/` — pure-Dart package: crypto envelopes, pairing, Double Ratchet, event model, sync engine, relay client (so far: interfaces, fakes, the libsodium primitives, device identity and the safety number, pairing, the Double Ratchet, signed envelopes, the hybrid logical clock, the event model with its idempotent apply, the outbox and sync loop, and the HTTP relay client)
- `relay/` — the **blind relay** (Cloudflare Workers + Durable Objects, TypeScript): it holds sealed envelopes for at most 30 days and cannot open them (so far: signed requests, inbox registration and its rate limit, pairing slots, envelopes, attachments and the 30-day delete; not deployed; see `relay/README.md`)
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
| `RelayClient` | every relay route: inbox, pairing slots, allow, envelopes, ACK, blobs, push token, delete | `FakeRelayClient` (checked when made with a signing key: the relay's rules and error codes) |
| `EventStore` + `SyncStore` | events, merged state; sync state (one shared transaction) | `InMemoryEventStore` + `InMemorySyncStore` |

The real `Clock`, `RandomSource` and `Storage` are supplied by the app; the real `RelayClient` is `HttpRelayClient` (below), given the relay's address by the app. `NotificationGateway` lives in the private `core` package. Run the tests with `cd packages/mawaddah_protocol && dart test`.

## Crypto primitives (`packages/mawaddah_protocol/lib/src/crypto`)
`Crypto` (implemented by `SodiumCrypto`) is a typed layer over libsodium 1.0.22 (sumo) through the [`sodium`](https://pub.dev/packages/sodium) package: X25519, Ed25519, XChaCha20-Poly1305 (IETF), BLAKE2b and HKDF-SHA-256 ([`PROTOCOL.md`](PROTOCOL.md) section 2). It adds no cryptography of its own.

- **No system libsodium needed.** The `sodium` build hook compiles the libsodium source shipped inside the package (checked against libsodium's signing key) the first time `dart test` or a build runs; this needs a C compiler (`gcc` or `clang`, plus `make`), not network access.
- **Typed keys.** Keys, nonces and signatures are their own types (`X25519PublicKey`, `Ed25519SecretKey`, `AeadKey`, `AeadNonce`, `SecretBytes`, ...), so a key made for one primitive cannot be passed to another. Secret keys live in libsodium's guarded memory; call `dispose()` to wipe them. Methods that import secret bytes zero the caller's list.
- **Randomness** for keys and nonces comes from the injected `RandomSource` (`SodiumRandomSource` = libsodium's CSPRNG by default; `SeededRandom` only in tests).
- **Loading:** `await SodiumCrypto.load()`, or `SodiumCrypto(sodiumSumo)` to reuse a libsodium instance the app already loaded.
- **Known-answer tests** in `test/crypto/` use the published vectors in `test/vectors/` (RFC 7748, RFC 8032, RFC 5869, RFC 7693, draft-irtf-cfrg-xchacha-03 and libsodium's own XChaCha20-Poly1305 test).

## Device identity and safety number (`packages/mawaddah_protocol/lib/src/identity`)
[`PROTOCOL.md`](PROTOCOL.md) sections 3 and 5.

- `DeviceIdentity.generate(crypto, random)` makes the two long-term key pairs, Ed25519 `IKsig` and X25519 `IKdh`, independently: the first 32 bytes from `random` are the Ed25519 seed, the next 32 the X25519 secret key. A device makes a new identity for every pairing attempt (ADR 0006).
- `toStorageBytes()` gives `0x01 || Ed25519 seed || X25519 secret` (65 bytes) for the app's Keystore-protected storage; zero the list once stored. `DeviceIdentity.fromStorageBytes` reads it back and zeroes its input. These bytes never leave the device; `toString` shows only the device ID.
- `DeviceId` = `SHA-256("mawaddah/v1/inbox" || IKsig_pub)[0..16]`, also the relay inbox ID, written as 22 base64url characters (`toBase64Url`, strict `DeviceId.parse`).
- `safetyNumber(crypto, a, b)` returns the 20 digits, the same in either order; `safetyNumberGroups` splits them into 5 groups of 4 for display.
- Generated vectors: `dart run tool/gen_vectors.dart` (from the package directory) writes every generated file in `test/vectors/` (identity, safety number, pairing, ratchet, envelope, HLC, UUID v7). Regenerate only with a protocol change and its ADR; the tests in `test/` check them.

## Envelopes, replay window and clock (`packages/mawaddah_protocol/lib/src/envelope`)
[`PROTOCOL.md`](PROTOCOL.md) sections 7 to 9.

- `Envelope.seal` pads the plaintext to 256-byte blocks, encrypts it with the `RatchetSession` and signs `"mawaddah/v1/envelope" || bytes[0..90+L]` with the sender's `IKsig`. Before sealing, the app stores the new counter; after, and before the bytes leave the phone, it saves the session.
- `Envelope.open` runs the receive checks in the order of section 8: structure, addresses, signature, `ReplayWindow` (RFC 4303, 1,024 counters, so out-of-order envelopes still pass), time window (at most 1 hour ahead, 31 days behind), decryption, unpadding. A failure throws `EnvelopeException`; its `EnvelopeFailure` says whether to acknowledge the envelope (`acknowledge`) and whether to keep the raw bytes (`keepUnapplied`). The app commits the session, the window, the HLC and the events in one transaction before the ACK.
- `HlcClock` (over the injected `Clock`) gives `Hlc` values that always increase, whatever the wall clock does: `send()` for a local event or an envelope, `receive()` to merge the partner's. `Hlc` has an 8-byte form (envelope) and a 16-hex-digit form (events).
- `Uuid7.generate(clock, random)` makes event and entity IDs (RFC 9562).
- Events (section 10): `Event` (strict JSON), `EventBatch.encode`/`decode` for the envelope plaintext, `EventFactory` for this device's events, and `Applier` over an `EventStore` (the app implements it over its database; `InMemoryEventStore` is the fake). Field-level last-writer-wins, append-only with final tombstones, unapplied events from a newer partner kept with a reason and shown through `EventStore.watchUnapplied`, applied again by `Applier.reapplyUnapplied` after an update.
- Generated vectors `envelope.json`, `hlc.json` and `uuid7.json`; `dart test test/envelope` checks them.

## Outbox and sync loop (`packages/mawaddah_protocol/lib/src/sync`)
[`PROTOCOL.md`](PROTOCOL.md) section 17.

- `SyncEngine.commitLocal(events)` applies this device's events and queues them in the outbox, in one transaction: the app works offline.
- `SyncEngine.syncOnce()` (one run at a time) fetches after the stored cursor, opens, applies and commits each envelope with its cursor, then acknowledges (cumulative); then it seals and deposits the outbox. A failed deposit is retried as the same sealed bytes (a new counter and key only after 1 day). It returns a `SyncReport` (counts only, `clockWarning`, and an advisory `retryAt` from `BackOff` that the app schedules itself). Relay failures are reported, store failures throw.
- `WakePolicy.v1` is the one table that decides `wake: 1` (a new chat message) or `wake: 0` (receipts, profile, hello).
- The app implements `SyncStore` over the same database transaction as its `EventStore`; `dart test test/sync` covers 7 days offline, duplicates, partial failures and lost ACKs.

## Relay client (`packages/mawaddah_protocol/lib/src/relay`)
[`relay/README.md`](relay/README.md) lists the routes and error codes; [`PROTOCOL.md`](PROTOCOL.md) section 13 the signing.

- `HttpRelayClient(baseUrl: …, signer: RelayRequestSigner(…))` implements `RelayClient` over HTTPS with `package:http`. The address is injected (plain `http` only to `localhost`, `127.0.0.1`, `[::1]` or the Android emulator's `10.0.2.2`); the package names no relay. One client signs as one device (one pairing attempt's identity). Without a signer only the unsigned code lookup works (the joiner looks the code up before its keys exist). `PairingInitiator.identity` gives the initiator's keys for signing during the attempt.
- Every failure is a `RelayException` with a `RelayErrorCode` (the relay's stable codes, plus `network`, `timeout`, `bad_response`, `invalid_response` and `unknown`), the HTTP status, `retryAfter` (`rate_limited`), `serverTime` (`clock_skew`: show the wrong-time card) and `nextChunk` (`chunk_out_of_order`). `retryable` says whether the same request may pass later (`sender_not_allowed` just after pairing, `inbox_full`, `rate_limited`, …); `toString` names no URL, ID or body.
- Retries: a try that gets no answer, times out (30 s), or meets a passing server fault is tried again after 1 s and 3 s, with a fresh signature. Refusals are thrown at once for the caller's back-off. Tried once only: `deposit` (a repeat after a lost answer would store the envelope twice and wake the partner twice; the sync engine resends the same bytes on its next run), `readPairingReply` (the reply can be read once) and a code lookup (a repeat could use up one of the network's 5 wrong guesses). `retry_after` is capped at one hour.
- Every answer is checked before use: the inbox ID must be the one computed from the key, cursors must increase, envelopes and blob chunks must have the right sizes, at most 2 MiB is read, and redirects are not followed. An answer that parses but breaks these rules is `invalid_response`: a broken or hostile relay, never retried. Argument errors never quote the value (IDs, codes, cursors).
- `uploadBlob` / `downloadBlob` move a whole encrypted file in 1 MiB relay chunks; an upload resumes at the chunk the relay names.
- `scripts/relay-integration.sh` starts the relay with `wrangler dev`, runs `test/relay/relay_integration_test.dart` against it (pairing on both paths, two sync engines chatting over HTTP, pages, blobs, refusals, rate limits, delete), then stops it. `scripts/test.sh` and CI run it.

## Toolchain and checks
Pinned versions: Dart in `.dart-version`, Node in `.node-version` (CI reads these files). `scripts/check.sh` = format, analyze, lint, typecheck, secret-file and fork-safety guards; `scripts/test.sh` = `dart test`, the relay's Vitest, and the Dart client against `wrangler dev` (`scripts/relay-integration.sh`; the first `dart test` compiles libsodium, about 15 s). CI runs both plus gitleaks (`.gitleaks.toml` keeps the default rules and skips only the test-vector files, whose "secret" keys are public on purpose: printed in the RFCs, or generated from fixed seeds by `tool/gen_vectors.dart`). Workflows use `pull_request` only, never `pull_request_target`, and no secrets, so fork PRs cannot reach any.

## Releases
Releases are tags `vX.Y.Z` on `main`. The `protocol-release` workflow runs the checks and tests, then publishes a GitHub Release with the matching CHANGELOG section (add `## [X.Y.Z] - date` first; `scripts/release-notes.sh vX.Y.Z` shows what will be published). The private app depends on the package by tag (`ref: vX.Y.Z`), never by branch.

## Contributing
Conventional Commits (`type(scope): subject`, see `.github/commit-types.txt`), PRs into `main`, CI green. Enable the git hook once per clone: `git config core.hooksPath .githooks`. Report security issues privately (see `SECURITY.md`).
