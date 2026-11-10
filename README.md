# mawaddah-protocol

The public, verifiable half of **Mawaddah** (مودّة), a private two-person app for engaged and married couples. This repository holds the code that carries and protects the couple's data, so anyone can check the privacy claims:

- `packages/mawaddah_protocol/` — pure-Dart package: crypto envelopes, pairing, Double Ratchet, event model, sync engine, relay client (skeleton: interfaces and fakes only)
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

## Toolchain and checks
Pinned versions: Dart in `.dart-version`, Node in `.node-version` (CI reads these files). `scripts/check.sh` = format, analyze, lint, typecheck, secret-file and fork-safety guards; `scripts/test.sh` = `dart test` and the relay's Vitest. CI runs both plus gitleaks. Workflows use `pull_request` only, never `pull_request_target`, and no secrets, so fork PRs cannot reach any.

## Contributing
Conventional Commits (`type(scope): subject`, see `.github/commit-types.txt`), PRs into `main`, CI green. Enable the git hook once per clone: `git config core.hooksPath .githooks`. Report security issues privately (see `SECURITY.md`).
