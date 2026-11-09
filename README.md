# mawaddah-protocol

The public, verifiable half of **Mawaddah** (مودّة), a private two-person app for engaged and married couples. This repository holds the code that carries and protects the couple's data, so anyone can check the privacy claims:

- `packages/mawaddah_protocol/` — pure-Dart package: crypto envelopes, pairing, Double Ratchet, event model, sync engine, relay client (planned)
- `relay/` — the **blind relay** (Cloudflare Workers + Durable Objects, TypeScript): it holds sealed envelopes for at most 30 days and cannot open them (planned)
- [`PROTOCOL.md`](PROTOCOL.md), [`PRIVACY.md`](PRIVACY.md), [`SECURITY.md`](SECURITY.md)

> **Status: scaffolding only.** The package and the relay are built in Phase 1 of the project; nothing here is usable yet, and nothing has been independently reviewed. An independent security review is planned before version 1.0.0.

The Mawaddah app itself is closed source and lives in a separate private repository. Licensed under [Apache-2.0](LICENSE).

## Contributing
Conventional Commits (`type(scope): subject`, see `.github/commit-types.txt`), PRs into `main`, CI green. Enable the git hook once per clone: `git config core.hooksPath .githooks`. Report security issues privately (see `SECURITY.md`).
