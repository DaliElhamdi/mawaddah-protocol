# Mawaddah protocol

> **Status: draft outline.** This document is written during Phase 1 together with the code and the committed test vectors. Until then it only lists the fixed design decisions. Do not rely on anything here as a finished specification.

## Fixed design decisions
- **No invented cryptography.** Vetted primitives from libsodium: X25519, Ed25519, XChaCha20-Poly1305, BLAKE2b/HKDF, Argon2id.
- **Pairing:** key derivation follows the X3DH specification, adapted to two parties who are online at the same time (no prekey server). Both sides contribute an identity key and an ephemeral key; the QR also carries a one-time 128-bit secret mixed into the key derivation. A 6-digit code is only a lookup handle for the relay pairing slot (10 minutes, single use, rate-limited) and cannot authenticate keys, so both people must compare the safety number.
- **Safety number:** derived from both identity keys (sorted), shown as digits in groups.
- **Messaging:** the Double Ratchet as defined in the Signal specification, with skipped-message keys bounded (1,000 stored, deleted after 30 days).
- **Authentication and replay:** every envelope is signed by the sender's Ed25519 key and carries a monotonic counter and a hybrid logical clock timestamp.
- **Relay requests:** signed over `method | path | sha256(body) | timestamp | nonce`; timestamps outside ±300 s and repeated nonces are rejected.
- **Sync:** immutable events, field-level last-writer-wins for mutable entities, append-only for chat and answers, tombstones for deletes, idempotent application.

## To be written (Phase 1)
Envelope format · pairing message flow · relay API (endpoints, limits, errors) · event schema and versioning · test vectors.
