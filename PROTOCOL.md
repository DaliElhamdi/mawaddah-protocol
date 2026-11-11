# Mawaddah protocol

> **Status: v1 draft, implemented in v0.1.0.** This is the wire format the `mawaddah_protocol` package and the relay implement in v0.1.0. Until v1.0.0 it may change, but only through a decision record (ADR 0006 and later, in the project's primary repository) and with committed test vectors. It has not been independently reviewed yet; a review is planned before v1.0.0.

Mawaddah connects exactly two phones (one pair). Each phone keeps its data in an encrypted local database. Changes travel between the two phones as signed, end-to-end encrypted envelopes, carried by a **blind relay** that stores them for at most 30 days and cannot open them.

**No cryptography is invented here.** Every primitive is a libsodium function, or SHA-256 where the relay needs it. Every construction follows a published specification: X3DH for pairing, the Double Ratchet for messages, HKDF (RFC 5869) for key derivation. Section 2 lists each source. Where we adapt a specification, the text says what changed and why.

## Contents
1. [Conventions](#1-conventions)
2. [Primitives and sources](#2-primitives-and-sources)
3. [Identity keys and device ID](#3-identity-keys-and-device-id)
4. [Pairing](#4-pairing)
5. [Safety number](#5-safety-number)
6. [Double Ratchet](#6-double-ratchet)
7. [Envelope](#7-envelope)
8. [Receiving an envelope](#8-receiving-an-envelope)
9. [Hybrid logical clock (HLC)](#9-hybrid-logical-clock-hlc)
10. [Events](#10-events)
11. [Versions and compatibility](#11-versions-and-compatibility)
12. [Attachments](#12-attachments)
13. [Relay request signing](#13-relay-request-signing)
14. [Constants](#14-constants)
15. [Test vectors](#15-test-vectors)
16. [Known limits](#16-known-limits)

## 1. Conventions
- `||` is byte concatenation. `X[a..b]` is bytes `a` (inclusive) to `b` (exclusive) of `X`.
- Integers on the wire are unsigned and big-endian: `u8`, `u32`, `u64`.
- **Labels** are ASCII strings with no terminator, for example `"mawaddah/v1/bundle"`. Every hash, signature, MAC and key derivation in this document starts with, or is keyed by, its own label, so an output made for one purpose can never be accepted for another (domain separation).
- In JSON, byte strings are **base64url without padding** (RFC 4648 §5). The size given for such a field is the size of the decoded bytes. A decoded field with the wrong size is an error.
- JSON is UTF-8 (RFC 8259). Readers ignore unknown fields and reject a message that is missing a required field.
- Binary structures have fixed offsets. Trailing bytes, short input or a wrong length make the whole structure invalid.
- "Reject" means: do not use the data and do not change any state.
- Comparisons of secrets (MACs) use libsodium's constant-time verify functions.

## 2. Primitives and sources
All primitives come from libsodium 1.0.22, reached from Dart through the `sodium` package (4.x, sumo build). On Android and in pure-Dart tests the package's build hook compiles libsodium from its bundled source.

| Use | Primitive | libsodium function | Source specification |
|---|---|---|---|
| Diffie–Hellman | X25519 | `crypto_scalarmult`, `crypto_scalarmult_base` | RFC 7748 |
| Signatures | Ed25519 (pure, no pre-hash) | `crypto_sign_seed_keypair`, `crypto_sign_detached`, `crypto_sign_verify_detached` | RFC 8032 |
| Key derivation | HKDF-SHA-256 | `crypto_kdf_hkdf_sha256_extract`, `crypto_kdf_hkdf_sha256_expand` | RFC 5869 |
| Message encryption | XChaCha20-Poly1305 (IETF) | `crypto_aead_xchacha20poly1305_ietf_encrypt` / `_decrypt` | draft-irtf-cfrg-xchacha-03 over RFC 8439 |
| Hashing (transcript, safety number) | BLAKE2b | `crypto_generichash` | RFC 7693 |
| Pairing key confirmation | HMAC-SHA-512 truncated to 256 bits (libsodium calls it HMAC-SHA-512-256; not the FIPS SHA-512/256 hash) | `crypto_auth`, `crypto_auth_verify` | RFC 2104 over SHA-512 (FIPS 180-4) |
| Attachment encryption | secretstream XChaCha20-Poly1305 | `crypto_secretstream_xchacha20poly1305_*` | libsodium secretstream construction |
| Padding | ISO/IEC 7816-4 | `sodium_pad`, `sodium_unpad` | ISO/IEC 7816-4 |
| Random bytes | OS CSPRNG | `randombytes_buf` (or the platform's secure random) | — |
| Relay body hash, device ID | SHA-256 | — (not in the `sodium` Dart API): `package:crypto` in Dart, WebCrypto in the relay | FIPS 180-4 |

Constructions followed:
- **X3DH** — *The X3DH Key Agreement Protocol*, M. Marlinspike and T. Perrin, Signal, revision 1, 2016-11-04. Adapted in section 4.
- **PQXDH** — *The PQXDH Key Agreement Protocol*, E. Kret and R. Schmidt, Signal, 2023. Only as precedent for appending one extra shared secret to the X3DH key material (section 4.4). No post-quantum KEM is used.
- **Double Ratchet** — *The Double Ratchet Algorithm*, T. Perrin and M. Marlinspike, Signal, revision 1, 2016-11-20 (public domain). Section 6.
- **Anti-replay window** — RFC 4303 §3.4.3 (IPsec ESP sliding window). Section 8.
- **Hybrid logical clock** — S. Kulkarni, M. Demirbas et al., *Logical Physical Clocks*, OPODIS 2014. Section 9.
- **UUID version 7** — RFC 9562. Section 10.
- **Safety-number digits** — the 5-bytes-to-digits mapping of Signal's numeric fingerprint (libsignal `NumericFingerprintGenerator`). Section 5.

HKDF `info` is always one of this document's ASCII labels: the Dart `sodium` API passes `info` as a string, and for ASCII the bytes are exactly the label.

Random values (keys, nonces, secrets) come from the injected `RandomSource`; the app backs it with a cryptographically secure generator. The deterministic `SeededRandom` is used only to generate test vectors.

## 3. Identity keys and device ID
Each device holds two independent long-term key pairs:

| Name | Type | Public | Private | Use |
|---|---|---|---|---|
| `IKsig` | Ed25519 | 32 bytes | 32-byte seed (64-byte libsodium secret key derived from it) | signs bundles, envelopes and relay requests |
| `IKdh` | X25519 | 32 bytes | 32 bytes | pairing Diffie–Hellman (section 4) |

- The two key pairs are generated separately. The X25519 key is **not** converted from the Ed25519 key.
- Private keys stay on the device in Keystore-protected storage (the app supplies it through `Storage`). They are never sent anywhere and never exported in a backup.
- **Fresh keys for every pairing attempt.** A device generates new identity keys when the person taps "Invite" or "Join" and keeps them for the life of that pair. Unpair, "Delete all data", a failed or abandoned attempt, and a backup restore discard them; the next attempt generates new ones. A device that abandons an attempt also deletes the inbox it registered for it (`DELETE /v1/inbox/{id}`). Section 5 explains why the safety number depends on this. (Spec 4.4 says "generated at install"; ADR 0006 records this change. The relay's limit of 5 inbox registrations per IP per hour must leave room for a failed attempt on a shared home network: one pairing registers two inboxes from the same IP.)

**Device ID** (also the relay inbox ID), 16 bytes:
```
device_id = SHA-256("mawaddah/v1/inbox" || IKsig_pub)[0..16]
```
The relay recomputes it when the device registers its inbox, so it cannot be chosen freely. It is written as base64url (22 characters) in JSON and URLs.

## 4. Pairing
Pairing follows X3DH with these adaptations, because both people are present (in the same room, or on a call) at the same time:
- There is no prekey server. The **initiator** (taps "Invite") plays X3DH's Bob; its ephemeral key `EKi`, signed by its identity key, plays the signed prekey. There is no one-time prekey.
- The **joiner** (scans the QR or types the code) plays X3DH's Alice.
- The QR adds a one-time 128-bit secret `S` to the key material, so a relay that did not see the QR cannot complete the exchange.

Names: `i` = initiator, `j` = joiner. `IKsig_i`, `IKdh_i`, `EKi` are the initiator's public keys; `IKsig_j`, `IKdh_j`, `EKj` the joiner's. `EK` key pairs are X25519, generated fresh for this attempt.

### 4.1 Initiator bundle (stored in the relay pairing slot)
JSON object posted to `POST /v1/pairing-slot`:

| Field | Type | Size | Meaning |
|---|---|---|---|
| `v` | integer | — | bundle format, `1` |
| `sig_pub` | bytes | 32 | `IKsig_i` |
| `dh_pub` | bytes | 32 | `IKdh_i` |
| `ek_pub` | bytes | 32 | `EKi` |
| `sig` | bytes | 64 | Ed25519 signature by `IKsig_i` over `"mawaddah/v1/bundle" \|\| 0x01 \|\| sig_pub \|\| dh_pub \|\| ek_pub` (`0x01` is the format version `v`) |

The bundle never contains `S`. The relay returns a 16-byte random `slot_id` and a 6-digit decimal `code`, both valid 10 minutes, single use.

### 4.2 QR payload
Binary, 129 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version `0x01` |
| 1 | 32 | `IKsig_i` |
| 33 | 32 | `IKdh_i` |
| 65 | 32 | `EKi` |
| 97 | 16 | `S`, one-time secret (random) |
| 113 | 16 | `slot_id` |

Encoding: the text `MAWADDAH:` followed by base64url (no padding) of the 129 bytes, 181 characters in all, in a QR code in byte mode with error correction level M. A reader rejects any other prefix, a decoded length other than 129, or an unknown version. The QR is the trust anchor of the QR path, so it carries no signature. The initiator's device ID is computed from `IKsig_i` (section 3). The QR (and `S`) is shown only on the initiator's screen and is discarded when the slot expires or pairing ends.

### 4.3 Joiner reply
JSON object posted to `POST /v1/pairing-slot/{slot_id}/reply`:

| Field | Type | Size | Meaning |
|---|---|---|---|
| `v` | integer | — | reply format, `1` |
| `path` | string | — | `"qr"` or `"code"`, how the joiner got the bundle |
| `sig_pub` | bytes | 32 | `IKsig_j` |
| `dh_pub` | bytes | 32 | `IKdh_j` |
| `ek_pub` | bytes | 32 | `EKj` |
| `confirm` | bytes | 32 | key confirmation (section 4.4) |
| `sig` | bytes | 64 | Ed25519 signature by `IKsig_j` over `"mawaddah/v1/reply" \|\| TH \|\| confirm` |

### 4.4 Key derivation (both sides)
```
path_byte = 0x01 (qr) or 0x02 (code)
S'        = S on the QR path; 16 zero bytes on the code path

DH1 = X25519(IKdh_j, EKi)      # X3DH DH1 = DH(IKA, SPKB)
DH2 = X25519(EKj, IKdh_i)      # X3DH DH2 = DH(EKA, IKB)
DH3 = X25519(EKj, EKi)         # X3DH DH3 = DH(EKA, SPKB)
     (the initiator computes the same values with its private keys)

F   = 32 bytes of 0xFF          # X3DH section 2.2, X25519
KM  = DH1 || DH2 || DH3 || S'
PRK = HKDF-Extract(salt = 32 zero bytes, IKM = F || KM)
SK  = HKDF-Expand(PRK, info = "mawaddah/v1/pairing/sk",      L = 32)
KC  = HKDF-Expand(PRK, info = "mawaddah/v1/pairing/confirm", L = 32)

TH  = BLAKE2b-256("mawaddah/v1/transcript" || 0x01 || path_byte
                  || IKsig_i || IKdh_i || EKi || IKsig_j || IKdh_j || EKj)
                                                    # 0x01 = format version
confirm = HMAC-SHA-512-256(key = KC, "mawaddah/v1/confirm" || TH)
AD  = IKsig_j || IKdh_j || IKsig_i || IKdh_i       # 128 bytes, X3DH AD = IKA || IKB
```
- If any X25519 output is all zeros (libsodium returns an error for low-order points), abort.
- Appending `S'` after the DH outputs follows PQXDH, which appends its KEM secret the same way.
- `SK` becomes the Double Ratchet's initial root key; `EKi` is the initiator's first ratchet key pair (Double Ratchet section 7.1). `AD` is the associated data of every ratchet message (section 6). Once the reply is sent (joiner) or checked (initiator), both sides erase `S`, `PRK`, `KC`, the DH outputs and the joiner's `EKj` private key. The initiator keeps `EKi`'s private key as its ratchet key `DHs` until the joiner's first message arrives and the first DH ratchet step replaces it; forward secrecy for that first exchange depends on that step.

### 4.5 Message flow
QR path (normal, D14):
1. Initiator: generate identity keys, `EKi` and `S`; register its inbox (`POST /v1/inbox`); create the slot with the bundle; show the QR, and under it the code.
2. Joiner: scan the QR. Generate identity keys and `EKj`. Register its inbox. Compute section 4.4 with `path = "qr"` and the QR's `S`. Post the reply.
3. Initiator: read the reply from the slot (the relay then deletes the slot). Verify `sig`, recompute `TH`, `SK`, `KC` and check `confirm`. If any check fails, show "Pairing did not work, try again" and start over with new keys.
4. Both: allow the partner's `IKsig` on their own inbox (`POST /v1/inbox/{id}/allow`). Both show the safety number; comparing is recommended.
5. Joiner sends the first ratchet envelope, a `device.hello` event (section 11), then both exchange `profile` events (first name, gender) inside the encrypted channel. The initiator cannot send until the joiner's first envelope arrives (a Double Ratchet property); anything it writes before then waits in its outbox.

Code path (fallback):
1. Initiator: as above; the person reads the 6-digit code to the partner.
2. Joiner: `GET /v1/pairing-slot/{code}` (unsigned; the response holds the `slot_id` and the bundle of section 4.1) and verify the bundle signature. **Only after that** generate identity keys, register the inbox and post the reply with `path = "code"` and `S'` = zeros.
3–4. As in the QR path.
5. Both phones show the safety number and **require** each person to tap "The numbers match" (section 5). Until the local person taps it, the session is *unverified*: the device sends and accepts only the `device` hello event (section 11), and shows nothing from the partner. `profile` events (first name, gender) and everything else wait in the outbox until the person taps "The numbers match". "They don't match" erases the session and the identity keys on that phone, deletes its inbox, and tells the person to start again.

Rules for both paths:
- The initiator learns the path from the reply. A reply with `path = "code"` always makes the safety-number check required on the initiator's phone, even if the initiator expected a scan, so a relay that fakes a code-path reply is caught by the comparison.
- A slot accepts one reply; the first one wins. The initiator checks one reply per attempt. A reply that fails the checks ends the attempt, and the initiator starts a new one (new keys, new slot).
- Anyone who learns the code, or photographs the QR, can answer first. On the code path this only blocks the attempt, because the safety-number check fails. On the QR path someone who photographed the QR could pair instead of the partner. The partner's phone then gets "This invitation was already used", and it must tell the person: "Ask your partner to check their screen and unpair if needed." Both phones show the safety number after a QR pairing too.
- A third device cannot join: after pairing, each inbox allows exactly one sender key, and the app keeps one pair per installation.

## 5. Safety number
20 decimal digits in 5 groups of 4, the same on both phones, derived from both identity keys sorted:
```
Ki = IKsig_i || IKdh_i                      # 64 bytes
Kj = IKsig_j || IKdh_j
(K1, K2) = (Ki, Kj) sorted as unsigned byte strings, smaller first
H  = BLAKE2b-256("mawaddah/v1/safety-number" || K1 || K2)
group[g] = u40(H[5g .. 5g+5]) mod 10000, for g = 0..4, written as 4 digits with leading zeros
safety_number = group[0] group[1] group[2] group[3] group[4]
```
- Displayed as `1234 5678 9012 3456 7890`, always left-to-right. The protocol value is the 20 ASCII digits; how the app draws them is a UI choice.
- Shown after pairing and in Settings at any time. It changes only when either phone's identity keys change, which means a new pairing.
- **Why fresh keys per attempt matter:** 20 digits are about 66 bits. A relay that substitutes keys must make both phones show the same number. If it knew both people's real keys in advance, it could search its two fake keys together (a birthday search, about 2^33 work). Because the joiner's identity keys are new for each attempt and are revealed only in the reply, after the joiner has already received the bundle (section 4.5), the relay's first substitute is fixed before it learns the joiner's keys, and it then needs a second preimage of the 66-bit value (about 2^66 work). Implementations must keep that order.

## 6. Double Ratchet
The Double Ratchet as specified by Signal (section 2), without header encryption, with these choices:

| Function | Choice |
|---|---|
| `GENERATE_DH()` | new X25519 key pair (32 random bytes as private key, public = `crypto_scalarmult_base`) |
| `DH(dh_pair, dh_pub)` | X25519; abort on an all-zero output |
| `KDF_RK(rk, dh_out)` | `HKDF-SHA-256(salt = rk, IKM = dh_out, info = "mawaddah/v1/ratchet/rk", L = 64)`; first 32 bytes = new `rk`, last 32 = new chain key |
| `KDF_CK(ck)` | message key `mk = HKDF-Expand(PRK = ck, info = "mawaddah/v1/ratchet/mk", L = 32)`; next chain key `= HKDF-Expand(PRK = ck, info = "mawaddah/v1/ratchet/ck", L = 32)` |
| `ENCRYPT(mk, plaintext, ad)` | `key || nonce = HKDF-Expand(PRK = mk, info = "mawaddah/v1/ratchet/aead", L = 56)` (32 + 24 bytes); XChaCha20-Poly1305-IETF with that key and nonce, associated data `ad` |
| `HEADER(dh_pair, pn, n)` | the envelope header of section 7 (contains `dh_pub`, `pn`, `n`) |
| `CONCAT(ad, header)` | `AD || header`, where `AD` is the 128 bytes of section 4.4 and `header` the 90 header bytes of section 7 |

- `KDF_CK` with HKDF-Expand is HMAC-SHA-256 keyed by `ck` over a distinct constant per output, which is what the Signal specification recommends (section 5.2 there). Deriving the AEAD nonce from `mk` is one of the options it lists; each `mk` is used once.
- **Initialisation** (Signal section 3.3): the joiner calls `RatchetInitAlice(SK, EKi_pub)`; the initiator calls `RatchetInitBob(SK, EKi_pair)`.
- **Skipped message keys:** one received message may create at most `MAX_SKIP = 1000` skipped keys in total, counting both `SkipMessageKeys` calls of a DH ratchet step (a header that would need more is rejected). At most 1,000 skipped keys are stored in total; when full, the oldest is deleted. A skipped key older than 30 days is deleted. Keys are stored by (`dh_pub`, `n`).
- Both people can send at the same time: the ratchet handles crossing messages by design.
- **Failure leaves the state unchanged** (Signal section 3.5): a receiver computes the DH ratchet step and the next chain key on copies, and keeps them only if the AEAD tag checks. A rejected message (bad tag, small-order `dh_pub`, a message number already used, or one that would need more skipped keys than allowed) changes nothing, so the next genuine message still opens.
- **Header and associated data:** `dh_pub`, `pn` and `n` are envelope bytes 50 to 90 (section 7). The ratchet authenticates the whole of bytes 0 to 90, so the version, type, device IDs, counter and HLC are bound to the ciphertext as well as signed.
- **Skipped keys in detail:** a stored key is used once and then deleted. A key is dated with the receiver's clock when it is stored; it counts as absent once it is more than 30 days old, and it is deleted at the next successful decryption or when the app asks. A message whose key was deleted (expired or evicted) is refused like a repeat. Setting the clock back never deletes a key early.
- Ratchet state lives only in the encrypted database. It is never put in a backup; a restored phone pairs again (spec 4.4). The state is saved as one byte string (`RatchetSession.toStorageBytes`, a local format with its own version byte, not part of the wire protocol). The receiver saves it in the same transaction as the events of the message (section 8, step 8). The sender saves it before the envelope leaves the device, because a session restored from older bytes would reuse a message key and its nonce.

## 7. Envelope
One envelope carries one ratchet message. Binary, at most 65,536 bytes (relay limit):

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 1 | `version` | `0x01` |
| 1 | 1 | `type` | `0x01` = ratchet message (the only type in v1) |
| 2 | 16 | `sender_id` | sender's device ID |
| 18 | 16 | `recipient_id` | recipient's device ID |
| 34 | 8 | `counter` | `u64`, per sender, starts at 1, +1 for every envelope sealed, never reused (the sender stores the new value before sealing, so a crash cannot reuse one) |
| 42 | 8 | `hlc` | `u64`, sender's HLC when sealed (section 9) |
| 50 | 32 | `dh_pub` | sender's current ratchet public key |
| 82 | 4 | `pn` | `u32`, length of the previous sending chain |
| 86 | 4 | `n` | `u32`, message number in the current sending chain |
| 90 | `L` | `ciphertext` | `ENCRYPT(mk, padded plaintext, AD \|\| bytes[0..90])`, includes the 16-byte Poly1305 tag |
| 90 + `L` | 64 | `signature` | Ed25519 by the sender's `IKsig` over `"mawaddah/v1/envelope" \|\| bytes[0 .. 90+L]` |

- **Plaintext** is a UTF-8 JSON object `{"events": [ ... ]}` holding 1 or more events (section 10), padded with `sodium_pad` to a multiple of 256 bytes. `sodium_pad` always adds at least one byte, so `L` is a multiple of 256 plus 16 and at least 272. The largest padded plaintext that fits is 65,280 bytes (65,536 − 90 − 16 − 64 = 65,366, rounded down to the block), so the largest JSON before padding is 65,279 bytes. The outbox splits larger batches.
- Header fields are not encrypted (standard Double Ratchet, not the header-encryption variant). The relay can therefore read the device IDs, the counter, the HLC time and the ratchet counters; section 16 lists what that reveals.
- The signature lets the receiver reject forged or altered envelopes before touching ratchet state. The AEAD tag authenticates the same header bytes again.

## 8. Receiving an envelope
In this order; any failure rejects the envelope:
1. **Parse.** Length 426 (90 + 272 + 64) to 65,536 bytes; known `version` and `type`. An unknown `version` or `type` is not an error to drop: keep the raw bytes as unapplied, acknowledge it, and show the "newer version" card (section 11). Its signature cannot be checked yet, so at most 100 such envelopes are kept (oldest deleted first).
2. **Addresses.** `recipient_id` is this device and `sender_id` is the paired partner.
3. **Signature** with the partner's `IKsig`.
4. **Replay window** (RFC 4303 §3.4.3, window `W = 1024`): reject if `counter` ≤ highest accepted counter − `W`, or if `counter` is already marked in the window.
5. **Time window:** let `t` = the physical part of `hlc` and `now` = the receiver's clock. If `t > now + 1 hour`, do not acknowledge it: leave it on the relay and try again at the next sync; after 24 hours of retrying, show "One of your phones has the wrong date or time". If `t < now − 31 days`, reject it (the relay deletes everything older than 30 days, so it cannot be genuine).
6. **Decrypt** with the ratchet (`RatchetDecrypt`, including skipped keys). If decryption fails, keep the raw envelope as unapplied with reason `undecryptable` rather than dropping it.
7. **Unpad and parse** the events; store and apply each one (sections 10–11).
8. **Commit** the new ratchet state, the replay window, the receiver's HLC and the events in one database transaction, **then** acknowledge the envelope to the relay. If the app dies before the ACK, the relay delivers it again and step 4 or event idempotency makes the repeat harmless.

Rejected envelopes (steps 2–4, and step 5 when too old) are acknowledged and discarded, and counted in the debug log with no content. An `undecryptable` envelope passed the signature check, so its counter is marked in the replay window.

## 9. Hybrid logical clock (HLC)
64 bits: the high 48 bits are the physical time in milliseconds since the Unix epoch (UTC), the low 16 bits a logical counter. Algorithm from Kulkarni et al. (section 2):
- **Local event or send:** `l' = max(l, now_ms)`; if `l' == l` then `c' = c + 1` else `c' = 0`.
- **Receive** (remote `l_m`, `c_m`): `l' = max(l, l_m, now_ms)`; `c'` = `max(c, c_m) + 1` if `l' == l == l_m`, `c + 1` if `l' == l`, `c_m + 1` if `l' == l_m`, else `0`.
- If `c` would exceed 65,535, wait for the next millisecond. `now_ms` comes from the injected `Clock`.
- Total order of events: compare `hlc`, then `author_device` bytes. This is the last-writer-wins order of section 10.
- In JSON an HLC is 16 lowercase hexadecimal digits, so string order equals numeric order.

## 10. Events
Every change is an immutable event (spec 4.6). Fields:

| Field | JSON type | Size / format | Meaning |
|---|---|---|---|
| `event_id` | string | UUID v7 (RFC 9562), 36 lowercase characters | unique; applying the same `event_id` twice has no effect |
| `entity_type` | string | 1–32 characters `[a-z_]` | kind of entity, see registry below |
| `entity_id` | string | UUID v7, 36 characters | the entity changed |
| `op` | string | `create`, `update`, `delete`, `snapshot` | operation |
| `payload` | object | JSON object | type-specific fields; `{}` for `delete` |
| `hlc` | string | 16 hex digits (section 9) | when the author made the change |
| `author_device` | string | base64url, 16 bytes | author's device ID |
| `protocol_version` | integer | ≥ 1 | protocol the author used (section 11) |
| `schema_version` | integer | ≥ 1 | version of this `entity_type`'s payload |

- The UUID v7 time comes from the `Clock` and the random bits from the `RandomSource`.
- **Merge rules** (spec 4.6): mutable entities use field-level last-writer-wins: an `update` payload holds only changed fields, and each field keeps the value of the event with the highest (`hlc`, `author_device`). Append-only entities (chat messages, answers, logs) are only created; a later `delete` is a tombstone: the entity is hidden and its payload is purged from the log. A `snapshot` replaces all earlier events of its entity type up to its `hlc` (compaction and initial sync).
- Events from the partner are checked: `author_device` must be the sender of the envelope that carried them.

Registry (v1). Each feature issue adds its types here, with the payload fields, in the same pull request as the code.

| `entity_type` | Ops | Rule | Introduced by |
|---|---|---|---|
| `device` | `update` | LWW; first event after pairing and after every app update is the `hello` (section 11) | protocol #16 |
| `profile` | `update` | LWW. Payload: `first_name` (1–50 characters, trimmed, no control characters), `gender` (`male` or `female`), `mode` (`engaged`, `contracted`, `married_cohab` or `married_remote`); `PairingProfile` in the package | protocol #12 (type), app pairing work |
| `message` | `create`, `delete` | append-only + tombstone | chat |
| `reaction` | `update` | LWW per (message, author) | chat |
| `receipt` | `update` | LWW, highest delivered/read HLC | chat |

## 11. Versions and compatibility
- `PROTOCOL_VERSION = 1` and `MIN_SUPPORTED_PROTOCOL = 1` are constants of each package release. The envelope `version` byte, the QR, bundle and reply formats are all `1` in protocol v1.
- **Hello:** `device` `update` event with payload `{"protocol_version": 1, "min_supported_protocol": 1, "envelope_versions": [1]}`, sent first after pairing and again after every update.
- A sender never uses an envelope version the partner did not list.
- An event is stored **unapplied** (with a reason, never dropped) if its `protocol_version` is above the local `PROTOCOL_VERSION`, its `entity_type` or `op` is unknown, or its `schema_version` is above the one this release knows. The app shows "Your partner has a newer version — please update". After an update, unapplied events are applied again in HLC order.
- If the partner's `min_supported_protocol` is above the local `PROTOCOL_VERSION`, the same card is shown. If the local `MIN_SUPPORTED_PROTOCOL` is above the partner's `protocol_version`, the app asks this person to tell their partner to update.
- New entity types, ops and payload fields do not need a new protocol version; they rely on the unapplied rule. A change to the meaning of existing fields, the envelope, the ratchet or the pairing does, together with an ADR.

## 12. Attachments
Photos and voice notes travel as encrypted blobs, not inside envelopes:
- Per file: a random 32-byte key and a random 16-byte `blob_id`.
- The file is encrypted with libsodium secretstream XChaCha20-Poly1305: the 24-byte stream header first, then the file in 65,536-byte plaintext chunks (the last one shorter and tagged `FINAL`). At most 10 MB of ciphertext per blob (relay limit).
- The key, `blob_id`, size and media type travel inside the encrypted event that refers to the attachment. The relay sees only the blob ID, its size and when it was uploaded and fetched.
- The relay upload and download API (chunked `PUT`/`GET /v1/blob/{id}`) is described with the relay.

## 13. Relay request signing
Every relay request except `GET /v1/pairing-slot/{slot_id or code}` and `GET /health` is signed with the device's `IKsig`. The signing input is these six lines joined by `\n` (0x0A), UTF-8, with no final newline (the spec's `method | path | sha256(body) | timestamp | nonce`, plus a label):
```
MAWADDAH-RELAY-V1
<METHOD>                 uppercase, e.g. PUT
<path>                   path and query exactly as sent, e.g. /v1/inbox/AbC.../envelopes?after=17
<sha256(body)>           64 lowercase hex digits; for an empty body the hash of zero bytes
<timestamp>              Unix time in seconds, decimal, no leading zeros
<nonce>                  16 random bytes, base64url (22 characters)
```
Headers:

| Header | Value |
|---|---|
| `Maw-Key` | `IKsig` public key, base64url (32 bytes) |
| `Maw-Timestamp` | the timestamp line |
| `Maw-Nonce` | the nonce line |
| `Maw-Signature` | Ed25519 signature over the signing input, base64url (64 bytes) |

The relay rejects a request if the signature does not verify, the timestamp is more than 300 seconds from its own clock, the nonce was seen in the last 15 minutes (spec 4.5 asks for at least 10; the accepted timestamps span 10 minutes, so the memory must be longer than that), or (for inbox routes) the key does not own that inbox or is not on its allow-list. `POST /v1/inbox` is signed with the key it registers, which proves the device holds it. The string names no relay, but a key is registered on one relay only (keys are per pairing), so a request captured on staging fails on production. Endpoints, bodies, limits and errors are in the relay documentation.

## 14. Constants
| Name | Value |
|---|---|
| `PROTOCOL_VERSION` / `MIN_SUPPORTED_PROTOCOL` | 1 / 1 |
| QR secret `S` | 16 bytes |
| Pairing slot lifetime, code | 10 minutes, single use, 6 digits |
| Safety number | 20 digits, 5 groups of 4 |
| `MAX_SKIP` / stored skipped keys / skipped-key lifetime | 1,000 / 1,000 / 30 days |
| Envelope size | ≤ 65,536 bytes; plaintext padded to 256-byte blocks |
| Replay window `W` | 1,024 envelopes |
| HLC time window | at most 1 hour ahead, at most 31 days behind |
| Relay request time window / nonce memory | ±300 s / 15 minutes |
| Attachment chunk / blob size | 65,536 bytes plaintext / ≤ 10 MB |

## 15. Test vectors
Committed in `packages/mawaddah_protocol/test/vectors/`, used by the package tests, the app's tests and the partner bot, and (for relay signing) by the relay tests. One JSON file per area:

| File | Contents |
|---|---|
| `rfc4231_hmac.json`, `rfc5869_hkdf.json`, `rfc7748_x25519.json`, `rfc8032_ed25519.json`, `rfc7693_blake2b.json`, `xchacha20poly1305.json` | published test cases (the RFCs, draft-irtf-cfrg-xchacha-03 and libsodium's own test), to check the libsodium bindings; these files name their `source` instead of `generated_by` |
| `identity.json` | seeds → `IKsig`, `IKdh`, `device_id` |
| `pairing.json` | both paths: the random bytes each side draws (initiator: identity 64, `EKi` 32, `S` 16; joiner: identity 64, `EKj` 32) and the slot ID → bundle, QR text, reply, DH1–3, `SK`, `KC`, `TH`, `confirm`, `AD`, safety number; failing cases (wrong `S`, changed `confirm`, reply for another initiator, relabelled path, second reply, bad bundle signature, malformed QR texts) with the error name |
| `safety_number.json` | key pairs (both orders) → 20 digits |
| `ratchet.json` | a scripted conversation from `SK`, `AD`, the initiator's `EKi` secret and each side's random bytes (32 per new ratchet key): each step's side, plaintext, envelope bytes 0..50, header, chain key, `mk`, AEAD key and nonce, ciphertext, and at each DH ratchet step the new ratchet key, root key and both chain keys; two cases: in order with turn changes and crossing messages, and out of order (keys skipped in the current chain and, through `pn`, in the previous one; messages opened later from stored keys), where receive steps also list the skipped keys they create and the number stored |
| `envelope.json` | header fields and plaintext → padded plaintext, envelope bytes, signature; rejected cases (tampered byte, replayed counter, time out of window, wrong recipient) with the expected error |
| `hlc.json`, `uuid7.json` | clock readings → HLC values; clock and random bytes → UUID v7 |
| `relay_signing.json` | method, path, body, timestamp, nonce, key seed → signing input and signature |

Format of every file:
```json
{
  "file": "pairing",
  "protocol_version": 1,
  "generated_by": "packages/mawaddah_protocol/tool/gen_vectors.dart",
  "cases": [
    { "name": "qr path, basic", "input": { "...": "..." }, "output": { "...": "..." } },
    { "name": "wrong secret", "input": { "...": "..." }, "error": "confirm_mismatch" }
  ]
}
```
Bytes are lowercase hex in vector files (easier to compare by eye than base64url). Values are deterministic: random bytes come from `SeededRandom` and are written into `input`, so another implementation can reproduce every output. Vectors are regenerated only together with a protocol change and its ADR; a pull request that changes a vector without one is wrong.

## 16. Known limits
Stated plainly, so nobody relies on more than this gives:
- **Not reviewed yet.** The implementation follows published specifications but has had no independent review; one is planned before v1.0.0.
- **The relay sees metadata** (spec 4.3): inbox IDs and that two inboxes are linked, envelope and blob sizes (rounded to 256 bytes for envelopes), times, whether a wake-up was asked, push tokens, and IP addresses for at most 24 hours. Because ratchet headers are not encrypted, it can also count messages per ratchet step and see the sender's clock time in each envelope.
- **Code path without comparison is not safe:** a 6-digit code cannot authenticate keys. The app requires the safety-number comparison on that path; skipping it is not possible by design.
- **The QR is a one-time bearer secret:** someone who photographs it during its 10 minutes can answer first. The real partner's phone then reports the invitation as used (section 4.5); the people have to notice and unpair.
- **Safety number strength** is about 66 bits and relies on fresh joiner keys revealed only after the bundle is received (section 5).
- **No post-quantum protection.** Recorded traffic could be decrypted by a future large quantum computer.
- **A phone that is unlocked and compromised** exposes what is on it; the ratchet only limits what an attacker learns before and after (forward secrecy and post-compromise recovery).
- **Clock trust:** HLC order depends on the phones' clocks within the windows above; a phone with a badly wrong clock delays its own envelopes until fixed.
