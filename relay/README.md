# Mawaddah relay

The **blind relay** (spec 4.5): a Cloudflare Worker with SQLite-backed Durable Objects. It carries sealed envelopes between the two phones of a pair and cannot open them. The wire format is in [`../PROTOCOL.md`](../PROTOCOL.md); what the relay can see is in [`../PRIVACY.md`](../PRIVACY.md).

> **Status: in progress, not deployed.** Done so far: request signing, nonce memory, inbox registration and its rate limit (protocol #19), pairing slots (#20). Still to come: allow-list, envelopes, ACK and delete (#21), blobs and the 30-day delete (#22), push (#23), deployment (#25).

## Endpoints so far
| Endpoint | Signed | Purpose |
|---|---|---|
| `GET /health` (and `HEAD`) | no | `{"ok":true}` |
| `POST /v1/inbox` | yes, with the key it registers | Register this device's inbox |
| `POST /v1/pairing-slot` | yes, by the bundle's key (needs an inbox) | Initiator opens a pairing slot |
| `GET /v1/pairing-slot/{slot_id or code}` | **no** | Joiner reads the initiator's bundle |
| `POST /v1/pairing-slot/{slot_id}/reply` | yes, by the reply's key (needs an inbox) | Joiner posts its reply |
| `GET /v1/pairing-slot/{slot_id}/reply` | yes, by the key that opened the slot | Initiator reads the reply; this closes the slot |

### `POST /v1/inbox`
Body (JSON, at most 8 KiB):
```json
{ "signing_key": "<IKsig, base64url, 32 bytes>", "push_token": "<FCM token>" , "platform": "android" }
```
- `signing_key` must be the key in the `Maw-Key` header (otherwise `400 key_mismatch`). Signing the request with that key proves the device holds it.
- `push_token` is a string of visible ASCII (at most 4,096 characters) or `null` (no token yet). It is required.
- `platform` is `android` or `ios`. Unknown fields are ignored.

Answer: `201 {"inbox_id": "<22 characters>"}` for a new inbox, `200` with the same body when the same key registers again (a retry after a lost answer; the push token and platform are updated). The inbox ID is computed by the relay as `SHA-256("mawaddah/v1/inbox" || IKsig)[0..16]` (PROTOCOL.md section 3); the client never chooses it.

**Rate limit:** 5 new inboxes per IP address per hour (sliding hour), `429 rate_limited` after that, with a `Retry-After` header and `retry_after` (seconds) in the body. Registering an existing inbox again is not counted, and a refused attempt is not counted either (two first registrations of one key sent at the same moment may both count). IPv6 addresses count per /64 prefix (one home or phone network usually has a whole /64); an IPv4-mapped IPv6 address counts as its IPv4 address. A request without a readable `cf-connecting-ip` (not possible behind Cloudflare; possible behind another front or in some local setups) falls into one shared bucket `unknown`, so the limit fails closed: 5 per hour for all such requests together. One pairing attempt registers two inboxes (one per phone, fresh keys per attempt, PROTOCOL.md section 3), so two phones on one home network can make two full attempts in an hour and still have one registration spare.

### Pairing slots
The message flow is PROTOCOL.md section 4.5; the bundle and reply are sections 4.1 and 4.3. A slot lives **10 minutes** from its creation and accepts **one reply**. Bodies are at most 4 KiB. The relay checks each body's fields and sizes, stores only the known fields (unknown ones are dropped), and requires the body's `sig_pub` to be the signing key (`400 key_mismatch` otherwise). It also verifies the bundle signature; the reply signature covers the transcript hash and is checked by the initiator.

`POST /v1/pairing-slot`, body: the bundle. Answer `201 {"slot_id": "<22 characters>", "code": "<6 digits>", "expires_at": <Unix seconds>}`. The signing key must already have an inbox (`403 inbox_required`), so opening slots is limited by the inbox rate limit. One slot per key: the same key sending the same bundle again (a retry after a lost answer) gets `200` and the same slot; a different bundle gets `409 slot_conflict`, also after the slot was used, until it expires (keys are fresh per attempt, so a new attempt has a new key). The code is uniformly random, may start with zeros, and is unique among live slots. At most 100,000 slots are alive at once (10 % of the codes): beyond that, `503 slots_full`.

`GET /v1/pairing-slot/{handle}`, **unsigned**: `handle` is the 6-digit code or the 22-character slot ID. Answer `200 {"slot_id": "...", "bundle": {...}}` while nobody has replied, `409 slot_used` once someone has, `404 slot_not_found` for an expired, unknown or badly formed handle. **Lookup limit:** 5 failed code lookups (`404`) per IP address (IPv6: per /64, as for registrations) per sliding 10 minutes. A sixth code lookup in that time gets `429 rate_limited` with `Retry-After` **before** the code is looked up, so even the right code is refused until a failure is 10 minutes old; refused lookups are not counted. Successful lookups, `slot_used` answers, slot-ID lookups (128-bit IDs cannot be guessed) and handles that are neither are not counted.

`POST /v1/pairing-slot/{slot_id}/reply`, body: the reply. The signing key must have an inbox. Answer `201 {}` for the first reply. The same key sending the same reply again gets `200 {}`. Any other reply gets `409 slot_used`: the first one wins and the pair is locked (spec 5.2). A code in place of the slot ID gets `404 slot_not_found`.

`GET /v1/pairing-slot/{slot_id}/reply`, signed by the key that opened the slot (any other key gets `404 slot_not_found`). Answer `200 {"reply": null}` while waiting (poll it; push comes with #23), then `200 {"reply": {...}}` once. Reading the reply closes the slot: the relay erases the bundle and the reply at once. A second read gets `409 slot_used`, so if that answer is lost the initiator starts a new attempt.

After its 10 minutes a slot is deleted whole, whatever its state, and every route answers `404 slot_not_found` for it.

## Request signing
Every request except `GET /health` and `GET /v1/pairing-slot/{slot_id or code}` carries the four headers of PROTOCOL.md section 13 (`Maw-Key`, `Maw-Timestamp`, `Maw-Nonce`, `Maw-Signature`). The relay checks, in this order:
1. Body size (`413 body_too_large` before anything else).
2. All four headers present (`auth_missing`) and well formed (`auth_malformed`): canonical base64url of the exact length, a decimal timestamp without leading zeros.
3. Timestamp within ±300 s of the relay clock (`clock_skew`; the body also has `server_time` in Unix seconds, so the app can tell the person their phone's clock is wrong).
4. Ed25519 signature over the signing input (`bad_signature`). The path line is the path and query as the runtime parsed the URL, so clients send paths that need no normalising: only the characters of base64url IDs, digits and `/?=&`, and no empty `?`.
5. Nonce not used by this key in the last 15 minutes (`nonce_reused`).

The vectors in `packages/mawaddah_protocol/test/vectors/relay_signing.json` are made by the Dart package and checked by these tests, so the relay and the Dart client build the same signing input.

## Errors
Every error is JSON `{"error": "<code>"}` with `cache-control: no-store`; a few codes add one documented field. Nothing else about a failure is returned (no stack traces, no internal messages). The codes are stable: clients may rely on them.

| Status | Code | Meaning |
|---|---|---|
| 400 | `malformed_request` | The body is not the JSON the endpoint expects |
| 400 | `key_mismatch` | The body names a key other than the signing key |
| 403 | `inbox_required` | The signing key has no inbox yet (pairing-slot routes) |
| 404 | `slot_not_found` | No live pairing slot with that code or ID (unknown, expired, or not yours) |
| 401 | `auth_missing` | A signing header is missing |
| 401 | `auth_malformed` | A signing header is badly formed |
| 401 | `clock_skew` | Timestamp more than 300 s from the relay clock; adds `server_time` |
| 401 | `bad_signature` | The signature does not verify |
| 401 | `nonce_reused` | The nonce was already used (a replay) |
| 404 | `not_found` | No such route |
| 405 | `method_not_allowed` | Wrong method; the `Allow` header lists the right ones |
| 409 | `inbox_conflict` | Another key already holds this inbox ID (not expected to happen) |
| 409 | `slot_used` | The pairing slot already has a reply (or it was read) |
| 409 | `slot_conflict` | This key already opened a slot with another bundle |
| 413 | `body_too_large` | Body over the endpoint's limit |
| 429 | `rate_limited` | Too many registrations, or failed code lookups, from this network; adds `retry_after` |
| 500 | `internal_error` | Something failed inside the relay |
| 503 | `slots_full` | Too many pairing slots are open right now; try again in a few minutes |

## What is stored
| Durable Object | Named by | Holds | Deleted |
|---|---|---|---|
| `DeviceObject` | the inbox ID | nonces of the last 15 minutes; the inbox: signing key, push token, platform | nonces after 15 minutes (alarm); an object with no inbox and no nonce deletes all its storage; the inbox itself by `DELETE /v1/inbox/{id}` (#21) |
| `RegistrationLimitObject` | `SHA-256("mawaddah/v1/rate-limit\n" + bucket)`, bucket = the IPv4 address or the IPv6 /64 | the times of the registrations of the last hour | each time after one hour; when none is left, all its storage (alarm) |
| `LookupLimitObject` | the same hash of the bucket (another namespace) | the times of failed code lookups of the last 10 minutes | each time after 10 minutes; when none is left, all its storage (alarm) |
| `PairingSlotsObject` | one object, `pairing-slots` | per live slot: slot ID, code, the two signing keys, expiry, and the bundle and reply (public keys only) until the initiator reads the reply | bundle and reply when the reply is read; the whole slot 10 minutes after creation (alarm, and on every access); when none is left, all its storage |

No names, profile data, request logs or raw IP addresses are stored. The IP address is used only to pick the rate-limit object; its name is a hash, which hides the address from a casual look but is **not** anonymous (all IPv4 addresses can be hashed and compared). Its times are deleted about one hour after its last registration (10 minutes after the last failed code lookup), by an alarm (alarms can run late or retry; the spec's bound is 24 hours). A secret key (HMAC) for these names would not hide the address from the only parties who see them, Cloudflare and the relay operator, who see the address at the edge anyway; it can be added with the deployment (#25) if wanted.

**Fresh keys:** a request with a valid signature from a key that has no inbox still records its nonce, so it creates a small `DeviceObject` that deletes itself after 15 minutes. Making many keys therefore costs the relay storage and requests before any per-IP limit applies. Planned for #25: a Cloudflare rate-limiting rule per IP at the edge.

## No request logs
The relay writes nothing to the console and keeps no request logs (spec 4.5). `wrangler.toml` sets `[observability] enabled = false`. When deploying (#25), also check in the Cloudflare dashboard, for the Worker:
- **Workers Logs / Observability:** off.
- **Logpush:** no job for this Worker (it would export request fields including IP addresses).
- **Tail Workers:** none attached.

Cloudflare itself still sees IP addresses at its edge (PRIVACY.md, third parties).

## Develop and test
```sh
npm ci
npm test          # unit tests (Node, in-memory SQLite, fake clock) + the Worker in wrangler's local runtime
npm run lint
npm run typecheck # src with Workers types, test/ with Node types
npm run dev       # local relay at http://localhost:8787
```
- Unit tests run the same SQL as the Durable Objects on Node's built-in `node:sqlite`, with a fake clock, so nonce expiry, slot expiry and the rate-limit windows are tested without waiting.
- The pairing tests use the bundles and replies of `packages/mawaddah_protocol/test/vectors/pairing.json` (made by the Dart package), so the relay accepts exactly what the Dart code sends and returns it unchanged.
- `test/worker.integration.test.ts` starts the real Worker with its Durable Objects (`unstable_startWorker` from wrangler, no network, nothing persisted) and talks to it over HTTP.
- Not covered automatically: Durable Object alarms firing (they need real minutes to pass), and anything on Cloudflare's network (needs #25).
