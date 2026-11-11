# Mawaddah relay

The **blind relay** (spec 4.5): a Cloudflare Worker with SQLite-backed Durable Objects. It carries sealed envelopes between the two phones of a pair and cannot open them. The wire format is in [`../PROTOCOL.md`](../PROTOCOL.md); what the relay can see is in [`../PRIVACY.md`](../PRIVACY.md).

> **Status: in progress, not deployed.** Done so far: request signing, nonce memory, inbox registration and its rate limit (protocol #19). Still to come: pairing slots (#20), allow-list, envelopes, ACK and delete (#21), blobs and the 30-day delete (#22), push (#23), deployment (#25).

## Endpoints so far
| Endpoint | Signed | Purpose |
|---|---|---|
| `GET /health` (and `HEAD`) | no | `{"ok":true}` |
| `POST /v1/inbox` | yes, with the key it registers | Register this device's inbox |

### `POST /v1/inbox`
Body (JSON, at most 8 KiB):
```json
{ "signing_key": "<IKsig, base64url, 32 bytes>", "push_token": "<FCM token>" , "platform": "android" }
```
- `signing_key` must be the key in the `Maw-Key` header (otherwise `400 key_mismatch`). Signing the request with that key proves the device holds it.
- `push_token` is a string of visible ASCII (at most 4,096 characters) or `null` (no token yet). It is required.
- `platform` is `android` or `ios`. Unknown fields are ignored.

Answer: `201 {"inbox_id": "<22 characters>"}` for a new inbox, `200` with the same body when the same key registers again (a retry after a lost answer; the push token and platform are updated). The inbox ID is computed by the relay as `SHA-256("mawaddah/v1/inbox" || IKsig)[0..16]` (PROTOCOL.md section 3); the client never chooses it.

**Rate limit:** 5 new inboxes per IP address per hour (sliding hour), `429 rate_limited` after that, with a `Retry-After` header and `retry_after` (seconds) in the body. Registering an existing inbox again is not counted, and a refused attempt is not counted either. IPv6 addresses count per /64 prefix (one home or phone network usually has a whole /64); an IPv4-mapped IPv6 address counts as its IPv4 address. One pairing attempt registers two inboxes (one per phone, fresh keys per attempt, PROTOCOL.md section 3), so two phones on one home network can make two full attempts in an hour and still have one registration spare.

## Request signing
Every request except `GET /health` and (from #20) `GET /v1/pairing-slot/{slot_id or code}` carries the four headers of PROTOCOL.md section 13 (`Maw-Key`, `Maw-Timestamp`, `Maw-Nonce`, `Maw-Signature`). The relay checks, in this order:
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
| 401 | `auth_missing` | A signing header is missing |
| 401 | `auth_malformed` | A signing header is badly formed |
| 401 | `clock_skew` | Timestamp more than 300 s from the relay clock; adds `server_time` |
| 401 | `bad_signature` | The signature does not verify |
| 401 | `nonce_reused` | The nonce was already used (a replay) |
| 404 | `not_found` | No such route |
| 405 | `method_not_allowed` | Wrong method; the `Allow` header lists the right ones |
| 409 | `inbox_conflict` | Another key already holds this inbox ID (not expected to happen) |
| 413 | `body_too_large` | Body over the endpoint's limit |
| 429 | `rate_limited` | Too many registrations from this network; adds `retry_after` |
| 500 | `internal_error` | Something failed inside the relay |

## What is stored
| Durable Object | Named by | Holds | Deleted |
|---|---|---|---|
| `DeviceObject` | the inbox ID | nonces of the last 15 minutes; the inbox: signing key, push token, platform | nonces after 15 minutes (alarm); an object with no inbox and no nonce deletes all its storage; the inbox itself by `DELETE /v1/inbox/{id}` (#21) |
| `RegistrationLimitObject` | `SHA-256("mawaddah/v1/rate-limit\n" + bucket)`, bucket = the IPv4 address or the IPv6 /64 | the times of the registrations of the last hour | each time after one hour; when none is left, all its storage (alarm) |

No names, profile data, request logs or IP addresses are stored. The IP address is used only to pick the rate-limit object; its name is a hash, which hides the address from a casual look but is **not** anonymous (all IPv4 addresses can be hashed and compared). Nothing about an IP address is kept more than one hour after its last registration.

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
- Unit tests run the same SQL as the Durable Objects on Node's built-in `node:sqlite`, with a fake clock, so nonce expiry and the rate-limit hour are tested without waiting.
- `test/worker.integration.test.ts` starts the real Worker with its Durable Objects (`unstable_startWorker` from wrangler, no network, nothing persisted) and talks to it over HTTP.
- Not covered automatically: Durable Object alarms firing (they need real minutes to pass), and anything on Cloudflare's network (needs #25).
