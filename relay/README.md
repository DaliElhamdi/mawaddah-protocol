# Mawaddah relay

The **blind relay** (spec 4.5): a Cloudflare Worker with SQLite-backed Durable Objects. It carries sealed envelopes between the two phones of a pair and cannot open them. The wire format is in [`../PROTOCOL.md`](../PROTOCOL.md); what the relay can see is in [`../PRIVACY.md`](../PRIVACY.md).

> **Status: built; deployment set up in #25.** Done: request signing, nonce memory, inbox registration and its rate limit (protocol #19), pairing slots (#20), allow-list, envelopes, ACK, push token and inbox delete (#21), blobs and the 30-day delete (#22), FCM wake-ups (#23), staging and production deploys (#25, see [Deploy](#deploy)).

## Endpoints so far
| Endpoint | Signed | Purpose |
|---|---|---|
| `GET /health` (and `HEAD`) | no | `{"ok":true}` |
| `POST /v1/inbox` | yes, with the key it registers | Register this device's inbox |
| `POST /v1/pairing-slot` | yes, by the bundle's key (needs an inbox) | Initiator opens a pairing slot |
| `GET /v1/pairing-slot/{slot_id or code}` | **no** | Joiner reads the initiator's bundle |
| `POST /v1/pairing-slot/{slot_id}/reply` | yes, by the reply's key (needs an inbox) | Joiner posts its reply |
| `GET /v1/pairing-slot/{slot_id}/reply` | yes, by the key that opened the slot | Initiator reads the reply; this closes the slot |
| `POST /v1/inbox/{id}/allow` | yes, by the owner | Allow the partner's key to deposit (exactly one key) |
| `PUT /v1/inbox/{id}/envelopes` | yes, by the allowed sender | Deposit one sealed envelope |
| `GET /v1/inbox/{id}/envelopes?after=cursor` | yes, by the owner | Fetch waiting envelopes |
| `POST /v1/inbox/{id}/ack` | yes, by the owner | Delete every envelope up to a cursor |
| `PUT /v1/inbox/{id}/blobs/{blob_id}?size=…&chunk=…` | yes, by the allowed sender | Upload one chunk of an encrypted attachment |
| `GET /v1/inbox/{id}/blobs/{blob_id}?chunk=…` | yes, by the owner | Download one chunk of a complete blob |
| `DELETE /v1/inbox/{id}/blobs/{blob_id}` | yes, by the owner or the allowed sender | Delete a blob (the owner's ACK, or an upload given up) |
| `POST /v1/inbox/{id}/push-token` | yes, by the owner | Replace the push token |
| `DELETE /v1/inbox/{id}` | yes, by the owner | Delete the inbox, its allowed sender, its envelopes and its blobs |

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

`GET /v1/pairing-slot/{handle}`, **unsigned**: `handle` is the 6-digit code or the 22-character slot ID. Answer `200 {"slot_id": "...", "bundle": {...}}` while nobody has replied, `409 slot_used` once someone has, `404 slot_not_found` for an expired, unknown or badly formed handle. **Lookup limit:** 5 code lookups that find no open slot (`404` or `409`) per IP address (IPv6: per /64, as for registrations) per sliding 10 minutes. Each code lookup is counted **before** the code is looked up, in one call to that address's limit object, and is given back if it finds an open slot. So parallel guesses cannot get past the limit, and once it is reached even the right code gets `429 rate_limited` with `Retry-After` until a counted lookup is 10 minutes old. Refused lookups are not counted. Because a lookup is counted while it runs, at most 5 code lookups from one address can be in flight at once. Slot-ID lookups (128-bit IDs cannot be guessed) and handles that are neither a code nor an ID are not counted. Phones behind one carrier-grade NAT address share the limit, so someone on the same address who makes 5 wrong guesses blocks code lookups there for up to 10 minutes; the QR path (by slot ID) is not affected.

`POST /v1/pairing-slot/{slot_id}/reply`, body: the reply. The signing key must have an inbox. Answer `201 {}` for the first reply. The same key sending the same reply again gets `200 {}`. Any other reply gets `409 slot_used`: the first one wins and the pair is locked (spec 5.2). A code in place of the slot ID gets `404 slot_not_found`.

`GET /v1/pairing-slot/{slot_id}/reply`, signed by the key that opened the slot (any other key gets `404 slot_not_found`). Answer `200 {"reply": null}` while waiting (poll it; the relay sends no push for a reply), then `200 {"reply": {...}}` once. Reading the reply closes the slot: the relay erases the bundle and the reply at once (spec 4.5). A second read gets `409 slot_used`, so if that answer is lost the attempt is lost and the initiator starts a new one.

After its 10 minutes a slot is deleted whole, whatever its state, and every route answers `404 slot_not_found` for it.

### Inbox routes
The **owner** of an inbox is the key it was registered with: the inbox ID in the path must be the one computed from the `Maw-Key` header, otherwise `403 not_inbox_owner`. A path ID that is not 22 base64url characters of 16 bytes, or an inbox that does not exist (never registered, or deleted), gets `404 inbox_not_found`. JSON bodies are at most 8 KiB; unknown fields are ignored.

`POST /v1/inbox/{id}/allow`, by the owner, body `{"sender_key": "<partner's IKsig, base64url, 32 bytes>"}` (PROTOCOL.md section 4.5 step 4). From then on only that key can deposit. Exactly one key per inbox: `201 {}` the first time, `200 {}` for the same key again (a retry), `409 allow_conflict` for any other key. The pair stays fixed until the inbox is deleted (keys are fresh for each pairing, so a new pair means new inboxes).

`PUT /v1/inbox/{id}/envelopes`, by the **allowed sender** (it needs no inbox of its own here), body: the sealed envelope as raw bytes (PROTOCOL.md section 7), 1 to 65,536 bytes (`413 body_too_large` above). Header `Maw-Wake: 0` or `1` is required: `1` asks for a push to the inbox owner (spec 8.7; see [Wake-ups](#wake-ups-fcm)). The header is not part of the signature (section 13 signs the method, path, body, time and nonce); TLS protects it in transit. Whoever terminates TLS (Cloudflare) could flip it, and so could the relay, which decides on pushes anyway: that causes a missed or an extra wake-up, never access to content (a push carries none, and the app must stay silent when a wake-up brings nothing to show). Answer `201 {}`. A key that is not the allowed sender (also before any allow) gets `403 sender_not_allowed`; just after pairing this can mean the partner has not finished step 4 yet, so the sender retries with its back-off. The relay does not read the envelope. A missing inbox gets `404 inbox_not_found` and an existing one `403`, so a key holder can tell whether an inbox ID exists; inbox IDs are 128-bit hashes of per-pairing keys that only the partner learns, so this tells nobody anything new. **Quota:** at most 100 MiB of envelopes wait in one inbox; a deposit that would pass it gets `409 inbox_full` (retry later: the owner's next ACK frees space).

`GET /v1/inbox/{id}/envelopes` or `…/envelopes?after=<cursor>`, by the owner. Answer:
```json
{ "envelopes": [ { "cursor": "17", "body": "<envelope, base64url>" } ], "more": false }
```
Envelopes come in deposit order, after `cursor` (from the start without `after`). A page holds at most 100 envelopes and at most 1 MiB of envelope bytes, but always at least one envelope when any is waiting; `more` says whether others wait after the last one. The cursor is opaque to clients: a decimal string that increases with every deposit and is never handed out twice in an inbox, also after the envelopes before it were deleted. `after` must be a cursor the relay gave (decimal, no leading zeros) or `0`; anything else in the query gets `400 malformed_request`, and a number above the last cursor handed out in this inbox gets `400 invalid_cursor` (resuming there would skip the envelopes deposited up to it). Like `DELETE`, this route takes no body (`413 body_too_large` for any).

`POST /v1/inbox/{id}/ack`, by the owner, body `{"cursor": "<cursor>"}`. Deletes at once, from storage, **every** envelope up to and including that cursor (the ACK is cumulative, PROTOCOL.md section 17). Answer `200 {}`, also when nothing was left to delete (a repeated ACK is harmless). A cursor above the last one handed out gets `400 invalid_cursor` and deletes nothing, so an ACK cannot delete envelopes the device has not fetched yet.

`POST /v1/inbox/{id}/push-token`, by the owner, body `{"push_token": "<FCM token>"}` or `{"push_token": null}`, with the same rules as at registration. Answer `200 {}`.

`DELETE /v1/inbox/{id}`, by the owner, no body. Deletes the inbox (signing key, push token, platform), its allowed sender, every waiting envelope and every blob. It also resets the inbox's cursor count, so nothing stored tells how many envelopes it ever received. Used by unpair and "Delete all data". Answer `200 {}`, also when the inbox was already gone, so a retry after a lost answer succeeds. The key's nonces are kept until they expire (15 minutes), so a request captured before the delete cannot be replayed to register the inbox again; then the device object deletes all of its storage. A device deletes **only its own** inbox: envelopes it already sent wait in the partner's inbox, where its key stays the allowed sender, until the partner's phone fetches and acknowledges them or deletes its own inbox, and at most 30 days.

### Blobs
Photos and voice notes travel as encrypted blobs (PROTOCOL.md section 12): the sender encrypts the file with its own key, uploads the ciphertext into the **receiving** phone's inbox, then sends the blob ID and key inside an envelope. The relay sees only the blob ID, its size and the times. The spec's `/v1/blob/{id}` is placed under the inbox (`/v1/inbox/{id}/blobs/{blob_id}`), so the signed path names the inbox, the same allowed-sender and owner rules apply, the quota is per inbox and `DELETE /v1/inbox/{id}` takes the blobs with it.

- `blob_id`: 16 random bytes chosen by the sender, as 22 base64url characters (anything else gets `404 blob_not_found`). IDs are per inbox.
- **Size and chunks:** a blob is 1 byte to **10 MiB** (10,485,760 bytes) and travels in chunks of **1 MiB** (1,048,576 bytes; the last one shorter), at most 10. The chunk size is the relay's; it has nothing to do with the 64 KiB secretstream chunks inside the ciphertext. A Durable Object SQLite value holds at most 2 MB, so each chunk is one row.

`PUT /v1/inbox/{id}/blobs/{blob_id}?size=<bytes>&chunk=<index>`, by the **allowed sender**, body: the chunk's raw bytes. The query is exactly these two decimal numbers in this order, no leading zeros (anything else `400 malformed_request`). `size` above 10 MiB gets `413 blob_too_large`; a body over 1 MiB gets `413 body_too_large`; an index past the last chunk, or a body that is not exactly that chunk's length, gets `400 malformed_request`. Chunks go **in order** from 0:
- Chunk 0 creates the blob and reserves its whole `size` in the inbox's **blob quota of 100 MiB** (complete or not); a blob that would pass it gets `413 blob_quota_exceeded` (retry later: the owner deletes blobs once it has them, and everything goes after 30 days). The blob quota is separate from the 100 MiB of envelopes.
- The next chunk in order: `201 {}`.
- A chunk already stored, with the same bytes: `200 {}` (a retry after a lost answer).
- A chunk already stored with other bytes, or another `size` than the blob was created with: `409 blob_conflict`. A stored blob never changes.
- A chunk after the next one expected (or any chunk but 0 for a blob the relay does not have): `409 chunk_out_of_order` with `next_chunk`, the index to send next. An app that restarts an upload sends the chunk it believes is next and follows `next_chunk`.
- Not the allowed sender: `403 sender_not_allowed`; no inbox: `404 inbox_not_found`.

Upload every chunk before depositing the envelope that names the blob, so the receiver never sees an incomplete one, and never upload a chunk of that blob again once the envelope is deposited: the receiver may already have deleted it, and a chunk 0 would then create a new blob that holds quota until its 30 days pass.

`GET /v1/inbox/{id}/blobs/{blob_id}?chunk=<index>`, by the owner, no body. Answer `200` with the chunk's raw bytes, `content-type: application/octet-stream`, `cache-control: no-store`, and the header `Maw-Blob-Size` (the blob's size, so the client knows how many chunks to fetch). A blob still being uploaded gets `409 blob_incomplete`; an unknown, deleted or expired one `404 blob_not_found`; an index past the last chunk `400 malformed_request`.

`DELETE /v1/inbox/{id}/blobs/{blob_id}`, no body, by:
- the **owner**, once it has the whole file: this is the blob's ACK (spec 4.5: deleted after ACK), and it frees the quota at once;
- the **allowed sender**, for an upload it gave up (for example the message was deleted before it was sent). It can also delete a finished blob the receiver has not fetched; that is no more than it could do by never uploading it.

Anyone else gets `403 sender_not_allowed`. Answer `200 {}`, also when the blob was already gone.

### The 30-day delete
Every envelope and every blob is **hard-deleted 30 days after it was stored** (a blob: after its first chunk; a slow upload does not extend it), whether or not it was fetched (spec 4.5). A blob can therefore expire between two chunk downloads (`404 blob_not_found`). Each read and write of an inbox first deletes what has passed 30 days, so nothing older is ever handed out or counted in a quota, even when an alarm runs late. The device object's alarm is also set, whenever something is stored, for the first moment something expires (a nonce after 15 minutes, an envelope or blob after 30 days), so the delete happens even if nobody uses the inbox again. The inbox itself (keys, push token, allowed sender) stays until `DELETE /v1/inbox/{id}`, with no time limit. "Deleted" means deleted from the object's live SQLite storage: Cloudflare keeps point-in-time recovery for SQLite-backed Durable Objects over the last 30 days, which the relay does not control (it holds only the same ciphertext).

## Wake-ups (FCM)
After a deposit with `Maw-Wake: 1` **is stored**, the relay sends the inbox's phone one Firebase Cloud Messaging (FCM) HTTP v1 message (spec 4.5, 8.7). Nothing is sent for `Maw-Wake: 0`, for a refused deposit, when the inbox has no push token, or when the relay has no service account. The message is always exactly this, with only the token changing:

```json
{"message":{"token":"<the inbox's push token>","data":{"t":"s"},"android":{"priority":"HIGH","collapse_key":"s"}}}
```

- A **data message** (no `notification` block, so Android shows nothing by itself), **high priority** so a sleeping phone wakes, data exactly `{"t":"s"}` ("sync"). No content, inbox ID, sender, count or time. The phone syncs, decrypts, and builds its own notification (spec 8.5); if nothing new arrives it must stay silent.
- **Collapse key `s`:** while the phone is offline FCM keeps only the newest wake-up, so a phone that comes back gets one, not one per envelope.
- **The answer does not wait.** The deposit is answered `201` first; the push runs afterwards (`waitUntil`). A push that fails is not retried and never changes the deposit's answer: the phone also syncs when the app opens.
- **Unregistered token:** if FCM answers `404` with error code `UNREGISTERED` (app uninstalled, data cleared, token replaced), the relay deletes that push token from the inbox, unless the phone sent a new one meanwhile. Wake-ups stop until the phone sends a token again (`POST /v1/inbox/{id}/push-token`), so the app re-sends its current token when it opens. Other FCM errors (quota, server, wrong project) change nothing.
- **Access token:** the Worker signs a Google service-account JWT itself (RS256, scope `firebase.messaging` only, one hour) and exchanges it at `https://oauth2.googleapis.com/token`. The access token is kept in the Worker's memory and asked for again 5 minutes before Google says it expires; wake-ups at the same moment share one request. If FCM refuses the token (`401`), the relay gets a new one and tries once more.
- **Google's addresses are fixed in the code** (`oauth2.googleapis.com`, `fcm.googleapis.com`); the `token_uri` in the key file is ignored, so a changed secret cannot send tokens or signed assertions anywhere else.
- **iOS:** an iOS registration is sent the same message, which does not wake an iPhone yet (FCM ignores the Android block; waking an iPhone needs APNs settings that come with iOS support, spec 4.8, v1.1).

**Setup (owner, once per environment):** in the Firebase project, use a **dedicated service account with only the "Firebase Cloud Messaging API Admin" role**, not the default `firebase-adminsdk` account the Firebase console offers (that one has broad roles on the whole project). In the Google Cloud console for the project: *IAM & Admin → Service accounts → Create service account* (e.g. `mawaddah-relay-push`), give it that one role, then *Keys → Add key → JSON*. Store the key as a Worker secret, then delete the file (and empty the trash):

```sh
npx wrangler secret put FCM_SERVICE_ACCOUNT < service-account.json
```

Use the `< file` form: pasting a multi-line JSON key at the prompt may store only its first line. The relay reads only `type`, `project_id`, `client_email`, `private_key_id` and `private_key` from it. Without the secret, or with a file that is not a service-account key, the relay works and sends **no** wake-ups, and says nothing (it logs nothing): after setting the secret, check on staging that a deposit with `Maw-Wake: 1` wakes a phone. The Worker never sends the key anywhere and never logs it; Google receives only the signed assertion. With the one role above, a leaked key lets someone send pushes through the project to the app's phones (content-free wake-ups: at worst a battery drain and an empty sync); a key of a broader account would give much more. Revoke a leaked key in the Google Cloud console and set a new one.

**Cost:** FCM messages are free. Each wake-up is one or two outbound requests from the Worker (FCM, plus a token request about once an hour per Worker instance), counted in the Worker's subrequests and CPU time.

## Deploy
Two environments, two separate Workers with separate Durable Object storage (staging data never reaches production):

| | Worker | Address | Deployed by |
|---|---|---|---|
| staging | `mawaddah-relay-staging` | `https://mawaddah-relay-staging.<account>.workers.dev` | every change to `relay/` merged into `main`, or *Actions → deploy-relay → Run workflow* on `main` |
| production | `mawaddah-relay` | `https://mawaddah-relay.<account>.workers.dev` | a final release tag `vX.Y.Z` (no suffix such as `-dev.1`) that is on `main` |

`.github/workflows/deploy-relay.yml` runs lint, type-check and the tests, then `wrangler deploy --env <name>`, then checks `GET /health` on the address wrangler printed. It starts only on `push` (never on a pull request, so a fork cannot reach the secrets), only in `DaliElhamdi/mawaddah-protocol`, one deploy at a time per environment. It also warns (it does not fail) when `FCM_SERVICE_ACCOUNT` is not set on the Worker.

**One-command deploy by hand** (needs the same two variables as the workflow):
```sh
cd relay && npm ci
CLOUDFLARE_ACCOUNT_ID=<account id> CLOUDFLARE_API_TOKEN=<token> npm run deploy:staging      # or deploy:production
curl https://mawaddah-relay-staging.<account>.workers.dev/health    # {"ok":true,...}
```

**Owner setup, once** (also in the private repository's `docs/owner-setup.md`, Phase 1):
1. A Cloudflare account; in *Workers & Pages* choose the account's `workers.dev` subdomain (the first time only; the deploy fails without it and says so).
2. An API token, limited to this one account: the *Edit Cloudflare Workers* template is enough (Workers Scripts: Edit, plus the read permissions the template adds). Durable Objects need nothing more. Do not use the Global API Key.
3. Repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` in the public repository (done 2026-11-10).
4. Per environment, when you want wake-ups: the FCM secret ([Wake-ups](#wake-ups-fcm)): `npx wrangler secret put FCM_SERVICE_ACCOUNT --env staging < service-account.json` (and `--env production`). Secrets belong to one Worker, so each environment needs its own.
5. Optional: *Settings → Environments → production* in GitHub, with *Required reviewers*, so a tag waits for your click before it goes live.

**Things to know**
- `wrangler.toml` repeats the Durable Object bindings and migrations in each environment, because wrangler does not inherit them. `test/wrangler_config.test.ts` fails if an environment drifts from the top level. Migrations are append-only: a new class needs a new tag, added at the top level and in both environments.
- A Durable Object migration is applied when the Worker is deployed; there is no automatic rollback of a migration. Roll back code by deploying an earlier tag or commit. Do not rename or delete a class that has stored data.
- Production is deployed from a tag, so cut the tag only when staging has run the same commit (the staging deploy happens when the change reaches `main`).
- `workers.dev` addresses are not on a zone of yours, so Cloudflare's zone-level rules (WAF custom rules, rate-limiting rules) cannot be attached to them. The per-IP registration limit lives in the Worker (above); the cost and abuse limit noted in #19 (any valid signature from a fresh key creates a small object that lives 15 minutes) stays open until the relay has its own domain, where an edge rate-limiting rule can go in front. Until then watch the Worker's request graph in the dashboard.

## Load test
`loadtest/loadtest.mjs` (Node 22, no dependencies) plays one couple against a running relay:
```sh
npm run dev &                                                    # a local relay, or use a deployed one
node loadtest/loadtest.mjs http://127.0.0.1:8787                 # local
node loadtest/loadtest.mjs https://mawaddah-relay-staging.<account>.workers.dev --requests 300 --concurrency 10
```
It registers two inboxes (A sends, B receives), allows A, then measures 300 requests each of `GET /health`, signed deposits of 1 KiB envelopes (`Maw-Wake: 0`, so no push), paged fetch with a cumulative ACK for every page, and polls of the then empty inbox; at the end it deletes both inboxes. It prints requests per second and p50, p95, p99 and max latency, plus the HTTP status counts, and exits non-zero if any request failed. `--json` prints the same as JSON.
- **Run it from your own machine or a runner, never against production**: it refuses a non-local address that is not a `-staging.` Worker unless you add `--allow-production`.
- **Registration limit:** a run registers 2 inboxes and the relay allows 5 per IP per hour. Run again at once with the same `--seed <text>` (registering the same key again is free). After a `429`, wait or change address.
- All traffic of one run goes to one inbox, so one Durable Object: that is what one couple does. It does not show how many couples one Worker carries; Durable Objects of different inboxes run in parallel. The numbers include the network from where you run it.
- Free-plan accounts allow 100,000 Worker requests and 100,000 Durable Object rows written per day; a default run uses about 1,500 requests and a few thousand rows.

## Monthly cost
An estimate for the Phase 1 report, from Cloudflare's published prices as read on 2026-11-12 ([Workers](https://developers.cloudflare.com/workers/platform/pricing/), [Durable Objects](https://developers.cloudflare.com/durable-objects/platform/pricing/)) and the assumptions below. It is a model, not a measurement: replace it with the dashboard's numbers after the first month of real use.

| | Free plan | Workers Paid plan |
|---|---|---|
| Price | $0 | $5 a month per account (both Workers) |
| Worker requests | 100,000 a day; 10 ms CPU per request | 10 million a month included, then $0.30 per million |
| DO requests | 100,000 a day | 1 million a month included, then $0.15 per million |
| DO rows written | 100,000 a day | 50 million a month included, then $1.00 per million |
| DO rows read | 5 million a day | 25 billion a month included |
| DO stored data | 5 GB in all | 5 GB-month included, then $0.20 per GB-month |

**Assumptions (per couple, per day):** 100 chat messages, each costing 3 requests (deposit by one phone, fetch and ACK by the other), plus 20 app-opens per phone that poll once: about 340 requests, so about 10,000 a month. Each request is one Worker request and one Durable Object request, and writes about 4 rows (its nonce, the envelope or cursor change, and their later deletes). Photos as in [Storage choice and cost](#storage-choice-and-cost).

| Couples | Requests a month | Rows written a month | Plan | Estimate |
|---|---|---|---|---|
| 10 | 0.1 million | 0.4 million | Free | $0 |
| 50 | 0.5 million | 2 million | Free is near its rows-written limit (about 70 couples); use Paid before launch | $0 to $5 |
| 1,000 | 10 million | 40 million | Paid | $5 + DO requests 9 million × $0.15 = about $1.35 → **about $6.50**, plus photos: the 1,000-couple example above adds about $5.40 for blobs → **about $12** |

Staging is a second Worker on the same account, so the $5 is paid once; its traffic is negligible. FCM is free. Not counted: Durable Object duration (400,000 GB-s a month included; these requests are milliseconds long) and the `workers.dev` address (free). The free plan's 10 ms of CPU per request has not been measured here (Ed25519 verification plus SQL): if a staging run shows error 1102 (CPU limit exceeded), use the Paid plan, which has no per-request limit this small.

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
| 400 | `invalid_cursor` | The cursor is above the last one this inbox handed out |
| 404 | `blob_not_found` | No blob with that ID in this inbox (never uploaded, deleted, older than 30 days, or a badly formed ID) |
| 403 | `inbox_required` | The signing key has no inbox yet (pairing-slot routes) |
| 403 | `not_inbox_owner` | The inbox in the path is not the signing key's own |
| 403 | `sender_not_allowed` | The signing key may not deposit into this inbox (not the allowed sender, or none allowed yet) |
| 404 | `slot_not_found` | No live pairing slot with that code or ID (unknown, expired, or not yours) |
| 404 | `inbox_not_found` | No inbox with that ID (never registered, deleted, or a badly formed ID) |
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
| 409 | `allow_conflict` | This inbox already allows another sender key |
| 409 | `inbox_full` | 100 MiB of envelopes are already waiting in this inbox; try again later |
| 409 | `blob_conflict` | The blob already has this chunk with other bytes, or another size |
| 409 | `chunk_out_of_order` | Chunks go in order; adds `next_chunk`, the index the relay expects |
| 409 | `blob_incomplete` | The blob is still being uploaded |
| 413 | `body_too_large` | Body over the endpoint's limit |
| 413 | `blob_too_large` | The blob's `size` is over 10 MiB |
| 413 | `blob_quota_exceeded` | This new blob would pass the inbox's 100 MiB of blobs; try again later |
| 429 | `rate_limited` | Too many registrations, or failed code lookups, from this network; adds `retry_after` |
| 500 | `internal_error` | Something failed inside the relay |
| 503 | `slots_full` | Too many pairing slots are open right now; try again in a few minutes |

## What is stored
| Durable Object | Named by | Holds | Deleted |
|---|---|---|---|
| `DeviceObject` | the inbox ID | nonces of the last 15 minutes; the inbox: signing key, push token, platform; the one allowed sender key; the waiting envelopes (bytes, size, deposit time, cursor); the blobs (ID, declared size, chunks stored, time of the first chunk, and the chunk bytes) | nonces after 15 minutes; each envelope when acknowledged; each blob when deleted by the owner or the sender; envelopes and blobs 30 days after they were stored, fetched or not (on every access, and by the alarm); the push token when FCM calls it unregistered; the inbox, allowed sender, envelopes and blobs by `DELETE /v1/inbox/{id}`; an object with nothing left (no inbox, envelope, blob, allowed sender or live nonce) deletes all its storage |
| `RegistrationLimitObject` | `SHA-256("mawaddah/v1/rate-limit\n" + bucket)`, bucket = the IPv4 address or the IPv6 /64 | the times of the registrations of the last hour | each time after one hour; when none is left, all its storage (alarm) |
| `LookupLimitObject` | the same hash of the bucket (another namespace) | the times of code lookups of the last 10 minutes that found no open slot | each time after 10 minutes; every counted lookup sets the alarm (also one given back), and when none is left the alarm deletes all its storage |
| `PairingSlotsObject` | one object, `pairing-slots` | per live slot: slot ID, code, the two signing keys, expiry, and the bundle and reply (public keys only) until the initiator reads the reply | bundle and reply when the reply is read; the whole slot 10 minutes after creation (alarm, and on every access); when none is left, all its storage |

No names, profile data, request logs or raw IP addresses are stored. The IP address is used only to pick the rate-limit object; its name is a hash, which hides the address from a casual look but is **not** anonymous (all IPv4 addresses can be hashed and compared). Its times are deleted about one hour after its last registration (10 minutes after the last counted code lookup), by an alarm (alarms can run late or retry; the spec's bound is 24 hours). A secret key (HMAC) for these names would not hide the address from the only parties who see them, Cloudflare and the relay operator, who see the address at the edge anyway; it can be added with the deployment (#25) if wanted.

**Fresh keys:** a request with a valid signature from a key that has no inbox still records its nonce, so it creates a small `DeviceObject` that deletes itself after 15 minutes. Making many keys therefore costs the relay storage and requests before any per-IP limit applies. The same holds for body size: a blob chunk `PUT` is read (up to 1 MiB) before its signature, and before the sender check, is verified. Planned for #25: a Cloudflare rate-limiting rule per IP at the edge.

## Storage choice and cost
Envelopes and blobs are stored in the receiving device's **SQLite-backed Durable Object**, not in R2:
- One place per inbox: the quota check and the write happen in one single-threaded object, so they cannot race; `DELETE /v1/inbox/{id}` and the 30-day delete are plain SQL in that object, with no listing of an external bucket.
- No extra service, binding or account setup, and nothing for the operator to keep in step (R2 lifecycle rules work on whole days and know nothing about inboxes).
- Limits fit: a SQLite value holds at most 2 MB (hence 1 MiB chunks), and an object holds up to 10 GB on the paid plan (1 GB on the free plan) against at most 200 MiB per inbox (100 MiB of envelopes + 100 MiB of blobs).

Cost (Cloudflare's published prices and limits as read in November 2026, Workers Paid plan; they change, so check the linked pages before relying on them; [Durable Objects](https://developers.cloudflare.com/durable-objects/platform/pricing/), [R2](https://developers.cloudflare.com/r2/pricing/)):

| | Durable Object SQLite (chosen) | R2 Standard |
|---|---|---|
| Stored data | 5 GB-month included, then $0.20 per GB-month | 10 GB-month free, then $0.015 per GB-month |
| Writes | 50 million rows/month included, then $1.00 per million (deletes and `setAlarm` count as writes) | 1 million Class A operations free, then $4.50 per million |
| Reads | 25 billion rows/month included, then $0.001 per million | 10 million Class B operations free, then $0.36 per million |

Stored data is what waits on the relay, not what passes through it: an attachment is deleted as soon as the receiver has it. One 3 MiB photo costs about 20 rows written in all (3 chunks, the blob row, their index entries, then the deletes) and about 3 rows read to download. **Example:** 1,000 couples, each sending 20 photos of 3 MiB a day: about 60 GiB a day pass through. If each photo waits 12 hours on average, about 32 GB wait at any time: about $5.40 a month above the 5 GB included (R2: about $0.35). About 12 million rows written a month, inside the 50 million included. Both choices also pay the same Workers and Durable Object request and duration charges per call (each chunk is one request), not counted here. In the worst case one inbox holds 200 MiB for 30 days: about $0.04 a month (R2: about $0.003). If stored blobs ever cost more than the simplicity is worth, they can move to R2 behind the same routes (the API does not depend on it). On the free plan, Durable Objects storage is capped at 5 GB for the account.

## No request logs
The relay writes nothing to the console and keeps no request logs (spec 4.5). `wrangler.toml` sets `[observability] enabled = false` at the top level and in both environments (`test/wrangler_config.test.ts` checks it, and that no variables, routes, tail consumers or log push are set). The dashboard can still turn things on that the file does not control, so after the first deploy of each Worker (*Workers & Pages → the Worker*) check:
- **Observability / Workers Logs:** off (no logs, no traces, no invocation logs).
- **Logpush:** no job for this Worker, and none at account level that covers it (it would export request fields including IP addresses).
- **Tail Workers:** none attached.
- **Account-level:** no Logpush or audit-style export that reads Worker requests; *Analytics* graphs (counts only) are fine.
- **Preview URLs:** off, or left alone: they are separate `*.workers.dev` addresses of the same code and storage.

Cloudflare itself still sees IP addresses at its edge (PRIVACY.md, third parties).

## Develop and test
```sh
npm ci
npm test          # unit tests (Node, in-memory SQLite, fake clock) + the Worker in wrangler's local runtime
npm run lint
npm run typecheck # src with Workers types, test/ with Node types
npm run dev       # local relay at http://localhost:8787
```
- Unit tests run the same SQL as the Durable Objects on Node's built-in `node:sqlite`, with a fake clock, so nonce expiry, slot expiry, the rate-limit windows and the 30-day delete (to the millisecond, and the next alarm time) are tested without waiting.
- The pairing tests use the bundles and replies of `packages/mawaddah_protocol/test/vectors/pairing.json` (made by the Dart package), so the relay accepts exactly what the Dart code sends and returns it unchanged.
- `test/worker.integration.test.ts` starts the real Worker with its Durable Objects (`unstable_startWorker` from wrangler, no network, nothing persisted) and talks to it over HTTP. It gives the Worker a throwaway service account (an RSA key made for the run) and intercepts every outbound `fetch` with a fake Google that checks the JWT signature, so wake-ups are tested without Firebase.
- `test/push.test.ts` tests the FCM sender with a fake `fetch` (the exact message, the JWT claims, the token cache, `UNREGISTERED`, failures) and the deposit route with a recording push sender.
- The Dart client (`HttpRelayClient`) is tested against this Worker too: `scripts/relay-integration.sh` (from the repository root) starts `wrangler dev` with empty storage, runs `packages/mawaddah_protocol/test/relay/relay_integration_test.dart` (both pairing paths, two sync engines chatting, pages, blobs, refusals, rate limits, delete), then stops it. It runs in `scripts/test.sh` and CI. The tests set `cf-connecting-ip` themselves so each has its own rate-limit bucket; the local runtime takes that header as given, Cloudflare's edge replaces it.
- `test/wrangler_config.test.ts` reads `wrangler.toml` as wrangler does and checks that staging and production have the same bindings and migrations as the top level, differently named Workers and observability off.
- Not covered automatically: Durable Object alarms firing (they need real minutes to pass; the tests check the time the alarm is set for and what the alarm's clean-up deletes), and anything on Cloudflare's network (the deploy workflow's health check and a manual staging run cover that).
