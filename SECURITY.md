# Security

## Reporting a vulnerability
Please report privately through this repository's **Security** tab ("Report a vulnerability"). Do not open a public issue for a security problem. Problems in the Mawaddah app (which is not public) are welcome through the same form.

Please test against a local relay (`relay/README.md`, "Develop and test"), never against a deployed relay or someone else's inbox. This is a small personal project: expect an acknowledgement and an honest answer, not a service-level guarantee. Fixes are released as new versions of this repository and named in `CHANGELOG.md`.

## Status
- Protocol v0.1.0. Nothing here has been independently reviewed yet. At least one independent review of this repository is planned before version 1.0.0; its findings will be tracked as issues.
- The relay is not deployed yet.
- The threat model below names which protections live in this repository (the protocol package and the relay, which you can check) and which live in the app (not public). App protections are marked **built** or **planned**.

## What the design protects
- **Content:** only the two paired phones can read what they send each other. Envelopes use the Double Ratchet with XChaCha20-Poly1305. Attachments are encrypted with a fresh key per file, and that key travels inside an envelope.
- **Authenticity:** each phone accepts envelopes only from the one partner key fixed at pairing, signed with Ed25519. The relay accepts deposits only from that key.
- **Forward secrecy and recovery:** keys change with every message and every turn of the conversation, so a key stolen today does not open recorded older traffic, and a passive thief loses access after the next turn.
- **Pairing:** the QR code carries a one-time secret. On the 6-digit-code path the safety-number comparison is required.

**Not protected:** that you use Mawaddah, and the metadata in `PRIVACY.md`; anything on a phone that is unlocked in someone else's hands or compromised; what your partner does with what they received; attackers with a future large quantum computer. Every primitive is a libsodium function, and every construction is a published one (pairing is X3DH, adapted as `PROTOCOL.md` section 4 explains). How they are put together has not been independently reviewed yet.

## Threat model
Each case says what protects you and, honestly, what does not.

### Lost or stolen phone
- **Protection:** the app's database is encrypted (SQLCipher), with its key in the phone's secure storage, Android Keystore (app, **built**). The app lock uses a 6-digit PIN or biometrics, with waits after wrong PINs (**built**). The app's content is hidden from the recent-apps screen while the lock is on (**built**). Android's cloud backup of app data is off (**built**). The other person can unpair (app, **planned**). This deletes their own inbox, so the lost phone can no longer send them anything, and their phone stops sending to it.
- **Limits:**
  - There is no remote wipe. Local data stays on the stolen phone until someone erases it.
  - Envelopes already waiting in the lost phone's inbox can still be fetched by it for up to 30 days.
  - The app lock is a speed bump against a casual finder, not protection against someone who can root the phone: the wrong-PIN counters sit next to the PIN hash, and the waits follow the phone's clock.
  - Someone who has the phone and its screen-lock code, or the phone unlocked, can open the app if the app lock is off.

### Shoulder-surfing
- **Protection:** the Discreet notification mode shows only generic text, with no names, previews or topic (app, **planned**). App lock and the blank recent-apps preview (**built**). Pushes carry no content in any mode (relay, **built**: always exactly `{"t":"s"}`).
- **Limits:** Standard mode, the default, shows the sender's name and a preview, also on the lock screen if Android is set to show it. Someone watching the screen while the app is open sees what is on it.

### Curious relay operator or Cloudflare
- **Protection:** the relay is blind (`PRIVACY.md`). It holds only ciphertext and public keys. It never receives private keys, the QR secret, names or settings. It writes no request logs.
- **Limits:**
  - It sees the metadata listed in `PRIVACY.md`: linked inboxes, sizes, times, wake-up flags, push tokens, and IP addresses at Cloudflare's edge.
  - You cannot check that the deployed relay runs exactly this code. A dishonest operator, or Cloudflare, could log more metadata (addresses, times). Content stays protected even then, because the keys are only on the phones.
  - Cloudflare keeps recovery copies of the relay's storage for up to 30 days (ciphertext only).

### A hostile relay (it changes, drops or invents traffic)
- **Protection:**
  - An envelope that is altered, or not signed by the partner's key, is refused (signature, then AEAD; `PROTOCOL.md` section 8).
  - A replayed envelope is refused (replay window), and so is a replayed relay request (nonce kept 15 minutes, time ±300 s).
  - An envelope older than 31 days is refused.
  - A reordered or late envelope is handled (skipped keys, HLC order).
  - Attachments are authenticated by their own key, which the relay never sees.
  - The client checks every relay answer (IDs, cursors, sizes) and does not follow redirects.
- **Limits:**
  - The relay can delay, drop or withhold anything, refuse service, or pretend an inbox does not exist. The app must treat "your partner's inbox is gone" (`inbox_not_found`) as a notice to show, and erase nothing on the relay's word alone.
  - It can flip the unsigned wake-up header, which causes a missed or extra wake-up, never content.
  - A relay that drops the latest envelopes, or all of them, cannot be noticed. Only gaps in the counters show. Anything left unfetched for 30 days is gone, and nobody can say what it was.

### Google FCM
- **Protection:** the payload is always exactly `{"t":"s"}`, with no inbox ID, sender, count or content. A push only makes the phone sync, and the phone syncs when the app opens as well.
- **Limits:** Google sees the push token, the app and Firebase project, and the time of each wake-up, which is close to when the partner sent a message. Google can delay or drop pushes. It could also send extra pushes, which only cause a sync.

### Leaked FCM service-account key (a relay secret)
- **Protection:** the key belongs to a dedicated account with only the "Firebase Cloud Messaging API Admin" role (`relay/README.md`). It is a Worker secret, never in this repository.
- **Limits:** with the key, someone can send content-free pushes to the app's phones. That causes an empty sync, never data. Revoke the key in Google Cloud and set a new secret.

### Man-in-the-middle at pairing
- **Protection:**
  - QR path: the QR carries the initiator's keys and a one-time secret. A relay that swaps keys fails the key confirmation.
  - Code path: a 6-digit code cannot authenticate keys. So both phones require each person to compare the safety number (20 digits, about 66 bits). Until then they send and show nothing but the device hello. The joiner's identity keys are new for each attempt and revealed only after the bundle. So a relay cannot search in advance for a fake key that gives the same number (`PROTOCOL.md` section 5).
  - A reply that claims the code path always requires the comparison on the initiator's phone too.
- **Limits:**
  - The QR is a bearer secret for its 10 minutes. Someone who photographs it can pair instead of the partner. The partner's phone then reports "already used", and the people must notice and unpair. Comparing the safety number, recommended on the QR path too, catches it.
  - Codes can be guessed slowly (5 wrong lookups per address per 10 minutes). A found code only blocks that attempt, because the comparison then fails.

### Malicious partner after a breakup
- **Protection:** either person can unpair alone (app, **planned**). That deletes their own data, keys and inbox, so the other phone can no longer send to them. A partner's phone, or a modified app, is still held to the protocol's checks: strict parsing, payload checks, size limits (64 KiB per envelope, 10 MiB per attachment) and inbox quotas.
- **Limits:**
  - Out of scope by nature: the partner keeps their own copy of everything they received, and can take screenshots or show it to others.
  - Until you unpair, a hostile partner can wake your phone on every deposit (battery, never content) and fill your inbox up to its quota.
  - A partner whose clock is set far ahead wins "last change wins" edits until the clocks agree.
  - A modified app can break app-level fairness rules (for example the order of answer reveals). The protocol only proves who sent each event.

### Tampered app content
- **Protection:** questions, ideas and Islamic texts are compiled into the signed app. The app downloads no content (v1), so nobody can push new content to it. The app's releases list a SHA-256 checksum for each file. This repository's releases are tags on `main`.
- **Limits:** a modified app installed from anywhere else than the official source is out of reach. Install only from an official release.

### Compromised device key
- **Protection:** the Double Ratchet heals: someone who copied a phone's ratchet state once, and then only listens, loses access after the next turn of the conversation (a new DH ratchet step with keys they do not know). Recorded older traffic stays closed (forward secrecy).
- **Limits:**
  - Healing works only against a passive attacker. Someone who has the identity signing key, or who copied the state and also controls the relay, can keep reading and impersonating. The fix is to re-pair, which makes completely new keys on both phones.
  - Forward secrecy protects traffic, not the history in the phone's database.
  - Keys are not post-quantum.

### Clocks
- **Protection:** the relay refuses requests more than 300 s from its time and tells the phone its time. An envelope more than 1 hour ahead waits on the relay, and the app shows a wrong-time card after 24 hours. Order between phones uses a hybrid logical clock that never goes back.
- **Limits:** a phone with a badly wrong clock delays its own envelopes until it is fixed. A partner clock ahead wins edits, as above.

### Abuse and cost
- **Protection:** 5 new inboxes per network per hour; pairing slots single use for 10 minutes, at most 100,000 open; per-inbox quotas (100 MiB of envelopes, 100 MiB of attachments); 30-day expiry.
- **Limits:** any request with a valid signature from a new key creates a small object that lives 15 minutes, before any per-network limit applies. A Cloudflare rate-limiting rule at the edge is planned with the deployment. Phones behind one carrier-grade NAT share the per-network limits.

### Supply chain
- **Protection:**
  - Cryptography comes from libsodium 1.0.22. Its source ships inside the `sodium` Dart package and is built locally, with nothing downloaded.
  - The relay's npm dependencies are pinned by `relay/package-lock.json`. The Dart package states version ranges in `pubspec.yaml`, as Dart packages do, and the app pins the exact versions in its own lock file. Updates come as reviewed pull requests (Dependabot).
  - CI actions are pinned by commit hash.
  - The git history is scanned for secrets on every pull request (gitleaks).
  - The app depends on this package by release tag, never by branch.
- **Limits:**
  - A compromised dependency, a compromised maintainer account or a compromised CI would not be caught by these steps alone.
  - Release tags can still be moved by the repository owner (a protection rule for tags is planned).
  - Nothing is reproducibly built yet.

### Deleted content waiting to be sent
- **Protection:** a delete removes the deleted item's events that are still waiting in the outbox, and drops an envelope already sealed with one of them, so deleted content that never left the phone is not sent; only the delete is (`PROTOCOL.md` section 17).
- **Limit:** an upload that had already started, or that the relay took while its answer was lost, cannot be recalled: the partner's phone receives the content, then its delete, and purges it (`PROTOCOL.md` section 16).

More limits, stated plainly: `PROTOCOL.md` section 16. What the relay and third parties see: `PRIVACY.md`.
