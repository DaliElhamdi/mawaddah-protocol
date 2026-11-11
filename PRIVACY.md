# Privacy

> **Status: draft.** The relay is not deployed yet. This document describes the intended design and will be finalized, and reviewed by the owner for Tunisian and EU requirements, before any release.

## In plain words
No one can read your private moments. Your data lives on your two phones. What travels between them is end-to-end encrypted and carried by a "blind relay" that holds sealed envelopes for at most 30 days and cannot open them. It does not know your names. Push wake-ups go through Google and contain no content.

## What the relay can and cannot see
| The relay can see | The relay cannot see |
|---|---|
| Inbox IDs (random, derived from device public keys) and that two inboxes are linked | Names, profile data, dates, mode |
| Ciphertext sizes, timestamps, whether an envelope asked for a wake-up | Any message, answer, task, photo, voice note or setting |
| FCM push tokens | Keys (it never holds them) |
| IP addresses, transiently: as a hash of the address (or of the IPv6 network) for the limit on new inboxes, kept about an hour and never more than 24 hours | |

What the relay stores for each inbox: the device's public signing key, its push token and its platform (Android or iOS). It also remembers each device's recent request nonces for 15 minutes, to refuse replayed requests. For the limit on new inboxes (5 per network per hour) it keeps the times of recent registrations under a hash of the IP address (or of the IPv6 /64 network), and deletes them about one hour after the last one (a scheduled clean-up does it; it can run late, never beyond 24 hours). The hash is not anonymous: anyone who sees the stored names and tries every IPv4 address can find the address. Only Cloudflare and the relay operator can see those names, and Cloudflare sees IP addresses at its edge anyway. For pairing, the relay keeps a pairing slot for 10 minutes: the inviting phone's public keys and, once the partner answers, the partner phone's public keys (no names, no QR secret). It erases those keys as soon as the inviting phone reads the answer, and the rest of the slot when its 10 minutes are over. To slow down people guessing 6-digit codes, it keeps the times of failed code lookups per hashed IP address (or IPv6 /64) for 10 minutes. The relay keeps no request logs. Details: `relay/README.md`.

## Third parties
- **Cloudflare** hosts the relay and sees IP addresses at its edge.
- **Google Firebase Cloud Messaging** delivers wake-ups and sees push tokens and timing, never content.

## Retention and erasure
Envelopes and attachment chunks are deleted when the receiving phone acknowledges them, and in any case after 30 days. "Delete all data" in the app wipes the phone and deletes the device's inbox on the relay.

## To complete before release
Data Protection details for Tunisia (personal data law and its national authority) and the EU (GDPR); final wording per language.
