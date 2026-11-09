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
| IP addresses, transiently (abuse protection, up to 24 hours) | |

## Third parties
- **Cloudflare** hosts the relay and sees IP addresses at its edge.
- **Google Firebase Cloud Messaging** delivers wake-ups and sees push tokens and timing, never content.

## Retention and erasure
Envelopes and attachment chunks are deleted when the receiving phone acknowledges them, and in any case after 30 days. "Delete all data" in the app wipes the phone and deletes the device's inbox on the relay.

## To complete before release
Data Protection details for Tunisia (personal data law and its national authority) and the EU (GDPR); final wording per language.
