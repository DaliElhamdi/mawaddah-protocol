# Privacy

> **Status: describes protocol v0.1.0.** The relay is not deployed yet. Everything about the relay and third parties is what the code in this repository does. The section "On the phones" describes the app, which is not public, so it cannot be checked here. The legal part (Tunisia, EU) is still to be written and reviewed before the app is released (last section).

## In plain words
English:

No one can read your private moments. Your data lives on your two phones. What travels between them is end-to-end encrypted and carried by a "blind relay" that holds sealed envelopes for at most 30 days and cannot open them. It does not know your names. Push wake-ups go through Google and contain no content.

العربية:

<div dir="rtl" lang="ar">

لا أحد يستطيع قراءة أسراركما. بياناتكما محفوظة على هاتفيكما، وما يمرّ بينهما مشفّر من طرف إلى طرف، يحمله "ساعي بريد أعمى" يحتفظ بالمظاريف المختومة 30 يومًا كحدّ أقصى ولا يستطيع فتحها، ولا يعرف أسماءكما. تمرّ تنبيهات الإيقاظ عبر Google دون أي محتوى.

</div>

Français :

Personne ne peut lire vos moments privés. Vos données restent sur vos deux téléphones. Ce qui circule entre eux est chiffré de bout en bout et transporté par un « relais aveugle » qui garde les enveloppes scellées au maximum 30 jours sans pouvoir les ouvrir. Il ne connaît pas vos noms. Les notifications de réveil passent par Google, sans aucun contenu.

"Blind" means the relay cannot read what it carries. It does not mean it sees nothing: it sees the metadata listed below, and so does Cloudflare, which hosts it. Who you are can sometimes be worked out from metadata (for example from an IP address), so we never call the service anonymous.

## Who can read what
- **Your two phones** can read everything you share with each other. Your partner's phone keeps its own copy of what it received.
- **The relay, Cloudflare and Google** cannot read any message, answer, task, photo, voice note, name or setting. The keys that open them are made on the phones and never leave them.
- **Nobody else** can read your data, and no other service is involved: no accounts, no analytics, no advertising or crash-reporting services.

## What the relay can and cannot see
| The relay can see | The relay cannot see |
|---|---|
| Inbox IDs (random, derived from device public keys) and that two inboxes are linked | Names, profile data, dates, mode |
| Ciphertext sizes, timestamps, whether an envelope asked for a wake-up | Any message, answer, task, photo, voice note or setting |
| FCM push tokens | Keys (it never holds them) |
| IP addresses, transiently (abuse protection, ≤ 24 h) | |

Details of that metadata:
- **Sizes:** envelopes are padded to blocks of 256 bytes. Attachments are not padded, so their exact size shows, which can hint at a photo or a voice note.
- **Times:** when each phone deposits, fetches, acknowledges, uploads and downloads. Over weeks this shows when you use the app and roughly how much you exchange.
- **In each envelope, unencrypted** (`PROTOCOL.md` section 7): the sender's and the recipient's device IDs (which are the inbox IDs, so this is how the relay links the two inboxes), the sending phone's clock time, a counter of the envelopes it has sent since pairing, and the ratchet header: the current ratchet public key, which changes at each turn of the conversation, and message numbers. So the relay can count messages between turns.
- **Wake-up flag:** whether the sender asked for a push. Today only a chat message asks for one, so the relay can tell a chat message from a read receipt, never what it says.
- **IP addresses:** the relay never stores an address. It uses it for two limits (new inboxes, wrong pairing codes) and keeps only the times of recent attempts under a hash of the address (IPv6: of the /64 network). A scheduled clean-up deletes those times after about an hour. It can run late, but the design bound is 24 hours. The hash has no secret key. So anyone who sees the stored names could find the address by hashing every IPv4 address. Only Cloudflare and the relay operator can see those names. Both see the address at Cloudflare's edge anyway.

## What the relay stores, and for how long
| Stored | Deleted |
|---|---|
| Per inbox: the device's public signing key, its push token, its platform (Android or iOS), and the one partner key allowed to deposit | When the phone deletes its inbox (unpairing or "Delete all data"). No time limit until then. The push token also goes when Google reports it invalid |
| Sealed envelopes waiting for a phone, with their size and arrival time | When the phone acknowledges them, and in any case 30 days after arrival |
| Encrypted attachments waiting for a phone: a random ID, the exact size, the upload time and the encrypted bytes | When the receiving phone has downloaded and deleted them (or the sending phone deletes an upload it gave up), and in any case 30 days after the upload started |
| Recent request nonces of each device, to refuse replayed requests | After 15 minutes |
| A pairing slot: the inviting phone's public keys and, once the partner answers, the partner phone's public keys. No names, no QR secret | The keys as soon as the inviting phone reads the answer. The rest (code, slot ID, the two public signing keys) 10 minutes after the slot was made |
| Times of recent inbox registrations and of wrong code lookups, under a hash of the IP address (see above) | About 1 hour (registrations) or 10 minutes (lookups) after the last one (design bound: 24 hours) |

The relay writes no request logs. Cloudflare's logging for it is off in its configuration, and the deployment steps check that the dashboard has no log export either (`relay/README.md`, "No request logs"). Exact tables: `relay/README.md`, "What is stored".

## Third parties
- **Cloudflare** hosts the relay. It sees IP addresses at its edge, the metadata above, and the encrypted bytes in storage. It also keeps its own recovery copies of the relay's storage for up to 30 days (point-in-time recovery), which the relay cannot switch off. Those copies hold the same encrypted bytes.
- **Google Firebase Cloud Messaging (FCM)** delivers wake-ups. It sees push tokens and timing, never content. For each wake-up the relay sends Google only the phone's push token and the fixed message `{"t":"s"}` ("sync"). There is no inbox ID, sender, count or content. Google can see when a phone was woken and which app and Firebase project it is for. It can also see that the request came from the relay (a Cloudflare address). A wake-up follows the partner's message within seconds, so its time is close to when the partner sent it. On Android, Google Play services on the phone also knows the phone's push token, as for any app that receives pushes.
- **No other service.** The relay sends nothing anywhere else.

## Retention and erasure
- Envelopes and attachments leave the relay's live storage when the receiving phone acknowledges them, and in any case 30 days after they arrived. A scheduled clean-up deletes them, and nothing older is ever handed out. Cloudflare's recovery copies (above) can hold the encrypted bytes for up to 30 more days.
- **Unpairing and "Delete all data"** wipe the phone and delete that phone's own inbox on the relay, with everything waiting in it. Envelopes and attachments that phone already sent wait in the partner's inbox until the partner's phone fetches them, the partner's inbox is deleted, or 30 days pass. The partner's phone keeps its own copy of what it received until the partner erases it.
- An inbox whose phone never comes back keeps its record (public keys, push token, platform) with no time limit. Only its envelopes and attachments expire.

## On the phones
The app is in a separate, private repository, so this part cannot be checked here. It keeps its data in an encrypted database (SQLCipher) whose key is in the phone's secure storage (Android Keystore). It turns off Android's cloud backup of app data. It has an app lock, and hides its content from the recent-apps screen while the lock is on. Keys never leave the phone. A file backup made by the person (planned) is encrypted with their passphrase.

## To complete before release
- Data protection details for Tunisia (Organic Law 2004-63 and its national authority, the INPDP) and the EU (GDPR): who is responsible for the relay, the legal basis, people's rights and how to contact us.
- The Tunisian Arabic wording, written natively and reviewed.
