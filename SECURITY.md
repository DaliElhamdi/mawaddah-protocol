# Security

## Reporting a vulnerability
Please report privately through this repository's **Security** tab ("Report a vulnerability"). Do not open a public issue for a security problem. This is a small personal project: expect an acknowledgement, not a service-level guarantee.

## Status
Nothing here has been independently reviewed yet. At least one independent review of this repository is planned before version 1.0.0; findings will be tracked as issues.

## Threat model (summary; expanded during Phase 1)
| Threat | Mitigation |
|---|---|
| Lost or stolen phone | App lock; the partner can revoke the device; local data stays on the stolen phone until erased |
| Shoulder-surfing | Discreet notification mode |
| Curious relay operator or Cloudflare | The relay is blind; the metadata it sees is listed in `PRIVACY.md` |
| Google FCM | Sees push tokens and timing only; payloads carry no content |
| Man-in-the-middle at pairing | QR carries a one-time secret; the safety number must be compared on the 6-digit-code path |
| Malicious partner after a breakup | Out of scope: they keep their own copy of what they received |
| Tampered app content | Content is compiled into the signed app |
| Compromised device key | Double Ratchet recovery; re-pair |
