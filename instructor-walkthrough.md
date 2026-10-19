# Instructor walkthrough — Zeus0x01 AiTM Investigation (v1.1.0)

Private/instructor use. Safe to keep when the repository is private.

## Web artifacts — what they are for

| File | Role |
|------|------|
| `redirect-hop-01.txt` / `02.txt` | Static **capture records** of a simulated redirect chain (not live HTTP). Teach hop reading and IOC spotting. |
| `login-page.html` | Static **phishing page replica** as delivered (pre-script state). |
| `saved-page.html` | **Browser-saved snapshot** after local script ran (rendered token / node field). |
| `page-source.js` | Inert kit script: XOR strings, timing gate, console-only behavior. |
| `device-code-page.html` | Static decoy matching the second email’s activation pretext. |

They exist so trainees practice web triage **without** a live phishing kit or network calls.

## Model answers

| Q | Answer | Notes |
|---|--------|-------|
| 1 | `203.0.113.44` | First/bottom Received on email-01 |
| 2 | `EVT-58107` | svc-hygiene failed sign-in from that IP |
| 3 | `larkspur-mail-relay-02.example,larkspur-itdesk.example` | Return-Path vs DKIM header.d |
| 4 | `SR-88031,identity-audit.json` | support_ticket on device-code grant |
| 5 | `/signin/azure_sso` | URL-safe base64 `u=` |
| 6 | `connection-events.json,EVT-C1052` | request_uri has client_request_id |
| 7 | `7K2-TOK-R9X4` | __tk only in saved-page |
| 8 | `CONSOLE_ONLY` | local diagnostics only |
| 9 | `SecArchives,EVT-58314` | NewInboxRule from 203.0.113.87 |
| 10 | `3` | EVT-58112, EVT-58103, EVT-58115 |
| 11 | `ALERT-7712,medium` | related to EVT-58103 |
| 12 | `CORR-2E71-05,EVT-58115` | grant ↔ device_code sign-in |
| 13 | `EVT-58315,docshare-online.example` | SetForwarding domain |
| 14 | `beacon.diremsto[.]com,Tycoon 2FA` | hop-02 IOC |
| 15 | `T1539` | Steal Web Session Cookie |
| 16 | `Storm-2372` | Microsoft device-code actor |
| 17 | `EVT-58103,EVT-58314,EVT-58315` | sign-in → rule → forward |
| 18 | `EVT-58311,EVT-C1052,EVT-58103` | delivery → click → sign-in |
| 19 | `SESSION_HIJACKED` | auth success + mailbox persistence |
| 20 | `20260915T080455Z-1d3e6b8c2@mail.audit-trail-software.example` | email-03 |
| 21 | `EVT-58316` | Finance-Reports rule (2025) |
| 22 | `MKD-2026-R480` | X-Msg-Route base64 |
| 23 | `NODE-4A9-7717` | XOR node array |
| 24 | `SESSION_COOKIE_CAPTURE` | implied, not logged |
| 25 | `2026-09-13T09:12:00Z` | earliest identity-audit after noise |
| 26 | `3,4` | Received counts |

### Flag fragments

| Frag | Value |
|------|--------|
| F1 | `MKD-2026-R480` |
| F2 | `NODE-4A9-7717` |
| F3 | `CORR-2E71-05` |
| F4 | `T1539` |

`FLAG{AiTM-MKD-2026-R480-NODE-4A9-7717-CORR-2E71-05-T1539}`

## Noise (v1.1.0)

Sign-ins, identity-audit, mailbox-audit, alerts, and connection-events include
extra benign/decoy rows. Critical incident event ids are unchanged.

## Scoring

Core threshold 23 / 30. Bonus optional.
