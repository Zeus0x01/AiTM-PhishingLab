#!/usr/bin/env python3
"""Part 2: trainee-facing and repo-level documentation."""
from __future__ import annotations

import os

from build import (ROOT, DS_VERSION, DS_NAME, CASE_ID, PORTAL_CASE,
                   CORP_DOMAIN,
                   VENDOR_DOMAIN, KIT_MAILER_DOMAIN, HOP1_DOMAIN, HOP2_DOMAIN,
                   KIT_PAGE_DOMAIN, ITDESK_DOMAIN, ENVELOPE_DOMAIN_E2,
                   IP_RELAY, IP_ATTACKER, USER_DANA_UPN, MSG_ID_E1, MSG_ID_E2,
                   MSG_ID_E3, TICKET_E2, DEVICE_CODE, CID, LOGID, TK_TOKEN,
                   CORR_AITM, CORR_DEV, w)


def write_field_reference():
    txt = f"""\
# Field reference — Zeus0x01 AiTM Investigation (dataset v{DS_VERSION})

All timestamps are UTC in ISO 8601 format (`YYYY-MM-DDTHH:MM:SSZ`).
All IP addresses in the dataset are RFC 5737 documentation ranges or other
reserved/synthetic values (see SAFETY.md). All domains are synthetic reserved
names under `.example`, except for exactly one verified, publicly reported
indicator that is included DEFANGED in `redirect-hop-02.txt` and defined in
`SAFETY.md` (defanged domains are not resolvable and are never contacted).

## Generated index file

`artifacts/logs/incident-timeline.csv` is a **generated index view** of
`incident-events.jsonl` (same rows; columns: `timestamp_utc,event_id,
source_dataset,category,actor`). It exists to make tabular review easier.
The JSONL file and the underlying per-dataset files are the authoritative
sources. The CSV adds no facts.

## Identity datasets

### `artifacts/identity/signins.json`

Synthetic sign-in records modeled on Entra ID sign-in shape. Fields are
populated only where the simulated event makes sense; `null` means
"not applicable / not recorded".

| Field | Meaning |
|---|---|
| `event_id` | Stable identifier; referenced from other datasets |
| `timestamp_utc` | Event time, UTC ISO 8601 |
| `user_id` | Internal short identity code (e.g. `USR-11018`) |
| `user_principal_name` | Corporate UPN |
| `source_ip` | Network address observed at sign-in |
| `application` | Simulated resource the sign-in targeted |
| `authentication_result` | `success` or `failed` |
| `authentication_method` | `password`, `device_code`, ... |
| `risk_level` | Simulated risk estimate (`low`/`medium`/`high`) |
| `risk_state` | Simulated risk disposition (`clean`, `at_risk`, ...) |
| `correlation_id` | Session-level token linking related events |
| `device_id` | Registered client identifier, when present |
| `user_agent` | Reported browser/service string |
| `mfa_claim` | *(synthetic)* MFA satisfaction claim carried by the session |
| `failure_reason` | *(synthetic)* present only on failed attempts |

### `artifacts/identity/identity-audit.json`

Synthetic identity audit events (authorization and account-settings shape).
Fields: `event_id`, `timestamp_utc`, `user_id`, `user_principal_name`,
`category` (`authentication` / `authorization` / `account_settings`),
`operation`, `resource`, `result`, `source_ip`, `scope`, `support_ticket`,
`reference_token`, `correlation_id`. Fields appear only when meaningful.

## Log datasets

### `artifacts/logs/alerts.json`

Compact synthetic alerts modeled on XDR-style alert shape. Fields:
`alert_id`, `created_utc`, `severity`, `category`, `affected_account`,
`related_event_ids` (event IDs that also exist in the identity or log
datasets), `evidence_refs` (`dataset:dataset_event_id` pairs),
`alert_status`. Alert titles are deliberately neutral; they neither confirm
nor deny intent, and one alert may deserve dismissal.

### `artifacts/logs/mailbox-audit.json`

Synthetic mailbox audit events. Fields: `event_id`, `timestamp_utc`,
`actor_user_id`, `actor_upn`, `action` (`EmailReceived`, `NewInboxRule`,
`SetForwarding`, `FolderAction`), `target_user_id`, `target_upn`,
`message_id`, `client_ip`, `correlation_id`, plus rule properties
(`rule_name`, `rule_conditions`, `rule_actions`, `rule_destination_folder`,
`forwarding_address`, `forwarding_type`) where applicable.
`actor_user_id: "system"` denotes provider-generated records.
**Not every new inbox rule is malicious — check the actor, client IP and
correlation_id before concluding.**

### `artifacts/logs/incident-events.jsonl`

Normalized event stream: **one JSON object per line**, no array wrapper.
Each record is COPIED from an underlying dataset; every record retains
`source_dataset` and `source_event_id` so the original row is always
traceable. The only generated fields are `category` (normalized label) and
`derived_summary` (always marked implicitly in the file header comment of
the schema below). No facts absent from the underlying records are
introduced. Reconstruct the timeline independently by reading the
underlying datasets directly and sorting by `timestamp_utc`.

Each line:
`{{"source_dataset":"...","source_event_id":"...","timestamp_utc":"...","category":"authentication|authorization|account_settings|mailbox|network|alert","actor":"...","derived_summary":"..."}}`

### `artifacts/network/connection-events.json`

Synthetic network observations. Fields: `event_id`, `timestamp_utc`,
`source_ip`, `dest_host`, `dest_ip`, `protocol`, `event_ref` (pointer to a
web artifact or email), `observation_type`, `request_uri`, `user_account`,
`data_source`. A connection row never proves intent on its own; correlate
with identity and mailbox records before concluding anything.

## Web artifacts

All files in `artifacts/web/` are **inert**: zero network requests, no
external resources, no credential collection, no session handling. See
SAFETY.md for the full inert model.

- `redirect-hop-01.txt` / `redirect-hop-02.txt` — static, analyst-authored
  capture records describing one observed hop each. Reading them performs
  no request; they are records of a *simulated* chain, not live redirects.
- `login-page.html` — static duplicate of a "sign-in to view shared
  documents" page. The form is disabled (`onsubmit` returns false), fields
  are inert, and the only script is the local `page-source.js`.
- `saved-page.html` — a browser-saved snapshot of the same page captured
  *after* the page script ran, so it contains rendered state that the
  static source does not. Its snapshot comment records where it came from.
- `page-source.js` — standalone, independently written script used by the
  login page. All behavior is local: XOR-based string deobfuscation, one
  simulated timing-gate, a decoy CAPTCHA state, and local-only diagnostics.
  There is no fetch, XMLHttpRequest, WebSocket, sendBeacon or EventSource.
  Nothing is submitted anywhere.
- `device-code-page.html` — static decoy for the device-code lure variant.
  The field is read-only, the button is disabled, and there is no form
  action and no code entry flow.

## Email artifacts

Mail files are plain RFC 5322 `.eml` text; open with any mail tool
(Thunderbird view-source, Python, CyberChef, a text editor). Bodies are
7-bit `text/plain`; every header is decodable without attachments.

- `email-01-aitm-lure.eml` — shares the document-notification pretext with
  Email 3, but is a different sender chain (typical of lookalike
  notification services).
- `email-02-device-code.eml` — the device-code lure variant (static decoy
  page included in `artifacts/web/`).
- `email-03-legitimate-review.eml` — legitimate security-review digest.

The `Authentication-Results` verdicts in these files are synthetic labels
attached to a fictional domain set; do not generalize them, and note that
**passing SPF, DKIM, or DMARC alone never establishes that a message is
benign** (and one of the lure emails deliberately passes all three).

## Cross-file consistency rules

- Event IDs are globally unique across all datasets; there are no overlaps.
- `correlation_id` values tie together events recorded as one session
  (identity + mailbox + network). Two distinct values exist in this
  incident; some events intentionally do not carry one.
- Message-IDs in mailbox-audit rows match the `.eml` Message-ID headers
  exactly (including angle brackets).
- Email 3's vendor portal host is referenced in benign connection rows used
  by other users; dana has NO benign connections recorded to it in this
  dataset window.
"""
    w("artifacts/documentation/field-reference.md", txt)


def write_evidence_inventory():
    txt = f"""\
# Evidence inventory — Zeus0x01 AiTM Investigation (dataset v{DS_VERSION})

Fictional corporate incident reference: **{CASE_ID}** (Larkspur Systems,
internal lab scenario). Provenance of every artifact: synthetic training
material generated for this dataset version; **not** genuine exports from
Microsoft Defender XDR, Splunk, Elastic, or any security product.

## Files you are given

| Path | Type | Investigative purpose |
|---|---|---|
| `mail/eml/email-01-aitm-lure.eml` | Email | Primary lure in the incident chain |
| `mail/eml/email-02-device-code.eml` | Email | Second lure variant (device-code pretext) |
| `mail/eml/email-03-legitimate-review.eml` | Email | Legitimate vendor digest (false-positive test) |
| `artifacts/web/redirect-hop-01.txt` | Capture record | First hop recorded in the simulated redirect chain |
| `artifacts/web/redirect-hop-02.txt` | Capture record | Second hop recorded in the simulated redirect chain; contains one defanged public IOC |
| `artifacts/web/login-page.html` | Static page | Static source duplicate of a sign-in page |
| `artifacts/web/saved-page.html` | Static page | Browser-saved snapshot of the same page after its script ran |
| `artifacts/web/page-source.js` | Script | Local-only page logic (decode target; no network) |
| `artifacts/web/device-code-page.html` | Static page | Decoy device-activation page (no live flow) |
| `artifacts/identity/signins.json` | JSON | Synthetic sign-in records |
| `artifacts/identity/identity-audit.json` | JSON | Synthetic identity audit events |
| `artifacts/logs/alerts.json` | JSON | Synthetic alerts (some relevant, some not) |
| `artifacts/logs/mailbox-audit.json` | JSON | Synthetic mailbox audit events |
| `artifacts/logs/incident-events.jsonl` | JSONL | Normalized index of selected events |
| `artifacts/logs/incident-timeline.csv` | CSV | Generated index view of the JSONL (not authoritative) |
| `artifacts/network/connection-events.json` | JSON | Synthetic network observations |
| `documentation/field-reference.md` | Doc | Field definitions and decode guidance |
| `documentation/evidence-inventory.md` | Doc | This file |

## Context documented for correlation (these are hints, not answers)

- **Vendor contract.** Larkspur Systems (fictional) holds an active support
  contract with **Audit-Trail Software** for identity-compliance reporting.
  The vendor's weekly digest arrives from `{VENDOR_DOMAIN}` and its portal
  lives at `portal.{VENDOR_DOMAIN}`. This relationship is part of the
  contracted environment, which matters when you classify sender activity.
- **Service connector.** The identity platform records a periodic service
  connector (`svc-hygiene`) that re-authenticates around mail-flow jobs and
  sometimes logs a failure. Its activity source may resemble addresses seen
  elsewhere in mail routing.
- **Benign mailbox housekeeping.** at least one inbox rule in the mailbox
  audit file predates the incident window by more than a year and was
  created from a corporate workstation; treat timeline boundaries seriously.
- **Device-code variant.** The device-code lure's ticket is tracked in the
  identity platform under the same support-desk reference the lure cites.

## Threat-intelligence anchor (public, verified, defanged)

Exactly one real, publicly published indicator is embedded in this dataset,
in defanged form, in `artifacts/web/redirect-hop-02.txt`:

- Indicator: `beacon.diremsto[.]com` (domain, defanged)
- Publisher: **Sekoia Threat Research & Detection (TDR)**
- Report: "Tycoon 2FA: an in-depth analysis of the latest version of the AiTM
  phishing kit" — https://blog.sekoia.io/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit
- Publication date: **2025-03-25** (report content frozen at this analysis
  snapshot; the IOC list is published in the report's IOC section)
- Context in report: one of the domains listed in the report's Tycoon 2FA
  IOC table; the report links the Tycoon 2FA phishing kit to AiTM activity
  harvesting Microsoft 365 session cookies.
- Purpose in the investigation: a public-research pivot. **Never resolved,
  contacted, or re-hosted.** Only involved in the threat-intelligence
  questions; it is otherwise inert text.
- Defanged representation (verify you quote it exactly): `beacon.diremsto[.]com`

## Aging note

Public IOCs decay: feeds expire, sandbox verdicts disappear, and blocks are
removed. Trainees should treat the indicator pivot exercise above as
time-sensitive; if a public report or listing goes offline, grade from the
instructor IOC notes rather than re-pivoting live.
"""
    w("artifacts/documentation/evidence-inventory.md", txt)


def write_readme():
    txt = f"""\
# Zeus0x01 — AiTM Phishing Investigation ({DS_NAME})

**Difficulty: hard · Format: downloadable DFIR investigation · Time budget: 3–4 h**

Welcome to the Zeus0x01 lab series. This is a **downloadable, offline,
tool-agnostic investigation** in the style of CyberDefenders / HTB
DFIR-style forensics: you download the evidence bundle, analyze it with the
tools of your choice, answer short questions, and (optionally) verify your
chain on the lab portal.

The incident: a fictional employee at fictional **Larkspur Systems**
received an email that looks like an ordinary corporate document
notification. The message contains a suspicious destination represented by a
static redirect chain, followed by identity, mailbox, and network evidence
plus a set of XDR-style alerts. A second email variant pushes a device-code
"activation" pretext. A third, legitimate vendor digest is included as a
false-positive test. Your job is to reconstruct what actually happened and
produce the final flag.

> **Do not contact any attacker infrastructure.** All indicators in the
> dataset are either synthetic reserved names (RFC `.example` / RFC 5737
> documentation IP ranges) or defanged public IOC text; see `SAFETY.md`.
> One published IOC domain appears **defanged** for threat-intel pivoting
> only; it is never resolvable in the artifacts and must stay that way.

## What you get

The training lab is distributed as an evidence ZIP you open, extract and
investigate locally. The ZIP is the primary deliverable; the hosted web
portal (this site) exists only as an optional answer-verification surface.
The complete evidence bundle you need is provided here:

`downloads/Zeus0x01-AiTM-Investigation.zip`

Extract anywhere; no SIEM, no subscription, and no Microsoft tenant are
required. The bundle includes:

- `mail/eml/` — three RFC 5322 email artifacts (lure, device-code variant,
  legitimate security-review digest)
- `artifacts/web/` — static redirect-hop capture records, a login-page
  replica, a browser-saved snapshot, the page script, and a device-code
  decoy page (all inert; zero network requests)
- `artifacts/identity/` — synthetic sign-in and identity-audit records
- `artifacts/logs/` — synthetic alerts, mailbox audit, and a normalized
  incident event stream
- `artifacts/network/` — synthetic network observations
- `artifacts/documentation/` — field reference + evidence inventory
- `tools/optional-import-examples/` — optional Splunk/Elastic/PowerShell/
  Python parsing snippets

## Learning objectives

- Header triage: hop chains, SPF/DKIM/DMARC verdicts and their limits,
  envelope/DKIM misalignment, encoded parameter decoding
- Static HTTP-analysis: redirect-hop records, replica-page snapshots,
  local-vs-rendered state differences, XOR-obfuscated script logic
- Identity correlation: sign-ins, token grants, device-code activity,
  device registration, MFA persistence
- Alert triage: filtering genuine signals from benign noise
- Timeline reconstruction: ordered chain from lure delivery to persistence
- Threat-intelligence pivoting: verified public IOC to attributed phishing
  family, plus MITRE ATT&CK technique mapping
- Classification discipline: choosing the strongest supported conclusion

## Prerequisites

- Any text editor; a terminal (PowerShell, bash, zsh)
- Python 3 (or PowerShell) for quick parsing, or jq / grep
- CyberChef (offline build) or plain `base64 -d` / Python for decodes
- Optional: Splunk or a free Elastic instance; optional: MHA ( nto required)

## Question workflow

1. Download and extract the evidence ZIP above (verify the SHA-256 against
   the `SHA256SUMS` manifest in the repository).
2. Answer the questions in `short-answer-questions.md` (21 core + 5 bonus).
   Every question names its artifact sources and its answer format.
3. Submit each answer through the hosted portal below (verification is
   server-side; per-question correctness is scored on the portal).
4. As you solve, four **flag fragments** fall out of the evidence: one from
   email/header evidence, one from the web artifacts, one from identity/audit
   logs, and one from the published threat-intel report. Enter all four on
   the portal to release the final flag once your core score clears the
   threshold. Full scoring rules: `instructor/scoring-rubric.md` in the
   instructor pack (not distributed to trainees; questions carry points
   metadata in the question bank instead).
5. Offline mode: the dataset is fully usable without the portal; the hosted
   portal is only an optional verification surface. Platform-hosted installs
   (HTB/CyberDefenders/CTFd-style) grade answers from the **question bank
   JSON** supplied by the lab maintainer.

## Tooling suggestions (all optional)

- `jq`, `python -m json.tool`, PowerShell `ConvertFrom-Json` for JSON
- plain `grep`/`rg` over the `.eml` and web artifacts
- CyberChef offline recipes for base64/XOR decoding
- any SIEM import hints live in `tools/optional-import-examples/`

## Safety summary (see SAFETY.md for full model)

* No live malware, no credential capture, no session replay, no device-code
  flow, no reverse proxy anywhere in the dataset.
* The web artifacts make **zero network requests** (no fetch, XHR,
  WebSocket, sendBeacon, EventSource, external `<img>`/`<script>`/`<link>`).
* Trainee-facing links point only at RFC-reserved synthetic names or a
  defanged public IOC that is never contacted. None lead to real attacker
  infrastructure.
* The device-code scenario exists only as text in the email plus a static
  decoy page; no real Microsoft code is generated and no live service is
  involved.

## Dataset integrity

Verify the extracted evidence bundle with the `SHA256SUMS` manifest shipped
in the repository root (run: `sha256sum -c SHA256SUMS` on Linux/macOS, or
`Get-FileHash` on Windows). Documented integrity and safety checks are
executed at build time and reproduced in the release notes for each dataset
version.

## Version

Dataset `Zeus0x01-AiTM-Investigation` v{DS_VERSION} (incident {CASE_ID}).
"""
    w("README.md", txt)


def write_safety():
    txt = f"""\
# SAFETY.md — inert guarantees for the Zeus0x01 AiTM lab (dataset v{DS_VERSION})

> READ FIRST if you plan to deploy, detonate, or redistribute anything in
> this repository. Everything here is a **training simulation built from
> inert artifacts**. This document states exactly what is inert, why, and
> under which rules the material must be handled.

## 1. Inert artifacts

| Artifact | Contains | Cannot do |
|---|---|---|
| `mail/eml/*.eml` | RFC 5322 source, plain-text bodies, custom X-headers | nothing — data only, no attachments, no scripts, no macros |
| `artifacts/web/*.html` | static replicas (login page, saved snapshot, device-code decoy) | never contacts the network; forms are disabled; buttons are inert |
| `artifacts/web/page-source.js` | locally-scoped logic: XOR string de-obfuscation, one simulated timing-gate, decoy CAPTCHA state, local console diagnostics | no fetch/XHR/WebSocket/sendBeacon/EventSource; nothing is submitted or exfiltrated; no reverse proxy |
| `artifacts/web/redirect-hop-0*.txt` | analyst-authored, sanitized capture records | records only; reading performs zero requests; never a live redirect |
| identity/log/network JSON & JSONL | fictional telemetry | not platform exports; render nothing, connect to nothing |
| `deploy/` verification portal | optional server-side answer checker | not part of the evidence; ignores trainee input except to verify digests |

**Nothing in this lab is a functional AiTM proxy, credential collector,
session-cookie capturer/replayer, OAuth device-code flow, or mail relay.**
The login page is a static, non-submitting artifact; the device-code
scenario exists only as the email text plus a static decoy page; every
redirect hop is a local flat file; no code path in the web artifact set
creates a functional authentication relay.

## 2. Network safety

* The web artifact set makes **zero network requests**. The repository
  build script enforces this by scanning for `fetch(`, `XMLHttpRequest`,
  `sendBeacon`, `WebSocket`, `EventSource`, and any external `<src>` /
  `<link>` / `@import`; the released evidence must fail closed.
* Every trainee-facing link points only at RFC-reserved synthetic names
  (`.example` domains, RFC 5737 documentation IPs) or at plain defanged
  text. Nothing resolves to real attacker infrastructure.
* No redirect chain in this lab actually executes; hops are flat capture
  records. Do not re-host them, and do not strip the `[.]` defanging.
* The single real, published IOC domain embedded here (see §3) appears only
  in defanged form in `redirect-hop-02.txt`, is never used as a live
  pointer, and must never be contacted as part of any lab flow.

## 3. Threat-intelligence references

**Verified public indicator (embedded, defanged):**

| Field | Value |
|---|---|
| Exact indicator (defanged) | `beacon.diremsto[.]com` |
| Indicator type | domain |
| Publisher | Sekoia Threat Research & Detection (TDR) |
| Report title | "Tycoon 2FA: an in-depth analysis of the latest version of the AiTM phishing kit" |
| Publication date | 2025-03-25 |
| URL | https://blog.sekoia.io/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit |
| Relevant context | One of the domains listed in the report's Tycoon 2FA IOC table; the report ties Tycoon 2FA PhaaS to AiTM activity harvesting Microsoft 365 session cookies |
| Defanged form used in the artifact | `beacon.diremsto[.]com` |
| Purpose in the lab | Threat-intelligence pivot for the TI questions only; never contacted or re-hosted |

Ancillary reports trainees are pointed at for context (not embedded in
artifacts): Darktrace, "Bypassing MFA: AiTM Tactics Exposed" (2025-04-29)
and Microsoft Threat Intelligence, "Storm-{{x}} conducts device code
phishing campaign" (2025-02-13). The Darktrace report maps Tycoon 2FA
campaign behavior to the MITRE ATT&CK technique **Steal Web Session
Cookie**; the Microsoft report documents device-code phishing as a named
tracked-actor technique. Neither indicator list is reproduced in the
dataset; trainees pivot on the one defanged IOC above.

**Synthetic lab indicators are clearly separate:** every domain under
`.example`, every RFC 5737 documentation IP, and every fictional user,
device, rule, and alert in this repository is *invented for training* and
must not be present in feeds as real malicious infrastructure.

## 4. Synthetic telemetry

The identity sign-in records, identity audit events, alerts, mailbox audit
records, network observations, and normalized event stream are **fictional
training data**. They are not genuine exports from Microsoft Defender XDR,
Entra ID, Splunk, Elastic, or any other platform; the "XDR-style" shape is
approximate, documented in `documentation/field-reference.md`, and exists
so analysts can practice correlation without a live product.

## 5. Integrity

Each distributed file's SHA-256 is recorded in the repository-level
`SHA256SUMS` manifest; the evidence ZIP records the same manifest inside
itself. Verify after extraction:

* Linux/macOS: `sha256sum -c SHA256SUMS` (from inside the extracted folder)
* Windows PowerShell: compare `Get-FileHash -Algorithm SHA256 <file>`.
  against the manifest values.

The archive's own SHA-256 is published in the release notes (see README).
Do not claim integrity verification passed unless the hashes were actually
checked against the shipped manifest.

## 6. Limitations

Synthetic telemetry models *selected investigative concepts* (sign-in risk,
token grant, device registration, mailbox rule abuse, connection tracking).
It does not reproduce every field, enum, or behavior of a commercial XDR
platform, and it must not be used to train production detections as-is.
The simulated kit artifacts show only mild, independently written
obfuscation, not the internals of any real phishing kit; no source code
from any real kit is reproduced here.

## 7. Handling rules

* Treat all artifacts as you would real triage material: isolated VM,
  snapshot taken, outbound networking disabled — even though nothing here
  can act on your system.
* Never resolve, contact, re-host, or de-fang any indicator as part of a
  lab flow; never automate contact with anything the artifacts point at.
* If you redistribute the bundle, keep this SAFETY.md next to the
  documentation and keep the defanged indicator defanged.
"""
    txt = txt.replace("Storm-{{x}}", "Storm-2372")
    w("SAFETY.md", txt)
