# SAFETY.md — inert guarantees for the Zeus0x01 AiTM lab (dataset v1.0.0)

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
and Microsoft Threat Intelligence, "Storm-{x} conducts device code
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
