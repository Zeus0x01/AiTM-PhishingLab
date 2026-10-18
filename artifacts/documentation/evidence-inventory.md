# Evidence inventory — Zeus0x01 AiTM Investigation (dataset v1.0.0)

Fictional corporate incident reference: **INC-2417** (Larkspur Systems,
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
  The vendor's weekly digest arrives from `audit-trail-software.example` and its portal
  lives at `portal.audit-trail-software.example`. This relationship is part of the
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
