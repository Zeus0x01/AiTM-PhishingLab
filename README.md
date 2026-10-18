# Zeus0x01 — AiTM Phishing Investigation (Zeus0x01-AiTM-Investigation)

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

Dataset `Zeus0x01-AiTM-Investigation` v1.0.0 (incident INC-2417).
