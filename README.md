# Zeus0x01 — AiTM Phishing Investigation (Zeus0x01-AiTM-Investigation)

**Difficulty: hard · Format: downloadable DFIR investigation · Time budget: 3–4 h**

Welcome to the Zeus0x01 lab series. This is a **downloadable, offline,
tool-agnostic investigation** in the style of CyberDefenders / HTB
DFIR forensics: you download the evidence bundle, analyze it with the tools
of your choice, and answer short questions.

The hosted web portal is **optional**. It is only an answer-verification
surface. You can complete the full lab without it. Platform-hosted installs
(CyberDefenders, HTB, CTFd-style) grade from the maintainer **question bank
JSON**, not from the portal.

## Scenario (no spoilers)

A fictional employee at fictional **Larkspur Systems** receives mail that
looks like an ordinary corporate document notification. The evidence set
includes:

- a suspicious destination represented by a static redirect-chain capture
- identity, mailbox, and network records
- XDR-style alerts
- a second message that uses a device-code “activation” pretext
- a third, legitimate vendor digest (false-positive test)

Your job is to reconstruct what happened, answer the short questions, and
(if used) assemble the flag fragments described in the question file.

> **Do not contact any attacker infrastructure.** All indicators in the
> dataset are either synthetic reserved names (RFC `.example` / RFC 5737
> documentation IP ranges) or **defanged** public IOC text. See `SAFETY.md`.
> One published IOC domain appears defanged for threat-intel pivoting only;
> it is never resolvable in the artifacts and must stay that way.

## What you get

**Primary deliverable:** the evidence ZIP.

```text
downloads/Zeus0x01-AiTM-Investigation.zip
```

Extract anywhere. No SIEM, no subscription, and no Microsoft tenant are
required. The same evidence also lives in this repository under `mail/`,
`artifacts/`, and related paths so you can work from a clone if preferred.

Bundle layout:

| Path | Contents |
|------|----------|
| `mail/eml/` | Three RFC 5322 emails (lure, device-code variant, legitimate vendor digest) |
| `artifacts/web/` | Redirect-hop capture records, login-page replica, browser-saved snapshot, page script, device-code decoy (all inert; zero network requests) |
| `artifacts/identity/` | Synthetic sign-in and identity-audit records |
| `artifacts/logs/` | Synthetic alerts, mailbox audit, incident event stream / timeline |
| `artifacts/network/` | Synthetic network observations |
| `artifacts/documentation/` | Field reference + evidence inventory |
| `tools/optional-import-examples/` | Optional Splunk / Elastic / PowerShell / Python parsing snippets |

Trainee questions live in:

```text
short-answer-questions.md
```

(21 core + 5 bonus; every item lists points, answer format, and evidence sources.)

## Learning objectives

- Header triage: hop chains, SPF/DKIM/DMARC verdicts and their limits,
  envelope/DKIM misalignment, encoded parameter decoding
- Static HTTP analysis: redirect-hop records, replica-page snapshots,
  local-vs-rendered state differences, XOR-obfuscated script logic
- Identity correlation: sign-ins, token grants, device-code activity,
  device registration, MFA-related signals
- Alert triage: real signals vs benign noise
- Timeline reconstruction: ordered chain from lure delivery to persistence
- Threat-intelligence pivoting: defanged public IOC → attributed family,
  plus MITRE ATT&CK technique mapping (facts mirrored in the documentation
  artifacts for offline use)
- Classification discipline: strongest conclusion the evidence supports

## Prerequisites

- Any text editor and a terminal (PowerShell, bash, or zsh)
- Python 3 (or PowerShell) for quick parsing, or `jq` / `grep` / `rg`
- CyberChef (offline build) or plain `base64` / Python for decodes
- Optional: Splunk or a free Elastic instance
- Optional: Message Header Analyzer (MHA) — **not** required

## How to solve (offline path — complete)

1. Download `downloads/Zeus0x01-AiTM-Investigation.zip` **or** clone this repo.
2. Verify integrity with `SHA256SUMS` (see below).
3. Extract / open the evidence files listed above.
4. Work through `short-answer-questions.md` in order (or any order you prefer).
5. Record short answers exactly in the formats requested.
6. Flag fragments (if your deployment uses them) fall out of four evidence
   categories described in the question file. You do **not** need the portal
   to obtain or justify those values from the artifacts.

That path is sufficient for self-study and for platform grading.

## Portal (optional only)

If a hosted portal is deployed for this lab:

- It is **not required** to finish the investigation.
- It may score submitted short answers and/or release a canonical flag after
  a core-point threshold.
- Verification is server-side and must be configured by the operator
  (environment variables). An unconfigured deployment should not expose
  answers in client-side code.

If no portal is available, ignore it and submit answers through whatever
interface your platform provides (or keep a local answer sheet).

## Platform grading

For CyberDefenders / HTB / CTFd-style hosting:

- Grade from the maintainer **question bank JSON** (instructor pack),
  not from the optional portal.
- Normalize answers per the bank (trim, case rules, Message-ID brackets, etc.).
- Core questions carry the pass threshold; bonus questions are extra credit.
- Full scoring rules live in the instructor pack (`scoring-rubric.md`), which
  is **not** distributed to trainees.

## Tooling suggestions (all optional)

- `jq`, `python -m json.tool`, PowerShell `ConvertFrom-Json` for JSON
- `grep` / `rg` over `.eml` and web artifacts
- CyberChef offline recipes for base64 / XOR decoding
- SIEM import hints in `tools/optional-import-examples/`

## Safety summary

Full model: `SAFETY.md`.

- No live malware, credential capture, session replay, live device-code flow,
  or reverse proxy in the dataset.
- Web artifacts make **zero network requests** (no `fetch`, XHR, WebSocket,
  `sendBeacon`, EventSource, or external `<img>` / `<script>` / `<link>`).
- Trainee-facing names are RFC-reserved synthetic hosts or a single defanged
  public IOC that must never be contacted.
- The device-code scenario is email text plus a static decoy page only.

## Dataset integrity

Manifest: `SHA256SUMS` in the repository root (covers the evidence ZIP and
critical evidence files).

Linux / macOS:

```bash
sha256sum -c SHA256SUMS
```

Windows (PowerShell), example for one file:

```powershell
Get-FileHash .\downloads\Zeus0x01-AiTM-Investigation.zip -Algorithm SHA256
```

Compare the digest to the matching line in `SHA256SUMS`. Re-download if any
check fails before analysis.

## Version

Dataset `Zeus0x01-AiTM-Investigation` **v1.0.0** (incident **INC-2417**).
