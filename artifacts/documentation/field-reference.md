# Field reference — Zeus0x01 AiTM Investigation (dataset v1.0.0)

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
`{"source_dataset":"...","source_event_id":"...","timestamp_utc":"...","category":"authentication|authorization|account_settings|mailbox|network|alert","actor":"...","derived_summary":"..."}`

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
