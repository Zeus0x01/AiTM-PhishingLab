# Field reference — Zeus0x01 AiTM Investigation (dataset v1.1.0)

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
traceable. Reconstruct the timeline independently by reading the
underlying datasets directly and sorting by `timestamp_utc`.

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

- `redirect-hop-01.txt` / `redirect-hop-02.txt` — static capture records of a simulated chain.
- `login-page.html` — static sign-in page replica (form disabled).
- `saved-page.html` — browser-saved snapshot after local script ran.
- `page-source.js` — local-only script (no network).
- `device-code-page.html` — static decoy for the device-activation message.

## Email artifacts

Mail files are plain RFC 5322 `.eml` text. Filenames are **neutral** (timestamp-based);
classify each message by headers and body, not by path.

- `msg-20260914-090147.eml` — document-notification theme
- `msg-20260915-080720.eml` — service / device-activation theme
- `msg-20260915-080455.eml` — contracted vendor security digest

**Passing SPF, DKIM, or DMARC alone never establishes that a message is benign.**

## Cross-file consistency rules

- Event IDs are globally unique across all datasets.
- `correlation_id` values tie related session events; two distinct values exist in this incident.
- Message-IDs in mailbox-audit rows match the `.eml` Message-ID headers (including angle brackets).

## Analysis discipline

See `artifacts/documentation/observed-vs-inferred.md` for **Path A** (browser / login-replica chain) vs **Path B** (device-code), and for what is observed vs inferred vs not logged (including session-cookie capture).
