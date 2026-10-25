# short-answer-questions.md — Zeus0x01 AiTM Phishing Investigation

Dataset **v1.1.0** · incident INC-2417 · 21 core + 5 bonus.

One short answer per question. Case-insensitive unless a format says otherwise;
leading/trailing spaces ignored. Answer formats are strict for grading.
Hints are intentionally limited: reconstruct the chain from the evidence
bundle rather than searching for a named field in a named file.

Core max 30 points · pass threshold 23 · bonus 22–26 are optional (+5).

## Core questions

1. (1 pt) Which connecting IPv4 address first accepted the primary document-notification lure, before Larkspur’s own mail gateways handled it?
Answer format: `IPv4 address`

2. (1 pt) That same origin address appears once in the identity sign-in stream against a non-human account. What is that event’s id?
Answer format: `event ID`

3. (2 pt) On the device-activation message, authentication results show a valid DKIM signature while the envelope sender domain does not match the signing domain. Submit `<envelope-sender-domain>,<dkim-signing-domain>`.
Answer format: `domain,domain`

4. (2 pt) The device-activation body cites an internal service ticket. Which dataset file records that same ticket on an identity event, and what is the ticket string?
Answer format: `ticket-ref,filename`

5. (1 pt) The private review link in the primary lure hides its real destination in a URL-safe parameter. After decoding, what path does the victim actually land on (path only, no query string)?
Answer format: `/path/segment` (example shape: `/signin/service`)

6. (2 pt) That destination carries a client request id which is echoed in network telemetry. Submit `<dataset-filename>,<event_id>` for the matching observation.
Answer format: `filename,event-id`

7. (1 pt) Compare the static login replica with the browser-saved snapshot. What token value is present only after the page script has run?
Answer format: `exact token string`

8. (1 pt) After the local timing gate in the page script finishes, what does the script actually do with the result? Choose one: ALERT, REDIRECT, CONSOLE_ONLY, FORM_FREEZE.
Answer format: `enum token`

9. (2 pt) Dana’s high-risk successful Exchange sign-in just after 08:47 UTC shares its source address with a newly created inbox rule. Submit `<rule_name>,<event_id>`.
Answer format: `rule-name,event-id`

10. (1 pt) How many sign-in rows in total use that same suspicious source address?
Answer format: `numeric value`

11. (2 pt) Which alert first frames that successful high-risk sign-in as risk activity, and at what severity?
Answer format: `alert-id,severity`

12. (2 pt) The successful device-code grant for Dana shares a session correlation token with exactly one sign-in row. Submit `<correlation_id>,<sign-in event_id>`.
Answer format: `correlation-id,event-id`

13. (2 pt) Mailbox forwarding was pointed at an external address whose domain also authored the primary lure’s return path. Submit `<forwarding-event-id>,<domain>`.
Answer format: `event-id,domain`

14. (2 pt) Recover the defanged host from the second redirect-hop capture.
Identify the AiTM PhaaS family tied to that indicator.
Public analysis of that family describes an earlier PhaaS kit whose panel and code were partly reused.
What is the name of that earlier kit?
Answer format: short kit name

15. (1 pt) Public analysis of AiTM kits that harvest cloud sessions maps the credential-access behavior “Steal Web Session Cookie” to which MITRE ATT&CK technique ID?
Answer format: `T####`

16. (1 pt) In Microsoft public reporting on large-scale **device-code** phishing against Microsoft 365 identities, which tracked actor designation is used? (Report naming only — do **not** treat this as attribution of INC-2417 to that actor.)
Answer format: `actor designation`

17. (2 pt) Order the attacker’s first successful malicious sign-in, the malicious inbox-rule creation, and the external forwarding change — ascending by time.
Answer format: `event-id_1,event-id_2,event-id_3`

18. (2 pt) Order the chain openers ascending by time: delivery of the primary lure into Dana’s mailbox, the first network fetch of the decoded sign-in URL, and the first successful malicious sign-in.
Answer format: `event-id_1,event-id_2,event-id_3`

19. (1 pt) Strongest **working hypothesis** supported by the full package (not a single email alone). Cookie theft / session replay is **not** directly logged — choose the label that best matches the combined observed chain: PHISHING_CLICK_ONLY, PHISHING_REPORT_ONLY, SESSION_HIJACKED, DATA_EXFIL_CONFIRMED.
Answer format: `enum token`

20. (1 pt) Which Message-ID belongs to the legitimate contracted-vendor digest (not a lure)? Angle brackets optional.
Answer format: `message-id`

21. (1 pt) One inbox rule on Dana’s mailbox long predates the incident window and is unrelated. What is its event id?
Answer format: `event-id`

## Bonus questions

22. (1 pt) Decode the `X-Msg-Route` stamp on the primary lure.
Answer format: `exact decoded token`

23. (1 pt) Recover the node stamp the page script derives via its XOR helper (shown in the saved snapshot’s node field).
Answer format: `exact decoded token`

24. (1 pt) Which step is **implied** by a real AiTM outcome but is **not recorded** anywhere in this package? DEVICE_CODE_GENERATION, MFA_PROMPT_DISPLAYED, INBOX_RULE_ACTIVATION, SESSION_COOKIE_CAPTURE.
Answer format: `enum token`

25. (1 pt) Earliest `timestamp_utc` value present in the identity-audit dataset (any row).
Answer format: `ISO 8601 UTC timestamp`

26. (1 pt) How many `Received:` headers does the primary lure have versus the legitimate vendor digest?
Answer format: `n,n`

## Flag fragments (optional portal / platform)

Four fragments fall out of independent work:

- **F1** — route stamp from the primary lure header (bonus decode)
- **F2** — node stamp from the page script (bonus decode)
- **F3** — correlation id shared by the device-code grant and its sign-in (use the correlation id only, not a comma pair)
- **F4** — MITRE technique id for Steal Web Session Cookie

Canonical shape: `FLAG{AiTM-<F1>-<F2>-<F3>-<F4>}`
