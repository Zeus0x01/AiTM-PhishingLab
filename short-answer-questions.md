# short-answer-questions.md — Zeus0x01 AiTM Phishing Investigation

One line per question; every answer is short and exact (an IP, a domain,
an ID, a timestamp, a path, a token, an enum value, or a
comma-separated pair).
No explanations. Case-insensitive unless a format says otherwise;
leading/trailing spaces ignored. Every question names its evidence
sources and its answer format. The README, SAFETY.md and the dataset
documentation files carry the scenario narrative; this file is
questions only.

Dataset v1.0.0 · incident INC-2417 · 21 core + 5 bonus.
Core questions are 1-21 (1 or 2 points, noted per question); bonuses
are 22-26 (1 point each).

## Core questions  (max 30 points, threshold 23)

1. (Origin relay IPv4) Email 1 has a four-hop `Received:` chain. Read the bottommost `Received:` header (the first server that received the message). What connecting IPv4 address does that header record in brackets?
Answer format: `IPv4 address`  (evidence: email-01-aitm-lure.eml)

2. (Relay-linked identity event) Use the IPv4 from the previous question. In `signins.json`, exactly one other event lists that same IPv4 as its source address. What is that event's `event_id`?
Answer format: `event ID`  (evidence: email-01-aitm-lure.eml, signins.json)

3. (Envelope vs DKIM mismatch) Email 2's Authentication-Results block shows the DKIM signature is valid yet the envelope sender domain differs from the DKIM signing domain. Submit the pair `<envelope-sender-domain>,<dkim-signing-domain>`.
Answer format: `domain,domain`  (evidence: email-02-device-code.eml)

4. (Ticket correlation) Email 2's body cites a service ticket number (`Ref: ...`). Which identity dataset file (by filename) contains an event whose properties repeat that exact ticket reference?
Answer format: `ticket-ref,filename`  (evidence: email-02-device-code.eml, identity-audit.json)

5. (Decoded destination) Email 1's link carries a URL-safe base64 parameter `u=`. Decode it. The resulting page is captured in `saved-page.html`. Submit only the URL path of the decoded destination.
Answer format: `/path/segment`  (evidence: email-01-aitm-lure.eml, saved-page.html)

6. (Request ID corroboration) The decoded URL contains `client_request_id=<value>`. That value appears verbatim in exactly one other JSON dataset (in a request_uri field). Submit `<dataset-filename>,<event_id>`.
Answer format: `filename,event-id`  (evidence: saved-page.html, connection-events.json)

7. (Rendered-only token) `login-page.html` and `saved-page.html` differ. The hidden `__tk` input is empty in the static duplicate but populated in the saved snapshot. What is that exact token value?
Answer format: `exact token string`  (evidence: login-page.html, saved-page.html)

8. (Timing-gate behavior) Read `page-source.js`: after the DON'T-RUN performance.now() wait loop resolves, what final behavior does the script produce? Choose exactly one: ALERT, REDIRECT, CONSOLE_ONLY, FORM_FREEZE.
Answer format: `enum token from fixed list`  (evidence: page-source.js, saved-page.html)

9. (Mailbox rule identity) Find the `NewInboxRule` record in `mailbox-audit.json` whose `client_ip` equals the suspicious sign-in's `source_ip` from the 08:47:32Z sign-in in `signins.json`. Submit `<rule_name>,<event_id>`.
Answer format: `rule-name,event-id`  (evidence: mailbox-audit.json, signins.json)

10. (Attacker IP row count) How many rows in `signins.json` list the suspicious sign-in's `source_ip` from the 08:47:32Z event as their own source_ip?
Answer format: `numeric value`  (evidence: signins.json)

11. (Alert linkage) Which alert in `alerts.json` lists the 08:47:32Z sign-in event as a `related_event_ids` member, and what severity did that alert carry?
Answer format: `alert-id,severity`  (evidence: alerts.json, signins.json)

12. (Device-code chain pair) In `identity-audit.json`, locate the `devicecode_token_grant` for dana.wexler. Which sign-in event in `signins.json` shares the SAME `correlation_id`? Submit `<correlation_id>,<sign-in event_id>`.
Answer format: `correlation-id,event-id`  (evidence: identity-audit.json, signins.json)

13. (Forwarding match) Somewhere in `mailbox-audit.json` a `SetForwarding` record gives an external forwarding address whose DOMAIN also appears as the sender domain of Email 1. Submit `<event_id>,<domain>`.
Answer format: `event-id,domain`  (evidence: mailbox-audit.json, email-01-aitm-lure.eml)

14. (IOC match to family) `redirect-hop-02.txt` lists one defanged, publicly reported domain. Confirm in the cited threat-intel report which phishing family it was associated with, submitting the exact defanged form plus the family name. Citation: Sekoia TDR, 'Tycoon 2FA: an in-depth analysis of the latest version of the AiTM phishing kit' (2025-03-25).
Answer format: `defanged-domain,family-name`  (evidence: redirect-hop-02.txt)

15. (MITRE technique id) The Darktrace report, 'Bypassing MFA: AiTM Tactics Exposed' (brighttrace.com/blog/mfa-under-attack-aitm-phishing-kits-abusing-legitimate-services, published 2025-04-29), maps its observed campaign to the credential-access technique it names 'Steal Web Session Cookie'. What is that technique's MITRE ATT&CK ID?
Answer format: `ATT&CK technique ID (e.g. T1xxx)`  (evidence: field-reference.md)

16. (Device-code actor) Microsoft Threat Intelligence (blog post published 2025-02-13, 'Storm-2372 conducts device code phishing campaign') documents active device-code phishing. Which tracked actor is named there for this technique? Use only the actor designation string.
Answer format: `actor designation (e.g._xx-####)`  (evidence: device-code-page.html)

17. (Sorted persistence chain) Provide the event IDs of the malicious sign-in, the malicious 'NewInboxRule' creation and the malicious 'SetForwarding' mutation above (the attacker's first-to-last persistence steps), in ascending chronological order, comma-separated.
Answer format: `event-id_1,event-id_2,event-id_3 (in order)`  (evidence: signins.json, mailbox-audit.json, identity-audit.json)

18. (Delivery / click / sign-in ladder) Sort the three events that open the attack chain into chronological order: mail delivery (mailbox-audit), the initial click connection (network), and the first successful malicious sign-in (identity). Submit all three `event_id`s comma-separated ascending.
Answer format: `event-id_1,event-id_2,event-id_3 (in order)`  (evidence: mailbox-audit.json, connection-events.json, signins.json)

19. (Incident classification) Based only on the supplied dataset, choose the strongest classification that your correlation supports. Choose exactly one: PHISHING_CLICK_ONLY, PHISHING_REPORT_ONLY, SESSION_HIJACKED, DATA_EXFIL_CONFIRMED.
Answer format: `enum token from fixed list`  (evidence: signins.json, mailbox-audit.json)

20. (Legitimate security email) One of the three emails is a legitimate contracted-vendor digest. Which Message-ID belongs to it? (Angle brackets optional.) Note: the vendor relationship is documented elsewhere in the dataset.
Answer format: `full message-id`  (evidence: email-03-legitimate-review.eml, evidence-inventory.md)

21. (Benign older rule) `mailbox-audit.json` contains several `NewInboxRule` events. Which one was created well before the current incident window and is therefore unrelated to it?
Answer format: `event-id`  (evidence: mailbox-audit.json)

## Bonus questions  (max 5 points)

22. (Route stamp decode) Email 1 carries the header `X-Msg-Route: <base64>`. Decode it and submit the plaintext value.
Answer format: `exact decoded token`  (evidence: email-01-aitm-lure.eml)

23. (Node token decode) `page-source.js` hides a runtime value via its XOR-based `_dk` helper (the array is used only to compute `KIT.counters.node`, which the DOM shows in the saved snapshot's node field). Decode it and submit the plaintext value.
Answer format: `exact decoded token`  (evidence: page-source.js, saved-page.html)

24. (Missing telemetry) Which step is definitively NOT captured anywhere in the supplied dataset, even though the incident's shape implies the real-world step had to occur? Choose exactly one: DEVICE_CODE_GENERATION, MFA_PROMPT_DISPLAYED, INBOX_RULE_ACTIVATION, SESSION_COOKIE_CAPTURE.
Answer format: `enum token from fixed list`  (evidence: evidence-inventory.md)

25. (Earliest audit timestamp) In `identity-audit.json`, which is the chronologically EARLIEST `timestamp_utc` value found among ALL rows in the file?
Answer format: `ISO 8601 UTC timestamp string`  (evidence: identity-audit.json)

26. (Received-hop counts) How many `Received:` headers does Email 1 have vs Email 3 respectively? Submit `<count_email1>,<count_email3>`.
Answer format: `n,n`  (evidence: email-01-aitm-lure.eml, email-03-legitimate-review.eml)

## Final flag

Four flag fragments fall out of four independent evidence
categories: (F1) email/header evidence, (F2) static web
artifact, (F3) identity/audit-log correlation, (F4) published
threat-intelligence reference. F3 and F4 correspond to core
questions 12 and 15; F1 and F2 are bonus decodes (questions
22 and 23).
Once your core score clears the threshold, submit all four
fragment codes on the lab portal to release the final flag.
