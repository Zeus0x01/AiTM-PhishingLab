# Observed vs inferred — analysis discipline (dataset v1.1.0)

This package mixes **two parallel access paths**. Keep them separate when writing findings.

## Path A — browser / login-replica chain (AiTM *style*)

**Observed in the dataset**

- Document-notification lure delivery and hop headers
- Static redirect-hop captures and login-page replica / saved snapshot / page script (inert)
- Network observation of the decoded sign-in URL (`client_request_id` present)
- High-risk successful cloud sign-in from a suspicious source IP shortly after
- Mailbox persistence: new inbox rule + external forwarding from that same source IP

**Not directly observed**

- A live reverse proxy or Adversary-in-the-Middle kit intercepting traffic
- Session-cookie capture, cookie replay, or token reflection from a proxy
- Proof that the first interactive sign-in and any later token use are the *same* browser session object beyond shared IP / timing / correlation fields present in the logs

**Reasonable inference (label as inference)**

- The login-replica + timing + success from an unusual client is *consistent with* credential or session abuse following a phishing click
- AiTM *would* explain MFA-satisfied success if a proxy had relayed an authenticated session — but that mechanism is **not logged here**

## Path B — device-code chain

**Observed in the dataset**

- Second message using a device-activation pretext
- Identity-audit `devicecode_token_grant` with support ticket echoed from the message body
- Sign-in row with `authentication_method: device_code` sharing a correlation id with that grant
- Device registration from the same suspicious source IP

**Not the same as Path A**

- Device-code phishing is a **distinct** technique (user is induced to enter a code at a legitimate identity provider)
- Do not collapse Path B into “AiTM cookie theft” without evidence of a proxy session

## Classification guidance (maps to Q19 / Q24)

| Label | Meaning in this lab |
|-------|---------------------|
| **Observed** | Present as a row, header, or static artifact |
| **Inferred** | Best explanation of multiple observed facts; still an analyst judgment |
| **Not directly observed** | Common in real AiTM/device-code campaigns but absent from this package (e.g. `SESSION_COOKIE_CAPTURE`) |

`SESSION_HIJACKED` as a **working hypothesis** is defensible from: phishing lure → replica interaction → MFA-satisfied success from attacker-controlled IP → mailbox takeover actions. It is **not** a claim that a cookie-capture event was recorded.

## Threat-intel naming (maps to Q16)

Public actor designations (e.g. Microsoft `Storm-2372` for device-code campaigns) are **report vocabulary**. Matching a technique family is not the same as attributing **INC-2417** to that actor.
