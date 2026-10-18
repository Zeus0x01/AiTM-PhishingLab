#!/usr/bin/env python3
"""Zeus0x01 AiTM Phishing Investigation Lab — deterministic dataset builder.

Generates every trainee-facing artifact, documentation file, the instructor
pack/question bank, the optional verification portal, and the downloadable
evidence ZIP with a SHA-256 manifest.

Build sources live in sources/ and are NEVER shipped to trainees.
All timestamps are UTC (ISO 8601). All IP addresses are RFC 5737
documentation ranges unless noted. All domains are synthetic reserved
".example" names, except one verified, defanged public IOC from Sekoia's
Tycoon 2FA report (kept defanged; never resolvable or contacted).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import textwrap
import zipfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ----------------------------------------------------------------------------
# Canonical scenario constants (single source of truth)
# ----------------------------------------------------------------------------
DS_VERSION = "1.0.0"
CORE_THRESH = 23            # core points required to release the flag
DS_NAME = "Zeus0x01-AiTM-Investigation"
CASE_ID = "INC-2417"
PORTAL_CASE = "2417-LSPR-A9F7"

CORP_DOMAIN = "larkspur-systems.example"
VENDOR_DOMAIN = "audit-trail-software.example"
KIT_MAILER_DOMAIN = "docshare-online.example"
HOP1_DOMAIN = "docs-notify.example"
HOP2_DOMAIN = "secure-link-verify.example"
KIT_PAGE_DOMAIN = "sso.docsview-online.example"
ITDESK_DOMAIN = "larkspur-itdesk.example"
ENVELOPE_DOMAIN_E2 = "larkspur-mail-relay-02.example"
REAL_IOC_DEFANGED = "beacon.diremsto[.]com"        # Sekoia Tycoon 2FA IOC table
DEFANG_PLACEHOLDER = "beacon.diremsto[.]com"       # keep defanged everywhere

IP_RELAY = "203.0.113.44"       # E1 originating relay (mta1.docshare-online.example)
IP_ATTACKER = "203.0.113.87"    # attacker sign-in source
IP_KIT_HOP1 = "203.0.113.71"
IP_KIT_HOP2 = "203.0.113.72"
IP_KIT_PAGE = "203.0.113.73"
IP_DANA_WS = "198.51.100.44"
IP_MARCUS_WS = "198.51.100.19"
IP_SARA_WS = "198.51.100.22"
IP_VEHICLE_GW = "198.51.100.12"
IP_VENDOR = "192.0.2.51"
IP_NOISE = "203.0.113.62"

USER_DANA = "dana.wexler"
USER_DANA_UPN = "dana.wexler@larkspur-systems.example"
USR_DANA = "USR-11018"
USR_MARCUS = "USR-10091"
USR_SARA = "USR-10088"
USR_SVC = "USR-10023"
USR_ADMIN = "USR-10002"

MSG_ID_E1 = "<7e9f2c44.5b1a.20260914090147@mta1.docshare-online.example>"
MSG_ID_E2 = "<50a3d7b1-22c9-4a10-a1d8-20260915080720@mail.larkspur-itdesk.example>"
MSG_ID_E3 = "<20260915T080455Z-1d3e6b8c2@mail.audit-trail-software.example>"

TICKET_E2 = "SR-88031"
DEVICE_CODE = "DCP-4183-KW7"
ROUTE_STAMP_B64 = "TUtELTIwMjYtUjQ4MA=="       # base64("MKD-2026-R480")
ROUTE_STAMP = "MKD-2026-R480"

SAVED_URL_QUERY = ("client_request_id=CID-20260914-5F2A-4B71"
                   "&logid=LOGID-2F8A-0931")
SAVED_URL = ("https://" + KIT_PAGE_DOMAIN + "/signin/azure_sso?"
             + SAVED_URL_QUERY)
CID = "CID-20260914-5F2A-4B71"
LOGID = "LOGID-2F8A-0931"
TK_TOKEN = "7K2-TOK-R9X4"
NODE_TOKEN = "NODE-4A9-7717"
CORR_AITM = "CORR-9F3A-11"      # E1 family: session + mailbox rule + forwarding
CORR_DEV = "CORR-2E71-05"       # E2 family: device-code grant + registration

XOR_KEY = 0x2A  # obfuscation key used in page-source.js (documented decode)

E1_URL_B64 = base64.urlsafe_b64encode(SAVED_URL.encode()).decode().rstrip("=")

# ----------------------------------------------------------------------------
# Small text helpers
# ----------------------------------------------------------------------------

def xor_obfuscate(s: str, key: int = XOR_KEY) -> list[int]:
    return [ord(c) ^ key for c in s]


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def w(relpath: str, text: str, binary: bool = False) -> str:
    """Write file with LF endings; return absolute path."""
    path = os.path.join(ROOT, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if binary else "w"
    with open(path, mode, newline="" if binary else "\n",
              encoding=None if binary else "utf-8") as fh:
        fh.write(text)
    return path


def join_js_array(values: list[int]) -> str:
    return ",".join(str(v) for v in values)


# ----------------------------------------------------------------------------
# Email artifacts (.eml, CRLF, RFC 5322 style)
# ----------------------------------------------------------------------------

def eml(headers_lines: list[str], body_lines: list[str]) -> str:
    raw = "\r\n".join(headers_lines) + "\r\n\r\n" + "\r\n".join(body_lines) + "\r\n"
    return raw


def build_email_1() -> str:
    headers = [
        "Return-Path: <maildaemon@" + KIT_MAILER_DOMAIN + ">",
        "Delivered-To: " + USER_DANA_UPN,
        "Received: from mail-gw." + CORP_DOMAIN + " ([" + IP_VEHICLE_GW + "]) by mx-in." + CORP_DOMAIN,
        "        with Microsoft SMTP Server id 15.1.2507.39; Mon, 14 Sep 2026 09:03:38 +0000",
        "Received: from edge-relay2." + KIT_MAILER_DOMAIN + " ([" + "203.0.113.45" + "]) by mail-gw." + CORP_DOMAIN,
        "        with ESMTPS id hl7-d3ec2199; Mon, 14 Sep 2026 09:02:51 +0000",
        "Received: from mta1." + KIT_MAILER_DOMAIN + " ([" + IP_RELAY + "]) by edge-relay2." + KIT_MAILER_DOMAIN,
        "        with ESMTP id 4b7f-91ac-2201; Mon, 14 Sep 2026 09:01:52 +0000",
        "Authentication-Results: mx-in." + CORP_DOMAIN + ";",
        "	spf=pass smtp.mailfrom=" + KIT_MAILER_DOMAIN + ";",
        "	dkim=pass header.d=" + KIT_MAILER_DOMAIN + " header.s=dk2026a header.b=XcP9nQ2T;",
        "	dmarc=pass header.from=" + KIT_MAILER_DOMAIN + " policy.pct=100",
        "X-Msg-Id: 4b7f-91ac-2201-4c4e",
        "X-Msg-Route: " + ROUTE_STAMP_B64,
        "X-Mailer: DocShare-Notification-Service/4.2 build 2260",
        "X-Priority: 3",
        "Date: Mon, 14 Sep 2026 09:01:47 +0000",
        "From: \"Larkspur Secure Documents\" <no-reply@" + KIT_MAILER_DOMAIN + ">",
        "Reply-To: billing-doccenter@" + KIT_MAILER_DOMAIN,
        "To: <" + USER_DANA_UPN + ">",
        "Subject: New shared documents require your secure sign-in",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=\"utf-8\"",
        "Content-Transfer-Encoding: 7bit",
        "Message-ID: " + MSG_ID_E1,
    ]
    body = [
        "Hello Dana,",
        "",
        "You have 2 new shared documents awaiting your review:",
        "  - Q3 FY-Forecast-revision.xlsx   (from m.hale)",
        "  - Vendor-STG-2841-terms.pdf      (from procurement)",
        "",
        "Because these files contain confidential contract data, they are available",
        "through your secure documents portal. Use the private review link below to",
        "open the workspace and sign in with your corporate account:",
        "",
        "    https://" + HOP1_DOMAIN + "/file/view?u=" + E1_URL_B64,
        "",
        "The workspace link remains active for 72 hours. After 72 hours it will be",
        "recycled automatically by the document retention schedule.",
        "",
        "Regards,",
        "Larkspur Secure Documents Center",
        "Automated notification service - do not discard this message",
    ]
    return eml(headers, body)


def build_email_2() -> str:
    headers = [
        "Return-Path: <bounces@" + ENVELOPE_DOMAIN_E2 + ">",
        "Delivered-To: " + USER_DANA_UPN,
        "Received: from mail-gw." + CORP_DOMAIN + " ([" + IP_VEHICLE_GW + "]) by mx-in." + CORP_DOMAIN,
        "        with Microsoft SMTP Server id 15.1.2507.39; Tue, 15 Sep 2026 08:09:20 +0000",
        "Received: from mta." + ENVELOPE_DOMAIN_E2 + " ([" + "198.51.100.201" + "]) by mail-gw." + CORP_DOMAIN,
        "        with ESMTPS id 77aa9c31-41bd; Tue, 15 Sep 2026 08:09:18 +0000",
        "Authentication-Results: mail-gw." + CORP_DOMAIN + ";",
        "	spf=softfail smtp.mailfrom=" + ENVELOPE_DOMAIN_E2 + ";",
        "	dkim=pass header.d=" + ITDESK_DOMAIN + " header.s=itdesk2026 header.b=oP4qLd1N;",
        "	dmarc=fail header.from=" + ITDESK_DOMAIN + " reason=\"envelope domain not aligned\"",
        "X-Mailer: ITDesk-Notification-Hub/2.11",
        "X-Desk-Queue: sr-escalation",
        "Date: Tue, 15 Sep 2026 08:07:12 +0000",
        "From: \"Larkspur IT Service Desk\" <m365-admin@" + ITDESK_DOMAIN + ">",
        "Reply-To: helpdesk-confirm@" + ITDESK_DOMAIN,
        "To: <" + USER_DANA_UPN + ">",
        "Subject: Action needed: license renewal block on your account",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=\"utf-8\"",
        "Content-Transfer-Encoding: 7bit",
        "Message-ID: " + MSG_ID_E2,
    ]
    body = [
        "Hi Dana,",
        "",
        "Ref: " + TICKET_E2,
        "",
        "Our renewal job could not complete against your account today. While the",
        "sync is pending, Microsoft licensing treats your mailbox as unlicensed and",
        "blocks document access.",
        "",
        "To clear the block, complete the device activation step now:",
        "  1. Open the device activation page shown below.",
        "  2. Enter activation code: " + DEVICE_CODE,
        "  3. Sign in with your corporate account when prompted.",
        "",
        "    https://" + KIT_PAGE_DOMAIN + "/device-login",
        "",
        "NOTE: the activation page may mention 'Microsoft 365'. This is expected;",
        "licensing is validated to the same tenant as your mailbox.",
        "",
        "If the block is not cleared within 4 hours, the renewal job escalates and a",
        "temporary mailbox lock is applied by our service automation.",
        "",
        "Larkspur IT Service Desk (automated ticket reply)",
    ]
    return eml(headers, body)


def build_email_3() -> str:
    headers = [
        "Return-Path: <noreply@" + VENDOR_DOMAIN + ">",
        "Delivered-To: " + USER_DANA_UPN,
        "Received: from mail-gw." + CORP_DOMAIN + " ([" + IP_VEHICLE_GW + "]) by mx-in." + CORP_DOMAIN,
        "        with Microsoft SMTP Server id 15.1.2507.39; Tue, 15 Sep 2026 08:05:12 +0000",
        "Received: from smtp-relay-b." + VENDOR_DOMAIN + " ([" + "192.0.2.61" + "]) by mail-gw." + CORP_DOMAIN,
        "        with ESMTPS id 71f4be2c-90d1; Tue, 15 Sep 2026 08:05:09 +0000",
        "Received: from smtp-relay-a." + VENDOR_DOMAIN + " ([" + "192.0.2.60" + "]) by smtp-relay-b." + VENDOR_DOMAIN,
        "        with ESMTPS id 82c9af04-55e8; Tue, 15 Sep 2026 08:05:06 +0000",
        "Received: from listworker-01.internal.audit-trail (10.44.7.28) by smtp-relay-a." + VENDOR_DOMAIN,
        "        with ESMTPS id 5392db8a-11c4; Tue, 15 Sep 2026 08:05:02 +0000",
        "Authentication-Results: mx-in." + CORP_DOMAIN + ";",
        "	spf=pass smtp.mailfrom=" + VENDOR_DOMAIN + ";",
        "	dkim=pass header.d=" + VENDOR_DOMAIN + " header.s=ats2026 header.b=rNq7Wk3F;",
        "	dmarc=pass header.from=" + VENDOR_DOMAIN + " policy.pct=100",
        "X-Mailer: AuditTrail-Weekly-Digest-Service",
        "List-Unsubscribe: <mailto:unsubscribe@" + VENDOR_DOMAIN + "?subject=weekly-digest>" ,
        "Date: Tue, 15 Sep 2026 08:04:57 +0000",
        "From: Audit-Trail Software <noreply@" + VENDOR_DOMAIN + ">",
        "Reply-To: support@" + VENDOR_DOMAIN,
        "To: <" + USER_DANA_UPN + ">",
        "Subject: Weekly security review: confirm your recovery settings",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=\"utf-8\"",
        "Content-Transfer-Encoding: 7bit",
        "Message-ID: " + MSG_ID_E3,
    ]
    body = [
        "Hello Dana Wexler,",
        "",
        "Audit-Trail Software (your contracted IT-control vendor) completed the",
        "scheduled weekly review against your Larkspur Systems identity.",
        "",
        "One item requires your confirmation before it is closed out automatically:",
        " - Recovery phone on file will expire in 6 days.",
        "",
        "Review the status in the vendor portal:",
        "    https://portal." + VENDOR_DOMAIN + "/secure-check",
        "",
        "This digest runs weekly. You can unsubscribe any time from the portal or by",
        "replying to this address.",
        "",
        "Audit-Trail Software, Notifications",
    ]
    return eml(headers, body)


# ----------------------------------------------------------------------------
# Static web artifacts (inert; no external resources, zero network requests)
# ----------------------------------------------------------------------------

def build_redirect_hop_1():
    t = "2026-09-15T08:44:10Z"
    lines = [
        "# redirect-hop-01.txt -- static capture record (NOT a live redirect).",
        "# This file documents one hop observed in the simulated chain. It is an",
        "# analyst-authored, sanitized copy: no request is made by reading this file.",
        "capture_id:      CAP-H1-" + "2C4d9Ef1",
        "observed_at_utc: " + t,
        "client_ip:       " + IP_DANA_WS,
        "method:          GET",
        "request_url:     https://" + HOP1_DOMAIN + "/file/view?u=" + E1_URL_B64,
        "response_code:   302",
        "location:        https://" + HOP2_DOMAIN + "/s/2C4d9Ef1a3B7",
        "server_header:   nginx/1.24.0 (dented-log-01)",
        "notes:           hop originated from the docs-notify.example link in email-01.",
    ]
    return "\n".join(lines) + "\n"


def build_redirect_hop_2():
    t = "2026-09-15T08:44:12Z"
    lines = [
        "# redirect-hop-02.txt -- static capture record (NOT a live redirect).",
        "# This file documents the next hop in the simulated chain.",
        "# Sanitized by the analyzing analyst: hostile indicators are defanged and",
        "# must never be re-hosted, resolved, or contacted.",
        "capture_id:      CAP-H2-91B7a20c",
        "observed_at_utc: " + t,
        "client_ip:       " + IP_DANA_WF if False else "client_ip:       " + IP_DANA_WS,
        "method:          GET",
        "request_url:     https://" + HOP2_DOMAIN + "/s/2C4d9Ef1a3B7",
        "response_code:   302",
        "location:        " + SAVED_URL,
        "server_header:   " + "nginx/1.22.1 (kit-edge-03)",
        "page_refs:       tracking/diagnostic host referenced by page script:",
        "                 " + REAL_IOC_DEFANGED + "  (defanged; public IOC; see SAFETY.md)",
        "notes:           target matches the Sign-in replica captured in saved-page.html.",
    ]
    return "\n".join(lines) + "\n"


def build_page_source_js():
    node_obf = xor_obfuscate(NODE_TOKEN)
    tk_obf = xor_obfuscate(TK_TOKEN, 0x34)
    js_head = """\
/* page-source.js -- static analysis artifact (no submission, no network).
 * Field-reference note: `_dk()` is a byte-wise XOR helper; arrays below are
 * obfuscated strings that reconstruct locally, in-page, and stay there.
 */
var KIT = {
  route: { op: 0 },
  wait_ms: 640,
  decoy_captcha: { enabled: true, region: "adsbox_l" },
  counters: { node: null, ticket: null }
};

function _dk(arr, k) {
  var s = "";
  for (var i = 0; i < arr.length; i++) {
    s += String.fromCharCode(arr[i] ^ k);
  }
  return s;
}

"""
    js = (js_head
          + "var _nodeArr = [" + join_js_array(node_obf) + "];\n"
          + "var _tkArr   = [" + join_js_array(tk_obf) + "];\n"
          + """\
var _nodeKey = 0x2a;
var _tkKey   = 0x34;

/* Local-only state machine; the page performs zero live network calls */
(function () {
  var t0 = performance.now();
  var probe = 0;
  while (performance.now() - t0 < KIT.wait_ms) { probe++; }
  if (probe > 0) {
    document.body.setAttribute("data-stage", "rippling");
    console.log("[kit] captcha-shadow ready; probing finished in", probe, "ticks");
  } else {
    console.log("[kit] probing failed; no local evaluation available");
  }
  KIT.counters.node = _dk(_nodeArr, _nodeKey);
  KIT.counters.ticket = _dk(_tkArr, _tkKey);
  document.getElementById("sig-in-mt").textContent = "Sign in securely";
  var el = document.getElementById("st-n");
  if (el) { el.textContent = KIT.counters.node; }
  console.log("[kit] local-diagnostics (no network): stage=", document.body.getAttribute("data-stage"));
  console.log("[kit] node-stamp=", KIT.counters.node, " ticket-stamp=", KIT.counters.ticket);
  window.__stageData = "CONSOLE_ONLY";
})();
""")
    return js


def build_login_page():
    base = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Documents Sign-in</title>
<style>
  body { font-family: system-ui, Arial, sans-serif; background:#eef1f5; margin:0; }
  .card { max-width: 420px; margin: 70px auto; background:#fff; border:1px solid #d8dde3;
          border-radius: 8px; padding: 30px 34px; }
  h1 { font-size: 20px; margin: 0 0 6px 0; }
  p.lead { font-size: 13px; color:#4a5568; margin-top: 0; }
  label { display: block; font-size: 12px; margin: 12px 0 4px 0; }
  input[type=text], input[type=password] { width: 100%; padding: 9px 10px; border: 1px solid #b8c0c9;
          border-radius: 4px; box-sizing: border-box; font-size: 14px; }
  button { margin-top: 18px; background: #14436e; border: 0; color:#fff; padding: 10px 16px;
           border-radius: 4px; font-size: 14px; cursor: pointer; }
  .captcha { background: #f6f7f9; border: 1px dashed #b8c0c9; padding: 10px 12px;
             font-size: 12px; color: #4a5568; }
  .st-n { font-family: monospace; font-size: 11px; color: #6b7280; }
</style>
</head>
<body data-stage="idle">
<div class="card">
  <h1>Secure Documents Sign-in</h1>
  <p class="lead">Review your pending documents. Sign in with your corporate account.</p>
  <form method="get" onsubmit="return false;">
    <label for="user">Corporate account</label>
    <input type="text" id="user" name="user" autocomplete="off">
    <label for="pass">Password</label>
    <input type="password" id="pass" name="pass" autocomplete="off">
    <div><input type="hidden" id="__tk" name="__tk" value=""></div>
    <div class="captcha">Captcha state: <span id="cap">probing</span>, node: <span class="st-n" id="st-n"></span></div>
    <div class="mfa-step" data-step="mfa" style="margin-top:14px;font-size:12px;color:var(--ink,#22303f);">
      Step 2 of 2 &mdash; approve sign-in request (second factor):
      <button type="button" disabled>Approve</button> or
      <button type="button" disabled>Use code instead</button>
    </div>
    <button type="submit" id="sig-in-mt">Sign in securely</button>
  </form>
  <p style="font-size:11px;color:#8a919a;margin-top:20px;">
    Static analysis artifact. No submission occurs; no network request is made.
  </p>
</div>
<script src="page-source.js"></script>
</body>
</html>
"""
    return base


def build_saved_page():
    base = build_login_page().replace(
        '<body data-stage="idle">',
        '<body data-stage="rippling">').replace(
        'value="">', 'value="' + TK_TOKEN + '">').replace(
        '<meta charset="utf-8">',
        '<meta charset="utf-8">\n<!-- dev-snapshot metadata: saved_from="'
        + SAVED_URL + '"; saved_at="2026-09-15T08:46:14Z"; case="' + CASE_ID + '" -->'
    )
    # remove the live script reference in the saved snapshot -- page already ran
    base = base.replace('<script src="page-source.js"></script>', '')
    return base


def build_device_code_page():
    t = "2026-09-15T08:14:22Z"
    return """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Device activation</title>
<style>
  body { font-family: system-ui, Arial, sans-serif; background:#161b22; color:#e6edf3; margin:0; }
  .box { max-width: 380px; margin: 90px auto; border:1px solid #30363d; border-radius:8px;
         padding: 26px 30px; }
  h1 { font-size: 19px; margin: 0 0 10px 0; }
  p { font-size: 13px; color: #9aa4b2; }
  input { width: 100%; padding: 9px 10px; border:1px solid #3d444d; background:#0d1117;
          color:#e6edf3; border-radius:4px; font-size:15px; }
  .btn { margin-top: 14px; background: #1f6feb; color:#fff; border:0; padding: 9px 16px;
         border-radius:4px; font-size: 14px; pointer-events: none; }
  .meta { margin-top: 22px; font-size: 11px; color:#6e7681; font-family: monospace; }
</style>
</head>
<body data-stage="awaiting">
<div class="box">
  <h1>Device activation</h1>
  <p>Enter the activation code shown in your service ticket to continue.</p>
  <input type="text" value="""" + DEVICE_CODE + """" readonly>
  <button class="btn" type="submit" disabled>Activate device</button>
  <p class="meta">snapshot ref: """ + t + """ (case """ + CASE_ID + """) -- static,
  code shown for analysis only; no form action; no network request possible</p>
</div>
</body>
</html>
"""


# ----------------------------------------------------------------------------
# JSON / JSONL datasets
# ----------------------------------------------------------------------------

def build_signins():
    return {
        "dataset": "identity_signins",
        "schema_version": "1.0",
        "incident_ref": CASE_ID,
        "provenance": "synthetic training data; not a genuine security-product export",
        "records": [
            {
                "event_id": "EVT-58101",
                "timestamp_utc": "2026-09-15T08:31:05Z",
                "user_id": USR_DANA,
                "user_principal_name": USER_DANA_UPN,
                "source_ip": IP_DANA_WS,
                "application": "Office 365 SharePoint Online",
                "authentication_result": "success",
                "authentication_method": "password",
                "risk_level": "low",
                "risk_state": "clean",
                "correlation_id": None,
                "device_id": "LSPR-D1193",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                "mfa_claim": "satisfied",
            },
            {
                "event_id": "EVT-58102",
                "timestamp_utc": "2026-09-15T08:40:12Z",
                "user_id": USR_MARCUS,
                "user_principal_name": "marcus.hale@" + CORP_DOMAIN,
                "source_ip": IP_MARCUS_WS,
                "application": "Office 365 SharePoint Online",
                "authentication_result": "success",
                "authentication_method": "password",
                "risk_level": "low",
                "risk_state": "clean",
                "correlation_id": None,
                "device_id": "LSPR-D0877",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            },
            {
                "event_id": "EVT-58107",
                "timestamp_utc": "2026-09-14T09:01:52Z",
                "user_id": USR_SVC,
                "user_principal_name": "svc-hygiene@" + CORP_DOMAIN,
                "source_ip": IP_RELAY,
                "application": "MailCorrelator-Connector",
                "authentication_result": "failed",
                "authentication_method": "password",
                "risk_level": "medium",
                "risk_state": "at_risk",
                "correlation_id": None,
                "device_id": None,
                "user_agent": "MailCorrelator-Connector/3.3.0",
                "failure_reason": "invalid_credentials",
            },
            {
                "event_id": "EVT-58112",
                "timestamp_utc": "2026-09-15T08:43:50Z",
                "user_id": USR_DANA,
                "user_principal_name": USER_DANA_UPN,
                "source_ip": IP_ATTACKER,
                "application": "Office 365 SharePoint Online",
                "authentication_result": "failed",
                "authentication_method": "password",
                "risk_level": "high",
                "risk_state": "at_risk",
                "correlation_id": None,
                "device_id": None,
                "user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36",
                "failure_reason": "invalid_password",
            },
            {
                "event_id": "EVT-58103",
                "timestamp_utc": "2026-09-15T08:47:32Z",
                "user_id": USR_DANA,
                "user_principal_name": USER_DANA_UPN,
                "source_ip": IP_ATTACKER,
                "application": "Microsoft Exchange Online",
                "authentication_result": "success",
                "authentication_method": "password",
                "risk_level": "high",
                "risk_state": "at_risk",
                "correlation_id": CORR_AITM,
                "device_id": None,
                "user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36",
                "mfa_claim": "satisfied",
            },
            {
                "event_id": "EVT-58115",
                "timestamp_utc": "2026-09-15T08:59:01Z",
                "user_id": USR_DANA,
                "user_principal_name": USER_DANA_UPN,
                "source_ip": IP_ATTACKER,
                "application": "Microsoft Exchange Online",
                "authentication_result": "success",
                "authentication_method": "device_code",
                "risk_level": "high",
                "risk_state": "at_risk",
                "correlation_id": CORR_DEV,
                "device_id": None,
                "user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36",
            },
            {
                "event_id": "EVT-58120",
                "timestamp_utc": "2026-09-15T09:10:02Z",
                "user_id": USR_SARA,
                "user_principal_name": "sara.okoye@" + CORP_DOMAIN,
                "source_ip": IP_SARA_WS,
                "application": "Office 365 SharePoint Online",
                "authentication_result": "success",
                "authentication_method": "password",
                "risk_level": "low",
                "risk_state": "clean",
                "correlation_id": None,
                "device_id": "LSPR-D0990",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            },
            {
                "event_id": "EVT-58125",
                "timestamp_utc": "2026-09-15T09:55:33Z",
                "user_id": USR_SARA,
                "user_principal_name": "sara.okoye@" + CORP_DOMAIN,
                "source_ip": IP_NOISE,
                "application": "Office 365 SharePoint Online",
                "authentication_result": "failed",
                "authentication_method": "password",
                "risk_level": "low",
                "risk_state": "clean",
                "correlation_id": None,
                "device_id": None,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                "failure_reason": "invalid_password",
            },
        ],
    }


def build_identity_audit():
    return {
        "dataset": "identity_audit",
        "schema_version": "1.0",
        "incident_ref": CASE_ID,
        "provenance": "synthetic training data; not a genuine security-product export; "
                      "field names are vendor-agnostic but modeled on Entra ID audit shape",
        "records": [
            {
                "event_id": "EVT-59011",
                "timestamp_utc": "2026-09-15T08:11:33Z",
                "user_id": USR_SARA,
                "user_principal_name": "sara.okoye@" + CORP_DOMAIN,
                "category": "authorization",
                "operation": "consent_granted",
                "resource": "AuditTrail Compliance Reader",
                "result": "success",
                "source_ip": IP_SARA_WS,
                "correlation_id": None,
            },
            {
                "event_id": "EVT-59012",
                "timestamp_utc": "2026-09-15T08:59:02Z",
                "user_id": USR_DANA,
                "user_principal_name": USER_DANA_UPN,
                "category": "authorization",
                "operation": "devicecode_token_grant",
                "resource": "Microsoft Exchange Online",
                "scope": "mail.readwrite mail.send",
                "result": "success",
                "source_ip": IP_ATTACKER,
                "correlation_id": CORR_DEV,
                "support_ticket": TICKET_E2,
            },
            {
                "event_id": "EVT-59013",
                "timestamp_utc": "2026-09-15T09:02:10Z",
                "user_id": USR_DANA,
                "user_principal_name": USER_DANA_UPN,
                "category": "account_settings",
                "operation": "mfa_method_added",
                "resource": "Authentication method -- email",
                "result": "success",
                "source_ip": IP_ATTACKER,
                "correlation_id": CORR_AITM,
            },
            {
                "event_id": "EVT-59015",
                "timestamp_utc": "2026-09-15T09:14:57Z",
                "user_id": USR_DANA,
                "user_principal_name": USER_DANA_UPN,
                "category": "account_settings",
                "operation": "device_registration",
                "resource": "LSPR-DWIN-D2026",
                "result": "success",
                "source_ip": IP_ATTACKER,
                "correlation_id": CORR_DEV,
            },
            {
                "event_id": "EVT-59021",
                "timestamp_utc": "2026-09-14T17:40:10Z",
                "user_id": USR_MARCUS,
                "user_principal_name": "marcus.hale@" + CORP_DOMAIN,
                "category": "account_settings",
                "operation": "password_changed",
                "resource": "Larkspur identity",
                "result": "success",
                "source_ip": IP_MARCUS_WS,
                "correlation_id": None,
            },
            {
                "event_id": "EVT-59022",
                "timestamp_utc": "2026-09-14T10:52:20Z",
                "user_id": USR_ADMIN,
                "user_principal_name": "soc-admin@" + CORP_DOMAIN,
                "category": "account_settings",
                "operation": "conditional_access_policy_updated",
                "resource": "CAP-TravelNotification",
                "result": "success",
                "source_ip": IP_DANA_WS,
                "correlation_id": None,
            },
        ],
    }


def build_mailbox_audit():
    return {
        "dataset": "mailbox_audit",
        "schema_version": "1.0",
        "incident_ref": CASE_ID,
        "provenance": "synthetic training data; not a genuine security-product export",
        "records": [
            {
                "event_id": "EVT-58311",
                "timestamp_utc": "2026-09-14T09:03:41Z",
                "actor_user_id": "system",
                "actor_upn": None,
                "action": "EmailReceived",
                "target_user_id": USR_DANA,
                "target_upn": USER_DANA_UPN,
                "message_id": MSG_ID_E1,
                "client_ip": None,
                "correlation_id": None,
            },
            {
                "event_id": "EVT-58312",
                "timestamp_utc": "2026-09-15T08:05:30Z",
                "actor_user_id": "system",
                "actor_upn": None,
                "action": "EmailReceived",
                "target_user_id": USR_DANA,
                "target_upn": USER_DANA_UPN,
                "message_id": MSG_ID_E3,
                "client_ip": None,
                "correlation_id": None,
            },
            {
                "event_id": "EVT-58313",
                "timestamp_utc": "2026-09-15T08:09:22Z",
                "actor_user_id": "system",
                "actor_upn": None,
                "action": "EmailReceived",
                "target_user_id": USR_DANA,
                "target_upn": USER_DANA_UPN,
                "message_id": MSG_ID_E2,
                "client_ip": None,
                "correlation_id": None,
            },
            {
                "event_id": "EVT-58314",
                "timestamp_utc": "2026-09-15T08:59:30Z",
                "actor_user_id": USR_DANA,
                "actor_upn": USER_DANA_UPN,
                "action": "NewInboxRule",
                "target_user_id": USR_DANA,
                "target_upn": USER_DANA_UPN,
                "rule_name": "SecArchives",
                "rule_conditions": {"subject_contains": ["security review", "audit"]},
                "rule_actions": ["mark_as_read", "move_to_folder"],
                "rule_destination_folder": "Archive-Process",
                "client_ip": IP_ATTACKER,
                "correlation_id": CORR_AITM,
                "message_id": None,
            },
            {
                "event_id": "EVT-58315",
                "timestamp_utc": "2026-09-15T09:02:10Z",
                "actor_user_id": USR_DANA,
                "actor_upn": USER_DANA_UPN,
                "action": "SetForwarding",
                "target_user_id": USR_DANA,
                "target_upn": USER_DANA_UPN,
                "forwarding_address": "billing-ops-sync@" + KIT_MAILER_DOMAIN,
                "forwarding_type": "smtp",
                "client_ip": IP_ATTACKER,
                "correlation_id": CORR_AITM,
                "message_id": None,
            },
            {
                "event_id": "EVT-58316",
                "timestamp_utc": "2025-03-04T09:14:22Z",
                "actor_user_id": USR_DANA,
                "actor_upn": USER_DANA_UPN,
                "action": "NewInboxRule",
                "target_user_id": USR_DANA,
                "target_upn": USER_DANA_UPN,
                "rule_name": "Finance-Reports",
                "rule_conditions": {"subject_contains": ["finance", "weekly report"]},
                "rule_actions": ["move_to_folder"],
                "rule_destination_folder": "Finance-Reports-2025",
                "client_ip": IP_DANA_WS,
                "correlation_id": None,
                "message_id": None,
            },
            {
                "event_id": "EVT-58318",
                "timestamp_utc": "2026-09-15T09:16:44Z",
                "actor_user_id": USR_DANA,
                "actor_upn": USER_DANA_UPN,
                "action": "InboxRuleExecuted",
                "target_user_id": USR_DANA,
                "target_upn": USER_DANA_UPN,
                "rule_name": "SecArchives",
                "rule_conditions": {"subject_contains": ["security review", "audit"]},
                "rule_actions": ["mark_as_read", "move_to_folder"],
                "rule_destination_folder": "Archive-Process",
                "client_ip": IP_ATTACKER,
                "correlation_id": CORR_AITM,
                "message_id": None,
            },
            {
                "event_id": "EVT-58317",
                "timestamp_utc": "2026-09-15T09:20:44Z",
                "actor_user_id": USR_MARCUS,
                "actor_upn": "marcus.hale@" + CORP_DOMAIN,
                "action": "FolderAction",
                "target_user_id": USR_MARCUS,
                "target_upn": "marcus.hale@" + CORP_DOMAIN,
                "rule_name": None,
                "rule_conditions": None,
                "rule_actions": ["create_folder"],
                "rule_destination_folder": "SOC-Weekly",
                "client_ip": IP_MARCUS_WS,
                "correlation_id": None,
                "message_id": None,
            },
        ],
    }


def build_alerts():
    return {
        "dataset": "xdr_style_alerts",
        "schema_version": "1.0",
        "incident_ref": CASE_ID,
        "provenance": "synthetic training data; not a genuine security-product export; "
                      "modeled on XDR alert shape",
        "records": [
            {
                "alert_id": "ALERT-7712",
                "created_utc": "2026-09-15T09:05:10Z",
                "severity": "medium",
                "category": "Sign-in risk detected",
                "affected_account": USER_DANA_UPN,
                "related_event_ids": ["EVT-58103"],
                "evidence_refs": ["signins.json:EVT-58103"],
                "alert_status": "new",
            },
            {
                "alert_id": "ALERT-7721",
                "created_utc": "2026-09-15T08:59:55Z",
                "severity": "low",
                "category": "Mailbox rule created",
                "affected_account": USER_DANA_UPN,
                "related_event_ids": ["EVT-58314"],
                "evidence_refs": ["mailbox-audit.json:EVT-58314"],
                "alert_status": "new",
            },
            {
                "alert_id": "ALERT-7733",
                "created_utc": "2026-09-15T09:14:59Z",
                "severity": "medium",
                "category": "Device registration from new location",
                "affected_account": USER_DANA_UPN,
                "related_event_ids": ["EVT-59015"],
                "evidence_refs": ["identity-audit.json:EVT-59015"],
                "alert_status": "new",
            },
            {
                "alert_id": "ALERT-7741",
                "created_utc": "2026-09-15T09:20:11Z",
                "severity": "medium",
                "category": "Forwarding configuration change",
                "affected_account": USER_DANA_UPN,
                "related_event_ids": ["EVT-58315"],
                "evidence_refs": ["mailbox-audit.json:EVT-58315"],
                "alert_status": "new",
            },
            {
                "alert_id": "ALERT-7752",
                "created_utc": "2026-09-15T08:10:00Z",
                "severity": "info",
                "category": "Consent grant recorded",
                "affected_account": "sara.okoye@" + CORP_DOMAIN,
                "related_event_ids": ["EVT-59011"],
                "evidence_refs": ["identity-audit.json:EVT-59011"],
                "alert_status": "resolved_false_positive",
            },
            {
                "alert_id": "ALERT-7761",
                "created_utc": "2026-09-15T09:55:40Z",
                "severity": "low",
                "category": "Repeated failed sign-in attempts (transient peer)",
                "affected_account": "sara.okoye@" + CORP_DOMAIN,
                "related_event_ids": ["EVT-58125"],
                "evidence_refs": ["signins.json:EVT-58125"],
                "alert_status": "resolved",
            },
            {
                "alert_id": "ALERT-7770",
                "created_utc": "2026-09-15T09:58:30Z",
                "severity": "info",
                "category": "Service health anomaly - mail flow",
                "affected_account": "tenant:" + CORP_DOMAIN,
                "related_event_ids": [],
                "evidence_refs": [],
                "alert_status": "resolved",
            },
        ],
    }


def build_connection_events():
    return {
        "dataset": "connection_events",
        "schema_version": "1.0",
        "incident_ref": CASE_ID,
        "provenance": "synthetic network observations; not a genuine security-product export",
        "records": [
            {
                "event_id": "EVT-C1050",
                "timestamp_utc": "2026-09-15T08:44:10Z",
                "source_ip": IP_DANA_WS,
                "dest_host": HOP1_DOMAIN,
                "dest_ip": IP_KIT_HOP1,
                "protocol": "https",
                "event_ref": "redirect-hop-01.txt",
                "observation_type": "http_get",
                "request_uri": "/file/view?u=" + E1_URL_B64,
                "user_account": USER_DANA_UPN,
                "data_source": "synthetic_proxy_telemetry",
            },
            {
                "event_id": "EVT-C1051",
                "timestamp_utc": "2026-09-15T08:44:12Z",
                "source_ip": IP_DANA_WS,
                "dest_host": HOP2_DOMAIN,
                "dest_ip": IP_KIT_HOP2,
                "protocol": "https",
                "event_ref": "redirect-hop-02.txt",
                "observation_type": "http_get",
                "request_uri": "/s/2C4d9Ef1a3B7",
                "user_account": USER_DANA_UPN,
                "data_source": "synthetic_proxy_telemetry",
            },
            {
                "event_id": "EVT-C1052",
                "timestamp_utc": "2026-09-15T08:44:14Z",
                "source_ip": IP_DANA_WS,
                "dest_host": KIT_PAGE_DOMAIN,
                "dest_ip": IP_KIT_PAGE,
                "protocol": "https",
                "event_ref": "artifacts/web/saved-page.html",
                "observation_type": "http_get",
                "request_uri": "/signin/azure_sso?" + SAVED_URL_QUERY,
                "user_account": USER_DANA_UPN,
                "data_source": "synthetic_proxy_telemetry",
            },
            {
                "event_id": "EVT-C1053",
                "timestamp_utc": "2026-09-15T08:46:22Z",
                "source_ip": IP_DANA_WS,
                "dest_host": KIT_PAGE_DOMAIN,
                "dest_ip": IP_KIT_PAGE,
                "protocol": "https",
                "event_ref": "artifacts/web/page-source.js",
                "observation_type": "http_post",
                "request_uri": "/signin/azure_sso?log=" + LOGID,
                "user_account": USER_DANA_UPN,
                "data_source": "synthetic_proxy_telemetry",
            },
            {
                "event_id": "EVT-C1009",
                "timestamp_utc": "2026-09-15T08:20:00Z",
                "source_ip": IP_MARCUS_WS,
                "dest_host": "portal." + VENDOR_DOMAIN,
                "dest_ip": IP_VENDOR,
                "protocol": "https",
                "event_ref": "email-03-legitimate-review.eml",
                "observation_type": "http_get",
                "request_uri": "/secure-check",
                "user_account": "marcus.hale@" + CORP_DOMAIN,
                "data_source": "synthetic_proxy_telemetry",
            },
            {
                "event_id": "EVT-C1015",
                "timestamp_utc": "2026-09-15T08:36:11Z",
                "source_ip": IP_SARA_WS,
                "dest_host": "portal." + VENDOR_DOMAIN,
                "dest_ip": IP_VENDOR,
                "protocol": "https",
                "event_ref": "email-03-legitimate-review.eml",
                "observation_type": "http_get",
                "request_uri": "/secure-check",
                "user_account": "sara.okoye@" + CORP_DOMAIN,
                "data_source": "synthetic_proxy_telemetry",
            },
        ],
    }


def build_incident_events():
    rows = []
    def add(src, *, actor=None, cat=None, ts=None, summary=None, eid=None):
        rows.append({
            "source_dataset": src,
            "source_event_id": eid,
            "timestamp_utc": ts,
            "category": cat,
            "actor": actor,
            "derived_summary": summary,
        })
    add("signins.json",        actor=USER_DANA_UPN, cat="authentication", ts="2026-09-14T09:01:52Z", summary="Failed connector sign-in from mail relay IP", eid="EVT-58107")
    add("mailbox-audit.json",  actor="system",      cat="mailbox",        ts="2026-09-14T09:03:41Z", summary="Message received in dana.wexler mailbox", eid="EVT-58311")
    add("alerts.json",         actor="tenant",      cat="alert",          ts="2026-09-15T08:10:00Z", summary="Alert raised (consent grant recorded)", eid="ALERT-7752")
    add("identity-audit.json", actor="sara.okoye",  cat="authorization",  ts="2026-09-15T08:11:33Z", summary="Consent granted to vendor app", eid="EVT-59011")
    add("connection-events.json", actor=USER_DANA_UPN, cat="network",     ts="2026-09-15T08:44:10Z", summary="Client GET to kit redirector chain", eid="EVT-C1050")
    add("connection-events.json", actor=USER_DANA_UPN, cat="network",     ts="2026-09-15T08:44:12Z", summary="Client GET to second hop in redirect chain", eid="EVT-C1051")
    add("connection-events.json", actor=USER_DANA_UPN, cat="network",     ts="2026-09-15T08:44:14Z", summary="Client GET to sign-in replica page", eid="EVT-C1052")
    add("connection-events.json", actor=USER_DANA_UPN, cat="network",     ts="2026-09-15T08:46:22Z", summary="Client POST observed on replica page", eid="EVT-C1053")
    add("signins.json",        actor=USER_DANA_UPN, cat="authentication", ts="2026-09-15T08:47:32Z", summary="Successful sign-in with MFA claim from unusual source", eid="EVT-58103")
    add("signins.json",        actor=USER_DANA_UPN, cat="authentication", ts="2026-09-15T08:59:01Z", summary="Successful sign-in via device_code method", eid="EVT-58115")
    add("mailbox-audit.json",  actor=USER_DANA_UPN, cat="mailbox",        ts="2026-09-15T08:59:30Z", summary="New inbox rule created", eid="EVT-58314")
    add("identity-audit.json", actor=USER_DANA_UPN, cat="authorization",  ts="2026-09-15T08:59:02Z", summary="Device-code token grant recorded", eid="EVT-59012")
    add("identity-audit.json", actor=USER_DANA_UPN, cat="account_settings", ts="2026-09-15T09:02:10Z", summary="MFA method added from external source", eid="EVT-59013")
    add("mailbox-audit.json",  actor=USER_DANA_UPN, cat="mailbox",        ts="2026-09-15T09:02:10Z", summary="External forwarding configuration set", eid="EVT-58315")
    add("alerts.json",         actor=USER_DANA_UPN, cat="alert",          ts="2026-09-15T09:05:10Z", summary="Alert raised (sign-in risk detected)", eid="ALERT-7712")
    add("identity-audit.json", actor=USER_DANA_UPN, cat="account_settings", ts="2026-09-15T09:14:57Z", summary="Device registration from external source", eid="EVT-59015")
    add("alerts.json",         actor="tenant",      cat="alert",          ts="2026-09-15T09:58:30Z", summary="Alert raised (service health anomaly)", eid="ALERT-7770")
    return rows


# ----------------------------------------------------------------------------
# Question bank / answers (interface for any platform)
# ----------------------------------------------------------------------------
# Each question: id, title, prompt, answer_format, points, accepted (canonical
# first), category, artifacts (paths referenced), note.

QUESTIONS = [
    dict(id=1, category="Email headers and sender analysis", points=1,
         title="(Origin relay IPv4)",
          prompt="Email 1 travels through a three-hop `Received:` chain. Read the bottommost `Received:` header (the first server that received the message). What connecting IPv4 address does that header record in brackets?",
         answer_format="IPv4 address",
         artifacts=["mail/eml/email-01-aitm-lure.eml"],
         accepted=[IP_RELAY]),

    dict(id=2, category="Email headers and sender analysis", points=1,
         title="(Relay-linked identity event)",
         prompt="Use the IPv4 from the previous question. In `signins.json`, exactly one other event lists that same IPv4 as its source address. What is that event's `event_id`?",
         answer_format="event ID",
         artifacts=["mail/eml/email-01-aitm-lure.eml", "artifacts/identity/signins.json"],
         accepted=["EVT-58107"]),

    dict(id=3, category="Email headers and sender analysis", points=2,
         title="(Envelope vs DKIM mismatch)",
         prompt="Email 2's Authentication-Results block shows the DKIM signature is valid yet the envelope sender domain differs from the DKIM signing domain. Submit the pair `<envelope-sender-domain>,<dkim-signing-domain>`.",
         answer_format="domain,domain",
         artifacts=["mail/eml/email-02-device-code.eml"],
         accepted=[ENVELOPE_DOMAIN_E2 + "," + ITDESK_DOMAIN]),

    dict(id=4, category="Email headers and sender analysis", points=2,
         title="(Ticket correlation)",
         prompt="Email 2's body cites a service ticket number (`Ref: ...`). Which identity dataset file (by filename) contains an event whose properties repeat that exact ticket reference?",
         answer_format="ticket-ref,filename",
         artifacts=["mail/eml/email-02-device-code.eml", "artifacts/identity/identity-audit.json"],
         accepted=[TICKET_E2 + ",identity-audit.json"]),

    dict(id=5, category="Redirect and static web analysis", points=1,
         title="(Decoded destination)",
         prompt="Email 1's link carries a URL-safe base64 parameter `u=`. Decode it. The resulting page is captured in `saved-page.html`. Submit only the URL path of the decoded destination.",
         answer_format="/path/segment",
         artifacts=["mail/eml/email-01-aitm-lure.eml", "artifacts/web/saved-page.html"],
         accepted=["/signin/azure_sso"]),

    dict(id=6, category="Redirect and static web analysis", points=2,
         title="(Request ID corroboration)",
         prompt="The decoded URL contains `client_request_id=<value>`. That value appears verbatim in exactly one other JSON dataset (in a request_uri field). Submit `<dataset-filename>,<event_id>`.",
         answer_format="filename,event-id",
         artifacts=["artifacts/web/saved-page.html", "artifacts/network/connection-events.json"],
         accepted=["connection-events.json,EVT-C1052"]),

    dict(id=7, category="Redirect and static web analysis", points=1,
         title="(Rendered-only token)",
         prompt="`login-page.html` and `saved-page.html` differ. The hidden `__tk` input is empty in the static duplicate but populated in the saved snapshot. What is that exact token value?",
         answer_format="exact token string",
         artifacts=["artifacts/web/login-page.html", "artifacts/web/saved-page.html"],
         accepted=[TK_TOKEN]),

    dict(id=8, category="Redirect and static web analysis", points=1,
         title="(Timing-gate behavior)",
         prompt="Read `page-source.js`: after the DON'T-RUN performance.now() wait loop resolves, what final behavior does the script produce? Choose exactly one: ALERT, REDIRECT, CONSOLE_ONLY, FORM_FREEZE.",
         answer_format="enum token from fixed list",
         artifacts=["artifacts/web/page-source.js", "artifacts/web/saved-page.html"],
         accepted=["CONSOLE_ONLY"]),

    dict(id=9, category="Identity and XDR evidence correlation", points=2,
         title="(Mailbox rule identity)",
         prompt="Find the `NewInboxRule` record in `mailbox-audit.json` whose `client_ip` equals the suspicious sign-in's `source_ip` from the 08:47:32Z sign-in in `signins.json`. Submit `<rule_name>,<event_id>`.",
         answer_format="rule-name,event-id",
         artifacts=["artifacts/logs/mailbox-audit.json", "artifacts/identity/signins.json"],
         accepted=["SecArchives,EVT-58314"]),

    dict(id=10, category="Identity and XDR evidence correlation", points=1,
         title="(Attacker IP row count)",
         prompt="How many rows in `signins.json` list the suspicious sign-in's `source_ip` from the 08:47:32Z event as their own source_ip?",
         answer_format="numeric value",
         artifacts=["artifacts/identity/signins.json"],
         accepted=["3"]),

    dict(id=11, category="Identity and XDR evidence correlation", points=2,
         title="(Alert linkage)",
         prompt="Which alert in `alerts.json` lists the 08:47:32Z sign-in event as a `related_event_ids` member, and what severity did that alert carry?",
         answer_format="alert-id,severity",
         artifacts=["artifacts/logs/alerts.json", "artifacts/identity/signins.json"],
         accepted=["ALERT-7712,medium"]),

    dict(id=12, category="Identity and XDR evidence correlation", points=2,
         title="(Device-code chain pair)",
         prompt="In `identity-audit.json`, locate the `devicecode_token_grant` for dana.wexler. Which sign-in event in `signins.json` shares the SAME `correlation_id`? Submit `<correlation_id>,<sign-in event_id>`.",
         answer_format="correlation-id,event-id",
         artifacts=["artifacts/identity/identity-audit.json", "artifacts/identity/signins.json"],
         accepted=[CORR_DEV + ",EVT-58115"]),

    dict(id=13, category="Identity and XDR evidence correlation", points=2,
         title="(Forwarding match)",
         prompt="Somewhere in `mailbox-audit.json` a `SetForwarding` record gives an external forwarding address whose DOMAIN also appears as the sender domain of Email 1. Submit `<event_id>,<domain>`.",
         answer_format="event-id,domain",
         artifacts=["artifacts/logs/mailbox-audit.json", "mail/eml/email-01-aitm-lure.eml"],
         accepted=["EVT-58315," + KIT_MAILER_DOMAIN]),

    dict(id=14, category="Threat intelligence and attribution", points=1,
         title="(IOC match to family)",
          prompt="`redirect-hop-02.txt` lists one defanged, publicly reported domain. Confirm in the cited threat-intel report which phishing family it was associated with, submitting the exact defanged form plus the family name. Citation: Sekoia TDR, 'Tycoon 2FA: an in-depth analysis of the latest version of the AiTM phishing kit' (2025-03-25).",
         answer_format="defanged-domain,family-name",
         artifacts=["artifacts/web/redirect-hop-02.txt"],
         accepted=[REAL_IOC_DEFANGED + ",Tycoon 2FA"]),

    dict(id=15, category="Threat intelligence and attribution", points=1,
         title="(MITRE technique id)",
          prompt="The Darktrace report, 'MFA Under Attack: AiTM Phishing Kits Abusing Legitimate Services' (darktrace.com/blog/mfa-under-attack-aitm-phishing-kits-abusing-legitimate-services, published 2025-04-29), maps its observed campaign to the credential-access technique it names 'Steal Web Session Cookie'. What is that technique's MITRE ATT&CK ID?",
         answer_format="ATT&CK technique ID (e.g. T1xxx)",
         artifacts=["artifacts/documentation/field-reference.md"],
         accepted=["T1539"]),

    dict(id=16, category="Threat intelligence and attribution", points=1,
         title="(Device-code actor)",
         prompt="Microsoft Threat Intelligence (blog post published 2025-02-13, 'Storm-2372 conducts device code phishing campaign') documents active device-code phishing. Which tracked actor is named there for this technique? Use only the actor designation string.",
         answer_format="actor designation (e.g._xx-####)",
         artifacts=["artifacts/web/device-code-page.html"],
         accepted=["Storm-2372"]),

    dict(id=17, category="Timeline reconstruction", points=2,
         title="(Sorted persistence chain)",
         prompt="Provide the event IDs of the malicious sign-in, the malicious 'NewInboxRule' creation and the malicious 'SetForwarding' mutation above (the attacker's first-to-last persistence steps), in ascending chronological order, comma-separated.",
         answer_format="event-id_1,event-id_2,event-id_3 (in order)",
         artifacts=["artifacts/identity/signins.json", "artifacts/logs/mailbox-audit.json", "artifacts/identity/identity-audit.json"],
         accepted=["EVT-58103,EVT-58314,EVT-58315"]),

    dict(id=18, category="Timeline reconstruction", points=2,
         title="(Delivery / click / sign-in ladder)",
         prompt="Sort the three events that open the attack chain into chronological order: mail delivery (mailbox-audit), the initial click connection (network), and the first successful malicious sign-in (identity). Submit all three `event_id`s comma-separated ascending.",
         answer_format="event-id_1,event-id_2,event-id_3 (in order)",
         artifacts=["artifacts/logs/mailbox-audit.json", "artifacts/network/connection-events.json", "artifacts/identity/signins.json"],
         accepted=["EVT-58311,EVT-C1050,EVT-58103"]),

    dict(id=19, category="Timeline reconstruction", points=1,
         title="(Incident classification)",
         prompt="Based only on the supplied dataset, choose the strongest classification that your correlation supports. Choose exactly one: PHISHING_CLICK_ONLY, PHISHING_REPORT_ONLY, SESSION_HIJACKED, DATA_EXFIL_CONFIRMED.",
         answer_format="enum token from fixed list",
         artifacts=["artifacts/identity/signins.json", "artifacts/logs/mailbox-audit.json"],
         accepted=["SESSION_HIJACKED"]),

    dict(id=20, category="False-positive identification", points=1,
         title="(Legitimate security email)",
         prompt="One of the three emails is a legitimate contracted-vendor digest. Which Message-ID belongs to it? (Angle brackets optional.) Note: the vendor relationship is documented elsewhere in the dataset.",
         answer_format="full message-id",
         artifacts=["mail/eml/email-03-legitimate-review.eml", "artifacts/documentation/evidence-inventory.md"],
         accepted=[MSG_ID_E3, MSG_ID_E3[1:-1]]),

    dict(id=20, category="False-positive identification", points=1, id_override=21,
         title="(Benign older rule)",
         prompt="`mailbox-audit.json` contains several `NewInboxRule` events. Which one was created well before the current incident window and is therefore unrelated to it?",
         answer_format="event-id",
         artifacts=["artifacts/logs/mailbox-audit.json"],
         accepted=["EVT-58316"]),

    dict(id=22, category="Bonus", points=1,
         title="(Route stamp decode)",
         prompt="Email 1 carries the header `X-Msg-Route: <base64>`. Decode it and submit the plaintext value.",
         answer_format="exact decoded token",
         artifacts=["mail/eml/email-01-aitm-lure.eml"],
         accepted=[ROUTE_STAMP]),

    dict(id=23, category="Bonus", points=1,
         title="(Node token decode)",
         prompt="`page-source.js` hides a runtime value via its XOR-based `_dk` helper (the array is used only to compute `KIT.counters.node`, which the DOM shows in the saved snapshot's node field). Decode it and submit the plaintext value.",
         answer_format="exact decoded token",
         artifacts=["artifacts/web/page-source.js", "artifacts/web/saved-page.html"],
         accepted=[NODE_TOKEN]),

    dict(id=24, category="Bonus", points=1,
         title="(Missing telemetry)",
         prompt="Which step is definitively NOT captured anywhere in the supplied dataset, even though the incident's shape implies the real-world step had to occur? Choose exactly one: DEVICE_CODE_GENERATION, MFA_PROMPT_DISPLAYED, INBOX_RULE_ACTIVATION, SESSION_COOKIE_CAPTURE.",
         answer_format="enum token from fixed list",
         artifacts=["artifacts/documentation/evidence-inventory.md"],
         accepted=["SESSION_COOKIE_CAPTURE"]),

    dict(id=25, category="Bonus", points=1,
         title="(Earliest audit timestamp)",
         prompt="In `identity-audit.json`, which is the chronologically EARLIEST `timestamp_utc` value found among ALL rows in the file?",
         answer_format="ISO 8601 UTC timestamp string",
         artifacts=["artifacts/identity/identity-audit.json"],
         accepted=[min(r["timestamp_utc"] for r in build_identity_audit()["records"])]),

    dict(id=26, category="Bonus", points=1,
         title="(Received-hop counts)",
         prompt="How many `Received:` headers does Email 1 have vs Email 3 respectively? Submit `<count_email1>,<count_email3>`.",
         answer_format="n,n",
         artifacts=["mail/eml/email-01-aitm-lure.eml", "mail/eml/email-03-legitimate-review.eml"],
         accepted=["3,4"]),
]

# Fix the duplicate id used purely for aliasing purposes above
for i, qq in enumerate(QUESTIONS):
    if qq.get("id_override"):
        qq["id"] = qq["id_override"]
    qq.pop("id_override", None)


def flag_fragments():
    return [
        ("F1", "Email evidence code", ROUTE_STAMP, "decoded X-Msg-Route", "mail/eml/email-01-aitm-lure.eml", "Bonus question 22"),
        ("F2", "Web artifact code", NODE_TOKEN, "decoded _dk array (node stamp)", "artifacts/web/page-source.js", "Bonus question 23"),
        ("F3", "Identity log code", CORR_DEV, "device-code correlation ID", "artifacts/identity/identity-audit.json", "Core question 12"),
        ("F4", "Threat-intel code", "T1539", "Darktrace-mapped ATT&CK technique", "docs (public TI)", "Core question 15"),
    ]


def canonical_flag():
    return "FLAG{AiTM-" + "-".join(f[2] for f in flag_fragments()) + "}"
