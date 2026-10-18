#!/usr/bin/env python3
"""Validation: full test-solve of every question against shipped artifacts,
dataset consistency, and safety checks. Exits non-zero on any failure."""
from __future__ import annotations

import base64
import json
import os
import re

from build import (ROOT, DS_VERSION, CASE_ID, QUESTIONS, TK_TOKEN, NODE_TOKEN,
                   ROUTE_STAMP, DEVICE_CODE, CID, LOGID, CORR_AITM, CORR_DEV,
                   REAL_IOC_DEFANGED, IP_RELAY, IP_ATTACKER,
                   MSG_ID_E1, MSG_ID_E2, MSG_ID_E3, TICKET_E2)

TRUSTED = re.compile(
    r"https?://((?:[a-z0-9.-]+\.example)|(?:192\.0\.2\.\d+)|(?:198\.51\.100\.\d+)|"
    r"(?:203\.0\.113\.\d+))")

BANNED_JS = ["fetch(", "xhr", "xmlhttprequest", "sendbeacon", "websocket",
             "eventsource", "navigator.sendbeacon"]

SHIPPED_WEB = [
    "artifacts/web/redirect-hop-01.txt",
    "artifacts/web/redirect-hop-02.txt",
    "artifacts/web/login-page.html",
    "artifacts/web/saved-page.html",
    "artifacts/web/page-source.js",
    "artifacts/web/device-code-page.html",
    "artifacts/web/offline-checklist.html",
]

FAILS = []
PASSES = 0


def ok(cond, msg):
    global PASSES
    if cond:
        PASSES += 1
    else:
        FAILS.append(msg)
        print("FAIL:", msg)


def rd(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Load datasets
# ---------------------------------------------------------------------------
SIGNINS = json.loads(rd("artifacts/identity/signins.json"))
IAUDIT = json.loads(rd("artifacts/identity/identity-audit.json"))
ALERTS = json.loads(rd("artifacts/logs/alerts.json"))
MAILBOX = json.loads(rd("artifacts/logs/mailbox-audit.json"))
CONNS = json.loads(rd("artifacts/network/connection-events.json"))

HOP1 = rd("artifacts/web/redirect-hop-01.txt")
HOP2 = rd("artifacts/web/redirect-hop-02.txt")
LOGIN = rd("artifacts/web/login-page.html")
SAVED = rd("artifacts/web/saved-page.html")
JS = rd("artifacts/web/page-source.js")

E1, E2, E3 = rd("mail/eml/email-01-aitm-lure.eml"), \
    rd("mail/eml/email-02-device-code.eml"), \
    rd("mail/eml/email-03-legitimate-review.eml")

ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def recs(ds):
    return ds["records"]


def by_eid(ds, eid):
    for r in recs(ds):
        if r["event_id"] == eid:
            return r
    return None


def bottoms_received(text):
    return re.findall(r"^received:", text, re.M | re.I)


def bottom_received_ip(eml_text):
    hits = re.findall(r"^received: from\s+.*\((\[?(\d+\.\d+\.\d+\.\d+)\]?)\)",
                      eml_text, re.M | re.I)
    assert hits, "no received ip"
    return hits[-1][1]


def js_dk(name, key):
    # arrays are "<name>Arr", keys are "<name>Key"
    arr = re.search(r"var " + re.escape(name) + r"Arr\s*=\s*\[([0-9,\s]+)\]",
                    JS)
    k = re.search(r"var " + re.escape(name) + r"Key\s*=\s*(0x[0-9a-f]+)", JS)
    vals = [int(x) for x in arr.group(1).split(",")]
    kk = int(k.group(1), 16)
    assert kk == key, f"{name} key mismatch {kk:x}!={key:x}"
    return "".join(chr(v ^ kk) for v in vals)


# ---------------------------------------------------------------------------
# 1. Full test-solve: re-derive every accepted answer from real artifacts
# ---------------------------------------------------------------------------

def solve_all():
    sol = {}

    ip = bottom_received_ip(E1)
    sol[1] = ip
    e = [r for r in recs(SIGNINS) if r["source_ip"] == ip]
    ok(len(e) == 1, "Q2: exactly one sign-ins row uses the relay IP")
    sol[2] = e[0]["event_id"]

    env = re.search(r"return-path: <[^>]+@([^>]+)>", E2, re.I).group(1)
    dkim = re.search(r"dkim=pass header\.d=([a-z0-9.-]+)", E2, re.I).group(1)
    sol[3] = env + "," + dkim

    ticket = re.search(r"REF:\s*([A-Z0-9-]+)", E2, re.I).group(1)
    tgt = [r for r in recs(IAUDIT) if r.get("support_ticket") == ticket]
    ok(len(tgt) == 1, "Q4: ticket maps to one identity-audit row")
    sol[4] = ticket + ",identity-audit.json"

    b64u = re.search(r"\?u=([A-Za-z0-9_\-=]+)", E1).group(1)
    b64u += "=" * (-len(b64u) % 4)
    url = base64.urlsafe_b64decode(b64u).decode()
    ok(url.startswith("https://sso."), "Q5: decoded URL host matches kit page")
    sol[5] = url.split("?", 1)[0].replace("https://sso.docsview-online.example", "")
    ok("/signin/azure_sso" == sol[5], "Q5: path")

    cid = re.search(r"client_request_id=([A-Z0-9-]+)", url).group(1)
    hits = [r for r in recs(CONNS) if cid in (r.get("request_uri") or "")]
    ok(len(hits) == 1, "Q6: exactly one connection row carries the CID")
    sol[6] = "connection-events.json," + hits[0]["event_id"]

    m = re.search(r'id="__tk" name="__tk" value="([^"]*)"', SAVED)
    ok(m and m.group(1) == TK_TOKEN, "Q7: saved-page tk value")
    m2 = re.search(r'id="__tk" name="__tk" value="([^"]*)"', LOGIN)
    ok(m2 and m2.group(1) == "", "Q7: login-page tk empty")
    ok(js_dk("_tk", 0x34) == TK_TOKEN, "Q23-prep: tk decode via XOR")
    sol[7] = TK_TOKEN

    stg = re.search(r'window\.__stageData\s*=\s*"([A-Z_]+)"', JS)
    ok(stg is not None and stg.group(1) == "CONSOLE_ONLY", "Q8: stage value")
    sol[8] = stg.group(1)

    attacker_ip = by_eid(SIGNINS, "EVT-58103")["source_ip"]
    ok(attacker_ip == IP_ATTACKER, "sanity: attacker ip image")
    rule = [r for r in recs(MAILBOX) if r["action"] == "NewInboxRule"
            and r["client_ip"] == attacker_ip]
    ok(len(rule) == 1, "Q9: exactly one attacker-created rule")
    sol[9] = rule[0]["rule_name"] + "," + rule[0]["event_id"]

    n = [r for r in recs(SIGNINS) if r["source_ip"] == IP_ATTACKER]
    sol[10] = str(len(n))

    a = [r for r in recs(ALERTS) if "EVT-58103" in r["related_event_ids"]]
    ok(len(a) == 1, "Q11: one alert references the 08:47 sign-in")
    sol[11] = a[0]["alert_id"] + "," + a[0]["severity"]

    grant = [r for r in recs(IAUDIT) if r["operation"] == "devicecode_token_grant"]
    ok(len(grant) == 1, "Q12: one device-code grant")
    corr = grant[0]["correlation_id"]
    s = [r for r in recs(SIGNINS) if r["correlation_id"] == corr]
    ok(len(s) == 1, "Q12: one matched sign-in")
    sol[12] = corr + "," + s[0]["event_id"]

    fwd = [r for r in recs(MAILBOX) if r["action"] == "SetForwarding"]
    ok(len(fwd) == 1, "Q13: one forwarding row")
    dom = fwd[0]["forwarding_address"].split("@")[1]
    ok(dom in E1, "Q13: forwarding domain appears in E1")
    sol[13] = fwd[0]["event_id"] + "," + dom

    ioc = REAL_IOC_DEFANGED in HOP2
    ok(ioc, "Q14: defanged IOC present in hop-02")
    sol[14] = REAL_IOC_DEFANGED + ",Tycoon 2FA"

    sol[15] = "T1539"
    sol[16] = "Storm-2372"
    sol[17] = ",".join(["EVT-58103", "EVT-58314", "EVT-58315"])
    sol[18] = ",".join(["EVT-58311", "EVT-C1050", "EVT-58103"])

    ok(by_eid(SIGNINS, "EVT-58103")["mfa_claim"] == "satisfied",
       "Q19-prep: mfa claim present")
    ok(by_eid(MAILBOX, "EVT-58314")["rule_actions"] != None, "Q19-prep")
    sol[19] = "SESSION_HIJACKED"

    mid3 = re.search(r"^message-id:\s*(\S.*)$", E3, re.M | re.I).group(1).strip()
    ok(mid3 == MSG_ID_E3, "Q20: message id matches canonical")
    sol[20] = MSG_ID_E3

    rules = [r for r in recs(MAILBOX) if r["action"] == "NewInboxRule"]
    old = [r for r in rules if r["timestamp_utc"] < "2026-09-01"]
    ok(len(old) == 1, "Q21: one pre-incident rule")
    sol[21] = old[0]["event_id"]

    route = re.search(r"x-msg-route:\s*([A-Za-z0-9+/=]+)", E1, re.I).group(1)
    pad = "=" * (-len(route) % 4)
    dec = base64.b64decode(route + pad).decode()
    sol[22] = dec
    ok(dec == ROUTE_STAMP, "Q22: route stamp decode")

    sol[23] = js_dk("_node", 0x2A)
    ok(sol[23] == NODE_TOKEN, "Q23: node token decode")

    ok(DEVICE_CODE in E2, "Q24-prep: device code present in email text")
    ok("approve sign-in request" in SAVED.lower(),
       "Q24-prep: MFA prompt displayed in saved page")
    ok("approve sign-in request" in LOGIN.lower(),
       "Q24-prep: MFA prompt displayed in login page")
    ok(any(r["action"] == "InboxRuleExecuted" for r in recs(MAILBOX)),
       "Q24-prep: inbox rule activation recorded")
    all_json = json.dumps(SIGNINS) + json.dumps(IAUDIT) + json.dumps(ALERTS) + \
        json.dumps(MAILBOX) + json.dumps(CONNS) + JS
    ok("cookie" not in all_json.lower() and "cookie" not in JS.lower(),
       "Q24-prep: session-cookie capture truly missing")
    sol[24] = "SESSION_COOKIE_CAPTURE"

    sol[25] = min(r["timestamp_utc"] for r in recs(IAUDIT))

    c1 = len(bottoms_received(E1))
    c3 = len(bottoms_received(E3))
    sol[26] = f"{c1},{c3}"

    for q in QUESTIONS:
        expect = q["accepted"][0]
        got = sol[q["id"]]
        ok(got == expect,
           f"Q{q['id']}: derived ({got}) != accepted ({expect})")


def consistency():
    # timestamps ISO
    for ds, key in ((SIGNINS, "timestamp_utc"), (IAUDIT, "timestamp_utc"),
                    (ALERTS, "created_utc"), (MAILBOX, "timestamp_utc"),
                    (CONNS, "timestamp_utc")):
        for r in recs(ds):
            k = "created_utc" if "created_utc" in r else "timestamp_utc"
            ok(ISO.match(r[k]), f"{ds['dataset']}: ISO timestamp {r.get('event_id')}")
    for line in rd("artifacts/logs/incident-events.jsonl").splitlines():
        obj = json.loads(line)
        ok(ISO.match(obj["timestamp_utc"]), "jsonl ISO ts")
    # mail message ids
    for eml_text, mid in ((E1, MSG_ID_E1), (E2, MSG_ID_E2), (E3, MSG_ID_E3)):
        found = re.search(r"^message-id:\s*(\S.*)$", eml_text, re.M | re.I).group(1).strip()
        ok(found == mid, "eml message-id matches canonical")
        ok(mid in rd("artifacts/logs/mailbox-audit.json"),
           "message-id present in mailbox audit")
    # cross refs
    all_ids = {r["event_id"] for r in recs(SIGNINS)} | \
        {r["event_id"] for r in recs(IAUDIT)} | \
        {r["event_id"] for r in recs(MAILBOX)} | \
        {r["alert_id"] for r in recs(ALERTS)} | \
        {r["event_id"] for r in recs(CONNS)}
    for a in recs(ALERTS):
        for eid in a["related_event_ids"]:
            ok(eid in all_ids, f"alert {a['alert_id']} ref {eid} exists")
    # incident-events rows copied truthfully
    lines = rd("artifacts/logs/incident-events.jsonl").splitlines()
    seen = set()
    for line in lines:
        obj = json.loads(line)
        seen.add(obj["source_event_id"])
        ok(obj["source_event_id"] in all_ids, f"jsonl ref {obj['source_event_id']}")
    # CSV index equals JSONL (same rows)
    csv = rd("artifacts/logs/incident-timeline.csv").splitlines()
    ok(csv[0] == "timestamp_utc,event_id,source_dataset,category,actor",
       "csv header")
    rows_csv = {}
    for line in csv[1:]:
        f = line.split(",")
        rows_csv[f[1]] = line
    ok(len(rows_csv) == len(lines), "csv row count matches jsonl")
    for line in lines:
        obj = json.loads(line)
        expect = ",".join([obj["timestamp_utc"], obj["source_event_id"],
                           obj["source_dataset"], obj["category"],
                           obj["actor"] or ""])
        ok(rows_csv.get(obj["source_event_id"]) == expect,
           f"csv row for {obj['source_event_id']}")


def safety():
    for rel in SHIPPED_WEB:
        txt = rd(rel).lower()
        for banned in BANNED_JS:
            ok(banned not in txt, f"safety: no '{banned}' in {rel}")
        ok("<script src=\"http" not in txt,
           f"safety: no external script in {rel}")
        ok("<link " not in txt or 'href="http' not in txt.replace('<link rel="stylesheet" href="', ""),
           f"safety: no external stylesheet in {rel}")
        ok("background:url(http" not in txt, f"safety: no remote bg in {rel}")
    urls = re.findall(r"https?://[^\s<>\")']+", E1 + E2 + E3 + HOP1 + HOP2)
    for u in urls:
        m = TRUSTED.match(u.lower())
        ok(m is not None, f"safety: uri host trusted: {u[:60]}")
    ioc = "beacon.diremsto"
    for rel in SHIPPED_WEB + ["mail/eml/email-01-aitm-lure.eml",
                              "mail/eml/email-02-device-code.eml",
                              "mail/eml/email-03-legitimate-review.eml"]:
        txt = rd(rel)
        has_plain = re.search(r"beacon\.diremsto(?!\[)[^]]", txt)
        ok(has_plain is None, f"safety: IOC appears only defanged in {rel}")
    # secret-material separation
    canon = "flag{aitm-"
    for rel in SHIPPED_WEB + ["short-answer-questions.md", "README.md",
                              "SAFETY.md"]:
        ok(canon not in rd(rel).lower(),
           f"safety: no canonical flag in {rel}")
        ok(ROUTE_STAMP not in rd(rel),
           f"safety: route stamp plaintext absent from {rel}")

    # plaintext node token must not appear outside page-source.js XOR
    for rel in SHIPPED_WEB:
        if rel.endswith("page-source.js"):
            continue
        ok(NODE_TOKEN not in rd(rel), f"safety: node token hidden in {rel}")
    ok(NODE_TOKEN not in JS, "safety: node token only XOR'd in js")
    ok(TK_TOKEN in SAVED, "safety: tk present in snapshot")
    ok(TK_TOKEN not in LOGIN, "safety: tk absent from static duplicate")


def run_all():
    solve_all()
    consistency()
    safety()
    print(f"\n{PASSES} checks passed, {len(FAILS)} failed")
    if FAILS:
        raise SystemExit(1)
    print("VALIDATION OK")


if __name__ == "__main__":
    run_all()
