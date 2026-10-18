#!/usr/bin/env python3
"""Optional hosted verification portal (root mirrors + deploy pair) + offline twin."""
from __future__ import annotations

import os

from build import (ROOT, CASE_ID, PORTAL_CASE, DS_VERSION, NODE_TOKEN,
                   TK_TOKEN, CORE_THRESH, w)


PORTAL_JS = r"""/**
 * Zeus0x01 AiTM lab - server-side answer verification (optional hosted surface).
 *
 * No plaintext answers and no digests are committed to this repository.
 * The deploy operator supplies configuration via environment variables:
 *
 *   LAB_VERIFY_HMAC_KEY   pepper for HMAC-SHA256 answer digests
 *   LAB_ANSWER_DIGESTS    JSON string:
 *                         {"1":{"d":["<digest hex>", ...],"t":"str|msgid|enum|dompair|num",
 *                               "p":<points>,"cat":"core|bonus"}, ...}
 *   LAB_FRAG_DIGESTS      JSON string {"F1":"<digest>", "F2":"...", "F3":"...", "F4":"..."}
 *   LAB_CANONICAL_FLAG    optional explicit canonical flag; if unset the flag is
 *                         assembled server-side from verified fragments only
 *
 * Generate digests with tools/generate-digests.js using your own pepper and the
 * instructor question bank; never commit the resulting values anywhere.
 */
var crypto = require('crypto');
var CORE_THRESHOLD = 23;

function safeEqual(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
  catch (e) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }
}

/* Normalization mirrors the instructor rubric */
function nrm(s) {
  return String(s == null ? '' : s).trim().toLowerCase().replace(/\s+/g, ' ');
}
function msgid(s) {
  var t = nrm(s);
  if (/^<.+>$/.test(t)) { t = t.slice(1, -1); }
  return t;
}
/* Return every acceptable normalized variant of a candidate answer; the
 * question is correct when any variant hashes to any recorded digest. */
function variants(type, raw) {
  var n = nrm(raw);
  var out = [n];
  if (type !== 'msgid') { out.push(n.replace(/,\s+/g, ',')); }
  if (type === 'msgid' && /^<.+\>?$/.test(n)) out.push(n.replace(/^<|>$/g, ''));
  if (type === 'enum') { out.push(n.replace(/[\s_-]+/g, '')); }
  if (type === 'dompair') {
    var ps = n.split(',').map(function (x) { return x.trim(); });
    out.push(ps.slice().sort().join(','));
    out.push(ps.join(','));
  }
  return out.filter(Boolean);
}

function loadConfig(envName) {
  var raw = process.env[envName];
  if (!raw) { return null; }
  try { return JSON.parse(raw); } catch (e) { return null; }
}

module.exports = function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'method not allowed' }); return; }
  var body = req.body || {};
  if (typeof body === 'string') { try { body = JSON.parse(body || '{}'); } catch (e) { body = {}; } }

  var salt = process.env.LAB_VERIFY_HMAC_KEY;
  var QD = loadConfig('LAB_ANSWER_DIGESTS');
  var FD = loadConfig('LAB_FRAG_DIGESTS');
  if (!salt || !QD || !FD) {
    res.status(503).json({ ok: false, error: 'verification not configured on this deployment' });
    return;
  }
  function mac(s) { return crypto.createHmac('sha256', salt).update(Buffer.from(s)).digest('hex'); }

  /* Final flag fragments */
  if (String(body.mode || '') === 'fragments') {
    var order = ['F1', 'F2', 'F3', 'F4'];
    var keys = ['f1', 'f2', 'f3', 'f4'];
    var ok = true;
    for (var i = 0; i < order.length; i++) {
      var cand = nrm(body[keys[i]] || '');
      if (!cand || !safeEqual(mac(cand), String(FD[order[i]] || '').toLowerCase())) { ok = false; break; }
    }
    if (!ok) {
      res.status(401).json({ ok: false, error: 'fragment verification failed' });
      return;
    }
    var flag = process.env.LAB_CANONICAL_FLAG ||
      ('FLAG{AiTM-' + keys.map(function (k) { return nrm(body[k] || '').toUpperCase(); }).join('-') + '}');
    res.status(200).json({ ok: true, flag: flag, message: 'All four fragments verified - flag released.' });
    return;
  }

  /* Short-answer scoring */
  var answers = body.answers || {};
  var coreCorrect = 0, corePoints = 0, coreTotal = 0, coreMax = 0;
  var bonusCorrect = 0, bonusTotal = 0;
  for (var qid in QD) {
    var e = QD[qid];
    if (e.cat === 'bonus') { bonusTotal += 1; } else { coreTotal += 1; coreMax += (e.p || 1); }
    var raw = answers[qid];
    if (raw == null || raw === '') { continue; }
    var cands = variants(e.t, raw);
    var digests = Array.isArray(e.d) ? e.d : [e.d];
    var hit = false;
    for (var v = 0; v < cands.length && !hit; v++) {
      for (var j = 0; j < digests.length && !hit; j++) {
        if (safeEqual(mac(cands[v]), String(digests[j]).toLowerCase())) { hit = true; }
      }
    }
    if (!hit) { continue; }
    if (e.cat === 'bonus') { bonusCorrect += 1; }
    else { coreCorrect += 1; corePoints += (e.p || 1); }
  }

  var revealFlag = null;
  if (corePoints >= CORE_THRESHOLD && process.env.LAB_CANONICAL_FLAG) {
    revealFlag = process.env.LAB_CANONICAL_FLAG;
  }

  res.status(200).json({
    ok: true,
    core_correct: coreCorrect,
    core_total: coreTotal,
    core_points: corePoints,
    core_max: coreMax,
    threshold: CORE_THRESHOLD,
    bonus_correct: bonusCorrect,
    bonus_total: bonusTotal,
    flag: revealFlag || undefined
  });
};
"""


PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Larkspur SOC — Investigation Portal (Training Replica)</title>
<style>
  :root { --brand:#12334f; --accent:#1f8f5a; --ink:#22303f; --muted:#6c7a89; --soft:#f2f5f9; }
  body { margin:0; font-family:system-ui,-apple-system,Calibri,Arial,sans-serif; background:var(--soft); color:var(--ink); }
  .train-banner { background:#5c4b00; color:#fff3c4; font-size:12px; text-align:center; padding:7px 12px; letter-spacing:.4px; }
  .wrap { max-width:720px; margin:40px auto; }
  .card { background:#fff; border:1px solid #dbe2ea; border-radius:10px; overflow:hidden; box-shadow:0 2px 6px rgba(15,30,50,.06); }
  .brand { background:var(--brand); padding:16px 28px; color:#fff; }
  .brand .a { font-size:21px; font-weight:700; letter-spacing:1px; }
  .brand .sub { color:#bcd2ec; font-size:11px; padding-top:2px; }
  .body { padding:24px 28px; }
  h1 { font-size:18px; margin:0 0 6px 0; }
  p.small { font-size:12px; color:var(--muted); }
  label { display:block; font-size:12px; margin:12px 0 4px 0; font-weight:600; }
  textarea { width:100%; padding:10px; border:1px solid #bcc7d1; border-radius:5px; font-size:13px; font-family:ui-monospace,Consolas,monospace; box-sizing:border-box; min-height:170px; }
  input[type=text] { width:100%; padding:9px 10px; border:1px solid #bcc7d1; border-radius:5px; font-size:14px; box-sizing:border-box; }
  button { margin-top:16px; background:var(--brand); color:#fff; border:0; padding:11px 26px; font-size:14px; border-radius:5px; cursor:pointer; }
  button:hover { background:#08306e; }
  button:disabled { opacity:.6; cursor:wait; }
  #verdict { margin-top:14px; font-size:13px; white-space:pre-wrap; }
  .err { color:#b3003c; } .ok { color:var(--accent); font-weight:600; }
  .flagbox { display:none; margin-top:14px; background:#eafaf1; border:1px solid #bfe8cf; border-left:5px solid var(--accent); padding:12px 14px; font-family:ui-monospace,Consolas,monospace; font-size:14px; color:#0a7a35; word-break:break-all; }
  details { margin-top:16px; font-size:12px; color:#55556e; }
  footer { font-size:11px; color:var(--muted); padding:12px 28px; border-top:1px solid #dbe2ea; background:#fafbfc; }
</style>
</head>
<body>
<div class="train-banner">TRAINING REPLICA — Zeus0x01 public lab endpoint (incident CASE_ID_PLACEHOLDER). Not affiliated with any real company.</div>
<div class="wrap">
  <div class="card">
    <div class="brand">
      <div class="a">Larkspur SOC</div>
      <div class="sub">Investigation Portal — Zeus0x01 AiTM lab (dataset DS_VERSION_PLACEHOLDER)</div>
    </div>
    <div class="body">
      <h1>Verify case INC-2417</h1>
      <p class="small">Paste your answers below, one per line, each prefixed with its question
      number, e.g. <code>26 - example</code>. Loose prefixes like
      <code>26: example</code> or <code>026) example</code> work too. The scoring format per
      question is documented in <code>short-answer-questions.md</code>.</p>

      <label for="answers">Answers (one per line)</label>
      <textarea id="answers" spellcheck="false"
        placeholder="Submit each answer as:  N: value   (one per line)
1: <ip-nnn.nnn.nnn.nnn>
2: EVT-nnnnn
3: <envelope-domain.example>,<dkim-domain.example>
4: <ticket-ref>,<filename>.json
5: /<url-path>
6: <dataset-filename>.json,<event-id>
7: <token-value>
8: ENUM_VALUE (hyphens/spaces optional)
9: <rule_name>,<event-id>
10: <row-count>
11: <alert-id>,<severity>
12: <correlation-id>,<event-id>
13: <event-id>,<forward-domain.example>
14: <domain[.]defanged>,<family-name>
15: T<nnnn>
16: <tracked-actor-designation>
17: EVT-id,EVT-id,EVT-id (first to last)
18: EVT-id,EVT-id,EVT-id (earliest first)
19: ENUM_VALUE (hyphens/spaces optional)
20: <local-part@host> (angle brackets optional)
21: EVT-nnnnn
22: <header-value-after-decoding>
23: <runtime-value-after-decoding>
24: ENUM_VALUE (the MISSING telemetry step)
25: yyyy-mm-ddThh:mm:ssZ
26: <count-email1>,<count-email3>"></textarea>
      <button type="button" id="btnA" onclick="postAnswers()">Score answers</button>
      <div id="verdict"></div>

      <hr style="border:0;border-top:1px solid #e3e8ee;margin:22px 0;">

      <h1 style="font-size:16px;">Release final flag</h1>
      <p class="small">Once your core score clears the threshold, enter the four
      recovered fragment codes (each from a different evidence category).</p>
      <label for="f1">Email evidence code</label>
      <input type="text" id="f1" autocomplete="off" placeholder="from the Email 1 header (decode)">
      <label for="f2">Web artifact code</label>
      <input type="text" id="f2" autocomplete="off" placeholder="from page-source.js (decode)">
      <label for="f3">Identity log code</label>
      <input type="text" id="f3" autocomplete="off" placeholder="correlation id from identity-audit.json / signins.json">
      <label for="f4">Threat-intel code</label>
      <input type="text" id="f4" autocomplete="off" placeholder="MITRE technique id from the cited reports">
      <button type="button" id="btnF" onclick="postFragments()">Submit fragments</button>
      <div id="flagbox"></div>
      <details>
        <summary>Need the evidence?</summary>
        <p>Download the dataset bundle <code>downloads/Zeus0x01-AiTM-Investigation.zip</code>
        from the lab repository and investigate offline. This portal cannot grade
        without the deployed serverless function.</p>
      </details>
      <noscript><p style="color:#b3003c;">JavaScript is disabled - the portal cannot verify answers.</p></noscript>
    </div>
    <footer>
      Zeus0x01 lab series &middot; server-side verification &middot; HMAC-SHA256 digest comparison
    </footer>
  </div>
</div>
<script>
function parseAnswers() {
  var lines = document.getElementById("answers").value.split(/\\r?\\n/);
  var out = {};
  for (var i = 0; i < lines.length; i++) {
    var m = lines[i].trim().match(/^0*(\\d{1,2})\\s*[\\)\\.:\\-]\\s*(.+)$/);
    if (m) { out[parseInt(m[1], 10)] = m[2].trim(); }
  }
  return out;
}

function postAnswers() {
  var btn = document.getElementById("btnA");
  var d = document.getElementById("verdict");
  btn.disabled = true; d.className = ""; d.textContent = "Verifying...";
  fetch("/api/verify", { method: "POST", contentType: false, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: "answers", answers: parseAnswers() }) })
    .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
    .then(function (res) {
      if (res.body && res.body.ok) {
        d.className = "ok";
        d.textContent = "Core correct: " + res.body.core_correct + " / " + res.body.core_total +
            " (points " + res.body.core_points + "/" + res.body.core_max + ")" +
            "\\nBonus correct: " + res.body.bonus_correct + " / " + res.body.bonus_total +
            "\\nFragment status: " + (res.body.frag_status || "not submitted");
        var fb = document.getElementById("flagbox");
        if (res.body.flag) { fb.style.display = "block"; fb.textContent = res.body.flag; }
        else { fb.style.display = "none"; }
      } else {
        d.className = "err";
        d.textContent = (res.body && res.body.error) || "Verification failed.";
        document.getElementById("flagbox").style.display = "none";
      }
    })
    .catch(function () { d.className = "err"; d.textContent = "Verification service unavailable. Deploy /api/verify with configured digests."; })
    .finally(function () { btn.disabled = false; });
  return false;
}

function postFragments() {
  var btn = document.getElementById("btnF");
  btn.disabled = true;
  var payload = {
    mode: "fragments",
    f1: document.getElementById("f1").value,
    f2: document.getElementById("f2").value,
    f3: document.getElementById("f3").value,
    f4: document.getElementById("f4").value
  };
  fetch("/api/verify", { headers: { "Content-Type": "application/json" }, method: "POST", body: JSON.stringify(payload) })
    .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
    .then(function (res) {
      var d2 = document.getElementById("verdict");
      var fb = document.getElementById("flagbox");
      if (res.body && res.body.ok && res.body.flag) {
        d2.className = "ok"; d2.textContent = "All four fragments verified - flag released.";
        fb.style.display = "block"; fb.textContent = res.body.flag;
      } else {
        d2.className = "err";
        d2.textContent = (res.body && res.body.error) || "Fragment verification failed.";
        fb.style.display = "none";
      }
    })
    .catch(function () { var d2 = document.getElementById("verdict"); d2.className = "err"; d2.textContent = "Verification service unavailable."; })
    .finally(function () { btn.disabled = false; });
  return false;
}
</script>
</body>
</html>
"""


# Offline twin — local page for the evidence ZIP; assembles nothing, no secrets
OFFLINE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AiTM lab — offline answer checklist</title>
<style>
  body { font-family: system-ui, Arial, sans-serif; background:#161b22; color:#e6edf3; margin:0; }
  .box { max-width: 640px; margin: 50px auto; border:1px solid #30363d; border-radius:8px; padding: 24px 30px; }
  h1 { font-size: 18px; margin-top: 0; }
  p, li { font-size: 13px; color: #9aa4b2; }
  input { width: 100%; padding: 9px 10px; border:1px solid #3d444d; background:#0d1117; color:#e6edf3; border-radius:4px; font-size:14px; }
  label { display:block; font-size:12px; margin:14px 0 4px 0; }
  button { margin-top:16px; background:#1f6feb; color:#fff; border:0; padding:10px 18px; border-radius:4px; font-size:14px; }
  .out { margin-top:14px; font-family: ui-monospace, Consolas, monospace; font-size: 13px; color:#e3b341; white-space: pre-wrap; }
</style>
</head>
<body data-stage="idle">
<div class="box">
  <h1>Offline answer checklist (no verification, no secrets)</h1>
  <p>This page is a local checklist only. It contains <b>no answer digests and no
  canonical flag</b> — client-side pages cannot provide genuine answer secrecy.
  Final verification happens either on a deployed lab portal or on the hosting
  platform itself (question bank supplied by the lab maintainer).</p>
  <label>Answers you believe are correct (for your own notes)</label>
  <input id="notes" value="" readonly>
  <label>Fragment 1 (email/header) — F1</label>
  <input id="g1" autocomplete="off">
  <label>Fragment 2 (web artifact) — F2</label>
  <input id="g2" autocomplete="off">
  <label>Fragment 3 (identity/audit logs) — F3</label>
  <input id="g3" autocomplete="off">
  <label>Fragment 4 (threat-intel reference) — F4</label>
  <input id="g4" autocomplete="off">
  <button id="b" onclick="stage()">Show fragment status</button>
  <div class="out" id="out"></div>
  <p style="margin-top:22px;">Submit all four fragments through the hosted portal
  or your lab platform's answer box once your core score clears the threshold.</p>
</div>
<script>
function stage() {
  var vals = ["g1","g2","g3","g4"].map(function (id) { return document.getElementById(id).value.trim(); });
  var filled = vals.filter(function (v) { return v; }).length;
  var out = "Fragments entered: " + filled + " / 4" + "\\n";
  if (filled === 4) {
    out += "All four fragments present.\\n";
  } else {
    out += "Each fragment must come from a different evidence category before submission.\\n";
  }
  out += "\\n(No flag can be assembled offline; the canonical flag lives\\n on the verification side only.)";
  document.getElementById("out").textContent = out;
}
</script>
</body>
</html>
"""


def write_portal():
    html = PORTAL_HTML.replace("CASE_ID_PLACEHOLDER", CASE_ID)
    html = html.replace("DS_VERSION_PLACEHOLDER", DS_VERSION)
    for path in ("public/index.html", "deploy/public/index.html"):
        w(path, html)
    for path in ("api/verify.js", "deploy/api/verify.js"):
        w(path, PORTAL_JS)
    # vercel config mirrors (root + deploy), matching the reference repo style
    vercel = """{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "cleanUrls": true,
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Robots-Tag", "value": "noindex, nofollow" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "no-referrer" }
      ]
    },
    {
      "source": "/instructor/(.*)",
      "headers": [
        { "key": "X-Robots-Tag", "value": "noindex, nofollow, noarchive" }
      ]
    }
  ]
}
"""
    for path in ("vercel.json", "deploy/vercel.json"):
        w(path, vercel)


def write_offline_twin():
    w(os.path.join("artifacts", "web", "offline-checklist.html"), OFFLINE_HTML)
