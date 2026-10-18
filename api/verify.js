/**
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
