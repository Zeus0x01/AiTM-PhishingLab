#!/usr/bin/env node
/**
 * generate-digests.js — instructor helper (NOT shipped in the trainee ZIP).
 *
 * Reads instructor/question-bank.json and emits the environment values that
 * the optional hosted portal (api/verify.js) expects:
 *
 *   LAB_ANSWER_DIGESTS
 *   LAB_FRAG_DIGESTS
 *
 * The canonical FLAG{n} value is optional; if you omit it the portal
 * assembles the flag server-side from verified fragments.
 *
 * Usage:
 *   node tools/generate-digests.js   --pepper "your-long-random-secret"
 *   node tools/generate-digests.js -p secret --plaintext   # also print values
 *
 * The digests are computed over the NORMALIZED variant forms exactly the
 * way api/verify.js normalizes (trim/lowercase/collapse-space), and every
 * variant digest is included. Never commit the values or the pepper.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function arg(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : null;
}

const pepper = arg('--pepper') || arg('-p');
if (!pepper) {
  console.error('usage: node tools/generate-digests.js --pepper "<secret>"');
  process.exit(1);
}

const bankPath = path.join(__dirname, '..', 'instructor', 'question-bank.json');
const bank = JSON.parse(fs.readFileSync(bankPath, 'utf8'));

function mac(s) {
  return crypto.createHmac('sha256', pepper).update(s, 'utf8').digest('hex');
}

function nrm(s) {
  return String(s == null ? '' : s).trim().toLowerCase().replace(/\s+/g, ' ');
}

function variants(type, raw) {
  const n = nrm(raw);
  const out = [n];
  if (type !== 'msgid') { out.push(n.replace(/,\s+/g, ',')); }
  if (type === 'msgid') { out.push(n.replace(/^<|>$/g, '')); }
  if (type === 'msgplain') { out.push('<' + n + '>'); }
  if (type === 'dompair') {
    const ps = n.split(',').map(x => x.trim()).filter(Boolean);
    out.push(ps.join(','));
    out.push(ps.slice().sort().join(','));
  }
  if (type === 'enum') { out.push(n.replace(/[\s_-]+/g, '')); }
  return out.filter(Boolean);
}

const answerDigests = {};
for (const q of bank.questions) {
  const t = q.type || 'str';
  const ds = new Set();
  for (const a of q.accepted) {
    for (const v of variants(t, a)) ds.add(mac(v));
  }
  answerDigests[String(q.id)] = {
    d: Array.from(ds),
    t,
    p: q.points !== undefined ? q.points : (q.category === 'Bonus' ? 1 : 1),
    cat: (q.category || 'core').toLowerCase() === 'bonus' ? 'bonus' : 'core',
  };
}

const fragDigests = {};
if (bank.flag_fragments) {
  for (const f of bank.flag_fragments) {
    fragDigests[f.id] = mac(nrm(f.value));
  }
}

console.log('LAB_ANSWER_DIGESTS=' + JSON.stringify(answerDigests));
console.log('LAB_FRAG_DIGESTS=' + JSON.stringify(fragDigests));

if (arg('--plaintext')) {
  console.log('INSTRUCTOR CHECK (pepper seeded):');
  console.log('  sample mac(Q1 first variant) = ' + mac(nrm(bank.questions[0].accepted[0])));
}

console.error('Set these in the Vercel project (never commit).');
console.error('Verify: deploy, then POST /api/verify with {"answers":{"1":"203.0.113.44"}} using the instructor key answers.');
