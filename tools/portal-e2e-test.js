'use strict';
/* End-to-end portal test: score a perfect run + fragment mode. */
process.env.LAB_VERIFY_HMAC_KEY = 'test-pepper-123';
const { execSync } = require('child_process');
const out = execSync('node tools/generate-digests.js -p test-pepper-123', { encoding: 'utf8', cwd: __dirname + '/..' });
for (const line of out.split(/\r?\n/)) {
  const m = line.match(/^(LAB_[A-Z_]+)=(.+)$/);
  if (m) process.env[m[1]] = m[2];
}

const handler = require('../api/verify.js');

function call(body, cb) {
  const res = {
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.code = code; return this; },
    json(o) { this.body = o; },
    end() {},
  };
  require('crypto').randomBytes(0);
  handler({ method: 'POST', body }, res);
  cb(res);
}

function run() {
  let failed = 0;
  call({ answers: ALL }, (res) => {
    console.log('POST /api/verify full answers =>', JSON.stringify(res.body));
    if (res.code !== 200 || res.body.core_correct !== 21 || res.body.bonus_correct !== 5 || res.body.core_points !== 30) {
      console.error('FAIL: scoring mismatch'); failed++;
    }
  });
  call({ mode: 'fragments', f1: 'MKD-2026-R480', f2: 'NODE-4A9-7717', f3: 'CORR-2E71-05', f4: 'T1539' }, (res) => {
    console.log('POST /api/verify fragments =>', JSON.stringify(res.body));
    if (res.code !== 200 || !/^FLAG\{/.test(res.body.flag || '')) {
      console.error('FAIL: fragment mode'); failed++;
    }
  });
  call({ answers: { '1': '203.0.113.1' } }, (res) => {
    console.log('POST /api/verify one wrong =>', JSON.stringify(res.body));
    if (res.code !== 200 || res.body.core_correct !== 0) {
      console.error('FAIL: wrong answer not rejected'); failed++;
    }
  });
  delete process.env.LAB_ANSWER_DIGESTS;
  call({ answers: {} }, (res) => {
    console.log('POST /api/verify unconfigured =>', JSON.stringify(res.body));
    if (res.code !== 503) { console.error('FAIL: unconfigured should 503'); failed++; }
  });
  console.log(failed === 0 ? 'PORTAL-E2E-PASS' : 'PORTAL-E2E-FAIL');
  process.exit(failed === 0 ? 0 : 1);
}
const ALL = {
  '1': '203.0.113.44',
  '2': 'EVT-58107',
  '3': 'larkspur-mail-relay-02.example, larkspur-itdesk.example',
  '4': 'SR-88031,identity-audit.json',
  '5': '/signin/azure_sso',
  '6': 'connection-events.json,EVT-C1052',
  '7': '7K2-TOK-R9X4',
  '8': 'CONSOLE_ONLY',
  '9': 'SecArchives,EVT-58314',
  '10': '3',
  '11': 'ALERT-7712,medium',
  '12': 'CORR-2E71-05,EVT-58115',
  '13': 'EVT-58315,docshare-online.example',
  '14': 'beacon.diremsto[.]com,Tycoon 2FA',
  '15': 'T1539',
  '16': 'Storm-2372',
  '17': 'EVT-58103, EVT-58314, EVT-58315',
  '18': 'EVT-58311,EVT-C1050,EVT-58103',
  '19': 'session-hijacked',
  '20': '<20260915T080455Z-1d3e6b8c2@mail.audit-trail-software.example>',
  '21': 'EVT-58316',
  '22': 'MKD-2026-R480',
  '23': 'NODE-4A9-7717',
  '24': 'SESSIONCOOKIECAPTURE',
  '25': '2026-09-14T10:52:20Z',
  '26': '3,4',
};
run();
