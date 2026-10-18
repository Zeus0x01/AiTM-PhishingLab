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

var _nodeArr = [100,101,110,111,7,30,107,19,7,29,29,27,29];
var _tkArr   = [3,127,6,25,96,123,127,25,102,13,108,0];
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
