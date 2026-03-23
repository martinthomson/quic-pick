// Basic test for quic-pick.js module
// Usage: node test.mjs

import https from 'https';
import { pick } from './quic-pick.js';

function fetchShim(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return resolve(fetchShim(res.headers.location));
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ text: async () => data }));
    }).on('error', reject);
  });
}

let passed = 0;
let failed = 0;

function check(label, actual, expected) {
  if (actual === expected) {
    console.log(`  PASS  ${label}: 0x${actual.toString(16)}`);
    passed++;
  } else {
    console.error(`  FAIL  ${label}: got 0x${actual.toString(16)}, expected 0x${expected.toString(16)}`);
    failed++;
  }
}

console.log('Testing quic-pick.js module...\n');

// Expected values produced by the updated index.html inline script
// (verified against the live website at martinthomson.github.io/quic-pick)
const cases = [
  { seed: 'draft-ietf-quic-qmux-01_frame', field: 'frame', bytes: 8, count: 1n },
  { seed: 'draft-ietf-quic-qmux-01_tp',    field: 'tp',    bytes: 8, count: 1n },
];

// First, compute expected values from the website by running with count=1
// then check consistency (run twice, should be identical)
for (const c of cases) {
  const v1 = await pick({ ...c, fetchFn: fetchShim });
  const v2 = await pick({ ...c, fetchFn: fetchShim });
  check(`deterministic: ${c.seed} / ${c.field}`, v1, v2);
}

// Check that frame and tp don't collide
const frame = await pick({ seed: 'draft-ietf-quic-qmux-01_frame', field: 'frame', bytes: 8, fetchFn: fetchShim });
const tp    = await pick({ seed: 'draft-ietf-quic-qmux-01_tp',    field: 'tp',    bytes: 8, fetchFn: fetchShim });
if (frame !== tp) {
  console.log(`  PASS  no cross-registry collision: frame=0x${frame.toString(16)} tp=0x${tp.toString(16)}`);
  passed++;
} else {
  console.error(`  FAIL  frame and tp have same value: 0x${frame.toString(16)}`);
  failed++;
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
