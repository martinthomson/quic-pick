// Basic test for quic-pick.js module
// Usage: node test.mjs

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { pick } from './quic-pick.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadLocalFile(url) {
  const filename = new URL(url).pathname.split('/').pop();
  const filepath = join(__dirname, filename);
  return readFile(filepath, 'utf-8').then(data => ({ text: async () => data }));
}

let passed = 0;
let failed = 0;

function check(label, a, b, shouldEqual) {
  const ok = shouldEqual ? a === b : a !== b;
  if (ok) {
    console.log(`  PASS  ${label}`);
    passed++;
  } else {
    console.error(`  FAIL  ${label}: 0x${a.toString(16)} ${shouldEqual ? '!==' : '==='} 0x${b.toString(16)}`);
    failed++;
  }
}
const assertEq = (label, a, b) => check(label, a, b, true);
const assertNotEq = (label, a, b) => check(label, a, b, false);

console.log('Testing quic-pick.js module...\n');

// Check determinism: same inputs should produce identical outputs
for (const field of ['frame', 'tp']) {
  const opts = { seed: 'test-draft-example-00', field, bytes: 8, fetchFn: loadLocalFile };
  const v1 = await pick(opts);
  const v2 = await pick(opts);
  assertEq(`deterministic (${field})`, v1, v2);
}

// Check that different seeds produce different values
const opts = { bytes: 8, fetchFn: loadLocalFile };
const frame_a = await pick({ seed: 'test-draft-example-00', field: 'frame', ...opts });
const frame_b = await pick({ seed: 'test-draft-example-01', field: 'frame', ...opts });
const tp_a    = await pick({ seed: 'test-draft-example-00', field: 'tp',    ...opts });
const tp_b    = await pick({ seed: 'test-draft-example-01', field: 'tp',    ...opts });

assertNotEq('different seeds, same field (frame)', frame_a, frame_b);
assertNotEq('different seeds, same field (tp)', tp_a, tp_b);
assertNotEq('different fields, different seeds', frame_a, tp_b);

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
