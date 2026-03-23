/**
 * quic-pick.js - deterministic QUIC codepoint selection algorithm
 *
 * Works in both browsers and Node.js (v18+).
 * See README.md for usage and examples.
 */

const BASE_URL = 'https://martinthomson.github.io/quic-pick/';

/**
 * Maps registry XML filenames to their IANA registry ID -> field name.
 * @type {Object.<string, Object.<string, string>>}
 */
export const sources = {
  "quic.xml": {
    "quic-versions": "version",
    "quic-transport": "tp",
    "quic-frame-types": "frame",
    "quic-transport-error-codes": "error",
  },
  "h3.xml": {
    "http3-parameters-frame-types": "h3frame",
    "http3-parameters-settings": "h3setting",
    "http3-parameters-error-codes": "h3error",
    "http3-parameters-stream-types": "h3stream",
  },
  "masque.xml": {
    "http-capsule-types": "capsule",
  },
};

// Already-assigned codepoints, keyed by field name. Populated lazily.
let taken = {};

async function getTaken(n, fetchFn) {
  fetchFn ??= fetch;
  const file = Object.keys(sources).find(s => Object.values(sources[s]).indexOf(n) >= 0);
  if (!file) { throw new Error(`Unable to find source for ${n}`); }
  console.log(`loading database from ${file} (for ${n})...`);

  const url = new URL(file, BASE_URL).href;
  const text = await (await fetchFn(url)).text();

  // Use DOMParser in browsers; fall back to regex in Node.js.
  let registries;
  if (typeof DOMParser !== 'undefined') {
    const xml = (new DOMParser).parseFromString(text, "text/xml");
    registries = [...xml.documentElement.children]
      .filter(r => r.localName === "registry")
      .map(r => ({
        id: r.getAttribute("id"),
        values: [...r.children]
          .filter(rec => rec.localName === "record")
          .flatMap(rec => [...rec.children]
            .filter(e => e.localName === "value")
            .map(e => e.textContent.trim())),
      }));
  } else {
    registries = [];
    const regPattern = /<registry[^>]*id="([^"]+)"[^>]*>([\s\S]*?)<\/registry>/g;
    let rm;
    while ((rm = regPattern.exec(text)) !== null) {
      const id = rm[1];
      const body = rm[2];
      const values = [];
      const valPattern = /<value>([^<]+)<\/value>/g;
      let vm;
      while ((vm = valPattern.exec(body)) !== null) {
        values.push(vm[1].trim());
      }
      registries.push({ id, values });
    }
  }

  for (const { id, values } of registries) {
    if (!(id in sources[file])) { continue; }
    const field = sources[file][id];
    const parsed = [];
    for (const raw of values) {
      try {
        let [start, end] = raw.split("-").map(v => BigInt(v));
        do {
          parsed.push(start++);
        } while (start < (end ?? start));
      } catch {
        // skip non-numeric values (e.g. "provisional", "permanent, 0x00-0x3f")
      }
    }
    taken[field] = parsed;
    console.log(`...loaded ${parsed.length} values for ${field}`);
  }
}

async function isTaken(v, field, fetchFn) {
  if (!(field in taken)) {
    await getTaken(field, fetchFn);
  }
  return taken[field].indexOf(v) >= 0;
}

async function hash(v) {
  return await globalThis.crypto.subtle.digest({ name: "SHA-256" }, v);
}

function rng(seed) {
  const s = "quic-pick-" + seed;
  const base = (new TextEncoder()).encode(s);
  const offset = base.length;
  let counter = 0;
  let seedBuf = new Uint8Array(offset + 2);
  seedBuf.set(base, 0);
  return async function (bits) {
    seedBuf.set([(counter >> 8) & 0xff, counter & 0xff], offset);
    const r = new Uint8Array(await hash(seedBuf));
    const shift = 8 - (bits % 8);
    let v = BigInt((shift === 8) ? r[0] : r[0] >> shift);
    let i = 1;
    for (let bytes = (bits - 1) >> 3; bytes > 0; --bytes) {
      v = (v << 8n) | BigInt(r[i++]);
    }
    counter++;
    return v;
  };
}

async function version(r, _bytes) {
  // A QUIC version number.
  r ??= rng();
  let v;
  do {
    v = await r(32);
  } while ((v & 0x0f0f0f0fn) === 0x0a0a0a0an);
  return v;
}

async function vi62(r, bytes) {
  // An unfiltered QUIC varint.
  r ??= rng();
  const shift = BigInt((bytes >> 1) * 8 - 2);
  let v;
  do {
    v = await r(bytes * 8 - 2);
  } while (v < (1n << shift));
  return v;
}

async function vi62gmod(r, bytes, rem, div) {
  // A 62-bit QUIC varint, except those equal to $rem mod $div,
  // except for any value that is less than $rem (so 2 is ok for 33 mod 31).
  let v;
  do {
    v = await vi62(r, bytes);
  } while (v % div === rem % div && v >= rem);
  return v;
}

async function vi62g2mod31(r, bytes) {
  return await vi62gmod(r, bytes, 33n, 31n);
}

async function vi62g27mod31(r, bytes) {
  return await vi62gmod(r, bytes, 27n, 31n);
}

async function vi62g23mod41(r, bytes) {
  return await vi62gmod(r, bytes, 23n, 41n);
}

/**
 * Maps field names to their generator function and optional fixed bit width.
 * @type {Object.<string, {r: Function, bits?: number}>}
 */
export const rules = {
  version:   { r: version,      bits: 32 },
  tp:        { r: vi62g27mod31 },
  frame:     { r: vi62 },
  error:     { r: vi62 },
  h3frame:   { r: vi62g2mod31 },
  h3setting: { r: vi62g2mod31 },
  h3error:   { r: vi62g2mod31 },
  h3stream:  { r: vi62g2mod31 },
  capsule:   { r: vi62g23mod41 },
};

/**
 * Pick a starting codepoint for n consecutive values, using a given generator.
 * Retries up to 32 times if any value in the range is already taken.
 *
 * @param {bigint} n - Number of consecutive values required.
 * @param {string} seed - Seed string for the RNG.
 * @param {Function} f - Generator function (e.g. vi62, vi62g27mod31).
 * @param {number} bytes - Encoded size in bytes (1, 2, 4, or 8).
 * @param {string} field - Registry field name (e.g. 'frame', 'tp').
 * @param {Function} [fetchFn] - Optional fetch override for loading registries.
 * @returns {Promise<bigint>} The selected codepoint.
 */
export async function draw(n, seed, f, bytes, field, fetchFn) {
  const tries = 32;
  let r = rng(seed);
  outer: for (let i = 0; i < tries; ++i) {
    const v = await f(r, bytes);
    for (let j = 0n; j < n; ++j) {
      if (await isTaken(v + j, field, fetchFn)) {
        console.log(`draw ${i + 1} for ${field}: ${v.toString(16)} taken@${(v + j).toString(16)} (offset ${j})`);
        continue outer;
      }
    }
    return v;
  }
  throw new Error(`failed to generate a value for ${field} after ${tries} draws`);
}

/**
 * Select a codepoint deterministically for a given seed and field type.
 *
 * @param {object} options
 * @param {string} options.seed - Seed string (e.g. 'draft-foo-bar-01_frame').
 * @param {string} options.field - Registry field name (e.g. 'frame', 'tp', 'version').
 * @param {number} [options.bytes=8] - Encoded size in bytes (1, 2, 4, or 8).
 * @param {number|bigint} [options.count=1] - Number of consecutive values needed.
 * @param {Function} [options.fetchFn] - fetch override; required in Node.js environments
 *   that don't have a global fetch (Node < 18).
 * @returns {Promise<bigint>} The selected codepoint (start of range if count > 1).
 */
export async function pick({ seed, field, bytes = 8, count = 1n, fetchFn } = {}) {
  if (!seed) { throw new Error('seed is required'); }
  if (!field) { throw new Error('field is required'); }
  const rule = rules[field];
  if (!rule) { throw new Error(`Unknown field: ${field}`); }

  const r = rng(seed);
  const n = BigInt(count);
  const tries = 32;

  outer: for (let i = 0; i < tries; ++i) {
    const v = await rule.r(r, bytes);
    for (let j = 0n; j < n; ++j) {
      if (await isTaken(v + j, field, fetchFn)) {
        console.log(`draw ${i + 1} for ${field}: ${v.toString(16)} taken@${(v + j).toString(16)} (offset ${j})`);
        continue outer;
      }
    }
    return v;
  }
  throw new Error(`failed to generate a value for ${field} after ${tries} draws`);
}
