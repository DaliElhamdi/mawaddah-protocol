// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Load test for a running relay (local `wrangler dev`, staging or production).
// No dependencies: Node 22 `fetch` and WebCrypto only.
//
//   node loadtest/loadtest.mjs <base-url> [--requests 300] [--concurrency 10]
//                              [--seed <text>] [--json] [--allow-production]
//
// It plays one couple: registers two inboxes (A sends, B receives), then
//   health   GET  /health                           (unsigned)
//   deposit  PUT  /v1/inbox/B/envelopes             (1 KiB envelope, Maw-Wake: 0, so no push)
//   fetch    GET  /v1/inbox/B/envelopes?after=...   (pages of up to 100 envelopes)
//   poll     GET  /v1/inbox/B/envelopes?after=last  (an empty inbox, what a phone does on open)
//   ack      POST /v1/inbox/B/ack                   (one cumulative ACK per page)
// and finally deletes both inboxes. The envelopes are random bytes (the relay
// does not read them); nothing is sent that names a real person.
//
// Limits to know: the relay allows 5 new inboxes per IP per hour, and a run
// registers 2. Use the same --seed to run again at once (registering the same
// key again is free). Every deposit goes to one Durable Object (one couple's
// inbox), which is the real access pattern: one couple never uses more than one.

import { createHash, randomBytes } from 'node:crypto';

const argv = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : fallback;
};
const has = (name) => argv.includes(`--${name}`);
const baseUrl = (argv[0] ?? '').replace(/\/+$/, '');
const requests = Number(flag('requests', '300'));
const concurrency = Number(flag('concurrency', '10'));
const seedText = flag('seed', randomBytes(8).toString('hex'));
const asJson = has('json');

if (!/^https?:\/\//.test(baseUrl) || !Number.isInteger(requests) || requests < 1 || !Number.isInteger(concurrency) || concurrency < 1) {
  console.error('usage: node loadtest/loadtest.mjs <base-url> [--requests N] [--concurrency C] [--seed TEXT] [--json]');
  process.exit(2);
}
const host = new URL(baseUrl).hostname;
const local = ['localhost', '127.0.0.1', '[::1]'].includes(host);
if (!local && !baseUrl.startsWith('https://')) {
  console.error('refusing plain HTTP to a non-local address');
  process.exit(2);
}
if (!local && !host.includes('-staging.') && !has('allow-production')) {
  console.error('refusing a non-local address that is not a staging Worker; add --allow-production if you mean it');
  process.exit(2);
}

const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** An Ed25519 key from a seed text (WebCrypto, via PKCS#8). */
async function keyFor(label) {
  const seed = createHash('sha256').update(`mawaddah-loadtest/${seedText}/${label}`).digest();
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  return { privateKey, keyText: jwk.x };
}

/** Signed request, PROTOCOL.md section 13. Returns { status, ms, body }. */
async function send(key, method, path, body = new Uint8Array(0), extra = {}) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = b64u(randomBytes(16));
  const input = ['MAWADDAH-RELAY-V1', method, path, sha256Hex(body), timestamp, nonce].join('\n');
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key.privateKey, Buffer.from(input)));
  const headers = {
    'Maw-Key': key.keyText,
    'Maw-Timestamp': timestamp,
    'Maw-Nonce': nonce,
    'Maw-Signature': b64u(signature),
    ...extra,
  };
  return timed(method, path, headers, body);
}

async function timed(method, path, headers, body) {
  const started = performance.now();
  try {
    const res = await fetch(baseUrl + path, { method, headers, body: method === 'GET' || method === 'DELETE' ? undefined : body });
    const text = await res.text();
    return { status: res.status, ms: performance.now() - started, body: text };
  } catch {
    return { status: 0, ms: performance.now() - started, body: '' };
  }
}

const json = (value) => Buffer.from(JSON.stringify(value));

/** Runs [count] tasks with at most [concurrency] in flight; returns their results. */
async function pool(count, task) {
  const results = new Array(count);
  let next = 0;
  const started = performance.now();
  await Promise.all(
    Array.from({ length: Math.min(concurrency, count) }, async () => {
      while (next < count) {
        const i = next++;
        results[i] = await task(i);
      }
    }),
  );
  return { results, seconds: (performance.now() - started) / 1000 };
}

const percentile = (sorted, p) => (sorted.length === 0 ? NaN : sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]);
const report = [];
function record(name, results, seconds) {
  const times = results.map((r) => r.ms).sort((a, b) => a - b);
  const statuses = {};
  for (const r of results) statuses[r.status] = (statuses[r.status] ?? 0) + 1;
  const ok = results.filter((r) => r.status >= 200 && r.status < 300).length;
  report.push({
    scenario: name,
    requests: results.length,
    ok,
    failed: results.length - ok,
    statuses,
    perSecond: Number((results.length / seconds).toFixed(1)),
    p50: Number(percentile(times, 50).toFixed(1)),
    p95: Number(percentile(times, 95).toFixed(1)),
    p99: Number(percentile(times, 99).toFixed(1)),
    max: Number((times.at(-1) ?? NaN).toFixed(1)),
  });
}

async function main() {
  const a = await keyFor('A');
  const b = await keyFor('B');
  const registration = (key) => json({ signing_key: key.keyText, push_token: null, platform: 'android' });

  const regA = await send(a, 'POST', '/v1/inbox', registration(a), { 'content-type': 'application/json' });
  const regB = await send(b, 'POST', '/v1/inbox', registration(b), { 'content-type': 'application/json' });
  if (regA.status > 201 || regB.status > 201) {
    console.error(`could not register the two inboxes (A: ${regA.status}, B: ${regB.status}); after 429 wait an hour or reuse --seed`);
    process.exit(1);
  }
  const inboxB = JSON.parse(regB.body).inbox_id;
  const inboxA = JSON.parse(regA.body).inbox_id;
  const allow = await send(b, 'POST', `/v1/inbox/${inboxB}/allow`, json({ sender_key: a.keyText }), { 'content-type': 'application/json' });
  if (allow.status > 201) {
    console.error(`allow failed (${allow.status}); use a new --seed`);
    process.exit(1);
  }

  try {
    // 1. health: unsigned and cheap (edge + Worker, no Durable Object).
    let run = await pool(requests, () => timed('GET', '/health', {}, undefined));
    record('health', run.results, run.seconds);

    // 2. deposit: A to B, 1 KiB random envelopes, no wake-up.
    const envelope = randomBytes(1024);
    const path = `/v1/inbox/${inboxB}/envelopes`;
    run = await pool(requests, () => send(a, 'PUT', path, envelope, { 'Maw-Wake': '0', 'content-type': 'application/octet-stream' }));
    record('deposit', run.results, run.seconds);

    // 3. fetch + 5. ack: B reads everything page by page and acknowledges each page.
    const fetched = [];
    const acked = [];
    let cursor = null;
    const fetchStart = performance.now();
    for (let guard = 0; guard < requests + 5; guard++) {
      const p = cursor === null ? path : `${path}?after=${cursor}`;
      const res = await send(b, 'GET', p);
      fetched.push(res);
      if (res.status !== 200) break;
      const page = JSON.parse(res.body);
      if (page.envelopes.length === 0) break;
      cursor = page.envelopes.at(-1).cursor;
      acked.push(await send(b, 'POST', `/v1/inbox/${inboxB}/ack`, json({ cursor }), { 'content-type': 'application/json' }));
      if (!page.more) break;
    }
    record('fetch (pages of <= 100)', fetched, (performance.now() - fetchStart) / 1000);
    record('ack (one per page)', acked, (performance.now() - fetchStart) / 1000);

    // 4. poll: an empty inbox, concurrent (what phones do on every app open).
    const pollPath = `${path}?after=${cursor ?? 0}`;
    run = await pool(requests, () => send(b, 'GET', pollPath));
    record('poll (empty inbox)', run.results, run.seconds);
  } finally {
    // Delete both inboxes, so nothing of the run waits on the relay.
    await send(a, 'DELETE', `/v1/inbox/${inboxA}`);
    await send(b, 'DELETE', `/v1/inbox/${inboxB}`);
  }

  if (asJson) {
    console.log(JSON.stringify({ baseUrl, requests, concurrency, report }, null, 2));
  } else {
    console.log(`relay ${baseUrl}: ${requests} requests per scenario, concurrency ${concurrency}`);
    console.table(
      report.map((r) => ({
        scenario: r.scenario,
        requests: r.requests,
        failed: r.failed,
        'req/s': r.perSecond,
        'p50 ms': r.p50,
        'p95 ms': r.p95,
        'p99 ms': r.p99,
        'max ms': r.max,
        statuses: JSON.stringify(r.statuses),
      })),
    );
  }
  if (report.some((r) => r.failed > 0)) process.exitCode = 1;
}

await main();
