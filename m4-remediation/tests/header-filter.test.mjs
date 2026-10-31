import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { BLOCKED_HEADER, carriesBlockedHeader, createBoundary, endToEnd } from '../header-filter/boundary.mjs';

// The boundary runs on loopback in front of a stub upstream that records what actually reaches it.
// Blocked-header requests use the same neutral value as M1's baseline test, never a bypass value.
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const close = server => new Promise(resolve => server.close(resolve));

async function harness(handler = (req, res) => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('upstream-ok'); }, limits = {}) {
  const seen = [];
  const upstream = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    seen.push({ method: req.method, url: req.url, rawHeaders: req.rawHeaders, headers: req.headers, body: Buffer.concat(chunks).toString() });
    handler(req, res);
  });
  const logs = [];
  const boundary = createBoundary({ upstream: `http://127.0.0.1:${await listen(upstream)}`, log: line => logs.push(JSON.parse(line)), limits });
  const port = await listen(boundary);
  // closeAllConnections: a failed assertion can leave a client mid-request, and close() alone would wait for it.
  const stop = async () => { boundary.closeAllConnections(); upstream.closeAllConnections(); await Promise.all([close(boundary), close(upstream)]); };
  return { port, seen, logs, stop };
}

// Raw HTTP/1.1 so header-name case, duplicates and request-target form are exactly as written.
function raw(port, text) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => socket.write(text));
    const chunks = [];
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('end', () => resolve(Buffer.concat(chunks).toString()));
    socket.on('error', reject);
  });
}
const statusOf = response => Number(response.split(' ')[1]);
async function waitFor(condition, ms = 3000) {
  const deadline = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('condition not met in time');
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}
const request = (port, path, options = {}) => fetch(`http://127.0.0.1:${port}${path}`, { redirect: 'manual', ...options });

test('only the framework-internal header name is blocked, in any case or repetition', () => {
  assert.equal(BLOCKED_HEADER, 'x-middleware-subrequest');
  for (const name of ['x-middleware-subrequest', 'X-Middleware-Subrequest', 'X-MIDDLEWARE-SUBREQUEST']) {
    assert.ok(carriesBlockedHeader(['Host', 'a', name, 'external-untrusted']));
    assert.ok(carriesBlockedHeader(['Host', 'a', name, '']));
  }
  assert.ok(carriesBlockedHeader(['Host', 'a', 'Accept', '*/*', BLOCKED_HEADER, 'one', BLOCKED_HEADER, 'two']));
  assert.ok(!carriesBlockedHeader(['Host', 'a', 'Cookie', `${BLOCKED_HEADER}=1`, 'X-Note', BLOCKED_HEADER]));
  assert.ok(!carriesBlockedHeader(['Host', 'a', 'X-Middleware-Prefetch', '1', 'X-Request-Id', 'abc']));
});

test('connection-specific headers are dropped and end-to-end headers keep their order', () => {
  const kept = endToEnd(['Host', 'h', 'Connection', 'keep-alive, X-Drop-Me', 'Keep-Alive', 'timeout=5', 'X-Drop-Me', '1', 'Transfer-Encoding', 'chunked', 'Content-Length', '9', 'Expect', '100-continue', 'Upgrade', 'h2c', 'Proxy-Authorization', 'x', 'TE', 'trailers', 'Cookie', 'a=1', 'Set-Cookie', 's=1', 'Set-Cookie', 't=2']);
  assert.deepEqual(kept, ['Host', 'h', 'Cookie', 'a=1', 'Set-Cookie', 's=1', 'Set-Cookie', 't=2']);
});

test('a request carrying the internal header is rejected and never reaches the application', async () => {
  const lab = await harness();
  try {
    for (const name of ['x-middleware-subrequest', 'X-Middleware-Subrequest']) {
      const response = await raw(lab.port, `GET /lab/header-filter/dashboard HTTP/1.1\r\nHost: header-filter:3000\r\n${name}: external-untrusted\r\nCookie: lab_header_filter_session=any\r\nConnection: close\r\n\r\n`);
      assert.equal(statusOf(response), 400);
      assert.match(response, /\r\nx-lab-boundary: header-filter\r\n/i);
      assert.match(response, /\r\nx-lab-boundary-decision: rejected-internal-header\r\n/i);
      assert.match(response, /"layer":"header-filter"/);
    }
    const duplicated = await raw(lab.port, `POST /lab/header-filter/api/login HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n${BLOCKED_HEADER}: a\r\n${BLOCKED_HEADER}: b\r\nConnection: close\r\n\r\nx=1`);
    assert.equal(statusOf(duplicated), 400);
    const viaFetch = await request(lab.port, '/lab/header-filter/api/records', { headers: { [BLOCKED_HEADER]: 'external-untrusted' } });
    assert.equal(viaFetch.status, 400);
    assert.equal((await viaFetch.json()).layer, 'header-filter');
    assert.equal(lab.seen.length, 0, 'the upstream application must not receive any rejected request');
    assert.equal(lab.logs.length, 4);
    for (const entry of lab.logs) {
      assert.equal(entry.decision, 'rejected-internal-header');
      assert.ok(!JSON.stringify(entry).includes('external-untrusted'), 'header values are never logged');
    }
  } finally { await lab.stop(); }
});

test('other requests are relayed unchanged in both directions', async () => {
  const lab = await harness((req, res) => {
    res.writeHead(307, ['Location', 'http://127.0.0.1:4317/lab/header-filter/login', 'Set-Cookie', 'first=1; Path=/lab/header-filter', 'Set-Cookie', 'second=2; Path=/lab/header-filter', 'Content-Type', 'text/plain', 'Connection', 'X-Upstream-Private', 'X-Upstream-Private', 'hidden']);
    res.end('upstream-body');
  });
  try {
    const response = await raw(lab.port, 'GET /lab/header-filter/dashboard?view=all HTTP/1.1\r\nHost: header-filter:3000\r\nCookie: lab_header_filter_session=token\r\nAccept: text/html\r\nRSC: 1\r\nNext-Router-State-Tree: %5B%22%22%5D\r\nNext-Url: /lab/header-filter\r\nX-Request-Id: abc\r\nConnection: close\r\n\r\n');
    assert.equal(statusOf(response), 307, 'redirects are relayed, never followed');
    assert.match(response, /\r\nLocation: http:\/\/127\.0\.0\.1:4317\/lab\/header-filter\/login\r\n/);
    assert.match(response, /\r\nSet-Cookie: first=1; Path=\/lab\/header-filter\r\nSet-Cookie: second=2; Path=\/lab\/header-filter\r\n/);
    assert.match(response, /\r\nX-Lab-Boundary: header-filter\r\n/);
    assert.match(response, /\r\nContent-Length: 13\r\n/);
    assert.doesNotMatch(response, /X-Upstream-Private/i);
    assert.ok(response.endsWith('\r\n\r\nupstream-body'));
    assert.equal(lab.seen.length, 1);
    const [forwarded] = lab.seen;
    assert.equal(forwarded.method, 'GET');
    assert.equal(forwarded.url, '/lab/header-filter/dashboard?view=all');
    // Complete list: every end-to-end header in order (Next's client-navigation headers included), nothing
    // injected. The final Connection: close comes from the boundary's own one-shot upstream connection.
    assert.deepEqual(forwarded.rawHeaders, ['Host', 'header-filter:3000', 'Cookie', 'lab_header_filter_session=token', 'Accept', 'text/html', 'RSC', '1', 'Next-Router-State-Tree', '%5B%22%22%5D', 'Next-Url', '/lab/header-filter', 'X-Request-Id', 'abc', 'Connection', 'close']);
    assert.deepEqual(lab.logs, [{ boundary: 'header-filter', decision: 'forwarded', status: 307, method: 'GET', path: '/lab/header-filter/dashboard?view=all' }]);
  } finally { await lab.stop(); }
});

test('form bodies are forwarded with recomputed framing, including chunked uploads', async () => {
  const lab = await harness((req, res) => { res.writeHead(303, { Location: '/lab/header-filter/dashboard' }); res.end(); });
  try {
    const plain = await request(lab.port, '/lab/header-filter/api/login', { method: 'POST', headers: { Origin: 'http://127.0.0.1:4317', 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=a&password=b' });
    assert.equal(plain.status, 303);
    const chunked = await raw(lab.port, 'POST /lab/header-filter/api/login HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nuser=\r\n1\r\nx\r\n0\r\n\r\n');
    assert.equal(statusOf(chunked), 303);
    assert.deepEqual(lab.seen.map(entry => [entry.body, entry.headers['content-length'], entry.headers['transfer-encoding']]), [['username=a&password=b', '21', undefined], ['user=x', '6', undefined]]);
    assert.equal(lab.seen[0].headers.origin, 'http://127.0.0.1:4317');
  } finally { await lab.stop(); }
});

test('HEAD keeps the upstream length without a body', async () => {
  const lab = await harness((req, res) => { res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': '1234' }); res.end(); });
  try {
    const response = await raw(lab.port, 'HEAD /lab/header-filter HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n');
    assert.equal(statusOf(response), 200);
    assert.match(response, /\r\nContent-Length: 1234\r\n/);
    assert.ok(response.endsWith('\r\n\r\n'));
  } finally { await lab.stop(); }
});

test('oversized bodies and non-origin request targets stop at the boundary', async () => {
  const lab = await harness();
  try {
    const big = await request(lab.port, '/lab/header-filter/api/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'x'.repeat(4097) });
    assert.equal(big.status, 413);
    assert.equal(big.headers.get('x-lab-boundary-decision'), 'rejected-request-size');
    const absolute = await raw(lab.port, 'GET http://elsewhere.invalid/ HTTP/1.1\r\nHost: elsewhere.invalid\r\nConnection: close\r\n\r\n');
    assert.equal(statusOf(absolute), 400);
    assert.match(absolute, /rejected-request-target/);
    assert.equal(lab.seen.length, 0);
  } finally { await lab.stop(); }
});

test('upstream failures are reported as errors, never as a successful block', async () => {
  const slow = await harness((req, res) => setTimeout(() => { res.writeHead(200); res.end('late'); }, 1000), { upstreamMs: 150 });
  try {
    const response = await request(slow.port, '/lab/header-filter/api/health');
    assert.equal(response.status, 504);
    assert.equal(response.headers.get('x-lab-boundary-decision'), 'upstream-timeout');
  } finally { await slow.stop(); }

  const large = await harness((req, res) => { res.writeHead(200); res.end('y'.repeat(2048)); }, { responseBytes: 1024 });
  try {
    const response = await request(large.port, '/lab/header-filter/dashboard');
    assert.equal(response.status, 502);
    assert.equal(response.headers.get('x-lab-boundary-decision'), 'upstream-response-too-large');
  } finally { await large.stop(); }

  const unused = net.createServer();
  const port = await listen(unused);
  await close(unused);
  const boundary = createBoundary({ upstream: `http://127.0.0.1:${port}`, log: () => {} });
  const boundaryPort = await listen(boundary);
  try {
    const response = await request(boundaryPort, '/lab/header-filter/dashboard');
    assert.equal(response.status, 502);
    assert.equal(response.headers.get('x-lab-boundary-decision'), 'upstream-unavailable');
  } finally { await close(boundary); }
});

test('concurrency is bounded', async () => {
  let release;
  const held = new Promise(resolve => { release = resolve; });
  const lab = await harness(async (req, res) => { await held; res.writeHead(200); res.end('ok'); }, { inFlight: 1 });
  try {
    const first = request(lab.port, '/lab/header-filter/dashboard');
    while (lab.seen.length === 0) await new Promise(resolve => setImmediate(resolve));
    const second = await request(lab.port, '/lab/header-filter/dashboard');
    assert.equal(second.status, 503);
    assert.equal(second.headers.get('x-lab-boundary-decision'), 'busy');
    release();
    assert.equal((await first).status, 200);
  } finally { release(); await lab.stop(); }
});

test('a slow or abandoned request body holds no upstream slot and is never blamed on the application', async () => {
  const lab = await harness(undefined, { inFlight: 1, requestMs: 400 });
  try {
    const started = Date.now();
    const slow = new Promise((resolve, reject) => {
      const socket = net.connect(lab.port, '127.0.0.1', () => socket.write('POST /lab/header-filter/api/login HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\n\r\nab'));
      const chunks = [];
      socket.on('data', chunk => chunks.push(chunk));
      socket.on('close', () => resolve(Buffer.concat(chunks).toString()));
      socket.on('error', reject);
    });
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal((await request(lab.port, '/lab/header-filter/dashboard')).status, 200, 'the slow body does not occupy the single upstream slot');
    assert.match(await slow, /^HTTP\/1\.1 408 /);
    assert.ok(Date.now() - started < 2000, 'the request deadline is enforced near its configured value, not on Node\'s 30 s default sweep');
    await new Promise(resolve => {
      const socket = net.connect(lab.port, '127.0.0.1', () => {
        socket.write('POST /lab/header-filter/api/login HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nab');
        setTimeout(() => { socket.destroy(); resolve(); }, 50);
      });
    });
    await waitFor(() => lab.logs.filter(entry => entry.decision === 'client-request-incomplete').length === 2);
    assert.equal(lab.seen.length, 1, 'only the complete request reached the application');
    assert.ok(!lab.logs.some(entry => entry.decision.startsWith('upstream-')), 'client failures are not reported as application failures');
  } finally { await lab.stop(); }
});

test('the upstream must be a plain http origin', () => {
  for (const upstream of ['https://header-filter-app:3000', 'http://header-filter-app:3000/lab', 'http://user:pw@header-filter-app:3000', 'http://header-filter-app:3000/?x=1']) {
    assert.throws(() => createBoundary({ upstream }), /plain http/);
  }
});
