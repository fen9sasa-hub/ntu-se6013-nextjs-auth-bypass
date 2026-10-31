import http from 'node:http';

// The one rule this profile adds: clients may not send the framework-internal header.
// Everything else is relayed unchanged, so the comparison with `vulnerable` isolates this rule.
export const BLOCKED_HEADER = 'x-middleware-subrequest';
export const LIMITS = { requestBytes: 4096, requestMs: 10000, responseBytes: 2 * 1024 * 1024, upstreamMs: 5000, inFlight: 16 };
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'expect']);

export function carriesBlockedHeader(rawHeaders) {
  for (let i = 0; i < rawHeaders.length; i += 2) if (rawHeaders[i].toLowerCase() === BLOCKED_HEADER) return true;
  return false;
}

// End-to-end headers in received order, minus connection-specific ones and any the Connection
// header nominates. Content-Length is dropped because the boundary recomputes framing.
export function endToEnd(rawHeaders) {
  const nominated = new Set();
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (rawHeaders[i].toLowerCase() === 'connection') for (const token of rawHeaders[i + 1].split(',')) nominated.add(token.trim().toLowerCase());
  }
  const kept = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i].toLowerCase();
    if (!HOP_BY_HOP.has(name) && !nominated.has(name) && name !== 'content-length') kept.push(rawHeaders[i], rawHeaders[i + 1]);
  }
  return kept;
}

async function readBounded(stream, limit, code) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error('Byte limit exceeded'), { code });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function send(origin, method, path, headers, body, ms) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: origin.hostname, port: origin.port || 80, method, path, headers, setHost: false, agent: false, signal: AbortSignal.timeout(ms) }, resolve);
    request.on('error', reject);
    request.end(body.length ? body : undefined);
  });
}

export function createBoundary({ upstream, log = line => console.log(line), limits: overrides = {} }) {
  const limits = { ...LIMITS, ...overrides };
  const origin = new URL(upstream);
  if (origin.protocol !== 'http:' || origin.pathname !== '/' || origin.search || origin.hash || origin.username || origin.password) throw new Error('UPSTREAM_ORIGIN must be a plain http://host:port origin');
  let inFlight = 0;
  // Node enforces requestTimeout on this sweep interval (default 30 s), so keep it well below the limit.
  const sweep = Math.min(1000, Math.max(50, Math.floor(limits.requestMs / 4)));
  const server = http.createServer({ connectionsCheckingInterval: sweep }, async (req, res) => {
    // One JSON line per decision, for correlating runner evidence. Header values are never logged.
    const record = (decision, status) => log(JSON.stringify({ boundary: 'header-filter', decision, status, method: req.method, path: req.url.slice(0, 200) }));
    const reply = (status, decision, error) => {
      record(decision, status);
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Lab-Boundary': 'header-filter', 'X-Lab-Boundary-Decision': decision, Connection: 'close' });
      res.end(JSON.stringify({ error, layer: 'header-filter' }));
    };
    if (carriesBlockedHeader(req.rawHeaders)) return reply(400, 'rejected-internal-header', `Rejected at the header-filter boundary: ${BLOCKED_HEADER} is framework-internal and is not accepted from clients.`);
    if (!req.url.startsWith('/')) return reply(400, 'rejected-request-target', 'Only origin-form request targets are accepted.');
    // The body is read before taking an upstream slot, so a slow client cannot hold one.
    let body;
    try { body = await readBounded(req, limits.requestBytes, 'REQUEST_TOO_LARGE'); }
    catch (error) {
      if (error.code === 'REQUEST_TOO_LARGE') return reply(413, 'rejected-request-size', 'Request body exceeds the lab limit.');
      // The client aborted, or Node's request timeout already answered 408 and closed the socket.
      record('client-request-incomplete', null);
      return res.destroy();
    }
    if (inFlight >= limits.inFlight) return reply(503, 'busy', 'Boundary busy. Retry after the current requests finish.');
    inFlight++;
    try {
      const headers = endToEnd(req.rawHeaders);
      if (!headers.some((value, i) => i % 2 === 0 && value.toLowerCase() === 'host')) headers.push('Host', origin.host);
      if (body.length || ['POST', 'PUT', 'PATCH'].includes(req.method)) headers.push('Content-Length', String(body.length));
      const response = await send(origin, req.method, req.url, headers, body, limits.upstreamMs);
      const payload = await readBounded(response, limits.responseBytes, 'RESPONSE_TOO_LARGE');
      const relayed = endToEnd(response.rawHeaders);
      const bodyless = req.method === 'HEAD' || response.statusCode === 204 || response.statusCode === 304;
      if (req.method === 'HEAD' && response.headers['content-length']) relayed.push('Content-Length', response.headers['content-length']);
      if (!bodyless) relayed.push('Content-Length', String(payload.length));
      relayed.push('X-Lab-Boundary', 'header-filter');
      record('forwarded', response.statusCode);
      res.writeHead(response.statusCode, relayed);
      res.end(bodyless ? undefined : payload);
    } catch (error) {
      if (res.headersSent) return res.destroy();
      if (error.code === 'RESPONSE_TOO_LARGE') return reply(502, 'upstream-response-too-large', 'The application response exceeded the lab limit.');
      if (error.name === 'TimeoutError' || error.name === 'AbortError') return reply(504, 'upstream-timeout', 'The application did not answer within the lab limit.');
      return reply(502, 'upstream-unavailable', 'The header-filter application could not be reached. Check its health and retry.');
    } finally { inFlight--; }
  });
  server.requestTimeout = limits.requestMs;
  server.headersTimeout = Math.min(5000, limits.requestMs);
  return server;
}
