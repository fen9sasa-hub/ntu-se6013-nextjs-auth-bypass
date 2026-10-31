import test from 'node:test';
import assert from 'node:assert/strict';
import { issueSession } from '../../m1-lab/shared/session.mjs';

// Live regression checks against running targets (M4_LIVE=1, normally the compose `m4-check` service).
// Normal, invalid-session and valid-session requests only. The anonymous-cve scenario is M3's fixed
// runner; this file never constructs it. The boundary checks send the internal header with the same
// neutral value as M1's baseline test.
const live = process.env.M4_LIVE === '1';
const marker = 'M1-FICTIONAL-RECORDS-ONLY';
const origin = process.env.LAB_PUBLIC_ORIGIN;
const user = process.env.LAB_USER;
const targets = [
  { id: 'vulnerable', version: '14.2.24', profile: 'middleware-only', password: 'LAB_PASSWORD' },
  { id: 'patched', version: '14.2.25', profile: 'middleware-only', password: 'PATCHED_PASSWORD' },
  { id: 'header-filter', version: '14.2.24', profile: 'header-filter', password: 'HEADER_FILTER_PASSWORD', boundary: 'header-filter' },
  { id: 'server-auth', version: '14.2.24', profile: 'server-auth', password: 'SERVER_AUTH_PASSWORD' }
];
const guardOnly = { id: 'server-auth', service: 'server-auth-guard-only', version: '14.2.24', profile: 'server-auth-guard-only', password: 'SERVER_AUTH_PASSWORD' };
const cookieName = target => `lab_${target.id.replaceAll('-', '_')}_session`;
const address = target => {
  const service = target.service || target.id;
  return process.env[`M4_ADDRESS_${service.toUpperCase().replaceAll('-', '_')}`] || `http://${service}:3000`;
};
const send = (target, path, { headers = {}, ...options } = {}) => fetch(`${address(target)}/lab/${target.id}${path}`, { redirect: 'manual', signal: AbortSignal.timeout(8000), ...options, headers });
const withoutMarker = async response => { const body = await response.text(); assert.ok(!body.includes(marker), `protected marker leaked (${response.status} ${response.url})`); return body; };
const form = fields => ({ method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields) });

async function login(target) {
  const response = await send(target, '/api/login', form({ username: user, password: process.env[target.password] }));
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), `${origin}/lab/${target.id}/dashboard`);
  const setCookie = response.headers.get('set-cookie');
  assert.match(setCookie, new RegExp(`^${cookieName(target)}=[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+;`));
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Strict/i);
  assert.match(setCookie, new RegExp(`Path=/lab/${target.id}(;|$)`));
  return setCookie.split(';')[0];
}

// invalid-session: a malformed value, and a well-formed unexpired token for this target signed with a key it does not hold.
const invalidSessions = async target => [`${cookieName(target)}=yes`, `${cookieName(target)}=${await issueSession('m4-invalid-session-key-held-by-no-target', target.id, user || 'analyst')}`];

async function deniedByMiddleware(target, headers = {}) {
  const page = await send(target, '/dashboard', { headers });
  assert.equal(page.status, 307);
  assert.equal(page.headers.get('location'), `${origin}/lab/${target.id}/login`);
  await withoutMarker(page);
  const flight = await send(target, '/dashboard', { headers: { ...headers, RSC: '1' } });
  assert.equal(flight.status, 307, 'client-navigation (RSC) requests are denied the same way');
  await withoutMarker(flight);
  const records = await send(target, '/api/records', { headers });
  assert.equal(records.status, 401);
  assert.deepEqual(JSON.parse(await withoutMarker(records)), { error: 'A valid target session is required.' });
}

for (const target of targets) {
  test(`${target.id}: the running identity matches the registry`, { skip: !live }, async () => {
    const health = await send(target, '/api/health');
    assert.equal(health.status, 200);
    assert.equal(health.headers.get('set-cookie'), null);
    assert.equal(health.headers.get('x-lab-boundary'), target.boundary ?? null);
    assert.deepEqual(JSON.parse(await withoutMarker(health)), { target: target.id, version: target.version, profile: target.profile, ready: true });
    const publicPage = await send(target, '');
    assert.equal(publicPage.status, 200);
    assert.match(await withoutMarker(publicPage), new RegExp(`${target.id[0].toUpperCase()}${target.id.slice(1)} lab target`));
  });

  test(`${target.id}: anonymous-normal and invalid sessions are denied without protected content`, { skip: !live }, async () => {
    await deniedByMiddleware(target);
    for (const cookie of await invalidSessions(target)) await deniedByMiddleware(target, { Cookie: cookie });
  });

  test(`${target.id}: a valid session reaches the protected page and data; logout clears the target cookie`, { skip: !live }, async () => {
    const cookie = await login(target);
    const page = await send(target, '/dashboard', { headers: { Cookie: cookie } });
    assert.equal(page.status, 200);
    assert.ok((await page.text()).includes(marker));
    const records = await send(target, '/api/records', { headers: { Cookie: cookie } });
    assert.equal(records.status, 200);
    assert.equal((await records.json()).marker, marker);
    if (target.boundary) assert.equal(records.headers.get('x-lab-boundary'), target.boundary);
    const logout = await send(target, '/api/logout', { method: 'POST', headers: { Origin: origin, Cookie: cookie } });
    assert.equal(logout.status, 303);
    // Sessions are stateless (see M1's README), so logout is verified as clearing this target's cookie path.
    const cleared = logout.headers.get('set-cookie');
    assert.match(cleared, new RegExp(`^${cookieName(target)}=;.*Max-Age=0`, 'i'));
    assert.match(cleared, new RegExp(`Path=/lab/${target.id}(;|$)`));
  });

  test(`${target.id}: login rejects wrong credentials and cross-origin forms`, { skip: !live }, async () => {
    const wrong = await send(target, '/api/login', form({ username: user, password: 'not-the-password' }));
    assert.equal(wrong.status, 303);
    assert.equal(wrong.headers.get('location'), `${origin}/lab/${target.id}/login?error=invalid`);
    assert.equal(wrong.headers.get('set-cookie'), null);
    const crossOrigin = await send(target, '/api/login', { ...form({ username: user, password: process.env[target.password] }), headers: { Origin: 'https://other.invalid', 'Content-Type': 'application/x-www-form-urlencoded' } });
    assert.equal(crossOrigin.status, 403);
    assert.equal(crossOrigin.headers.get('set-cookie'), null);
  });
}

test('a genuine session from one target is never accepted by another', { skip: !live }, async () => {
  const sessions = Object.fromEntries(await Promise.all(targets.map(async target => [target.id, (await login(target)).split('=')[1]])));
  for (const holder of targets) {
    for (const other of targets.filter(target => target !== holder)) await deniedByMiddleware(other, { Cookie: `${cookieName(other)}=${sessions[holder.id]}` });
  }
});

test('header-filter rejects the internal header at the boundary, even alongside a valid session', { skip: !live }, async () => {
  const target = targets.find(value => value.id === 'header-filter');
  const internal = { 'x-middleware-subrequest': 'external-untrusted' };
  const cookie = await login(target);
  for (const [path, headers] of [['', {}], ['/dashboard', {}], ['/api/records', {}], ['/api/health', {}], ['/dashboard', { Cookie: cookie }], ['/api/records', { Cookie: cookie }]]) {
    const response = await send(target, path, { headers: { ...internal, ...headers } });
    assert.equal(response.status, 400, path);
    assert.equal(response.headers.get('x-lab-boundary'), 'header-filter');
    assert.equal(response.headers.get('x-lab-boundary-decision'), 'rejected-internal-header');
    assert.equal(JSON.parse(await withoutMarker(response)).layer, 'header-filter');
  }
  const loginAttempt = await send(target, '/api/login', { ...form({ username: user, password: process.env[target.password] }), headers: { ...form({}).headers, ...internal } });
  assert.equal(loginAttempt.status, 400);
  assert.equal(loginAttempt.headers.get('set-cookie'), null);
});

test('server-auth guard alone (check-only build without middleware) denies anonymous and invalid sessions and admits a valid one', { skip: !live }, async () => {
  const health = await send(guardOnly, '/api/health');
  assert.deepEqual(JSON.parse(await withoutMarker(health)), { target: guardOnly.id, version: guardOnly.version, profile: guardOnly.profile, ready: true });
  for (const cookie of [null, ...await invalidSessions(guardOnly)]) {
    const headers = cookie ? { Cookie: cookie } : {};
    const page = await send(guardOnly, '/dashboard', { headers });
    assert.equal(page.status, 307);
    assert.equal(page.headers.get('location'), `/lab/${guardOnly.id}/login?denied=server-auth`, 'the server-side guard, not middleware, made this decision');
    await withoutMarker(page);
    // Client-navigation (RSC) requests get the guard's redirect inside a 200 flight payload, not as a 307.
    const flight = await send(guardOnly, '/dashboard', { headers: { ...headers, RSC: '1' } });
    assert.equal(flight.status, 200);
    assert.match(flight.headers.get('content-type'), /^text\/x-component/);
    assert.ok((await withoutMarker(flight)).includes('NEXT_REDIRECT;replace;/login?denied=server-auth;307;'), 'the RSC denial carries the guard redirect');
    const records = await send(guardOnly, '/api/records', { headers });
    assert.equal(records.status, 401);
    assert.deepEqual(JSON.parse(await withoutMarker(records)), { error: 'A valid target session is required.', layer: 'server-auth' });
  }
  const cookie = await login(guardOnly);
  const page = await send(guardOnly, '/dashboard', { headers: { Cookie: cookie } });
  assert.equal(page.status, 200);
  assert.ok((await page.text()).includes(marker));
  const records = await send(guardOnly, '/api/records', { headers: { Cookie: cookie } });
  assert.equal(records.status, 200);
  assert.equal((await records.json()).marker, marker);
});
