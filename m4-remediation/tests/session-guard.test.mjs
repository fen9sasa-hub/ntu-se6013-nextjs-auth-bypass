import test from 'node:test';
import assert from 'node:assert/strict';
import { issueSession, verifySession } from '../../m1-lab/shared/session.mjs';

// Unit coverage for the session validation the server-auth guard depends on.
//
// The guard (server-auth/overlay/lib/server-auth.mjs) authorises via `verify`, which is M1's
// `verify = token => verifySession(token, LAB_SESSION_SECRET, TARGET)`. So the guard accepts a
// request only when verifySession accepts the cookie: a correctly-signed, unexpired, target-bound
// token. These assertions exercise that exact function across every invalid form.
//
// The expired case can only be covered here, not in the live suite: `tests/targets.test.mjs` (and
// the `m4-check` container) deliberately hold no target signing secret, so the checker cannot mint a
// correctly-signed-but-expired token for a running target. The live suite covers the forms it can
// forge black-box (malformed value, wrong signing key, another target's genuine token); this file
// adds the expiry and lifetime dimensions with a locally known secret.

const secret = 'server-auth-guard-unit-test-secret-0123456789';
const target = 'server-auth';
const now = 1_000_000; // fixed clock; issueSession/verifySession take an explicit `now`.

test('a correctly-signed, unexpired, target-bound token verifies (control)', async () => {
  const token = await issueSession(secret, target, 'analyst', now);
  const session = await verifySession(token, secret, target, now + 10);
  assert.equal(session?.target, target);
  assert.equal(session.user, 'analyst');
});

test('an expired token is rejected even though its signature is valid', async () => {
  const token = await issueSession(secret, target, 'analyst', now);
  // Lifetime is 900s (exp = iat + 900). At or past expiry the guard must deny.
  assert.equal(await verifySession(token, secret, target, now + 900), null, 'rejected at the exact expiry second');
  assert.equal(await verifySession(token, secret, target, now + 10_000), null, 'rejected well past expiry');
  // A not-yet-valid (future-issued) token is likewise denied.
  const future = await issueSession(secret, target, 'analyst', now + 10_000);
  assert.equal(await verifySession(future, secret, target, now + 10), null);
});

test('forged, wrong-key, and cross-target tokens are rejected', async () => {
  const genuine = await issueSession(secret, target, 'analyst', now);
  assert.equal(await verifySession('yes', secret, target, now + 10), null, 'malformed value');
  assert.equal(await verifySession(`${genuine}.extra`, secret, target, now + 10), null, 'extra segment');
  assert.equal(await verifySession(genuine, `${secret}-different`, target, now + 10), null, 'wrong signing key');
  const otherTarget = await issueSession(secret, 'patched', 'analyst', now);
  assert.equal(await verifySession(otherTarget, secret, target, now + 10), null, 'genuine token from another target');
});
