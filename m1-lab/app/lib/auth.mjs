import { issueSession, verifySession } from '../../shared/session.mjs';
// Inlined at build time from next.config.mjs `env`, so middleware, pages and handlers agree.
export const TARGET = process.env.LAB_TARGET_ID;
export const BASE = `/lab/${TARGET}`;
export const COOKIE = `lab_${TARGET.replaceAll('-', '_')}_session`;
export function required(name, minimum = 1) {
  const value = process.env[name];
  if (!value || value.length < minimum) throw new Error(`Missing or short ${name}`);
  return value;
}
export const verify = token => verifySession(token, required('LAB_SESSION_SECRET', 32), TARGET);
export const issue = () => issueSession(required('LAB_SESSION_SECRET', 32), TARGET, required('LAB_USER'));
export function cookieOptions() {
  return { httpOnly: true, sameSite: 'strict', secure: process.env.COOKIE_SECURE === 'true', path: BASE, maxAge: 900 };
}
export function sameOrigin(request) {
  return request.headers.get('origin') === required('LAB_PUBLIC_ORIGIN');
}
export async function sameValue(a, b) {
  const hash = value => crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  const x = new Uint8Array(await hash(a));
  const y = new Uint8Array(await hash(b));
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
