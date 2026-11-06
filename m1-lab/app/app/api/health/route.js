import nextPackage from 'next/package.json';
import { TARGET } from '../../../lib/auth.mjs';
export const dynamic = 'force-dynamic';
export async function GET() {
  // Same minimums the handlers enforce, so a placeholder or short secret reports not-ready instead of failing at login.
  const ready = [['LAB_SESSION_SECRET', 32], ['LAB_PASSWORD', 16], ['LAB_USER', 1], ['LAB_PUBLIC_ORIGIN', 1]].every(([name, minimum]) => (process.env[name] || '').length >= minimum);
  return Response.json({ target: TARGET, version: nextPackage.version, profile: process.env.LAB_PROFILE, ready }, { status: ready ? 200 : 503, headers: { 'Cache-Control': 'no-store' } });
}
