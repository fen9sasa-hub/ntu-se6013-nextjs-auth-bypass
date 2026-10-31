import { authorised } from '../../../lib/server-auth.mjs';
import { GET as m1Records } from './m1-route.js';
export const dynamic = 'force-dynamic';
export async function GET() {
  // Deny before M1's unchanged handler returns any record; `layer` attributes the decision.
  if (!await authorised()) return Response.json({ error: 'A valid target session is required.', layer: 'server-auth' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });
  return m1Records();
}
