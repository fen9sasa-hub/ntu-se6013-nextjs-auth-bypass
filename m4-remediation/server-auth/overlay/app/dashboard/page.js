import { redirect } from 'next/navigation';
import { authorised } from '../../lib/server-auth.mjs';
import M1Dashboard from './m1-page.js';
export const dynamic = 'force-dynamic';
export default async function Dashboard() {
  // Deny before M1's unchanged dashboard renders any record; `denied` attributes the decision to this layer.
  if (!await authorised()) redirect('/login?denied=server-auth');
  return <M1Dashboard />;
}
