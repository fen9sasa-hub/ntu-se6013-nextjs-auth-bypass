import { randomBytes } from 'node:crypto';
import { appendFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// Adds a separate password and signing secret per M4 target to M1's private m1-lab/.env.
// Existing lines are never rewritten; values are never printed.
const destination = fileURLToPath(new URL('../m1-lab/.env', import.meta.url));
const wanted = ['PATCHED', 'HEADER_FILTER', 'SERVER_AUTH'].flatMap(prefix => [[`${prefix}_PASSWORD`, 24], [`${prefix}_SESSION_SECRET`, 32]]);
let current = null;
try { current = readFileSync(destination, 'utf8'); } catch {}
if (current === null) {
  console.error('m1-lab/.env not found. Run `node deploy/init-env.mjs` in m1-lab/ first.');
  process.exitCode = 1;
} else {
  const values = new Map(current.split(/\r?\n/).map(line => /^([A-Z0-9_]+)=(.*)$/.exec(line)).filter(Boolean).map(([, name, value]) => [name, value]));
  // A copied .env.example would otherwise leave publicly known placeholders in place. M1's own example
  // placeholders are long enough for the targets to accept, so they are refused here too.
  const placeholder = name => values.has(name) && (values.get(name) === '' || values.get(name).startsWith('GENERATE'));
  const m1Unusable = ['CONTROL_PASSWORD', 'LAB_PASSWORD', 'LAB_SESSION_SECRET'].filter(placeholder);
  const unusable = wanted.map(([name]) => name).filter(placeholder);
  const missing = wanted.filter(([name]) => !values.has(name));
  if (m1Unusable.length) {
    console.error(`${m1Unusable.join(', ')} in m1-lab/.env are empty or .env.example placeholders. Create m1-lab/.env with \`node deploy/init-env.mjs\`, never by copying .env.example.`);
    process.exitCode = 1;
  } else if (unusable.length) {
    console.error(`${unusable.join(', ')} in m1-lab/.env are empty or placeholders. Delete those lines, then rerun this script to generate real values.`);
    process.exitCode = 1;
  } else if (!missing.length) console.log('All M4 target variables already exist in m1-lab/.env; nothing changed.');
  else {
    const lines = missing.map(([name, bytes]) => `${name}=${randomBytes(bytes).toString('hex')}`);
    appendFileSync(destination, (current === '' || current.endsWith('\n') ? '' : '\n') + lines.join('\n') + '\n');
    console.log(`Added ${missing.map(([name]) => name).join(', ')} to m1-lab/.env. Open it locally to read them.`);
  }
}
