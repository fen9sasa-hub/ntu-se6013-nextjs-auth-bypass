import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

// Static checks that each M4 profile changes exactly one thing relative to M1's `vulnerable` target.
// They read the committed sources only; nothing here builds or contacts a target.
const root = new URL('../../', import.meta.url);
const read = path => readFileSync(new URL(path, root), 'utf8');
const json = path => JSON.parse(read(path));
const files = dir => readdirSync(new URL(dir, root)).flatMap(name => statSync(new URL(`${dir}/${name}`, root)).isDirectory() ? files(`${dir}/${name}`).map(sub => `${name}/${sub}`) : [name]);

function stages(dockerfile) {
  const lines = read(dockerfile).replace(/\\\n\s*/g, '').split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  const found = {};
  let current = null;
  for (const line of lines) {
    const from = /^FROM\s+(\S+)(?:\s+AS\s+(\S+))?$/i.exec(line);
    if (from) found[from[2] || `#${Object.keys(found).length}`] = current = { base: from[1], steps: [] };
    else if (current) current.steps.push(line);
  }
  return found;
}

test('patched changes only the framework dependency and its lockfile', () => {
  const m1 = json('m1-lab/app/package.json');
  assert.deepEqual(json('m4-remediation/patched/package.json'), { ...m1, dependencies: { ...m1.dependencies, next: '14.2.25' } });
  assert.equal(m1.dependencies.next, '14.2.24');
  const before = json('m1-lab/app/package-lock.json');
  const after = json('m4-remediation/patched/package-lock.json');
  const { packages: a, ...restA } = before;
  const { packages: b, ...restB } = after;
  assert.deepEqual(restB, restA);
  const changed = [...new Set([...Object.keys(a), ...Object.keys(b)])].filter(key => JSON.stringify(a[key]) !== JSON.stringify(b[key]));
  assert.ok(changed.includes('node_modules/next'));
  for (const key of changed) {
    if (key === '') {
      assert.deepEqual(b[key], { ...a[key], dependencies: { ...a[key].dependencies, next: '14.2.25' } });
      continue;
    }
    // Framework entries may carry new registry metadata; every other installed package must be identical.
    assert.ok(key === 'node_modules/next' || key.startsWith('node_modules/@next/'), `unexpected lockfile change: ${key}`);
    assert.equal(a[key]?.version, '14.2.24', key);
    assert.equal(b[key]?.version, '14.2.25', key);
  }
});

test('every M4 image starts from M1\'s pinned Node runtime', () => {
  const pinned = /^FROM (node:22-bookworm-slim@sha256:[0-9a-f]{64})/m.exec(read('m1-lab/app/Dockerfile'))[1];
  assert.match(read('m4-remediation/target.Dockerfile'), new RegExp(`^ARG NODE_IMAGE=${pinned.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'));
  for (const dockerfile of ['m4-remediation/header-filter/Dockerfile', 'm4-remediation/check.Dockerfile']) {
    assert.equal(/^FROM (\S+)$/m.exec(read(dockerfile))[1], pinned, dockerfile);
  }
});

test('each change stage contains only its named change', () => {
  const found = stages('m4-remediation/target.Dockerfile');
  assert.deepEqual(found['m1-source'].steps, ['WORKDIR /lab/app', 'COPY m1-lab/app/ ./', 'COPY m1-lab/shared/ /lab/shared/']);
  assert.deepEqual(found['change-patched'], { base: 'm1-source', steps: ['COPY m4-remediation/patched/package.json m4-remediation/patched/package-lock.json ./'] });
  assert.deepEqual(found['change-header-filter'], { base: 'm1-source', steps: [] });
  assert.deepEqual(found['change-server-auth'], { base: 'm1-source', steps: ['RUN mv app/dashboard/page.js app/dashboard/m1-page.js && mv app/api/records/route.js app/api/records/m1-route.js', 'COPY m4-remediation/server-auth/overlay/ ./'] });
  assert.deepEqual(found['change-server-auth-guard-only'], { base: 'change-server-auth', steps: ['RUN rm middleware.js'] });
  assert.equal(found.build.base, 'change-${M4_CHANGE}');
  // The shared stages are pinned too: a step added here would change every M4 target at once.
  assert.deepEqual(found.build.steps, ['ARG LAB_TARGET_ID', 'ARG LAB_PROFILE', 'ENV NEXT_TELEMETRY_DISABLED=1 LAB_TARGET_ID=${LAB_TARGET_ID} LAB_PROFILE=${LAB_PROFILE}', 'RUN npm ci --ignore-scripts --no-audit --no-fund && npm run build']);
  assert.deepEqual(found.runtime.steps, stages('m1-lab/app/Dockerfile').runtime.steps, 'the runtime stage is M1\'s, step for step');
  assert.deepEqual(Object.keys(found).filter(name => name.startsWith('change-')).sort(), ['change-header-filter', 'change-patched', 'change-server-auth', 'change-server-auth-guard-only']);
});

test('server-auth wraps M1\'s unchanged handlers before any protected data is returned', () => {
  assert.deepEqual(files('m4-remediation/server-auth/overlay').sort(), ['app/api/records/route.js', 'app/dashboard/page.js', 'lib/server-auth.mjs']);
  const guard = read('m4-remediation/server-auth/overlay/lib/server-auth.mjs');
  assert.match(guard, /^import \{ COOKIE, verify \} from '\.\/auth\.mjs';$/m, 'same signed-session validation as every target');
  // The exact guard line must exist (a missing or inverted guard gives -1) and precede the delegation.
  const guardedBefore = (source, guard, delegate) => {
    const g = source.indexOf(guard);
    const d = source.indexOf(delegate);
    assert.ok(g >= 0, `guard missing or altered: ${guard}`);
    assert.ok(d > g, `delegation must follow the guard: ${delegate}`);
  };
  const page = read('m4-remediation/server-auth/overlay/app/dashboard/page.js');
  assert.match(page, /^import M1Dashboard from '\.\/m1-page\.js';$/m);
  guardedBefore(page, "if (!await authorised()) redirect('/login?denied=server-auth');", 'return <M1Dashboard />;');
  const route = read('m4-remediation/server-auth/overlay/app/api/records/route.js');
  assert.match(route, /^import \{ GET as m1Records \} from '\.\/m1-route\.js';$/m);
  guardedBefore(route, 'if (!await authorised()) return Response.json(', 'return m1Records();');
  // M1's own handlers keep no server-side check, so vulnerable, patched and header-filter have none either.
  for (const path of ['m1-lab/app/app/dashboard/page.js', 'm1-lab/app/app/api/records/route.js']) {
    assert.doesNotMatch(read(path), /verify|cookies|authorised|next\/headers/, path);
  }
});

test('the header-filter boundary adds one header rule and no authorisation', async () => {
  const source = read('m4-remediation/header-filter/boundary.mjs');
  assert.deepEqual(source.split('\n').filter(line => line.startsWith('import ')), ["import http from 'node:http';"]);
  assert.doesNotMatch(source, /session|verify|signature|LAB_SESSION_SECRET/i);
  const { BLOCKED_HEADER } = await import('../header-filter/boundary.mjs');
  assert.equal(BLOCKED_HEADER, 'x-middleware-subrequest');
});

test('M1 build defaults still produce the vulnerable target, and identities are fixed per build', async () => {
  const saved = { target: process.env.LAB_TARGET_ID, profile: process.env.LAB_PROFILE };
  const load = async (target, profile, tag) => {
    for (const [name, value] of [['LAB_TARGET_ID', target], ['LAB_PROFILE', profile]]) if (value === undefined) delete process.env[name]; else process.env[name] = value;
    return (await import(`../../m1-lab/app/next.config.mjs?${tag}`)).default;
  };
  try {
    const defaults = await load(undefined, undefined, 'defaults');
    assert.equal(defaults.basePath, '/lab/vulnerable');
    assert.deepEqual(defaults.env, { LAB_TARGET_ID: 'vulnerable', LAB_PROFILE: 'middleware-only' });
    const serverAuth = await load('server-auth', 'server-auth', 'server-auth');
    assert.equal(serverAuth.basePath, '/lab/server-auth');
    await assert.rejects(load('admin', undefined, 'unknown'), /Unknown LAB_TARGET_ID/);
    await assert.rejects(load('patched', 'Bad Profile', 'bad-profile'), /Invalid LAB_PROFILE/);
    // A Dockerfile ARG that was never passed arrives as an empty string; it must not fall back to `vulnerable`.
    await assert.rejects(load('', 'middleware-only', 'empty-target'), /Unknown LAB_TARGET_ID/);
    await assert.rejects(load('patched', '', 'empty-profile'), /Invalid LAB_PROFILE/);
    process.env.LAB_TARGET_ID = 'header-filter';
    const auth = await import('../../m1-lab/app/lib/auth.mjs?header-filter');
    assert.equal(auth.BASE, '/lab/header-filter');
    assert.equal(auth.COOKIE, 'lab_header_filter_session');
  } finally {
    for (const [name, value] of [['LAB_TARGET_ID', saved.target], ['LAB_PROFILE', saved.profile]]) if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});

// Structural compose checks need a YAML parser; PyYAML is used when present rather than adding a Node dependency.
const yaml = spawnSync('python3', ['-c', 'import json,sys,yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))', new URL('m4-remediation/compose.defences.yaml', root).pathname], { encoding: 'utf8' });
test('compose keeps each defence separate and every target private', { skip: yaml.status !== 0 && 'python3 with PyYAML is not available' }, () => {
  const { services, networks } = JSON.parse(yaml.stdout);
  const expected = {
    patched: { M4_CHANGE: 'patched', LAB_TARGET_ID: 'patched', LAB_PROFILE: 'middleware-only', secrets: 'PATCHED', networks: ['lab'] },
    'header-filter-app': { M4_CHANGE: 'header-filter', LAB_TARGET_ID: 'header-filter', LAB_PROFILE: 'header-filter', secrets: 'HEADER_FILTER', networks: ['header-filter-backend'] },
    'server-auth': { M4_CHANGE: 'server-auth', LAB_TARGET_ID: 'server-auth', LAB_PROFILE: 'server-auth', secrets: 'SERVER_AUTH', networks: ['lab'] },
    'server-auth-guard-only': { M4_CHANGE: 'server-auth-guard-only', LAB_TARGET_ID: 'server-auth', LAB_PROFILE: 'server-auth-guard-only', secrets: 'SERVER_AUTH', networks: ['m4-check'], profiles: ['check'] }
  };
  assert.deepEqual(Object.keys(services).sort(), [...Object.keys(expected), 'header-filter', 'm4-check'].sort());
  for (const [name, want] of Object.entries(expected)) {
    const service = services[name];
    assert.deepEqual(service.build, { context: '..', dockerfile: 'm4-remediation/target.Dockerfile', args: { M4_CHANGE: want.M4_CHANGE, LAB_TARGET_ID: want.LAB_TARGET_ID, LAB_PROFILE: want.LAB_PROFILE } }, name);
    assert.deepEqual(service.networks, want.networks, name);
    assert.deepEqual(service.profiles, want.profiles, name);
    assert.match(service.environment.LAB_PASSWORD, new RegExp(`^\\$\\{${want.secrets}_PASSWORD:\\?`), name);
    assert.match(service.environment.LAB_SESSION_SECRET, new RegExp(`^\\$\\{${want.secrets}_SESSION_SECRET:\\?`), name);
    assert.ok(service.healthcheck.test.at(-1).includes(`/lab/${want.LAB_TARGET_ID}/api/health`), name);
  }
  assert.deepEqual(services['header-filter'].networks, ['lab', 'header-filter-backend']);
  assert.equal(services['header-filter'].environment.UPSTREAM_ORIGIN, 'http://header-filter-app:3000');
  assert.equal(services['header-filter'].build.context, '../m4-remediation/header-filter');
  assert.deepEqual(services['m4-check'].profiles, ['check']);
  for (const [name, service] of Object.entries(services)) {
    for (const key of ['ports', 'expose', 'volumes', 'privileged', 'network_mode', 'pid', 'ipc', 'cap_add', 'devices']) assert.equal(service[key], undefined, `${name}.${key}`);
    assert.equal(service.read_only, true, name);
    assert.deepEqual(service.cap_drop, ['ALL'], name);
    assert.deepEqual(service.security_opt, ['no-new-privileges:true'], name);
  }
  for (const name of ['header-filter-backend', 'm4-check']) assert.equal(networks[name].internal, true, name);
});
