import path from 'node:path';
import { fileURLToPath } from 'node:url';
// Target identity is fixed at build time. No build args = M1's `vulnerable` target; M4 builds its targets from this same source.
const target = process.env.LAB_TARGET_ID ?? 'vulnerable';
const profile = process.env.LAB_PROFILE ?? 'middleware-only';
if (!['vulnerable', 'patched', 'header-filter', 'server-auth'].includes(target)) throw new Error(`Unknown LAB_TARGET_ID: ${target}`);
if (!/^[a-z][a-z-]{2,40}$/.test(profile)) throw new Error(`Invalid LAB_PROFILE: ${profile}`);
export default {
  basePath: `/lab/${target}`,
  env: { LAB_TARGET_ID: target, LAB_PROFILE: profile },
  output: 'standalone',
  poweredByHeader: false,
  experimental: { cpus: 1, externalDir: true, outputFileTracingRoot: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..') },
  async headers() {
    return [{ source: '/:path*', headers: [
      { key: 'Cache-Control', value: 'no-store' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'Referrer-Policy', value: 'same-origin' }
    ] }];
  }
};
