import { BLOCKED_HEADER, createBoundary } from './boundary.mjs';

const upstream = process.env.UPSTREAM_ORIGIN;
if (!upstream) throw new Error('Missing UPSTREAM_ORIGIN');
const server = createBoundary({ upstream });
server.listen(Number(process.env.PORT || 3000), process.env.HOST || '0.0.0.0', () => console.log(`header-filter boundary ready; rejects ${BLOCKED_HEADER} before the application.`));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close(() => process.exit(0)));
