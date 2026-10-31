import './globals.css';
import { TARGET } from '../lib/auth.mjs';
export const metadata = { title: 'Middleware Lab Target', robots: { index: false, follow: false } };
export default function Layout({ children }) {
  return <html lang="en"><body><header><strong>Example records app</strong><span>{`${TARGET[0].toUpperCase()}${TARGET.slice(1)} lab target`}</span></header><main>{children}</main></body></html>;
}
