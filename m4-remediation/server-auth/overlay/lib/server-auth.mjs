import { cookies } from 'next/headers';
import { COOKIE, verify } from './auth.mjs';
// server-auth profile only: authorise again where protected data is returned, without relying on
// middleware having run. Same signed-session validation as every other target.
export const authorised = async () => Boolean(await verify(cookies().get(COOKIE)?.value || ''));
