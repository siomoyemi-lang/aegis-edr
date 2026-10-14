// Gateway location. Override at build/dev time with NEXT_PUBLIC_AEGIS_API_URL (e.g. http://192.168.1.20:8000).
export const API_URL = (process.env.NEXT_PUBLIC_AEGIS_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');
export const WS_URL = API_URL.replace(/^http/, 'ws') + '/ws/frontend';

// Optional shared secret for the kill endpoint (must match AEGIS_API_KEY on the gateway).
// NOTE: anything NEXT_PUBLIC_* ships to the browser, so this only deters casual misuse on a trusted LAN;
// put the console behind real authentication before exposing it.
const API_KEY = process.env.NEXT_PUBLIC_AEGIS_API_KEY ?? '';

export const authHeaders = (): Record<string, string> => (API_KEY ? { 'X-API-Key': API_KEY } : {});
