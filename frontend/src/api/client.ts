import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

// ── Client-side GET cache ──────────────────────────────────────────────────────
// Caches GET responses so tab switching shows data instantly.
// TTLs: dashboard = 2 min, scans/findings = 30 s, everything else = 60 s.
const CACHE = new Map<string, { data: unknown; ts: number }>();

const TTL_RULES: Array<[RegExp, number]> = [
  [/\/dashboard\//, 120_000],
  [/\/scans|\/findings/, 30_000],
];

function getTTL(url: string): number {
  for (const [re, ms] of TTL_RULES) if (re.test(url)) return ms;
  return 60_000;
}

function cacheKey(url: string, params?: unknown): string {
  const q = params ? '?' + new URLSearchParams(params as Record<string, string>).toString() : '';
  return url + q;
}

// Intercept outgoing GET requests — serve from cache if still fresh
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;

  if (config.method?.toLowerCase() === 'get' && config.url) {
    const key = cacheKey(config.url, config.params);
    const entry = CACHE.get(key);
    if (entry && Date.now() - entry.ts < getTTL(config.url)) {
      // Signal to the response interceptor to return cached data
      const ctrl = new AbortController();
      ctrl.abort();
      config.signal = ctrl.signal;
      (config as any).__cachedData = entry.data;
    }
  }
  return config;
});

// Intercept responses — store fresh responses; return cached ones for aborted hits
api.interceptors.response.use(
  (response) => {
    if (response.config.method?.toLowerCase() === 'get' && response.config.url) {
      const key = cacheKey(response.config.url, response.config.params);
      CACHE.set(key, { data: response.data, ts: Date.now() });
    }
    return response;
  },
  async (error) => {
    // AbortError from our cache shortcut — return cached data as a real response
    if ((error as any).config?.__cachedData !== undefined) {
      return Promise.resolve({
        data: (error as any).config.__cachedData,
        status: 200,
        headers: {},
        config: (error as any).config,
      });
    }
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

/** Invalidate cache entries matching a URL pattern (call after mutations). */
export function invalidateCache(urlPattern: RegExp) {
  for (const key of CACHE.keys()) {
    if (urlPattern.test(key)) CACHE.delete(key);
  }
}

export default api;
