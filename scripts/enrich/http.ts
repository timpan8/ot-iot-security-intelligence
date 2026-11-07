/**
 * Härdad HTTP-klient för datainhämtning (körs ENBART i Node/GitHub Actions, aldrig i webbläsaren).
 *
 * - Host-allowlist: bara officiella, dokumenterade feeds får kontaktas.
 * - Timeout via AbortController, återförsök med exponentiell backoff + jitter (429/5xx/nätfel).
 * - ETag / If-Modified-Since via sources/enrichment/http-cache.json.
 * - Rate limiting per host (NVD: 6,5 s utan nyckel, 0,7 s med NVD_API_KEY).
 * - API-nyckel läses endast från process.env och loggas aldrig.
 * - Svar valideras som JSON-objekt; ingen eval, ingen dynamisk kodkörning.
 */
import { existsSync } from 'node:fs';
import { p, readJson, writeJson, nowIso } from '../lib/fs';

export const USER_AGENT =
  'ot-iot-security-intelligence-data-update/0.1.0 (+https://github.com/timpan8/ot-iot-security-intelligence)';

/** Tillåtna värdar. Allt annat avvisas innan någon förfrågan går ut. */
export const ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  'services.nvd.nist.gov',
  'api.first.org',
  'www.cisa.gov',
  'cert-portal.siemens.com',
  'raw.githubusercontent.com',
]);

/** För raw.githubusercontent.com tillåts enbart CISA:s CSAF-repo. */
const RAW_GITHUB_PREFIX = '/cisagov/CSAF/';

export interface HttpCacheEntry {
  etag?: string;
  last_modified?: string;
  fetched_at: string;
}
export type HttpCache = Record<string, HttpCacheEntry>;

export const HTTP_CACHE_PATH = p('sources', 'enrichment', 'http-cache.json');

export function loadHttpCache(path: string = HTTP_CACHE_PATH): HttpCache {
  if (!existsSync(path)) return {};
  try {
    const data = readJson<unknown>(path);
    return data && typeof data === 'object' && !Array.isArray(data) ? (data as HttpCache) : {};
  } catch {
    return {};
  }
}

export function saveHttpCache(cache: HttpCache, path: string = HTTP_CACHE_PATH): void {
  writeJson(path, cache);
}

export class HostNotAllowedError extends Error {
  constructor(url: string) {
    super(`Värden i ${url} finns inte i allowlistan för datainhämtning.`);
    this.name = 'HostNotAllowedError';
  }
}

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    message?: string,
  ) {
    super(message ?? `HTTP ${status} för ${url}`);
    this.name = 'HttpError';
  }
}

export function assertAllowedUrl(url: string): URL {
  const u = new URL(url);
  if (u.protocol !== 'https:') throw new HostNotAllowedError(url);
  if (!ALLOWED_HOSTS.has(u.hostname)) throw new HostNotAllowedError(url);
  if (u.hostname === 'raw.githubusercontent.com' && !u.pathname.startsWith(RAW_GITHUB_PREFIX)) {
    throw new HostNotAllowedError(url);
  }
  return u;
}

/** Enkel per-host-ratelimiter: väntar tills minsta intervall gått sedan senaste anrop. */
export class RateLimiter {
  private last = new Map<string, number>();
  constructor(
    private readonly intervalMs: (host: string) => number,
    private readonly sleep: (ms: number) => Promise<void> = defaultSleep,
    private readonly now: () => number = () => Date.now(),
  ) {}

  async wait(host: string): Promise<void> {
    const interval = this.intervalMs(host);
    const prev = this.last.get(host);
    if (prev !== undefined) {
      const elapsed = this.now() - prev;
      if (elapsed < interval) await this.sleep(interval - elapsed);
    }
    this.last.set(host, this.now());
  }
}

export function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function hasNvdApiKey(env: NodeJS.ProcessEnv = process.env): boolean {
  return typeof env.NVD_API_KEY === 'string' && env.NVD_API_KEY.trim().length > 0;
}

/** NVD: 5 anrop/30 s utan nyckel, 50/30 s med nyckel (med marginal). */
export function defaultIntervalMs(host: string, env: NodeJS.ProcessEnv = process.env): number {
  if (host === 'services.nvd.nist.gov') return hasNvdApiKey(env) ? 700 : 6500;
  if (host === 'api.first.org') return 1000;
  return 500;
}

export const defaultRateLimiter = new RateLimiter((h) => defaultIntervalMs(h));

export interface FetchJsonOptions {
  timeoutMs?: number;
  maxRetries?: number;
  /** Använd villkorlig hämtning (ETag/If-Modified-Since). */
  conditional?: boolean;
  cache?: HttpCache;
  rateLimiter?: RateLimiter;
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  env?: NodeJS.ProcessEnv;
  headers?: Record<string, string>;
}

export interface FetchJsonResult<T = unknown> {
  status: number;
  /** true när servern svarade 304 Not Modified. */
  notModified: boolean;
  data: T | null;
  etag?: string;
  lastModified?: string;
}

export function backoffDelayMs(attempt: number, random: () => number = Math.random): number {
  // 1s, 2s, 4s, 8s + upp till 25 % jitter
  const base = 1000 * 2 ** attempt;
  return Math.round(base + base * 0.25 * random());
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status === 408 || (status >= 500 && status <= 599);
}

/**
 * Hämtar JSON från en tillåten URL med retry, timeout, rate limit och villkorlig cache.
 * Kastar HttpError för 4xx som inte är 304/429 (t.ex. 404) så att anroparen kan avgöra.
 */
export async function fetchJson<T = unknown>(
  url: string,
  opts: FetchJsonOptions = {},
): Promise<FetchJsonResult<T>> {
  const u = assertAllowedUrl(url);
  const {
    timeoutMs = 60_000,
    maxRetries = 4,
    conditional = true,
    cache,
    rateLimiter = defaultRateLimiter,
    fetchImpl = fetch,
    sleep = defaultSleep,
    env = process.env,
    headers: extraHeaders = {},
  } = opts;

  const headers: Record<string, string> = {
    'User-Agent': USER_AGENT,
    Accept: 'application/json',
    ...extraHeaders,
  };
  if (u.hostname === 'services.nvd.nist.gov' && hasNvdApiKey(env)) {
    headers['apiKey'] = env.NVD_API_KEY!.trim(); // loggas aldrig
  }
  const cached = cache?.[url];
  if (conditional && cached) {
    if (cached.etag) headers['If-None-Match'] = cached.etag;
    if (cached.last_modified) headers['If-Modified-Since'] = cached.last_modified;
  }

  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    await rateLimiter.wait(u.hostname);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(u.toString(), {
        headers,
        signal: controller.signal,
        redirect: 'follow',
      });
      clearTimeout(timer);

      if (res.status === 304) {
        return {
          status: 304,
          notModified: true,
          data: null,
          etag: cached?.etag,
          lastModified: cached?.last_modified,
        };
      }
      if (isRetryableStatus(res.status)) {
        lastError = new HttpError(res.status, url);
        if (attempt < maxRetries) {
          const retryAfter = Number(res.headers.get('retry-after'));
          const delay =
            Number.isFinite(retryAfter) && retryAfter > 0
              ? retryAfter * 1000
              : backoffDelayMs(attempt);
          await sleep(delay);
          continue;
        }
        throw lastError;
      }
      if (!res.ok) throw new HttpError(res.status, url);

      const text = await res.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error(`Svaret från ${u.hostname} var inte giltig JSON.`);
      }
      if (parsed === null || typeof parsed !== 'object') {
        throw new Error(`Svaret från ${u.hostname} var inte ett JSON-objekt.`);
      }
      const etag = res.headers.get('etag') ?? undefined;
      const lastModified = res.headers.get('last-modified') ?? undefined;
      if (cache) {
        cache[url] = {
          fetched_at: nowIso(),
          ...(etag ? { etag } : {}),
          ...(lastModified ? { last_modified: lastModified } : {}),
        };
      }
      return { status: res.status, notModified: false, data: parsed as T, etag, lastModified };
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof HttpError && !isRetryableStatus(err.status)) throw err;
      if (err instanceof HostNotAllowedError) throw err;
      lastError = err;
      if (attempt < maxRetries) {
        await sleep(backoffDelayMs(attempt));
        continue;
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error(`Hämtning misslyckades: ${url}`);
}

/** Redigerar bort eventuell API-nyckel ur text innan loggning. */
export function redactSecrets(text: string, env: NodeJS.ProcessEnv = process.env): string {
  const key = env.NVD_API_KEY?.trim();
  if (!key) return text;
  return text.split(key).join('[REDACTED]');
}
