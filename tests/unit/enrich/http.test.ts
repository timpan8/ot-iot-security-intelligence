import { describe, it, expect, vi } from 'vitest';
import {
  assertAllowedUrl,
  HostNotAllowedError,
  fetchJson,
  RateLimiter,
  backoffDelayMs,
  defaultIntervalMs,
  redactSecrets,
  HttpError,
} from '../../../scripts/enrich/http';

const noSleep = async () => {};
const limiter = new RateLimiter(() => 0, noSleep);

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

describe('host-allowlist', () => {
  it('tillåter officiella feeds', () => {
    expect(() =>
      assertAllowedUrl('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-41450'),
    ).not.toThrow();
    expect(() =>
      assertAllowedUrl('https://api.first.org/data/v1/epss?cve=CVE-2025-41450'),
    ).not.toThrow();
    expect(() =>
      assertAllowedUrl(
        'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-057-10.json',
      ),
    ).not.toThrow();
  });
  it('blockerar otillåtna värdar, http och andra GitHub-repon', () => {
    expect(() => assertAllowedUrl('https://evil.example.com/feed.json')).toThrow(
      HostNotAllowedError,
    );
    expect(() => assertAllowedUrl('http://services.nvd.nist.gov/rest/json/cves/2.0')).toThrow(
      HostNotAllowedError,
    );
    expect(() =>
      assertAllowedUrl('https://raw.githubusercontent.com/someone/else/main/x.json'),
    ).toThrow(HostNotAllowedError);
  });
  it('fetchJson gör ingen förfrågan mot otillåten värd', async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchJson('https://evil.example.com/x', { fetchImpl, rateLimiter: limiter, sleep: noSleep }),
    ).rejects.toThrow(HostNotAllowedError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('retry/backoff', () => {
  it('gör om vid 429/5xx med backoff och lyckas sedan', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ e: 1 }, 429, { 'retry-after': '1' }))
      .mockResolvedValueOnce(jsonResponse({ e: 2 }, 503))
      .mockResolvedValueOnce(jsonResponse({ ok: true }, 200, { etag: 'W/"abc"' }));
    const sleeps: number[] = [];
    const cache = {};
    const res = await fetchJson<{ ok: boolean }>(
      'https://api.first.org/data/v1/epss?cve=CVE-2025-41450',
      {
        fetchImpl,
        rateLimiter: limiter,
        sleep: async (ms) => {
          sleeps.push(ms);
        },
        cache,
      },
    );
    expect(res.data).toEqual({ ok: true });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(sleeps[0]).toBe(1000); // Retry-After respekteras
    expect(sleeps[1]).toBeGreaterThanOrEqual(2000); // exponentiell backoff
    expect(cache).toHaveProperty(
      ['https://api.first.org/data/v1/epss?cve=CVE-2025-41450', 'etag'],
      'W/"abc"',
    );
  });
  it('ger upp efter maxRetries', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({}, 500));
    await expect(
      fetchJson('https://api.first.org/data/v1/epss', {
        fetchImpl,
        rateLimiter: limiter,
        sleep: noSleep,
        maxRetries: 2,
      }),
    ).rejects.toBeInstanceOf(HttpError);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });
  it('404 kastas direkt utan retry', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({}, 404));
    await expect(
      fetchJson('https://api.first.org/data/v1/epss', {
        fetchImpl,
        rateLimiter: limiter,
        sleep: noSleep,
      }),
    ).rejects.toMatchObject({ status: 404 });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
  it('skickar If-None-Match från cache och hanterar 304', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(null, { status: 304 }));
    const cache = {
      'https://www.cisa.gov/x.json': { etag: '"e1"', fetched_at: '2026-01-01T00:00:00Z' },
    };
    const res = await fetchJson('https://www.cisa.gov/x.json', {
      fetchImpl,
      rateLimiter: limiter,
      sleep: noSleep,
      cache,
    });
    expect(res.notModified).toBe(true);
    const headers = (fetchImpl.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(headers['If-None-Match']).toBe('"e1"');
  });
  it('avvisar svar som inte är JSON-objekt', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response('<html>', { status: 200 }));
    await expect(
      fetchJson('https://api.first.org/x', {
        fetchImpl,
        rateLimiter: limiter,
        sleep: noSleep,
        maxRetries: 0,
      }),
    ).rejects.toThrow(/JSON/);
  });
  it('backoffDelayMs växer exponentiellt med jitter', () => {
    expect(backoffDelayMs(0, () => 0)).toBe(1000);
    expect(backoffDelayMs(2, () => 0)).toBe(4000);
    expect(backoffDelayMs(2, () => 1)).toBe(5000);
  });
});

describe('rate limiter och nyckelhantering', () => {
  it('väntar mellan anrop till samma värd', async () => {
    let t = 0;
    const sleeps: number[] = [];
    const rl = new RateLimiter(
      () => 6500,
      async (ms) => {
        sleeps.push(ms);
        t += ms;
      },
      () => t,
    );
    await rl.wait('services.nvd.nist.gov');
    t += 1000;
    await rl.wait('services.nvd.nist.gov');
    expect(sleeps).toEqual([5500]);
  });
  it('NVD-intervall beror på om API-nyckel finns', () => {
    expect(defaultIntervalMs('services.nvd.nist.gov', {})).toBe(6500);
    expect(defaultIntervalMs('services.nvd.nist.gov', { NVD_API_KEY: 'x' })).toBe(700);
  });
  it('apiKey-header sätts bara mot NVD och loggas redigerad', async () => {
    const fetchImpl = vi.fn(async (_input: string | URL | Request, _init?: RequestInit) =>
      jsonResponse({ totalResults: 0 }),
    );
    const env = { NVD_API_KEY: 'super-secret-key' };
    await fetchJson('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-41450', {
      fetchImpl,
      rateLimiter: limiter,
      sleep: noSleep,
      env,
    });
    const headers = (fetchImpl.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(headers['apiKey']).toBe('super-secret-key');
    await fetchJson('https://api.first.org/data/v1/epss', {
      fetchImpl,
      rateLimiter: limiter,
      sleep: noSleep,
      env,
    });
    const headers2 = (fetchImpl.mock.calls[1]![1] as RequestInit).headers as Record<string, string>;
    expect(headers2['apiKey']).toBeUndefined();
    expect(redactSecrets('fel: super-secret-key läckte', env)).toBe('fel: [REDACTED] läckte');
  });
});
