import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { summarizeNvd, fetchNvd, type NvdResponse } from '../../../scripts/enrich/nvd';
import { filterKev, type KevFeed } from '../../../scripts/enrich/kev';
import { parseEpss, chunk } from '../../../scripts/enrich/epss';
import { collectCveIds } from '../../../scripts/enrich/cve-list';
import { csafCacheName, summarizeCsaf } from '../../../scripts/enrich/csaf';
import { RateLimiter } from '../../../scripts/enrich/http';
import { parseArgs } from '../../../scripts/enrich/run';

const fixture = JSON.parse(
  readFileSync(new URL('../../fixtures/enrich/nvd-CVE-2025-41450.json', import.meta.url), 'utf8'),
) as NvdResponse;
const limiter = new RateLimiter(
  () => 0,
  async () => {},
);

describe('NVD', () => {
  it('sammanfattar en verklig NVD-post (Danfoss CVE-2025-41450)', () => {
    const s = summarizeNvd(fixture)!;
    expect(s.cve_id).toBe('CVE-2025-41450');
    expect(s.vuln_status).toBe('Deferred');
    expect(s.cvss.some((c) => c.version === '3.1' && c.score === 8.2)).toBe(true);
    expect(s.reference_urls.some((u) => u.includes('dsa-2025-03-01'))).toBe(true);
    expect(s.kev_added).toBeNull();
  });
  it('skriver cache, missing-fil och flaggar Rejected', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'nvd-'));
    const rejected: NvdResponse = {
      ...fixture,
      vulnerabilities: [
        {
          cve: { ...fixture.vulnerabilities[0]!.cve, id: 'CVE-2020-0001', vulnStatus: 'Rejected' },
        },
      ],
    };
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes('CVE-2025-41450'))
        return new Response(JSON.stringify(fixture), { status: 200 });
      if (url.includes('CVE-2020-0001'))
        return new Response(JSON.stringify(rejected), { status: 200 });
      return new Response(JSON.stringify({ ...fixture, totalResults: 0, vulnerabilities: [] }), {
        status: 200,
      });
    }) as unknown as typeof fetch;
    const logs: string[] = [];
    const r = await fetchNvd(['CVE-2025-41450', 'CVE-2020-0001', 'CVE-2099-9999'], {
      dir,
      fetchImpl,
      rateLimiter: limiter,
      sleep: async () => {},
      log: (m) => logs.push(m),
    });
    expect(r.fetched).toEqual(['CVE-2025-41450', 'CVE-2020-0001']);
    expect(r.rejected).toEqual(['CVE-2020-0001']);
    expect(r.missing).toEqual(['CVE-2099-9999']);
    expect(existsSync(join(dir, 'CVE-2025-41450.json'))).toBe(true);
    expect(existsSync(join(dir, 'CVE-2099-9999.missing.json'))).toBe(true);
    expect(logs.some((l) => l.includes('AVVISAD'))).toBe(true);
    // inkrementellt: andra körningen hoppar över färska filer
    const r2 = await fetchNvd(['CVE-2025-41450'], {
      dir,
      fetchImpl,
      rateLimiter: limiter,
      sleep: async () => {},
      log: () => {},
    });
    expect(r2.skipped).toEqual(['CVE-2025-41450']);
  });
});

describe('KEV', () => {
  it('filtrerar feeden till följda CVE:er och bevarar metadata', () => {
    const feed: KevFeed = {
      title: 'CISA Catalog of Known Exploited Vulnerabilities',
      catalogVersion: '2026.11.06',
      dateReleased: '2026-11-06T19:44:45.1797Z',
      count: 3,
      vulnerabilities: [
        {
          cveID: 'CVE-2023-6448',
          vendorProject: 'Unitronics',
          product: 'Vision',
          vulnerabilityName: 'x',
          dateAdded: '2023-12-11',
          shortDescription: '',
          requiredAction: '',
          dueDate: '2023-12-18',
          knownRansomwareCampaignUse: 'Unknown',
        },
        {
          cveID: 'CVE-2021-0001',
          vendorProject: 'Other',
          product: 'y',
          vulnerabilityName: 'y',
          dateAdded: '2021-01-01',
          shortDescription: '',
          requiredAction: '',
          dueDate: '2021-01-15',
          knownRansomwareCampaignUse: 'Known',
        },
      ],
    };
    const sub = filterKev(feed, ['CVE-2023-6448', 'CVE-2025-41450'], '2026-11-07T00:00:00Z');
    expect(sub.vulnerabilities.map((v) => v.cveID)).toEqual(['CVE-2023-6448']);
    expect(sub.count_total).toBe(3);
    expect(sub.checked_cve_ids).toEqual(['CVE-2023-6448', 'CVE-2025-41450']);
    expect(sub.catalogVersion).toBe('2026.11.06');
  });
});

describe('EPSS', () => {
  it('parsar råsvar och kastar ogiltiga poster', () => {
    const data = parseEpss({
      status: 'OK',
      data: [
        {
          cve: 'CVE-2025-41451',
          epss: '0.044620000',
          percentile: '0.914960000',
          date: '2026-11-07',
        },
        { cve: 'X', epss: 'abc', percentile: '1', date: '2026-11-07' },
      ],
    });
    expect(data).toHaveLength(1);
    expect(Number(data[0]!.epss)).toBeCloseTo(0.04462);
    expect(parseEpss('<html>')).toEqual([]);
  });
  it('batchar max 100 per anrop', () => {
    expect(
      chunk(
        Array.from({ length: 250 }, (_, i) => i),
        100,
      ).map((c) => c.length),
    ).toEqual([100, 100, 50]);
  });
});

describe('CVE-lista och CSAF', () => {
  it('samlar CVE-ID:n ur godtyckliga strukturer (nycklar och värden)', () => {
    const ids = collectCveIds({
      'CVE-2026-34223': { x: 1 },
      list: [{ cve_id: 'CVE-2025-41450' }, { cve_ids: ['CVE-2022-38465', 'inte-ett-cve'] }],
    });
    expect([...ids].sort()).toEqual(['CVE-2022-38465', 'CVE-2025-41450', 'CVE-2026-34223']);
  });
  it('namnger CSAF-cache per utgivare och id', () => {
    expect(csafCacheName({ advisory_id: 'SSA-330084', issuer: 'Siemens ProductCERT' })).toBe(
      'siemens-ssa-330084.json',
    );
    expect(csafCacheName({ advisory_id: 'ICSA-26-057-10', issuer: 'CISA ICS' })).toBe(
      'cisa-icsa-26-057-10.json',
    );
  });
  it('sammanfattar ett CSAF-dokument', () => {
    const s = summarizeCsaf({
      document: {
        tracking: {
          id: 'SSA-1',
          status: 'interim',
          version: '1',
          current_release_date: '2026-09-08T00:00:00Z',
        },
      },
      vulnerabilities: [{ cve: 'CVE-2026-34223' }],
    });
    expect(s).toEqual({
      id: 'SSA-1',
      status: 'interim',
      version: '1',
      current_release_date: '2026-09-08T00:00:00Z',
      cve_ids: ['CVE-2026-34223'],
    });
  });
});

describe('run.ts argument', () => {
  it('tolkar flaggor och avvisar okända', () => {
    const a = parseArgs(['--only=nvd,kev', '--force', '--dry-run', '--max-age-hours=48']);
    expect([...a.only]).toEqual(['nvd', 'kev']);
    expect(a.force && a.dryRun).toBe(true);
    expect(a.maxAgeHours).toBe(48);
    expect(() => parseArgs(['--only=shodan'])).toThrow();
    expect(() => parseArgs(['--bogus'])).toThrow();
  });
});
