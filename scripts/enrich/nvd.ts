/**
 * NVD CVE API 2.0 – hämtar en CVE-post per anrop (?cveId=) och sparar RÅTT svar i
 * sources/enrichment/nvd/<CVE-ID>.json. Inkrementellt: hoppar över poster som hämtats
 * nyligen om inte --force. Saknade poster (totalResults 0) skrivs som <id>.missing.json.
 */
import { existsSync, statSync } from 'node:fs';
import { p, readJson, writeJson, nowIso } from '../lib/fs';
import { fetchJson, HttpError, type FetchJsonOptions } from './http';

export const NVD_CVE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
export const NVD_CACHE_DIR = p('sources', 'enrichment', 'nvd');

export interface NvdResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities: Array<{ cve: NvdCve }>;
}
export interface NvdCve {
  id: string;
  sourceIdentifier?: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: Array<{ lang: string; value: string }>;
  metrics?: Record<string, Array<Record<string, unknown>>>;
  weaknesses?: Array<{
    source: string;
    type: string;
    description: Array<{ lang: string; value: string }>;
  }>;
  configurations?: Array<{
    nodes: Array<{
      cpeMatch: Array<Record<string, unknown> & { criteria: string; vulnerable: boolean }>;
    }>;
  }>;
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
  cisaExploitAdd?: string;
  cisaActionDue?: string;
  cisaVulnerabilityName?: string;
}

export interface NvdStepResult {
  fetched: string[];
  skipped: string[];
  missing: string[];
  rejected: string[];
  errors: Array<{ cve_id: string; message: string }>;
}

export function cacheFileFor(cveId: string, dir: string = NVD_CACHE_DIR): string {
  return `${dir}/${cveId}.json`;
}

export function isFresh(path: string, maxAgeHours: number, now: number = Date.now()): boolean {
  if (!existsSync(path)) return false;
  const ageMs = now - statSync(path).mtimeMs;
  return ageMs < maxAgeHours * 3_600_000;
}

/** Kompakt sammanfattning av en NVD-post – används av diff och tester. */
export interface NvdSummary {
  cve_id: string;
  vuln_status: string;
  last_modified: string | null;
  cvss: Array<{
    version: string;
    score: number | null;
    vector: string | null;
    type: string | null;
  }>;
  version_bounds: Array<{
    criteria: string;
    end_excluding?: string;
    end_including?: string;
    start_including?: string;
  }>;
  reference_urls: string[];
  kev_added: string | null;
}

export function summarizeNvd(resp: NvdResponse): NvdSummary | null {
  const cve = resp.vulnerabilities?.[0]?.cve;
  if (!cve) return null;
  const cvss: NvdSummary['cvss'] = [];
  for (const [key, list] of Object.entries(cve.metrics ?? {})) {
    if (!key.startsWith('cvssMetric')) continue;
    for (const m of list) {
      const data = (m['cvssData'] ?? {}) as Record<string, unknown>;
      cvss.push({
        version: String(data['version'] ?? key.replace('cvssMetricV', '')),
        score: typeof data['baseScore'] === 'number' ? data['baseScore'] : null,
        vector: typeof data['vectorString'] === 'string' ? data['vectorString'] : null,
        type: typeof m['type'] === 'string' ? (m['type'] as string) : null,
      });
    }
  }
  const version_bounds: NvdSummary['version_bounds'] = [];
  for (const cfg of cve.configurations ?? []) {
    for (const node of cfg.nodes) {
      for (const m of node.cpeMatch) {
        if (!m.vulnerable) continue;
        version_bounds.push({
          criteria: m.criteria,
          ...(typeof m['versionEndExcluding'] === 'string'
            ? { end_excluding: m['versionEndExcluding'] as string }
            : {}),
          ...(typeof m['versionEndIncluding'] === 'string'
            ? { end_including: m['versionEndIncluding'] as string }
            : {}),
          ...(typeof m['versionStartIncluding'] === 'string'
            ? { start_including: m['versionStartIncluding'] as string }
            : {}),
        });
      }
    }
  }
  return {
    cve_id: cve.id,
    vuln_status: cve.vulnStatus ?? 'unknown',
    last_modified: cve.lastModified ?? null,
    cvss,
    version_bounds,
    reference_urls: [...new Set((cve.references ?? []).map((r) => r.url))].sort(),
    kev_added: cve.cisaExploitAdd ?? null,
  };
}

export interface NvdRunOptions extends FetchJsonOptions {
  dir?: string;
  force?: boolean;
  maxAgeHours?: number;
  dryRun?: boolean;
  log?: (msg: string) => void;
}

export async function fetchNvd(cveIds: string[], opts: NvdRunOptions = {}): Promise<NvdStepResult> {
  const {
    dir = NVD_CACHE_DIR,
    force = false,
    maxAgeHours = 24,
    dryRun = false,
    log = console.log,
    ...http
  } = opts;
  const result: NvdStepResult = { fetched: [], skipped: [], missing: [], rejected: [], errors: [] };
  for (const id of cveIds) {
    const file = cacheFileFor(id, dir);
    if (!force && isFresh(file, maxAgeHours)) {
      result.skipped.push(id);
      continue;
    }
    if (dryRun) {
      log(`[dry-run] skulle hämta ${id}`);
      result.skipped.push(id);
      continue;
    }
    const url = `${NVD_CVE_URL}?cveId=${encodeURIComponent(id)}`;
    try {
      const res = await fetchJson<NvdResponse>(url, { ...http, conditional: false });
      const data = res.data;
      if (!data || typeof data.totalResults !== 'number') {
        result.errors.push({ cve_id: id, message: 'Oväntat svarsformat från NVD' });
        continue;
      }
      if (data.totalResults < 1 || !data.vulnerabilities?.length) {
        writeJson(`${dir}/${id}.missing.json`, {
          cve_id: id,
          checked_at: nowIso(),
          note: 'totalResults=0 – kan vara reserverad eller avvisad',
        });
        result.missing.push(id);
        log(`NVD: ${id} saknas (reserverad/avvisad?)`);
        continue;
      }
      writeJson(file, data);
      result.fetched.push(id);
      const status = data.vulnerabilities[0]?.cve.vulnStatus;
      if (status === 'Rejected') {
        result.rejected.push(id);
        log(`NVD: ${id} är AVVISAD (Rejected) – kräver granskning`);
      } else {
        log(`NVD: ${id} hämtad (${status ?? 'okänd status'})`);
      }
    } catch (err) {
      const message =
        err instanceof HttpError
          ? `HTTP ${err.status}`
          : err instanceof Error
            ? err.message
            : String(err);
      result.errors.push({ cve_id: id, message });
      log(`NVD: fel för ${id}: ${message}`);
    }
  }
  return result;
}

export function readNvdCache(cveId: string, dir: string = NVD_CACHE_DIR): NvdResponse | null {
  const file = cacheFileFor(cveId, dir);
  return existsSync(file) ? readJson<NvdResponse>(file) : null;
}
