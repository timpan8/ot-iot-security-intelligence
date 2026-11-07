/**
 * FIRST EPSS API – statistisk sannolikhetsindikator (INTE bevis för exploatering,
 * INTE en modell av OT-konsekvens). Batchar upp till 100 CVE per anrop och skriver
 * sources/enrichment/epss.json i API:ts råformat {status, status-code, version, total, data[]}.
 */
import { p, writeJson } from '../lib/fs';
import { fetchJson, type FetchJsonOptions } from './http';

export const EPSS_URL = 'https://api.first.org/data/v1/epss';
export const EPSS_CACHE_PATH = p('sources', 'enrichment', 'epss.json');
export const EPSS_BATCH_SIZE = 100;

export interface EpssRecord {
  cve: string;
  epss: string;
  percentile: string;
  date: string;
}
export interface EpssResponse {
  status: string;
  'status-code'?: number;
  version?: string;
  access?: string;
  total?: number;
  offset?: number;
  limit?: number;
  data: EpssRecord[];
}

export function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

export function parseEpss(resp: unknown): EpssRecord[] {
  if (!resp || typeof resp !== 'object') return [];
  const data = (resp as EpssResponse).data;
  if (!Array.isArray(data)) return [];
  return data.filter(
    (d): d is EpssRecord =>
      !!d &&
      typeof d.cve === 'string' &&
      typeof d.epss === 'string' &&
      typeof d.percentile === 'string' &&
      typeof d.date === 'string' &&
      Number.isFinite(Number(d.epss)) &&
      Number.isFinite(Number(d.percentile)),
  );
}

export interface EpssRunOptions extends FetchJsonOptions {
  outPath?: string;
  dryRun?: boolean;
  log?: (msg: string) => void;
}

export async function fetchEpss(
  cveIds: string[],
  opts: EpssRunOptions = {},
): Promise<{ fetched: number; errors: string[]; response: EpssResponse | null }> {
  const { outPath = EPSS_CACHE_PATH, dryRun = false, log = console.log, ...http } = opts;
  const errors: string[] = [];
  const all: EpssRecord[] = [];
  let meta: Partial<EpssResponse> = {};
  for (const batch of chunk(cveIds, EPSS_BATCH_SIZE)) {
    const url = `${EPSS_URL}?cve=${batch.join(',')}`;
    if (dryRun) {
      log(`[dry-run] skulle hämta EPSS för ${batch.length} CVE`);
      continue;
    }
    try {
      const res = await fetchJson<EpssResponse>(url, { ...http, conditional: false });
      if (res.data) {
        meta = { status: res.data.status, version: res.data.version, access: res.data.access };
        all.push(...parseEpss(res.data));
      }
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  if (dryRun) return { fetched: 0, errors, response: null };
  if (all.length === 0 && errors.length > 0) return { fetched: 0, errors, response: null };
  const response: EpssResponse = {
    status: meta.status ?? 'OK',
    'status-code': 200,
    version: meta.version ?? '1.0',
    access: meta.access ?? 'public',
    total: all.length,
    offset: 0,
    limit: all.length,
    data: all.sort((a, b) => a.cve.localeCompare(b.cve)),
  };
  writeJson(outPath, response);
  log(`EPSS: ${all.length} poster skrivna (${response.data[0]?.date ?? 'okänt datum'})`);
  return { fetched: all.length, errors, response };
}
