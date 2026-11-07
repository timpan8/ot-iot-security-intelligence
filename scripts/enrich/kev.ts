/**
 * CISA KEV – katalog över sårbarheter med OBSERVERAT utnyttjande i verkliga angrepp.
 * (Inte synonymt med att det finns en publik PoC.) Hämtar hela feeden och sparar ett
 * subset för de CVE:er katalogen följer: sources/enrichment/kev.json.
 */
import { p, writeJson, nowIso } from '../lib/fs';
import { fetchJson, type FetchJsonOptions } from './http';

export const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const KEV_CACHE_PATH = p('sources', 'enrichment', 'kev.json');

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes?: string;
  cwes?: string[];
}
export interface KevFeed {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}
export interface KevSubset {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count_total: number;
  checked_cve_ids: string[];
  fetched_at: string;
  vulnerabilities: KevEntry[];
}

export function filterKev(
  feed: KevFeed,
  cveIds: string[],
  fetchedAt: string = nowIso(),
): KevSubset {
  const wanted = new Set(cveIds);
  return {
    title: feed.title,
    catalogVersion: feed.catalogVersion,
    dateReleased: feed.dateReleased,
    count_total: feed.count,
    checked_cve_ids: [...wanted].sort(),
    fetched_at: fetchedAt,
    vulnerabilities: (feed.vulnerabilities ?? [])
      .filter((v) => wanted.has(v.cveID))
      .sort((a, b) => a.cveID.localeCompare(b.cveID)),
  };
}

export interface KevRunOptions extends FetchJsonOptions {
  outPath?: string;
  dryRun?: boolean;
  log?: (msg: string) => void;
}

export async function fetchKev(
  cveIds: string[],
  opts: KevRunOptions = {},
): Promise<{ hits: number; notModified: boolean; errors: string[] }> {
  const { outPath = KEV_CACHE_PATH, dryRun = false, log = console.log, ...http } = opts;
  if (dryRun) {
    log(`[dry-run] skulle hämta KEV och filtrera på ${cveIds.length} CVE`);
    return { hits: 0, notModified: false, errors: [] };
  }
  try {
    const res = await fetchJson<KevFeed>(KEV_URL, {
      ...http,
      timeoutMs: http.timeoutMs ?? 180_000,
    });
    if (res.notModified) {
      log('KEV: oförändrad (304)');
      return { hits: 0, notModified: true, errors: [] };
    }
    const feed = res.data;
    if (!feed || !Array.isArray(feed.vulnerabilities)) throw new Error('Oväntat KEV-format');
    const subset = filterKev(feed, cveIds);
    writeJson(outPath, subset);
    log(
      `KEV ${subset.catalogVersion}: ${subset.vulnerabilities.length} träffar av ${cveIds.length} kontrollerade`,
    );
    return { hits: subset.vulnerabilities.length, notModified: false, errors: [] };
  } catch (err) {
    return {
      hits: 0,
      notModified: false,
      errors: [err instanceof Error ? err.message : String(err)],
    };
  }
}
