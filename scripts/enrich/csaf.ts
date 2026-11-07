/**
 * CSAF-dokument (maskinläsbara bulletiner) för advisories i sources/curated/advisories.json
 * som har `csaf_url`. Sparas råa under sources/enrichment/csaf/<issuer>-<id>.json.
 * Endast Siemens ProductCERT och CISA (via cisagov/CSAF på GitHub) tillåts av http-allowlistan.
 */
import { existsSync } from 'node:fs';
import { p, readJson, writeJson } from '../lib/fs';
import { fetchJson, HttpError, type FetchJsonOptions } from './http';

export const CSAF_CACHE_DIR = p('sources', 'enrichment', 'csaf');

export interface CuratedAdvisoryLike {
  advisory_id: string;
  issuer?: string;
  csaf_url?: string | null;
}

export function csafCacheName(advisory: CuratedAdvisoryLike): string {
  const issuer =
    (advisory.issuer ?? 'unknown')
      .toLowerCase()
      .replace(/productcert|ics|\s+/g, ' ')
      .trim()
      .split(/\s+/)[0] ?? 'unknown';
  const slug = advisory.advisory_id.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return `${issuer}-${slug}.json`;
}

export interface CsafDoc {
  document?: {
    title?: string;
    tracking?: {
      id?: string;
      status?: string;
      version?: string;
      initial_release_date?: string;
      current_release_date?: string;
      revision_history?: Array<{ number: string; date: string; summary: string }>;
    };
  };
  vulnerabilities?: Array<{ cve?: string; product_status?: Record<string, string[]> }>;
}

export function summarizeCsaf(doc: CsafDoc): {
  id: string | null;
  status: string | null;
  version: string | null;
  current_release_date: string | null;
  cve_ids: string[];
} {
  const tr = doc.document?.tracking ?? {};
  return {
    id: tr.id ?? null,
    status: tr.status ?? null,
    version: tr.version ?? null,
    current_release_date: tr.current_release_date ?? null,
    cve_ids: [
      ...new Set((doc.vulnerabilities ?? []).map((v) => v.cve).filter((c): c is string => !!c)),
    ].sort(),
  };
}

export function loadCuratedAdvisories(
  path: string = p('sources', 'curated', 'advisories.json'),
): CuratedAdvisoryLike[] {
  if (!existsSync(path)) return [];
  const raw = readJson<unknown>(path);
  const data = Array.isArray(raw)
    ? raw
    : raw && typeof raw === 'object' && Array.isArray((raw as { advisories?: unknown }).advisories)
      ? (raw as { advisories: unknown[] }).advisories
      : [];
  return data.filter(
    (a): a is CuratedAdvisoryLike =>
      !!a && typeof a === 'object' && typeof (a as CuratedAdvisoryLike).advisory_id === 'string',
  );
}

export interface CsafRunOptions extends FetchJsonOptions {
  dir?: string;
  dryRun?: boolean;
  log?: (msg: string) => void;
}

export async function fetchCsaf(
  advisories: CuratedAdvisoryLike[],
  opts: CsafRunOptions = {},
): Promise<{
  fetched: string[];
  skipped: string[];
  errors: Array<{ advisory_id: string; message: string }>;
}> {
  const { dir = CSAF_CACHE_DIR, dryRun = false, log = console.log, ...http } = opts;
  const out = {
    fetched: [] as string[],
    skipped: [] as string[],
    errors: [] as Array<{ advisory_id: string; message: string }>,
  };
  for (const adv of advisories) {
    if (!adv.csaf_url) {
      out.skipped.push(adv.advisory_id);
      continue;
    }
    if (dryRun) {
      log(`[dry-run] skulle hämta CSAF ${adv.advisory_id}`);
      out.skipped.push(adv.advisory_id);
      continue;
    }
    try {
      const res = await fetchJson<CsafDoc>(adv.csaf_url, http);
      if (res.notModified) {
        out.skipped.push(adv.advisory_id);
        log(`CSAF ${adv.advisory_id}: oförändrad (304)`);
        continue;
      }
      if (!res.data?.document?.tracking)
        throw new Error('Svaret saknar document.tracking – inte ett CSAF-dokument');
      writeJson(`${dir}/${csafCacheName(adv)}`, res.data);
      out.fetched.push(adv.advisory_id);
      const s = summarizeCsaf(res.data);
      log(
        `CSAF ${adv.advisory_id}: ${s.status ?? '?'} v${s.version ?? '?'} (${s.current_release_date ?? '?'}), ${s.cve_ids.length} CVE`,
      );
    } catch (err) {
      const message =
        err instanceof HttpError
          ? `HTTP ${err.status}`
          : err instanceof Error
            ? err.message
            : String(err);
      out.errors.push({ advisory_id: adv.advisory_id, message });
      log(`CSAF ${adv.advisory_id}: fel – ${message}`);
    }
  }
  return out;
}
