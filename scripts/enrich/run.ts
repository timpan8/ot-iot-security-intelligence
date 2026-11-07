/**
 * Orkestrerar datainhämtning: nvd → epss → kev → csaf.
 *
 *   npx tsx scripts/enrich/run.ts [--only=nvd,epss,kev,csaf] [--force] [--dry-run] [--max-age-hours=24]
 *
 * Skriver sources/enrichment/last-run.json. Exit-kod ≠ 0 endast vid hårda fel
 * (t.ex. inget steg kunde nå nätet), inte vid enskilda 404/saknade poster.
 * Extern data skriver ALDRIG över kuraterade uppgifter – det sker i normalize/diff med konfliktredovisning.
 */
import { p, writeJson, nowIso } from '../lib/fs';
import { deriveCveList } from './cve-list';
import { fetchNvd } from './nvd';
import { fetchEpss } from './epss';
import { fetchKev } from './kev';
import { fetchCsaf, loadCuratedAdvisories } from './csaf';
import { loadHttpCache, saveHttpCache, redactSecrets } from './http';

export interface StepResult {
  name: string;
  ok: boolean;
  fetched: number;
  skipped: number;
  errors: string[];
  details?: Record<string, unknown>;
}

export interface RunArgs {
  only: Set<string>;
  force: boolean;
  dryRun: boolean;
  maxAgeHours: number;
}

export function parseArgs(argv: string[]): RunArgs {
  const args: RunArgs = {
    only: new Set(['nvd', 'epss', 'kev', 'csaf']),
    force: false,
    dryRun: false,
    maxAgeHours: 24,
  };
  for (const a of argv) {
    if (a === '--force') args.force = true;
    else if (a === '--dry-run') args.dryRun = true;
    else if (a.startsWith('--only=')) {
      const list = a
        .slice('--only='.length)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const valid = list.filter((s) => ['nvd', 'epss', 'kev', 'csaf'].includes(s));
      if (valid.length !== list.length) throw new Error(`Okänt steg i --only: ${list.join(',')}`);
      args.only = new Set(valid);
    } else if (a.startsWith('--max-age-hours=')) {
      const n = Number(a.slice('--max-age-hours='.length));
      if (!Number.isFinite(n) || n < 0) throw new Error('--max-age-hours måste vara ett tal ≥ 0');
      args.maxAgeHours = n;
    } else if (a.startsWith('--')) {
      throw new Error(`Okänd flagga: ${a}`);
    }
  }
  return args;
}

export async function runEnrichment(
  args: RunArgs,
  log: (m: string) => void = (m) => console.log(redactSecrets(m)),
) {
  const startedAt = nowIso();
  const cache = loadHttpCache();
  const cveIds = deriveCveList();
  log(
    `Enrichment startar: ${cveIds.length} CVE-ID:n, steg: ${[...args.only].join(', ')}${args.dryRun ? ' (dry-run)' : ''}`,
  );
  const steps: StepResult[] = [];

  if (args.only.has('nvd')) {
    const r = await fetchNvd(cveIds, {
      force: args.force,
      maxAgeHours: args.maxAgeHours,
      dryRun: args.dryRun,
      cache,
      log,
    });
    steps.push({
      name: 'nvd',
      ok: r.errors.length < cveIds.length || cveIds.length === 0,
      fetched: r.fetched.length,
      skipped: r.skipped.length,
      errors: r.errors.map((e) => `${e.cve_id}: ${e.message}`),
      details: { missing: r.missing, rejected: r.rejected },
    });
  }
  if (args.only.has('epss')) {
    const r = await fetchEpss(cveIds, { dryRun: args.dryRun, cache, log });
    steps.push({
      name: 'epss',
      ok: args.dryRun || r.errors.length === 0 || r.fetched > 0,
      fetched: r.fetched,
      skipped: 0,
      errors: r.errors,
    });
  }
  if (args.only.has('kev')) {
    const r = await fetchKev(cveIds, { dryRun: args.dryRun, cache, conditional: !args.force, log });
    steps.push({
      name: 'kev',
      ok: r.errors.length === 0,
      fetched: r.notModified ? 0 : r.hits,
      skipped: r.notModified ? 1 : 0,
      errors: r.errors,
    });
  }
  if (args.only.has('csaf')) {
    const advisories = loadCuratedAdvisories();
    const r = await fetchCsaf(advisories, {
      dryRun: args.dryRun,
      cache,
      conditional: !args.force,
      log,
    });
    steps.push({
      name: 'csaf',
      ok: r.errors.length < Math.max(1, advisories.filter((a) => a.csaf_url).length),
      fetched: r.fetched.length,
      skipped: r.skipped.length,
      errors: r.errors.map((e) => `${e.advisory_id}: ${e.message}`),
    });
  }

  if (!args.dryRun) saveHttpCache(cache);
  const summary = {
    started_at: startedAt,
    finished_at: nowIso(),
    dry_run: args.dryRun,
    cve_count: cveIds.length,
    steps,
  };
  if (!args.dryRun) writeJson(p('sources', 'enrichment', 'last-run.json'), summary);
  for (const s of steps)
    log(
      `  ${s.ok ? 'OK ' : 'FEL'} ${s.name}: hämtade ${s.fetched}, hoppade över ${s.skipped}, fel ${s.errors.length}`,
    );
  return summary;
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  let args: RunArgs;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    process.exit(2);
  }
  runEnrichment(args)
    .then((summary) => {
      const hardFailure = summary.steps.length > 0 && summary.steps.every((s) => !s.ok);
      if (hardFailure) {
        console.error('Alla steg misslyckades – nätet nere eller blockerat?');
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error(
        'Enrichment avbröts:',
        redactSecrets(err instanceof Error ? err.message : String(err)),
      );
      process.exit(1);
    });
}
