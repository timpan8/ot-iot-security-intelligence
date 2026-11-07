/**
 * Diff-rapport för granskning: jämför enrichment-cachen med föregående commit (git HEAD)
 * och med kuraterade uppgifter. Ändrar ALDRIG kuraterade filer. Allt nytt märks needs_review.
 *
 *   npx tsx scripts/enrich/diff.ts [--base=HEAD]
 *
 * Skriver sources/enrichment/diff-report.md och diff-report.json.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, writeFileSync } from 'node:fs';
import { relative } from 'node:path';
import { p, readJson, writeJson, nowIso, ROOT } from '../lib/fs';
import { summarizeNvd, type NvdResponse, type NvdSummary } from './nvd';
import { parseEpss, type EpssRecord } from './epss';
import type { KevSubset } from './kev';
import { summarizeCsaf, type CsafDoc } from './csaf';

export interface CuratedMatchLike {
  id: string;
  product_family_id: string;
  cve_id?: string | null;
  vulnerability_id?: string | null;
  status?: string;
  verification_status?: string;
  version_rule?: {
    type: string;
    version?: string | null;
    version_end?: string | null;
    text?: string;
  };
  component?: string | null;
}

export interface DiffReport {
  generated_at: string;
  base_ref: string;
  base_available: boolean;
  new_cves: Array<{ cve_id: string; vuln_status: string }>;
  changed_cves: Array<{ cve_id: string; changes: string[] }>;
  rejected_cves: string[];
  missing_cves: string[];
  new_kev: Array<{ cve_id: string; date_added: string }>;
  epss_changes: Array<{
    cve_id: string;
    from: EpssRecord | null;
    to: EpssRecord;
    delta_epss: number;
    delta_percentile: number;
  }>;
  csaf_changes: Array<{ file: string; changes: string[] }>;
  conflicts: Array<{ kind: string; entity_id: string; cve_id: string | null; detail: string }>;
  counts: { cached_cves: number; curated_matches: number };
}

/** Läser filens innehåll i base-ref via git; null om filen saknas där eller git inte går. */
export function readFromGit(
  relPath: string,
  baseRef: string = 'HEAD',
  cwd: string = ROOT,
): string | null {
  try {
    return execFileSync('git', ['show', `${baseRef}:${relPath}`], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return null;
  }
}

export function gitBaseAvailable(baseRef: string = 'HEAD', cwd: string = ROOT): boolean {
  try {
    execFileSync('git', ['rev-parse', '--verify', `${baseRef}^{commit}`], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

function parseJsonSafe<T>(text: string | null): T | null {
  if (text === null) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

export function normalizeVersion(v: string | null | undefined): string {
  return (v ?? '').trim().toLowerCase().replace(/^v/, '');
}

export function compareNvdSummaries(prev: NvdSummary | null, cur: NvdSummary): string[] {
  const changes: string[] = [];
  if (!prev) return changes;
  if (prev.vuln_status !== cur.vuln_status)
    changes.push(`vulnStatus: ${prev.vuln_status} → ${cur.vuln_status}`);
  if (prev.last_modified !== cur.last_modified)
    changes.push(`lastModified: ${prev.last_modified} → ${cur.last_modified}`);
  const key = (c: NvdSummary['cvss'][number]) => `${c.version}|${c.type}|${c.score}|${c.vector}`;
  const prevC = new Set(prev.cvss.map(key));
  const curC = new Set(cur.cvss.map(key));
  for (const c of cur.cvss)
    if (!prevC.has(key(c)))
      changes.push(`CVSS ${c.version} (${c.type}): ny/ändrad poäng ${c.score} ${c.vector}`);
  for (const c of prev.cvss)
    if (!curC.has(key(c)))
      changes.push(`CVSS ${c.version} (${c.type}): borttagen (${c.score} ${c.vector})`);
  const bkey = (b: NvdSummary['version_bounds'][number]) => JSON.stringify(b);
  const prevB = new Set(prev.version_bounds.map(bkey));
  const curB = new Set(cur.version_bounds.map(bkey));
  for (const b of cur.version_bounds)
    if (!prevB.has(bkey(b)))
      changes.push(
        `CPE-versionsgräns ny/ändrad: ${b.criteria} ${JSON.stringify({ ...b, criteria: undefined })}`,
      );
  for (const b of prev.version_bounds)
    if (!curB.has(bkey(b))) changes.push(`CPE-versionsgräns borttagen: ${b.criteria}`);
  const prevR = new Set(prev.reference_urls);
  for (const r of cur.reference_urls) if (!prevR.has(r)) changes.push(`ny referens: ${r}`);
  if (prev.kev_added !== cur.kev_added)
    changes.push(`KEV-markering i NVD: ${prev.kev_added} → ${cur.kev_added}`);
  return changes;
}

/**
 * Konfliktkontroll: en kuraterad match med verification_status=verified_primary som anger en
 * versionsgräns som inte återfinns bland NVD:s CPE-gränser för samma CVE.
 */
export function findMatchConflicts(
  matches: CuratedMatchLike[],
  summaries: Map<string, NvdSummary>,
): DiffReport['conflicts'] {
  const conflicts: DiffReport['conflicts'] = [];
  for (const m of matches) {
    const cve =
      m.cve_id ??
      (m.vulnerability_id ? m.vulnerability_id.replace(/^cve-/, 'CVE-').toUpperCase() : null);
    if (!cve) continue;
    const s = summaries.get(cve);
    if (!s) continue;
    if (s.vuln_status === 'Rejected') {
      conflicts.push({
        kind: 'rejected_cve_in_match',
        entity_id: m.id,
        cve_id: cve,
        detail: `${cve} är avvisad (Rejected) i NVD men används i matchning ${m.id}.`,
      });
      continue;
    }
    if (m.verification_status !== 'verified_primary' || m.status !== 'affected') continue;
    const rule = m.version_rule;
    if (!rule || !['lt', 'lte'].includes(rule.type) || !rule.version) continue;
    if (s.version_bounds.length === 0) continue; // NVD har ingen CPE-gräns – ingen konflikt, bara avsaknad
    const want = normalizeVersion(rule.version);
    const bounds = s.version_bounds.map((b) =>
      normalizeVersion(b.end_excluding ?? b.end_including ?? ''),
    );
    if (!bounds.includes(want)) {
      conflicts.push({
        kind: 'version_bound_mismatch',
        entity_id: m.id,
        cve_id: cve,
        detail: `Kuraterad gräns ${rule.type} ${rule.version} saknas bland NVD:s CPE-gränser [${[...new Set(bounds)].join(', ')}] för ${cve}.`,
      });
    }
  }
  return conflicts;
}

export function buildDiff(opts: { baseRef?: string; root?: string } = {}): DiffReport {
  const baseRef = opts.baseRef ?? 'HEAD';
  const root = opts.root ?? ROOT;
  const rel = (abs: string) => relative(root, abs).split('\\').join('/');
  const baseAvailable = gitBaseAvailable(baseRef, root);

  const nvdDir = `${root}/sources/enrichment/nvd`;
  const report: DiffReport = {
    generated_at: nowIso(),
    base_ref: baseRef,
    base_available: baseAvailable,
    new_cves: [],
    changed_cves: [],
    rejected_cves: [],
    missing_cves: [],
    new_kev: [],
    epss_changes: [],
    csaf_changes: [],
    conflicts: [],
    counts: { cached_cves: 0, curated_matches: 0 },
  };

  const summaries = new Map<string, NvdSummary>();
  if (existsSync(nvdDir)) {
    for (const f of readdirSync(nvdDir).sort()) {
      if (/^CVE-\d{4}-\d{4,}\.missing\.json$/.test(f)) {
        report.missing_cves.push(f.replace('.missing.json', ''));
        continue;
      }
      if (!/^CVE-\d{4}-\d{4,}\.json$/.test(f)) continue;
      const abs = `${nvdDir}/${f}`;
      const cur = summarizeNvd(readJson<NvdResponse>(abs));
      if (!cur) continue;
      summaries.set(cur.cve_id, cur);
      report.counts.cached_cves++;
      if (cur.vuln_status === 'Rejected') report.rejected_cves.push(cur.cve_id);
      const prevRaw = baseAvailable
        ? parseJsonSafe<NvdResponse>(readFromGit(rel(abs), baseRef, root))
        : null;
      const prev = prevRaw ? summarizeNvd(prevRaw) : null;
      if (!prev) {
        report.new_cves.push({ cve_id: cur.cve_id, vuln_status: cur.vuln_status });
      } else {
        const changes = compareNvdSummaries(prev, cur);
        if (changes.length) report.changed_cves.push({ cve_id: cur.cve_id, changes });
      }
    }
  }

  // KEV
  const kevPath = `${root}/sources/enrichment/kev.json`;
  if (existsSync(kevPath)) {
    const cur = readJson<KevSubset>(kevPath);
    const prev = baseAvailable
      ? parseJsonSafe<KevSubset>(readFromGit(rel(kevPath), baseRef, root))
      : null;
    const prevIds = new Set((prev?.vulnerabilities ?? []).map((v) => v.cveID));
    for (const v of cur.vulnerabilities ?? [])
      if (!prevIds.has(v.cveID)) report.new_kev.push({ cve_id: v.cveID, date_added: v.dateAdded });
  }

  // EPSS
  const epssPath = `${root}/sources/enrichment/epss.json`;
  if (existsSync(epssPath)) {
    const cur = parseEpss(readJson(epssPath));
    const prevList = baseAvailable
      ? parseEpss(parseJsonSafe(readFromGit(rel(epssPath), baseRef, root)))
      : [];
    const prevMap = new Map(prevList.map((r) => [r.cve, r]));
    for (const r of cur) {
      const before = prevMap.get(r.cve) ?? null;
      const dE = Number(r.epss) - Number(before?.epss ?? 0);
      const dP = Number(r.percentile) - Number(before?.percentile ?? 0);
      if (before && (Math.abs(dE) > 0.05 || Math.abs(dP) > 0.1)) {
        report.epss_changes.push({
          cve_id: r.cve,
          from: before,
          to: r,
          delta_epss: round(dE),
          delta_percentile: round(dP),
        });
      }
    }
  }

  // CSAF
  const csafDir = `${root}/sources/enrichment/csaf`;
  if (existsSync(csafDir)) {
    for (const f of readdirSync(csafDir).sort()) {
      if (!f.endsWith('.json')) continue;
      const abs = `${csafDir}/${f}`;
      const cur = summarizeCsaf(readJson<CsafDoc>(abs));
      const prevDoc = baseAvailable
        ? parseJsonSafe<CsafDoc>(readFromGit(rel(abs), baseRef, root))
        : null;
      if (!prevDoc) {
        report.csaf_changes.push({
          file: f,
          changes: [`nytt dokument ${cur.id ?? f} (${cur.status ?? '?'}, v${cur.version ?? '?'})`],
        });
        continue;
      }
      const prev = summarizeCsaf(prevDoc);
      const changes: string[] = [];
      if (prev.status !== cur.status) changes.push(`status: ${prev.status} → ${cur.status}`);
      if (prev.version !== cur.version) changes.push(`version: ${prev.version} → ${cur.version}`);
      if (prev.current_release_date !== cur.current_release_date)
        changes.push(
          `current_release_date: ${prev.current_release_date} → ${cur.current_release_date}`,
        );
      const prevC = new Set(prev.cve_ids);
      for (const c of cur.cve_ids) if (!prevC.has(c)) changes.push(`ny CVE i bulletin: ${c}`);
      if (changes.length) report.csaf_changes.push({ file: f, changes });
    }
  }

  // Konflikter mot kuraterade uppgifter
  const matchesPath = `${root}/sources/curated/matches.json`;
  if (existsSync(matchesPath)) {
    const raw = readJson<unknown>(matchesPath);
    const matches = Array.isArray(raw)
      ? (raw as CuratedMatchLike[])
      : raw && typeof raw === 'object' && Array.isArray((raw as { matches?: unknown }).matches)
        ? (raw as { matches: CuratedMatchLike[] }).matches
        : [];
    report.counts.curated_matches = matches.length;
    report.conflicts.push(...findMatchConflicts(matches, summaries));
  }
  const overridesPath = `${root}/sources/curated/vulnerability_overrides.json`;
  if (existsSync(overridesPath)) {
    const ovRaw = readJson<Record<string, unknown>>(overridesPath);
    const ov =
      ovRaw && typeof ovRaw['overrides'] === 'object' && ovRaw['overrides'] !== null
        ? (ovRaw['overrides'] as Record<string, { verification_status?: string }>)
        : (Object.fromEntries(
            Object.entries(ovRaw ?? {}).filter(([k]) => !k.startsWith('_')),
          ) as Record<string, { verification_status?: string }>);
    for (const [cve, o] of Object.entries(ov)) {
      const s = summaries.get(cve);
      if (!s) {
        report.conflicts.push({
          kind: 'override_without_cache',
          entity_id: cve,
          cve_id: cve,
          detail: `Kuraterad uppgift för ${cve} men ingen NVD-post i cachen (reserverad/avvisad/ej hämtad?).`,
        });
      } else if (s.vuln_status === 'Rejected' && o?.verification_status === 'verified_primary') {
        report.conflicts.push({
          kind: 'rejected_cve_marked_verified',
          entity_id: cve,
          cve_id: cve,
          detail: `${cve} är Rejected i NVD men markerad verified_primary.`,
        });
      }
    }
  }

  return report;
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000;
}

export function renderMarkdown(r: DiffReport): string {
  const lines: string[] = [];
  lines.push('# Diff-rapport: automatisk datauppdatering (kräver granskning)');
  lines.push('');
  lines.push(`Genererad: ${r.generated_at}  `);
  lines.push(
    `Jämförelsebas: \`${r.base_ref}\`${r.base_available ? '' : ' (ej tillgänglig – allt rapporteras som nytt)'}  `,
  );
  lines.push(
    `Cachade CVE-poster: ${r.counts.cached_cves} · Kuraterade matchningar: ${r.counts.curated_matches}`,
  );
  lines.push('');
  lines.push(
    '> Alla poster nedan har status **needs_review**. Extern data skriver aldrig över mänskligt verifierade uppgifter; konflikter måste avgöras manuellt och dokumenteras i `sources/curated/`.',
  );
  lines.push('');
  const section = (title: string, items: string[]) => {
    lines.push(`## ${title} (${items.length})`);
    lines.push('');
    if (items.length === 0) lines.push('_Inga._');
    else for (const i of items) lines.push(`- ${i}`);
    lines.push('');
  };
  section(
    'Kräver mänsklig granskning (disputed-kandidater)',
    r.conflicts.map(
      (c) => `**${c.kind}** – ${c.entity_id}${c.cve_id ? ` (${c.cve_id})` : ''}: ${c.detail}`,
    ),
  );
  section('Avvisade CVE (Rejected)', r.rejected_cves);
  section('Saknade CVE i NVD (reserverade/avvisade?)', r.missing_cves);
  section(
    'Nya KEV-träffar (observerat utnyttjande)',
    r.new_kev.map((k) => `${k.cve_id} – tillagd ${k.date_added}`),
  );
  section(
    'Nya CVE-poster i cachen',
    r.new_cves.map((c) => `${c.cve_id} (${c.vuln_status})`),
  );
  section(
    'Ändrade CVE-poster',
    r.changed_cves.map((c) => `${c.cve_id}:\n${c.changes.map((x) => `  - ${x}`).join('\n')}`),
  );
  section(
    'EPSS-förändringar (Δepss > 0,05 eller Δpercentil > 0,1)',
    r.epss_changes.map(
      (e) =>
        `${e.cve_id}: ${e.from?.epss ?? '–'} → ${e.to.epss} (Δ ${e.delta_epss}), percentil ${e.from?.percentile ?? '–'} → ${e.to.percentile}`,
    ),
  );
  section(
    'CSAF-ändringar',
    r.csaf_changes.map((c) => `${c.file}: ${c.changes.join('; ')}`),
  );
  return lines.join('\n') + '\n';
}

export function hasChanges(r: DiffReport): boolean {
  return (
    r.new_cves.length +
      r.changed_cves.length +
      r.rejected_cves.length +
      r.new_kev.length +
      r.epss_changes.length +
      r.csaf_changes.length +
      r.conflicts.length >
    0
  );
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const baseArg = process.argv.slice(2).find((a) => a.startsWith('--base='));
  const baseRef = baseArg ? baseArg.slice('--base='.length) : 'HEAD';
  if (!/^[A-Za-z0-9_./~^-]+$/.test(baseRef)) {
    console.error('Ogiltig --base');
    process.exit(2);
  }
  const report = buildDiff({ baseRef });
  writeJson(p('sources', 'enrichment', 'diff-report.json'), report);
  const md = renderMarkdown(report);
  writeFileSync(p('sources', 'enrichment', 'diff-report.md'), md, 'utf8');
  console.log(md);
  console.error(
    hasChanges(report) ? 'Diff: ändringar finns (needs_review).' : 'Diff: inga ändringar.',
  );
}
